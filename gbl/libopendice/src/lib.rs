// Copyright 2025, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This is a wrapper for libopendice.

// TODO: As this was pulled in from Virtualization (libs/dice/open_dice/src/bcc.rs), move common
// Rust wrapper code to external open dice repo.

#![cfg_attr(not(test), no_std)]

use cbor::{DiceContext, DiceKeyAlgorithm};
use ciborium_ll::{Decoder, Header};
use core::ffi::CStr;
use core::ptr;
use opendice_android_bindgen::{
    DiceAndroidConfigValues, DiceAndroidFormatConfigDescriptor, DiceAndroidHandoverMainFlow,
    DICE_ANDROID_CONFIG_COMPONENT_NAME, DICE_ANDROID_CONFIG_COMPONENT_VERSION,
    DICE_ANDROID_CONFIG_RESETTABLE, DICE_ANDROID_CONFIG_RKP_VM_MARKER,
    DICE_ANDROID_CONFIG_SECURITY_VERSION,
};
use opendice_cbor_bindgen as cbor;

mod clear_memory;

pub mod dice;
use dice::InputValues;

pub mod error;
use error::{check_result, DiceError, Result};

/// Open Profile for DICE CWT-payload label for the subject public key.
/// See <https://pigweed.googlesource.com/open-dice/+/refs/heads/main/docs/specification.md>.
const DICE_CWT_LABEL_SUBJECT_PUBLIC_KEY: i64 = -4670552;

/// Recursion depth limit for [`Cursor::skip`]. Comfortably exceeds the depth
/// of a well-formed DICE BCC (chain > Sign1 > payload bstr > map > pubkey bstr > map).
const MAX_NESTING: usize = 16;

/// Minimum number of elements in a well-formed DICE BCC (1 root key + at least 1 certificate).
const MIN_BCC_LENGTH: usize = 2;

/// The number of elements in a standard COSE_Sign1 array (protected, unprotected, payload, and signature).
const COSE_SIGN1_NUM_ELEMENTS: usize = 4;

/// A streaming cursor over a CBOR byte slice: the raw-CBOR engine beneath the
/// BCC types below. Each method advances the cursor past the bytes it consumes;
/// any decode error maps to [`DiceError::InvalidInput`].
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self(buf)
    }

    fn pull(&mut self) -> Result<Header> {
        Decoder::from(&mut self.0).pull().map_err(|_| DiceError::InvalidInput)
    }

    fn read_array(&mut self) -> Result<usize> {
        match self.pull()? {
            Header::Array(Some(n)) => Ok(n),
            _ => Err(DiceError::InvalidInput),
        }
    }

    fn read_int(&mut self) -> Result<i64> {
        match self.pull()? {
            Header::Positive(n) => i64::try_from(n).map_err(|_| DiceError::InvalidInput),
            // CBOR negative encoding (RFC 8949 §3.1): value = -1 - n.
            // Negative value is [i64::MIN, -1] so `-1 - n` cannot overflow.
            Header::Negative(n) => {
                i64::try_from(n).map(|n| -1 - n).map_err(|_| DiceError::InvalidInput)
            }
            _ => Err(DiceError::InvalidInput),
        }
    }

    /// Reads a definite-length byte string and returns a fresh cursor over its body.
    fn descend_bstr(&mut self) -> Result<Cursor<'a>> {
        let Header::Bytes(Some(n)) = self.pull()? else {
            return Err(DiceError::InvalidInput);
        };
        if n > self.0.len() {
            return Err(DiceError::InvalidInput);
        }
        let (body, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(Cursor(body))
    }

    /// Opens the int-keyed map at the cursor and positions the cursor on the value
    /// whose key equals `label`.
    fn enter_map_value(&mut self, label: i64) -> Result<()> {
        let Header::Map(Some(pairs)) = self.pull()? else {
            return Err(DiceError::InvalidInput);
        };
        for _ in 0..pairs {
            if self.read_int()? == label {
                return Ok(());
            }
            self.skip()?;
        }
        Err(DiceError::InvalidInput)
    }

    fn skip(&mut self) -> Result<()> {
        self.skip_with_depth(MAX_NESTING)
    }

    fn skip_with_depth(&mut self, depth: usize) -> Result<()> {
        if depth == 0 {
            return Err(DiceError::InvalidInput);
        }
        match self.pull()? {
            Header::Positive(_) | Header::Negative(_) | Header::Float(_) | Header::Simple(_) => {
                Ok(())
            }
            Header::Tag(_) => self.skip_with_depth(depth - 1),
            Header::Bytes(Some(n)) | Header::Text(Some(n)) => {
                if n > self.0.len() {
                    return Err(DiceError::InvalidInput);
                }
                self.0 = &self.0[n..];
                Ok(())
            }
            Header::Array(Some(n)) => {
                for _ in 0..n {
                    self.skip_with_depth(depth - 1)?;
                }
                Ok(())
            }
            Header::Map(Some(n)) => {
                for _ in 0..n {
                    self.skip_with_depth(depth - 1)?;
                    self.skip_with_depth(depth - 1)?;
                }
                Ok(())
            }
            // Indefinite-length items and a lone `Break` are malformed in a
            // deterministic CBOR encoding such as the Android DICE profile.
            _ => Err(DiceError::InvalidInput),
        }
    }
}

/// The DICE certificate chain (BCC): `[ pubkey, BccEntry, ..., BccEntry ]`.
struct DiceChain<'a>(Cursor<'a>);

impl<'a> DiceChain<'a> {
    fn new(bcc: &'a [u8]) -> Self {
        DiceChain(Cursor::new(bcc))
    }

    /// The most recent certificate (the last entry); its subject key is the
    /// current stage's signing key.
    fn leaf_certificate(mut self) -> Result<Certificate<'a>> {
        let entries = self.0.read_array()?;
        if entries < MIN_BCC_LENGTH {
            return Err(DiceError::InvalidInput);
        }
        for _ in 0..entries - 1 {
            self.0.skip()?;
        }
        Ok(Certificate(self.0))
    }
}

/// A `BccEntry`: a `COSE_Sign1 = [protected, unprotected, payload, signature]`.
struct Certificate<'a>(Cursor<'a>);

impl<'a> Certificate<'a> {
    /// The payload: a byte string wrapping the CWT claims map.
    fn payload(mut self) -> Result<CwtClaims<'a>> {
        if self.0.read_array()? != COSE_SIGN1_NUM_ELEMENTS {
            return Err(DiceError::InvalidInput);
        }
        self.0.skip()?; // protected header
        self.0.skip()?; // unprotected header
        Ok(CwtClaims(self.0.descend_bstr()?))
    }
}

/// The CWT claims map carried in a certificate payload.
struct CwtClaims<'a>(Cursor<'a>);

impl<'a> CwtClaims<'a> {
    /// The subject public key: a byte string wrapping a COSE_Key.
    fn subject_public_key(mut self) -> Result<CoseKey<'a>> {
        self.0.enter_map_value(DICE_CWT_LABEL_SUBJECT_PUBLIC_KEY)?;
        Ok(CoseKey(self.0.descend_bstr()?))
    }
}

/// A `COSE_Key` map.
struct CoseKey<'a>(Cursor<'a>);

impl<'a> CoseKey<'a> {
    /// The COSE algorithm identifier.
    fn algorithm(mut self) -> Result<i64> {
        self.0.enter_map_value(cbor::kCoseKeyAlgLabel)?;
        self.0.read_int()
    }
}

fn cose_alg_to_dice_key_algorithm(alg: i64) -> Result<DiceKeyAlgorithm> {
    match alg {
        cbor::kCoseAlgEdDsa => Ok(DiceKeyAlgorithm::kDiceKeyAlgorithmEd25519),
        cbor::kCoseAlgEs256 => Ok(DiceKeyAlgorithm::kDiceKeyAlgorithmP256),
        cbor::kCoseAlgEs384 => Ok(DiceKeyAlgorithm::kDiceKeyAlgorithmP384),
        cbor::kCoseAlgMldsa65 => Ok(DiceKeyAlgorithm::kDiceKeyAlgorithmMldsa65),
        cbor::kCoseAlgMldsa87 => Ok(DiceKeyAlgorithm::kDiceKeyAlgorithmMldsa87),
        _ => Err(DiceError::UnsupportedKeyAlgorithm),
    }
}

/// Recovers the algorithm of the leaf certificate's subject public key. Per the
/// Android Profile for DICE this is the current stage's signing key, i.e. the
/// `authority_algorithm` for the next [`DiceAndroidHandoverMainFlow`] call.
pub fn extract_subject_algorithm_from_dice_chain(bcc: &[u8]) -> Result<DiceKeyAlgorithm> {
    let cose_alg =
        DiceChain::new(bcc).leaf_certificate()?.payload()?.subject_public_key()?.algorithm()?;
    cose_alg_to_dice_key_algorithm(cose_alg)
}

/// Executes the main Android DICE handover flow.
///
/// A handover combines the DICE chain and CDIs in a single CBOR object.
/// This function takes the current boot stage's handover bundle and produces a
/// bundle for the next stage.
pub fn dice_android_handover_main_flow(
    current_handover: &[u8],
    input_values: &InputValues,
    next_handover: &mut [u8],
) -> Result<usize> {
    // Recover the algorithm of the current signing key from the leaf cert's
    // subject pubkey. That alg becomes our `authority_algorithm`; we keep the
    // chain homogeneous by reusing it for `subject_algorithm`.
    let bcc =
        dice::bcc_handover_parse(current_handover)?.bcc.ok_or(DiceError::DiceChainNotFound)?;
    let subject_algorithm = extract_subject_algorithm_from_dice_chain(bcc)?;
    let mut dice_context =
        DiceContext { authority_algorithm: subject_algorithm, subject_algorithm };

    let mut next_handover_size = 0;
    check_result(
        // SAFETY: The function only reads `current_handover` and writes to `next_handover`
        // within its bounds, reads `input_values` as a constant input without storing any
        // pointer, and reads `dice_context` (a stack-local) for the duration of the call.
        unsafe {
            DiceAndroidHandoverMainFlow(
                &mut dice_context as *mut _ as *mut _,
                current_handover.as_ptr(),
                current_handover.len(),
                input_values.as_ptr(),
                next_handover.len(),
                next_handover.as_mut_ptr(),
                &mut next_handover_size,
            )
        },
        next_handover_size,
    )?;

    Ok(next_handover_size)
}

/// Contains the input values used to construct the Android Profile for DICE
/// configuration descriptor.
#[derive(Debug, Default)]
pub struct DiceAndroidConfig<'a> {
    /// Name of the component.
    pub component_name: Option<&'a CStr>,
    /// Version of the component.
    pub component_version: Option<u64>,
    /// Whether the key changes on factory reset.
    pub resettable: bool,
    /// Monotonically increasing version of the component.
    pub security_version: Option<u64>,
    /// Whether the component can take part in running the RKP VM.
    pub rkp_vm_marker: bool,
}

/// Formats a configuration descriptor following the Android Profile for DICE specification.
/// See <https://pigweed.googlesource.com/open-dice/+/refs/heads/main/docs/android.md>.
pub fn dice_android_format_config_descriptor(
    values: &DiceAndroidConfig,
    buffer: &mut [u8],
) -> Result<usize> {
    let mut configs = 0;

    let component_name = values.component_name.map_or(ptr::null(), |name| {
        configs |= DICE_ANDROID_CONFIG_COMPONENT_NAME;
        name.as_ptr()
    });
    let component_version = values.component_version.map_or(0, |version| {
        configs |= DICE_ANDROID_CONFIG_COMPONENT_VERSION;
        version
    });
    if values.resettable {
        configs |= DICE_ANDROID_CONFIG_RESETTABLE;
    }
    let security_version = values.security_version.map_or(0, |version| {
        configs |= DICE_ANDROID_CONFIG_SECURITY_VERSION;
        version
    });
    if values.rkp_vm_marker {
        configs |= DICE_ANDROID_CONFIG_RKP_VM_MARKER;
    }

    let values =
        DiceAndroidConfigValues { configs, component_name, component_version, security_version };

    let mut buffer_size = 0;
    check_result(
        // SAFETY: The function writes to the buffer, within the given bounds, and only reads the
        // input values. It writes its result to buffer_size.
        unsafe {
            DiceAndroidFormatConfigDescriptor(
                &values,
                buffer.len(),
                buffer.as_mut_ptr(),
                &mut buffer_size,
            )
        },
        buffer_size,
    )?;
    Ok(buffer_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a 32-byte BCC whose leaf COSE_Sign1 declares a single-byte COSE
    /// alg id `alg_byte` (e.g. `0x27` for EdDSA = -8) as its subject pubkey alg.
    fn bcc_with_single_byte_alg(alg_byte: u8) -> [u8; 32] {
        [
            0x82, // array(2)
            // [0] placeholder root COSE_Key — contents not consulted.
            0xa6, 0x01, 0x02, 0x03, 0x27, 0x04, 0x02, 0x20, 0x01, 0x21, 0x40, 0x22, 0x40,
            // [1] leaf COSE_Sign1: [bstr(3){1:-8}, {}, bstr(10){..}, bstr(0)].
            0x84, 0x43, 0xa1, 0x01, 0x27, 0xa0, //
            0x4a, 0xa1, 0x3a, 0x00, 0x47, 0x44, 0x57, // payload: {-4670552: ...
            0x43, 0xa1, 0x03, alg_byte, //               ... bstr(3){3: alg_byte}}
            0x40,     // signature
        ]
    }

    #[test]
    fn extracts_ed25519() {
        assert_eq!(
            extract_subject_algorithm_from_dice_chain(&bcc_with_single_byte_alg(0x27)).unwrap(),
            DiceKeyAlgorithm::kDiceKeyAlgorithmEd25519,
        );
    }

    #[test]
    fn extracts_p256() {
        assert_eq!(
            extract_subject_algorithm_from_dice_chain(&bcc_with_single_byte_alg(0x26)).unwrap(),
            DiceKeyAlgorithm::kDiceKeyAlgorithmP256,
        );
    }

    #[test]
    fn extracts_p384() {
        // ES384 = -35 needs a 2-byte CBOR negative (0x38 0x22), so the COSE_Key bstr grows by 1.
        let bcc: [u8; 33] = [
            0x82, //
            0xa6, 0x01, 0x02, 0x03, 0x27, 0x04, 0x02, 0x20, 0x01, 0x21, 0x40, 0x22, 0x40, //
            0x84, 0x43, 0xa1, 0x01, 0x27, 0xa0, //
            0x4b, 0xa1, 0x3a, 0x00, 0x47, 0x44, 0x57, //
            0x44, 0xa1, 0x03, 0x38, 0x22, //
            0x40, //
        ];
        assert_eq!(
            extract_subject_algorithm_from_dice_chain(&bcc).unwrap(),
            DiceKeyAlgorithm::kDiceKeyAlgorithmP384,
        );
    }

    #[test]
    fn extracts_mldsa65() {
        // MLDSA65 = -49 is encoded in CBOR as [0x38, 0x30].
        let bcc: [u8; 33] = [
            0x82, //
            0xa6, 0x01, 0x02, 0x03, 0x27, 0x04, 0x02, 0x20, 0x01, 0x21, 0x40, 0x22, 0x40, //
            0x84, 0x43, 0xa1, 0x01, 0x27, 0xa0, //
            0x4b, 0xa1, 0x3a, 0x00, 0x47, 0x44, 0x57, //
            0x44, 0xa1, 0x03, 0x38, 0x30, //
            0x40, //
        ];
        assert_eq!(
            extract_subject_algorithm_from_dice_chain(&bcc).unwrap(),
            DiceKeyAlgorithm::kDiceKeyAlgorithmMldsa65,
        );
    }

    #[test]
    fn extracts_mldsa87() {
        // MLDSA87 = -50 is encoded in CBOR as [0x38, 0x31].
        let bcc: [u8; 33] = [
            0x82, //
            0xa6, 0x01, 0x02, 0x03, 0x27, 0x04, 0x02, 0x20, 0x01, 0x21, 0x40, 0x22, 0x40, //
            0x84, 0x43, 0xa1, 0x01, 0x27, 0xa0, //
            0x4b, 0xa1, 0x3a, 0x00, 0x47, 0x44, 0x57, //
            0x44, 0xa1, 0x03, 0x38, 0x31, //
            0x40, //
        ];
        assert_eq!(
            extract_subject_algorithm_from_dice_chain(&bcc).unwrap(),
            DiceKeyAlgorithm::kDiceKeyAlgorithmMldsa87,
        );
    }

    #[test]
    fn rejects_unsupported_alg() {
        assert!(matches!(
            extract_subject_algorithm_from_dice_chain(&bcc_with_single_byte_alg(0x05)),
            Err(DiceError::UnsupportedKeyAlgorithm),
        ));
    }

    #[test]
    fn rejects_truncated_chain() {
        let bcc = bcc_with_single_byte_alg(0x27);
        assert!(extract_subject_algorithm_from_dice_chain(&bcc[..5]).is_err());
    }

    #[test]
    fn rejects_single_element_chain() {
        let bcc: [u8; 14] =
            [0x81, 0xa6, 0x01, 0x02, 0x03, 0x27, 0x04, 0x02, 0x20, 0x01, 0x21, 0x40, 0x22, 0x40];
        assert!(extract_subject_algorithm_from_dice_chain(&bcc).is_err());
    }

    #[test]
    fn rejects_indefinite_length_array() {
        // 0x9f is the indefinite-length array marker — not allowed in deterministic CBOR.
        let bcc: [u8; 16] = [
            0x9f, 0xa6, 0x01, 0x02, 0x03, 0x27, 0x04, 0x02, 0x20, 0x01, 0x21, 0x40, 0x22, 0x40,
            0xff, 0x00,
        ];
        assert!(extract_subject_algorithm_from_dice_chain(&bcc).is_err());
    }

    #[test]
    fn rejects_missing_subject_public_key_label() {
        // Payload carries key 1 instead of -4670552.
        let bcc: [u8; 28] = [
            0x82, //
            0xa6, 0x01, 0x02, 0x03, 0x27, 0x04, 0x02, 0x20, 0x01, 0x21, 0x40, 0x22, 0x40, //
            0x84, 0x43, 0xa1, 0x01, 0x27, 0xa0, //
            0x46, 0xa1, 0x01, 0x43, 0xa1, 0x03, 0x27, // payload bstr(6){1: bstr(3){3:-8}}
            0x40, //
        ];
        assert!(extract_subject_algorithm_from_dice_chain(&bcc).is_err());
    }

    #[test]
    fn skip_rejects_lone_break() {
        // A standalone 0xFF byte is malformed outside an indefinite-length container.
        let mut cursor = Cursor::new(&[0xff]);
        assert!(cursor.skip().is_err());
    }
}
