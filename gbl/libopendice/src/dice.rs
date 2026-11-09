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

//! Structs and functions about the types used in DICE.

// TODO: As this was pulled in from Virtualization (libs/dice/open_dice/src/dice.rs), move common
// Rust wrapper code to external open dice repo.

use crate::{
    check_result,
    error::{DiceError, Result},
};
use core::{marker::PhantomData, ptr};
use libutils::const_cast;
use opendice_android_bindgen::DiceAndroidHandoverParse;

pub use opendice_cbor_bindgen::{DiceConfigType, DiceInputValues, DiceKeyAlgorithm, DiceMode};

/// The size of a CDI.
pub const CDI_SIZE: usize = const_cast!(opendice_cbor_bindgen::DICE_CDI_SIZE);
/// The size of a DICE hash.
pub const HASH_SIZE: usize = const_cast!(opendice_cbor_bindgen::DICE_HASH_SIZE);
/// The size of the DICE hidden value.
pub const HIDDEN_SIZE: usize = const_cast!(opendice_cbor_bindgen::DICE_HIDDEN_SIZE);
/// The size of a DICE inline config.
pub const INLINE_CONFIG_SIZE: usize = const_cast!(opendice_cbor_bindgen::DICE_INLINE_CONFIG_SIZE);

/// Array type of inline configuration values.
type InlineConfig = [u8; INLINE_CONFIG_SIZE];
/// Array type of CDIs.
pub type Cdi = [u8; CDI_SIZE];
/// Array type of additional input.
type Hidden = [u8; HIDDEN_SIZE];
/// Array type of hashes used by DICE.
type Hash = [u8; HASH_SIZE];

/// Wrap of DiceInputValues
#[derive(Clone, Debug)]
pub struct InputValues<'a> {
    dice_inputs: DiceInputValues,
    // DiceInputValues contains a pointer to the separate config descriptor, which must therefore
    // outlive it. Make sure the borrow checker can enforce that.
    config_descriptor: PhantomData<&'a [u8]>,
}

impl<'a> InputValues<'a> {
    /// Creates a new `InputValues`.
    pub fn new(
        code_hash: Hash,
        config: Config<'a>,
        authority_hash: Hash,
        mode: DiceMode,
        hidden: Hidden,
    ) -> Self {
        Self {
            dice_inputs: DiceInputValues {
                code_hash,
                code_descriptor: ptr::null(),
                code_descriptor_size: 0,
                config_type: config.dice_config_type(),
                config_value: config.inline_config(),
                config_descriptor: config.descriptor_ptr(),
                config_descriptor_size: config.descriptor_size(),
                authority_hash,
                authority_descriptor: ptr::null(),
                authority_descriptor_size: 0,
                mode,
                hidden,
            },
            config_descriptor: PhantomData,
        }
    }

    /// Returns a raw pointer to the wrapped `DiceInputValues`.
    pub fn as_ptr(&self) -> *const DiceInputValues {
        &self.dice_inputs as *const DiceInputValues
    }
}

/// Configuration descriptor for DICE input values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Config<'a> {
    /// Reference to an inline descriptor.
    Inline(&'a InlineConfig),
    /// Reference to a free form descriptor that will be hashed by the implementation.
    Descriptor(&'a [u8]),
}

impl Config<'_> {
    fn dice_config_type(&self) -> DiceConfigType {
        match self {
            Self::Inline(_) => DiceConfigType::kDiceConfigTypeInline,
            Self::Descriptor(_) => DiceConfigType::kDiceConfigTypeDescriptor,
        }
    }

    fn inline_config(&self) -> InlineConfig {
        match self {
            Self::Inline(inline) => **inline,
            Self::Descriptor(_) => [0u8; INLINE_CONFIG_SIZE],
        }
    }

    fn descriptor_ptr(&self) -> *const u8 {
        match self {
            Self::Descriptor(descriptor) => descriptor.as_ptr(),
            _ => ptr::null(),
        }
    }

    fn descriptor_size(&self) -> usize {
        match self {
            Self::Descriptor(descriptor) => descriptor.len(),
            _ => 0,
        }
    }
}

/// An Android DICE handover object combines the DICE chain and CDIs in a single CBOR object.
/// This struct is used as return of the function `android_dice_handover_parse`, its lifetime is
/// tied to the lifetime of the raw handover slice.
#[derive(Debug)]
pub struct BccHandover<'a> {
    /// Attestation CDI.
    pub cdi_attest: &'a Cdi,
    /// Sealing CDI.
    pub cdi_seal: &'a Cdi,
    /// DICE chain.
    pub bcc: Option<&'a [u8]>,
}

/// This function parses the `handover` to extracts the DICE chain and CDIs.
/// The lifetime of the returned `DiceAndroidHandover` is tied to the given `handover` slice.
pub fn bcc_handover_parse(handover: &[u8]) -> Result<BccHandover<'_>> {
    let mut cdi_attest: *const u8 = ptr::null();
    let mut cdi_seal: *const u8 = ptr::null();
    let mut chain: *const u8 = ptr::null();
    let mut chain_size = 0;
    check_result(
        // SAFETY: The `handover` is only read and never stored and the returned pointers should
        // all point within the address range of the `handover` or be NULL.
        unsafe {
            DiceAndroidHandoverParse(
                handover.as_ptr(),
                handover.len(),
                &mut cdi_attest,
                &mut cdi_seal,
                &mut chain,
                &mut chain_size,
            )
        },
        chain_size,
    )?;
    let cdi_attest = sub_slice(handover, cdi_attest, CDI_SIZE)?;
    let cdi_seal = sub_slice(handover, cdi_seal, CDI_SIZE)?;
    let bcc = sub_slice(handover, chain, chain_size).ok();
    Ok(BccHandover {
        cdi_attest: cdi_attest.try_into().map_err(|_| DiceError::PlatformError)?,
        cdi_seal: cdi_seal.try_into().map_err(|_| DiceError::PlatformError)?,
        bcc,
    })
}

/// Gets a slice the `addr` points to and of length `len`.
/// The slice should be contained in the buffer.
fn sub_slice(buffer: &[u8], addr: *const u8, len: usize) -> Result<&[u8]> {
    if addr.is_null() || !buffer.as_ptr_range().contains(&addr) {
        return Err(DiceError::PlatformError);
    }
    // SAFETY: This is safe because addr is not null and is within the range of the buffer.
    let start: usize = unsafe {
        addr.offset_from(buffer.as_ptr()).try_into().map_err(|_| DiceError::PlatformError)?
    };
    start.checked_add(len).and_then(|end| buffer.get(start..end)).ok_or(DiceError::PlatformError)
}
