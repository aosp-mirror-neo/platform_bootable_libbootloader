// Copyright (C) 2026 The Android Open Source Project
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

//! Checked integer conversions, to use instead of `as` casts.
//!
//! * For constants, use [const_cast]. It works for any integer types and checks the value at
//!   compile time.
//! * For runtime values, use [From], [Into] or [InfallibleCast] for unsigned integers. If the
//!   conversion can actually fail, use [TryFrom], [TryInto] and handle the error.

/// Converts the integer constant `$value` to the integer type expected by the context, failing to
/// compile if the value doesn't fit.
///
/// Use it in place of an unchecked `as` cast when defining a constant of another integer type.
/// Supports integer types of up to 64 bits, which `i128` can represent exactly.
///
/// ```
/// use libutils::const_cast;
///
/// const SIZE_U32: u32 = const_cast!(size_of::<u64>());
/// assert_eq!(SIZE_U32, 8);
/// ```
///
/// Values that don't fit in the target type fail to compile:
///
/// ```compile_fail,E0080
/// # use libutils::const_cast;
/// const TOO_LARGE: u8 = const_cast!(256usize);
/// ```
///
/// ```compile_fail,E0080
/// # use libutils::const_cast;
/// const NEGATIVE: u64 = const_cast!(-1i64);
/// ```
///
/// ```compile_fail,E0080
/// # use libutils::const_cast;
/// const SIGN_CHANGE: i8 = const_cast!(200u8);
/// ```
///
/// So do types larger than 64 bits and non-integer types:
///
/// ```compile_fail,E0277
/// # use libutils::const_cast;
/// const TOO_WIDE: i128 = const_cast!(5u64);
/// ```
///
/// ```compile_fail,E0277
/// # use libutils::const_cast;
/// const FLOAT: u32 = const_cast!(1.5f32);
/// ```
#[macro_export]
macro_rules! const_cast {
    ($value:expr) => {
        const {
            let value = $value;
            let converted = value as _;
            $crate::conversion::const_cast_internal::assert_supported(&value);
            $crate::conversion::const_cast_internal::assert_supported(&converted);
            assert!(
                converted as i128 == value as i128,
                concat!("`", stringify!($value), "` doesn't fit in the target type")
            );
            converted
        }
    };
}
#[doc(no_inline)]
pub use crate::const_cast;

/// Implementation details of [const_cast].
#[doc(hidden)]
pub mod const_cast_internal {
    /// Integer types supported by [const_cast], which `i128` can represent exactly.
    pub trait Supported {}

    macro_rules! impl_supported {
        ($($ty:ty),*) => { $(impl Supported for $ty {})* };
    }
    impl_supported!(u8, u16, u32, u64, usize, i8, i16, i32, i64, isize);

    /// Fails to compile unless `T` is supported by [const_cast].
    pub const fn assert_supported<T: Supported>(_: &T) {}
}

/// Infallible integer conversion into `U`, statically verified at compile time.
///
/// Complements [`From`] and [`Into`] on 64-bit targets by supporting infallible conversions
/// between `usize` and `u32`/`u64` (which `From` omits for target portability):
///
/// ```
/// use libutils::InfallibleCast;
///
/// let buf = [10, 20, 30, 40];
/// let offset: u64 = 2;
/// assert_eq!(&buf[offset.cast()..], &[30, 40]);
/// ```
///
/// ```compile_fail
/// # use libutils::InfallibleCast;
/// let truncated: u32 = 5usize.cast();
/// ```
///
/// ```compile_fail
/// # use libutils::InfallibleCast;
/// let sign_changed: usize = (-1i32).cast();
/// ```
pub trait InfallibleCast<U>: private::Sealed<U> {
    /// Infallibly converts `self` into `U`.
    fn cast(self) -> U;
}

/// Seals `InfallibleCast` so that it cannot be implemented by external crate.
mod private {
    pub trait Sealed<U> {}
}

macro_rules! impl_infallible_cast {
    ($src:ty => $dst:ty) => {
        const _: () = assert!(
            <$dst>::MIN as i128 <= <$src>::MIN as i128
                && <$src>::MAX as u128 <= <$dst>::MAX as u128,
            concat!("`", stringify!($src), "` doesn't fit in `", stringify!($dst), "`")
        );

        impl private::Sealed<$dst> for $src {}

        impl InfallibleCast<$dst> for $src {
            #[inline(always)]
            fn cast(self) -> $dst {
                self as $dst
            }
        }
    };
}

impl_infallible_cast!(u8 => usize);
impl_infallible_cast!(u16 => usize);
impl_infallible_cast!(u32 => usize);
impl_infallible_cast!(u64 => usize);
impl_infallible_cast!(usize => u64);

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_const_cast() {
        const U8_MAX: u8 = const_cast!(255usize);
        const I8_MIN: i8 = const_cast!(-128i64);
        let size: u32 = const_cast!(size_of::<u64>());
        assert_eq!(U8_MAX, 255u8);
        assert_eq!(I8_MIN, -128i8);
        assert_eq!(size, 8u32);
    }

    #[test]
    fn test_infallible_cast() {
        let from_u8: usize = u8::MAX.cast();
        let from_u16: usize = u16::MAX.cast();
        let from_u32: usize = u32::MAX.cast();
        let from_u64: usize = u64::MAX.cast();
        let from_usize: u64 = usize::MAX.cast();

        assert_eq!(from_u8, usize::from(u8::MAX));
        assert_eq!(from_u16, usize::from(u16::MAX));
        assert_eq!(from_u32, u32::MAX.try_into().unwrap());
        assert_eq!(from_u64, u64::MAX.try_into().unwrap());
        assert_eq!(from_usize, usize::MAX.try_into().unwrap());
    }
}
