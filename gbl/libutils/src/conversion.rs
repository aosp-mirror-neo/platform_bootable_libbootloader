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

#[cfg(test)]
mod test {
    #[test]
    fn test_const_cast() {
        const U8_MAX: u8 = const_cast!(255usize);
        const I8_MIN: i8 = const_cast!(-128i64);
        let size: u32 = const_cast!(size_of::<u64>());
        assert_eq!(U8_MAX, 255u8);
        assert_eq!(I8_MIN, -128i8);
        assert_eq!(size, 8u32);
    }
}
