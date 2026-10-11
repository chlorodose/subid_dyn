use libc::{c_char, c_int, c_ulong, c_void, uid_t};
use std::{
    ffi::CStr,
    mem,
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
};

use crate::{db, user};

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct subid_range {
    pub start: c_ulong,
    pub count: c_ulong,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum subid_type {
    IdTypeUid = 1,
    IdTypeGid = 2,
}

impl TryFrom<c_int> for subid_type {
    type Error = subid_status;

    fn try_from(value: c_int) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::IdTypeUid),
            2 => Ok(Self::IdTypeGid),
            _ => Err(subid_status::SubidStatusError),
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum subid_status {
    SubidStatusSuccess = 0,
    SubidStatusUnknownUser = 1,
    SubidStatusErrorConn = 2,
    SubidStatusError = 3,
}

// Raw integer input preserves the C ABI while rejecting invalid enum values
// before constructing a Rust enum.
unsafe fn c_str_to_uid(owner: *const c_char) -> Result<uid_t, subid_status> {
    if owner.is_null() {
        return Err(subid_status::SubidStatusError);
    }
    let name = unsafe { CStr::from_ptr(owner) };
    user::lookup_uid(name)
        .map_err(|_| subid_status::SubidStatusErrorConn)?
        .ok_or(subid_status::SubidStatusUnknownUser)
}

fn ffi_status(action: impl FnOnce() -> Result<(), subid_status>) -> subid_status {
    match catch_unwind(AssertUnwindSafe(action)) {
        Ok(Ok(())) => subid_status::SubidStatusSuccess,
        Ok(Err(status)) => status,
        Err(_) => subid_status::SubidStatusError,
    }
}

fn vec_into_c_array<T: Copy>(items: Vec<T>) -> Result<(*mut T, c_int), subid_status> {
    vec_into_c_array_with(items, libc::calloc)
}

fn vec_into_c_array_with<T: Copy>(
    items: Vec<T>,
    allocator: unsafe extern "C" fn(usize, usize) -> *mut c_void,
) -> Result<(*mut T, c_int), subid_status> {
    let len = c_int::try_from(items.len()).map_err(|_| subid_status::SubidStatusError)?;
    if len == 0 {
        return Ok((ptr::null_mut(), 0));
    }
    items
        .len()
        .checked_mul(mem::size_of::<T>())
        .ok_or(subid_status::SubidStatusError)?;
    let dst = unsafe { allocator(items.len(), mem::size_of::<T>()) }.cast::<T>();
    if dst.is_null() {
        return Err(subid_status::SubidStatusError);
    }
    unsafe { ptr::copy_nonoverlapping(items.as_ptr(), dst, items.len()) };
    Ok((dst, len))
}

/// Query whether an owner holds a range, allocating when policy permits it.
///
/// # Safety
/// `owner` must point to a valid NUL-terminated string. `result` must be null or
/// point to writable, aligned storage for a C bool, disjoint from the inputs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shadow_subid_has_range(
    owner: *const c_char,
    start: c_ulong,
    count: c_ulong,
    idtype: c_int,
    result: *mut bool,
) -> subid_status {
    if result.is_null() {
        return subid_status::SubidStatusError;
    }
    unsafe { *result = false };
    ffi_status(|| {
        let id_type = subid_type::try_from(idtype)?;
        let uid = unsafe { c_str_to_uid(owner) }?;
        db::ensure_allocation(uid, id_type).map_err(|_| subid_status::SubidStatusErrorConn)?;
        let found = db::has_range(uid, start, count, id_type)
            .map_err(|_| subid_status::SubidStatusErrorConn)?;
        unsafe { *result = found };
        Ok(())
    })
}

/// Return an owner's ranges in an array freed with shadow_subid_free.
///
/// # Safety
/// `owner` must point to a valid NUL-terminated string. Output pointers must be
/// null or point to aligned, writable, mutually disjoint storage, disjoint from
/// the inputs. Callers must release a successful non-null array exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shadow_subid_list_owner_ranges(
    owner: *const c_char,
    id_type: c_int,
    ranges: *mut *mut subid_range,
    count: *mut c_int,
) -> subid_status {
    if ranges.is_null() || count.is_null() {
        return subid_status::SubidStatusError;
    }
    unsafe {
        *ranges = ptr::null_mut();
        *count = 0;
    }
    ffi_status(|| {
        let id_type = subid_type::try_from(id_type)?;
        let uid = unsafe { c_str_to_uid(owner) }?;
        db::ensure_allocation(uid, id_type).map_err(|_| subid_status::SubidStatusErrorConn)?;
        let items = db::list_ranges(uid, id_type)
            .map_err(|_| subid_status::SubidStatusErrorConn)?
            .into_iter()
            .map(|(start, count)| subid_range { start, count })
            .collect();
        let (buffer, len) = vec_into_c_array(items)?;
        unsafe {
            *ranges = buffer;
            *count = len;
        }
        Ok(())
    })
}

/// Find owners of a subordinate ID.
///
/// # Safety
/// Output pointers must be null or point to aligned, writable and mutually
/// disjoint storage. Release a successful non-null array with shadow_subid_free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shadow_subid_find_subid_owners(
    id: c_ulong,
    id_type: c_int,
    uids: *mut *mut uid_t,
    count: *mut c_int,
) -> subid_status {
    if uids.is_null() || count.is_null() {
        return subid_status::SubidStatusError;
    }
    unsafe {
        *uids = ptr::null_mut();
        *count = 0;
    }
    ffi_status(|| {
        let id_type = subid_type::try_from(id_type)?;
        let owners =
            db::find_owners(id, id_type).map_err(|_| subid_status::SubidStatusErrorConn)?;
        let (buffer, len) = vec_into_c_array(owners)?;
        unsafe {
            *uids = buffer;
            *count = len;
        }
        Ok(())
    })
}

/// Release a returned C array.
///
/// # Safety
/// `ptr` must be null or a live allocation returned by this module. It must not
/// have been freed before, and no access to it may occur after this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shadow_subid_free(ptr: *mut c_void) {
    unsafe { libc::free(ptr) };
}

/// Explicitly allocate a range for an owner.
///
/// # Safety
/// `owner` must point to a valid NUL-terminated string. Output pointers must be
/// null or point to aligned, writable and mutually disjoint storage, disjoint
/// from the inputs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shadow_subid_allocate(
    owner: *const c_char,
    id_type: c_int,
    start: *mut c_ulong,
    count: *mut c_ulong,
) -> subid_status {
    if start.is_null() || count.is_null() {
        return subid_status::SubidStatusError;
    }
    unsafe {
        *start = 0;
        *count = 0;
    }
    ffi_status(|| {
        let id_type = subid_type::try_from(id_type)?;
        let uid = unsafe { c_str_to_uid(owner) }?;
        let (new_start, new_count) =
            db::allocate(uid, id_type).map_err(|_| subid_status::SubidStatusErrorConn)?;
        unsafe {
            *start = new_start;
            *count = new_count;
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn failing_calloc(_: usize, _: usize) -> *mut c_void {
        ptr::null_mut()
    }

    #[test]
    fn allocation_failure_is_an_error_not_an_empty_result() {
        assert_eq!(
            vec_into_c_array_with(vec![123u32], failing_calloc),
            Err(subid_status::SubidStatusError)
        );
        assert_eq!(
            vec_into_c_array_with(Vec::<u32>::new(), failing_calloc),
            Ok((ptr::null_mut(), 0))
        );
    }

    #[test]
    fn c_arrays_have_the_expected_contents_and_can_be_freed() {
        let (buffer, len) = vec_into_c_array(vec![1001u32, 1002]).unwrap();
        assert_eq!(len, 2);
        unsafe {
            assert_eq!(std::slice::from_raw_parts(buffer, 2), &[1001, 1002]);
            shadow_subid_free(buffer.cast());
            shadow_subid_free(ptr::null_mut());
        }
    }

    #[test]
    fn invalid_inputs_reset_outputs_without_accessing_the_database() {
        let mut result = true;
        let mut ranges = ptr::dangling_mut();
        let mut count = 99;
        let mut start = 99;
        let mut allocation_count = 99;
        unsafe {
            assert_eq!(
                shadow_subid_has_range(c"root".as_ptr(), 1, 1, 0, &mut result),
                subid_status::SubidStatusError
            );
            assert!(!result);
            assert_eq!(
                shadow_subid_list_owner_ranges(c"root".as_ptr(), 99, &mut ranges, &mut count),
                subid_status::SubidStatusError
            );
            assert!(ranges.is_null());
            assert_eq!(count, 0);
            assert_eq!(
                shadow_subid_allocate(ptr::null(), 1, &mut start, &mut allocation_count),
                subid_status::SubidStatusError
            );
            assert_eq!(start, 0);
            assert_eq!(allocation_count, 0);
            assert_eq!(
                shadow_subid_has_range(ptr::null(), 1, 1, 1, ptr::null_mut()),
                subid_status::SubidStatusError
            );
        }
    }

    #[test]
    fn missing_owner_is_reported_separately() {
        let mut result = true;
        assert_eq!(
            unsafe {
                shadow_subid_has_range(
                    c"subid_dyn_test_nonexistent_7295281".as_ptr(),
                    1,
                    1,
                    1,
                    &mut result,
                )
            },
            subid_status::SubidStatusUnknownUser
        );
        assert!(!result);
    }

    #[test]
    fn operation_errors_and_panics_do_not_become_success() {
        assert_eq!(
            ffi_status(|| Err(subid_status::SubidStatusErrorConn)),
            subid_status::SubidStatusErrorConn
        );
        assert_eq!(
            ffi_status(|| panic!("test panic")),
            subid_status::SubidStatusError
        );
    }
}
