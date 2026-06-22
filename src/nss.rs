use libc::{c_char, c_int, c_ulong, c_void, uid_t};
use std::{
    ffi::{CStr, CString},
    mem, ptr,
};

use crate::db;

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

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum subid_status {
    SubidStatusSuccess = 0,
    SubidStatusUnknownUser = 1,
    SubidStatusErrorConn = 2,
    SubidStatusError = 3,
}

fn c_str_to_str<'a>(value: *const c_char) -> Result<&'a str, subid_status> {
    if value.is_null() {
        return Err(subid_status::SubidStatusError);
    }
    let cs = unsafe { CStr::from_ptr(value) };
    cs.to_str().map_err(|_| subid_status::SubidStatusError)
}

fn owner_to_uid(owner: &str) -> Option<uid_t> {
    let c_owner = CString::new(owner).ok()?;
    unsafe {
        let pwd = libc::getpwnam(c_owner.as_ptr());
        if pwd.is_null() {
            return None;
        }
        Some((*pwd).pw_uid)
    }
}

fn c_str_to_uid(owner: *const c_char) -> Result<uid_t, subid_status> {
    let owner = c_str_to_str(owner)?;
    owner_to_uid(owner).ok_or(subid_status::SubidStatusUnknownUser)
}

unsafe fn vec_into_c_array<T: Copy>(items: Vec<T>) -> (*mut T, usize) {
    let len = items.len();
    if len == 0 {
        return (ptr::null_mut(), 0);
    }
    let buffer = unsafe { libc::calloc(len, mem::size_of::<T>()) };
    if buffer.is_null() {
        return (ptr::null_mut(), 0);
    }
    let dst = buffer as *mut T;
    for (i, item) in items.into_iter().enumerate() {
        unsafe { ptr::write(dst.add(i), item) };
    }
    (dst, len)
}

#[unsafe(no_mangle)]
pub extern "C" fn shadow_subid_has_range(
    owner: *const c_char,
    start: c_ulong,
    count: c_ulong,
    idtype: subid_type,
    result: *mut bool,
) -> subid_status {
    if result.is_null() {
        return subid_status::SubidStatusError;
    }
    let uid = match c_str_to_uid(owner) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let _ = db::allocate(uid, idtype);
    match db::has_range(uid, start, count, idtype) {
        Ok(v) => {
            unsafe { *result = v };
            subid_status::SubidStatusSuccess
        }
        Err(_) => subid_status::SubidStatusErrorConn,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn shadow_subid_list_owner_ranges(
    owner: *const c_char,
    id_type: subid_type,
    ranges: *mut *mut subid_range,
    count: *mut c_int,
) -> subid_status {
    if ranges.is_null() || count.is_null() {
        return subid_status::SubidStatusError;
    }
    let uid = match c_str_to_uid(owner) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let _ = db::allocate(uid, id_type);
    let items: Vec<subid_range> = match db::list_ranges(uid, id_type) {
        Ok(v) => v
            .into_iter()
            .map(|(s, c)| subid_range { start: s, count: c })
            .collect(),
        Err(_) => return subid_status::SubidStatusErrorConn,
    };
    let (ptr, len) = unsafe { vec_into_c_array(items) };
    unsafe {
        *ranges = ptr;
        *count = len as c_int;
    }
    subid_status::SubidStatusSuccess
}

#[unsafe(no_mangle)]
pub extern "C" fn shadow_subid_find_subid_owners(
    id: c_ulong,
    id_type: subid_type,
    uids: *mut *mut uid_t,
    count: *mut c_int,
) -> subid_status {
    if uids.is_null() || count.is_null() {
        return subid_status::SubidStatusError;
    }
    let owners = match db::find_owners(id, id_type) {
        Ok(v) => v,
        Err(_) => return subid_status::SubidStatusErrorConn,
    };
    let (ptr, len) = unsafe { vec_into_c_array(owners) };
    unsafe {
        *uids = ptr;
        *count = len as c_int;
    }
    subid_status::SubidStatusSuccess
}

#[unsafe(no_mangle)]
pub extern "C" fn shadow_subid_free(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    unsafe { libc::free(ptr) };
}

#[unsafe(no_mangle)]
pub extern "C" fn shadow_subid_allocate(
    owner: *const c_char,
    id_type: subid_type,
    start: *mut c_ulong,
    count: *mut c_ulong,
) -> subid_status {
    if start.is_null() || count.is_null() {
        return subid_status::SubidStatusError;
    }
    let uid = match c_str_to_uid(owner) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match db::allocate(uid, id_type) {
        Ok((s, c)) => {
            unsafe {
                *start = s;
                *count = c;
            }
            subid_status::SubidStatusSuccess
        }
        Err(_) => subid_status::SubidStatusErrorConn,
    }
}
