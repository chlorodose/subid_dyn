use std::{
    ffi::{c_char, c_int, c_uint},
    os::raw::c_void,
};

use crate::db;
use crate::nss::subid_type;

pub const PAM_IGNORE: c_int = 25;

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_get_user(pamh: *mut c_void, user: &mut *const c_char, prompt: *const c_char) -> c_int;
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_acct_mgmt(
    pamh: *mut c_void,
    _flags: c_uint,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    let mut username: *const c_char = std::ptr::null();
    if unsafe { pam_get_user(pamh, &mut username, std::ptr::null()) } != 0 {
        return PAM_IGNORE;
    }
    if username.is_null() {
        return PAM_IGNORE;
    }
    let pwd = unsafe { libc::getpwnam(username) };
    if pwd.is_null() {
        return PAM_IGNORE;
    }
    let uid = unsafe { (*pwd).pw_uid };

    // Ensure the user has subuid / subgid allocations
    let _ = db::allocate(uid, subid_type::IdTypeUid);
    let _ = db::allocate(uid, subid_type::IdTypeGid);

    PAM_IGNORE
}
