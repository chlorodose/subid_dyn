use std::{
    ffi::{CStr, CString, c_char, c_int},
    os::raw::c_void,
    panic::{AssertUnwindSafe, catch_unwind},
};

use crate::{db, nss::subid_type, user};

pub const PAM_IGNORE: c_int = 25;

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_get_user(pamh: *mut c_void, user: &mut *const c_char, prompt: *const c_char) -> c_int;
    fn pam_syslog(pamh: *const c_void, priority: c_int, format: *const c_char, ...);
}

fn log_error(pamh: *mut c_void, message: &str) {
    if let Ok(message) = CString::new(message) {
        unsafe {
            pam_syslog(
                pamh,
                libc::LOG_ERR,
                c"subid_dyn: %s".as_ptr(),
                message.as_ptr(),
            )
        };
    }
}

/// Provision subids during the account phase without deciding login eligibility.
/// Failures are reported through the PAM system logger.
///
/// # Safety
/// `pamh` must be a valid PAM handle owned by the caller for the entire call.
/// Remaining arguments must obey the Linux-PAM module callback contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_acct_mgmt(
    pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    if pamh.is_null() {
        return PAM_IGNORE;
    }
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let mut username = std::ptr::null();
        let status = unsafe { pam_get_user(pamh, &mut username, std::ptr::null()) };
        if status != 0 || username.is_null() {
            log_error(pamh, "could not obtain the PAM user");
            return;
        }
        let name = unsafe { CStr::from_ptr(username) };
        let uid = match user::lookup_uid(name) {
            Ok(Some(uid)) => uid,
            Ok(None) => {
                log_error(pamh, "PAM user not found in the passwd database");
                return;
            }
            Err(error) => {
                log_error(pamh, &format!("passwd lookup failed: {error}"));
                return;
            }
        };
        for id_type in [subid_type::IdTypeUid, subid_type::IdTypeGid] {
            if let Err(error) = db::ensure_allocation(uid, id_type) {
                log_error(
                    pamh,
                    &format!("{id_type:?} allocation failed for UID {uid}: {error}"),
                );
            }
        }
    }));
    if outcome.is_err() {
        log_error(pamh, "unexpected panic while provisioning subids");
    }
    PAM_IGNORE
}
