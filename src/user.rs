use std::{ffi::CStr, io, mem::MaybeUninit, ptr};

/// Copy the UID out of a caller-owned getpwnam_r result. No shared passwd storage.
pub(crate) fn lookup_uid(name: &CStr) -> io::Result<Option<libc::uid_t>> {
    let mut buffer = Vec::new();
    let mut size = 16 * 1024usize;
    loop {
        buffer.try_reserve(size - buffer.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                "passwd lookup buffer allocation failed",
            )
        })?;
        buffer.resize(size, 0u8);
        let mut passwd = MaybeUninit::<libc::passwd>::uninit();
        let mut result = ptr::null_mut();
        let rc = unsafe {
            libc::getpwnam_r(
                name.as_ptr(),
                passwd.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE {
            size = size.checked_mul(2).ok_or_else(|| {
                io::Error::new(io::ErrorKind::OutOfMemory, "passwd lookup buffer overflow")
            })?;
            continue;
        }
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc));
        }
        if result.is_null() {
            return Ok(None);
        }
        return Ok(Some(unsafe { passwd.assume_init() }.pw_uid));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwd_lookup_is_reentrant() {
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    for _ in 0..100 {
                        assert_eq!(lookup_uid(c"root").unwrap(), Some(0));
                        let _ = lookup_uid(c"nobody").unwrap();
                    }
                });
            }
        });
    }

    #[test]
    fn unknown_user_is_not_a_lookup_error() {
        assert_eq!(
            lookup_uid(c"subid_dyn_test_nonexistent_7295281").unwrap(),
            None
        );
    }
}
