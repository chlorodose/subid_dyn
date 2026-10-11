use std::{
    ffi::CString,
    fs::File,
    io::{self, BufRead, BufReader, ErrorKind, Write},
    os::fd::{AsRawFd, FromRawFd},
    os::unix::fs::MetadataExt,
    path::{Component, Path},
};

use libc::{c_ulong, uid_t};

use crate::nss::subid_type;

pub const SUBID_DB_PATH: &str = "/var/db/subid/allocated";
const LOGIN_DEFS_PATH: &str = "/etc/login.defs";
// Linux reserves (uid_t)-1. Use an exclusive end, representable on 32-bit hosts too.
const MAX_ID: c_ulong = (uid_t::MAX - 1) as c_ulong;

#[derive(Debug, Clone)]
pub struct SubidConfig {
    pub uid_min: c_ulong,
    pub uid_max: c_ulong,
    pub uid_count: c_ulong,
    pub gid_min: c_ulong,
    pub gid_max: c_ulong,
    pub gid_count: c_ulong,
}

impl Default for SubidConfig {
    fn default() -> Self {
        Self {
            uid_min: 100000,
            uid_max: 600100000,
            uid_count: 65536,
            gid_min: 100000,
            gid_max: 600100000,
            gid_count: 65536,
        }
    }
}

impl SubidConfig {
    fn limits(&self, id_type: subid_type) -> (c_ulong, c_ulong, c_ulong) {
        match id_type {
            subid_type::IdTypeUid => (self.uid_min, self.uid_max, self.uid_count),
            subid_type::IdTypeGid => (self.gid_min, self.gid_max, self.gid_count),
        }
    }

    fn validate(&self) -> io::Result<()> {
        for id_type in [subid_type::IdTypeUid, subid_type::IdTypeGid] {
            let (min, max, count) = self.limits(id_type);
            if min == 0 || min > max || max > MAX_ID || count > max - min + 1 {
                return Err(invalid_data("invalid subid limits in login.defs"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct DbEntry {
    pub uid: uid_t,
    pub start: c_ulong,
    pub count: c_ulong,
    pub id_type: subid_type,
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message.into())
}

/// Defaults apply only when login.defs is absent or a setting is unspecified.
/// Invalid settings and read failures are errors, never implicit defaults.
pub fn parse_login_defs() -> io::Result<SubidConfig> {
    match File::open(LOGIN_DEFS_PATH) {
        Ok(file) => parse_config(BufReader::new(file)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(SubidConfig::default()),
        Err(e) => Err(e),
    }
}

fn parse_config(reader: impl BufRead) -> io::Result<SubidConfig> {
    let mut cfg = SubidConfig::default();
    for (index, line) in reader.lines().enumerate() {
        let line = line?;
        let mut parts = line.split('#').next().unwrap_or("").split_whitespace();
        let field = match parts.next() {
            Some("SUB_UID_MIN") => &mut cfg.uid_min,
            Some("SUB_UID_MAX") => &mut cfg.uid_max,
            Some("SUB_UID_COUNT") => &mut cfg.uid_count,
            Some("SUB_GID_MIN") => &mut cfg.gid_min,
            Some("SUB_GID_MAX") => &mut cfg.gid_max,
            Some("SUB_GID_COUNT") => &mut cfg.gid_count,
            _ => continue,
        };
        *field = parts
            .next()
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| {
                invalid_data(format!("invalid login.defs value on line {}", index + 1))
            })?;
        if parts.next().is_some() {
            return Err(invalid_data(format!(
                "extra login.defs value on line {}",
                index + 1
            )));
        }
    }
    cfg.validate()?;
    Ok(cfg)
}

fn range_end(start: c_ulong, count: c_ulong) -> Option<c_ulong> {
    if start == 0 || start > MAX_ID || count == 0 || count - 1 > MAX_ID - start {
        return None;
    }
    start.checked_add(count)
}

fn validate_entries(entries: &[DbEntry]) -> io::Result<()> {
    for entry in entries {
        if entry.uid == uid_t::MAX || range_end(entry.start, entry.count).is_none() {
            return Err(invalid_data("invalid UID or subid range in database"));
        }
    }
    for id_type in [subid_type::IdTypeUid, subid_type::IdTypeGid] {
        let mut occupied: Vec<_> = entries.iter().filter(|e| e.id_type == id_type).collect();
        occupied.sort_unstable_by_key(|e| e.start);
        let mut previous_end = 0;
        for entry in occupied {
            if entry.start < previous_end {
                return Err(invalid_data("overlapping subid allocations in database"));
            }
            previous_end = range_end(entry.start, entry.count).expect("validated range");
        }
    }
    Ok(())
}

fn parse_db(mut reader: impl BufRead) -> io::Result<Vec<DbEntry>> {
    let mut entries = Vec::new();
    let mut line = String::new();
    let mut line_number = 0;
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        line_number += 1;
        // A torn append cannot safely be discarded: it may describe IDs in use.
        if !line.ends_with('\n') {
            return Err(invalid_data(
                "unterminated database record; manual recovery required",
            ));
        }
        let text = line.trim();
        if text.is_empty() || text.starts_with('#') {
            continue;
        }
        let fields: Vec<_> = text.split(':').collect();
        let bad_record = || invalid_data(format!("invalid database record on line {line_number}"));
        if fields.len() != 4 {
            return Err(bad_record());
        }
        entries.push(DbEntry {
            uid: fields[0].parse().map_err(|_| bad_record())?,
            start: fields[1].parse().map_err(|_| bad_record())?,
            count: fields[2].parse().map_err(|_| bad_record())?,
            id_type: match fields[3] {
                "u" => subid_type::IdTypeUid,
                "g" => subid_type::IdTypeGid,
                _ => return Err(bad_record()),
            },
        });
    }
    validate_entries(&entries)?;
    Ok(entries)
}

fn validate_directory(file: &File, owner: (uid_t, libc::gid_t)) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != owner.0
        || metadata.gid() != owner.1
        || metadata.mode() & 0o022 != 0
    {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "untrusted database directory",
        ));
    }
    Ok(())
}

/// Walk from / using directory FDs. Neither parent nor final symlinks are followed.
/// Every ancestor must be root-owned and not writable by group or other users.
fn open_directory(path: &Path, create: bool) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "database path must be absolute",
        ));
    }
    let mut directory = File::open("/")?;
    validate_directory(&directory, (0, 0))?;
    for component in path.components() {
        let name = match component {
            Component::RootDir => continue,
            Component::Normal(name) => CString::new(name.as_encoded_bytes())
                .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "invalid database path"))?,
            _ => {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    "invalid database path",
                ));
            }
        };
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        let mut created = false;
        let mut fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 && create && io::Error::last_os_error().kind() == ErrorKind::NotFound {
            if unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o755) } != 0 {
                let error = io::Error::last_os_error();
                if error.kind() != ErrorKind::AlreadyExists {
                    return Err(error);
                }
            } else {
                created = true;
            }
            directory.sync_all()?;
            fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        }
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let next = unsafe { File::from_raw_fd(fd) };
        if created {
            set_created_owner(&next, (0, 0))?;
        }
        validate_directory(&next, (0, 0))?;
        if created {
            // Do not let a restrictive login-service umask hide the database
            // from unprivileged NSS readers.
            if unsafe { libc::fchmod(next.as_raw_fd(), 0o755) } != 0 {
                return Err(io::Error::last_os_error());
            }
            next.sync_all()?;
        }
        directory = next;
    }
    Ok(directory)
}

// A setuid-root caller may still have the user's effective GID. Correct only
// newly created objects, using their original FD, and check every failure.
fn set_created_owner(file: &File, owner: (uid_t, libc::gid_t)) -> io::Result<()> {
    if unsafe { libc::fchown(file.as_raw_fd(), owner.0, owner.1) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

struct Database {
    directory: File,
    owner: (uid_t, libc::gid_t),
}

impl Database {
    fn open(create: bool) -> io::Result<Self> {
        let parent = Path::new(SUBID_DB_PATH)
            .parent()
            .expect("constant database parent");
        Ok(Self {
            directory: open_directory(parent, create)?,
            owner: (0, 0),
        })
    }

    fn open_file(&self, write: bool) -> io::Result<File> {
        let flags = libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | libc::O_NONBLOCK
            | if write {
                libc::O_RDWR | libc::O_APPEND
            } else {
                libc::O_RDONLY
            };
        let mut created = false;
        let mut fd =
            unsafe { libc::openat(self.directory.as_raw_fd(), c"allocated".as_ptr(), flags) };
        if fd < 0 && write && io::Error::last_os_error().kind() == ErrorKind::NotFound {
            fd = unsafe {
                libc::openat(
                    self.directory.as_raw_fd(),
                    c"allocated".as_ptr(),
                    flags | libc::O_CREAT | libc::O_EXCL,
                    0o644,
                )
            };
            if fd < 0 && io::Error::last_os_error().kind() == ErrorKind::AlreadyExists {
                fd = unsafe {
                    libc::openat(self.directory.as_raw_fd(), c"allocated".as_ptr(), flags)
                };
            } else if fd >= 0 {
                created = true;
            }
        }
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        if created {
            set_created_owner(&file, self.owner)?;
        }
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != self.owner.0
            || metadata.gid() != self.owner.1
            || metadata.mode() & 0o7022 != 0
        {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "untrusted database file",
            ));
        }
        if created && unsafe { libc::fchmod(file.as_raw_fd(), 0o644) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(file)
    }

    fn read(&self) -> io::Result<Vec<DbEntry>> {
        let file = match self.open_file(false) {
            Ok(file) => file,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let _lock = FileLock::shared(&file)?;
        let entries = parse_db(BufReader::new(&file))?;
        // Do not authorize a visible append left by a writer whose sync failed.
        file.sync_all()?;
        self.directory.sync_all()?;
        Ok(entries)
    }

    fn append_locked(&self, file: &File, entry: &DbEntry) -> io::Result<()> {
        let type_char = match entry.id_type {
            subid_type::IdTypeUid => 'u',
            subid_type::IdTypeGid => 'g',
        };
        // Build the entire line before writing. An interrupted/short write remains
        // a detectable incomplete record; never truncate it or reuse its IDs.
        let line = format!(
            "{}:{}:{}:{}\n",
            entry.uid, entry.start, entry.count, type_char
        );
        let mut writer = file;
        writer.write_all(line.as_bytes())?;
        file.sync_all()?;
        // Also persist the directory entry when the database was newly created.
        self.directory.sync_all()
    }

    fn allocate(
        &self,
        uid: uid_t,
        id_type: subid_type,
        cfg: &SubidConfig,
    ) -> io::Result<(c_ulong, c_ulong)> {
        // Existing allocations remain readable without write privileges. Sync
        // before reporting allocation success even after a previous writer's error.
        match self.open_file(false) {
            Ok(file) => {
                let _lock = FileLock::shared(&file)?;
                let entries = parse_db(BufReader::new(&file))?;
                if let Some(entry) = entries
                    .iter()
                    .find(|e| e.uid == uid && e.id_type == id_type)
                {
                    file.sync_all()?;
                    self.directory.sync_all()?;
                    return Ok((entry.start, entry.count));
                }
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        if uid < 1000 || uid == uid_t::MAX {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "UID is not eligible for automatic allocation",
            ));
        }
        cfg.validate()?;
        let file = self.open_file(true)?;
        let _lock = FileLock::exclusive(&file)?;
        let entries = parse_db(BufReader::new(&file))?;
        if let Some(entry) = entries
            .iter()
            .find(|e| e.uid == uid && e.id_type == id_type)
        {
            file.sync_all()?;
            self.directory.sync_all()?;
            return Ok((entry.start, entry.count));
        }
        // Selection happens only after locking and reading the current database.
        let (start, count) = find_free_range(&entries, id_type, cfg)
            .ok_or_else(|| io::Error::other("no free subid range"))?;
        self.append_locked(
            &file,
            &DbEntry {
                uid,
                start,
                count,
                id_type,
            },
        )?;
        Ok((start, count))
    }
}

struct FileLock<'a>(&'a File);

impl<'a> FileLock<'a> {
    fn shared(file: &'a File) -> io::Result<Self> {
        Self::acquire(file, libc::LOCK_SH)
    }

    fn exclusive(file: &'a File) -> io::Result<Self> {
        Self::acquire(file, libc::LOCK_EX)
    }

    fn acquire(file: &'a File, operation: libc::c_int) -> io::Result<Self> {
        loop {
            if unsafe { libc::flock(file.as_raw_fd(), operation) } == 0 {
                return Ok(Self(file));
            }
            let error = io::Error::last_os_error();
            if error.kind() != ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

impl Drop for FileLock<'_> {
    fn drop(&mut self) {
        // Closing the descriptor also releases the lock on every error path.
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// Read a complete, validated snapshot under a shared lock.
pub fn read_db() -> io::Result<Vec<DbEntry>> {
    match Database::open(false) {
        Ok(db) => db.read(),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// Create a trusted root-owned database, or reject an unsafe existing file.
pub fn ensure_db_permissions() -> io::Result<()> {
    let db = Database::open(true)?;
    let file = db.open_file(true)?;
    let _lock = FileLock::exclusive(&file)?;
    parse_db(BufReader::new(&file))?;
    file.sync_all()?;
    db.directory.sync_all()
}

/// Validate and append an allocation under an exclusive lock.
pub fn append_db_entry(entry: &DbEntry) -> io::Result<()> {
    let db = Database::open(true)?;
    let file = db.open_file(true)?;
    let _lock = FileLock::exclusive(&file)?;
    let mut entries = parse_db(BufReader::new(&file))?;
    entries.push(entry.clone());
    validate_entries(&entries)?;
    db.append_locked(&file, entry)
}

/// First-fit allocation with checked arithmetic and an inclusive configured max.
pub fn find_free_range(
    entries: &[DbEntry],
    id_type: subid_type,
    cfg: &SubidConfig,
) -> Option<(c_ulong, c_ulong)> {
    let (min, max, count) = cfg.limits(id_type);
    if min == 0 || min > max || max > MAX_ID || count == 0 || count > max - min + 1 {
        return None;
    }
    let mut occupied = Vec::new();
    for entry in entries.iter().filter(|e| e.id_type == id_type) {
        occupied.push((entry.start, range_end(entry.start, entry.count)?));
    }
    occupied.sort_unstable_by_key(|&(start, _)| start);
    let mut candidate = min;
    for (start, end) in occupied {
        let candidate_end = range_end(candidate, count)?;
        if candidate_end - 1 > max {
            return None;
        }
        if candidate_end <= start {
            return Some((candidate, count));
        }
        candidate = candidate.max(end);
    }
    let end = range_end(candidate, count)?;
    (end - 1 <= max).then_some((candidate, count))
}

fn covers_range(
    entries: &[DbEntry],
    uid: uid_t,
    start: c_ulong,
    count: c_ulong,
    id_type: subid_type,
) -> bool {
    let Some(end) = range_end(start, count) else {
        return false;
    };
    let mut ranges: Vec<_> = entries
        .iter()
        .filter(|e| e.uid == uid && e.id_type == id_type)
        .collect();
    ranges.sort_unstable_by_key(|e| e.start);
    let mut cursor = start;
    for entry in ranges {
        if entry.start > cursor {
            return false;
        }
        if let Some(entry_end) = range_end(entry.start, entry.count) {
            cursor = cursor.max(entry_end);
            if cursor >= end {
                return true;
            }
        }
    }
    false
}

pub fn has_range(
    uid: uid_t,
    start: c_ulong,
    count: c_ulong,
    id_type: subid_type,
) -> io::Result<bool> {
    Ok(covers_range(&read_db()?, uid, start, count, id_type))
}

pub fn list_ranges(uid: uid_t, id_type: subid_type) -> io::Result<Vec<(c_ulong, c_ulong)>> {
    Ok(read_db()?
        .into_iter()
        .filter(|e| e.uid == uid && e.id_type == id_type)
        .map(|e| (e.start, e.count))
        .collect())
}

pub fn find_owners(id: c_ulong, id_type: subid_type) -> io::Result<Vec<uid_t>> {
    let mut owners: Vec<_> = read_db()?
        .into_iter()
        .filter(|e| {
            e.id_type == id_type
                && id >= e.start
                && range_end(e.start, e.count).is_some_and(|end| id < end)
        })
        .map(|e| e.uid)
        .collect();
    owners.sort_unstable();
    owners.dedup();
    Ok(owners)
}

pub fn allocate(uid: uid_t, id_type: subid_type) -> io::Result<(c_ulong, c_ulong)> {
    // Preserve existing grants even when allocation has since been disabled or
    // the configuration changed. read_db confirms their durability.
    if let Some(entry) = read_db()?
        .iter()
        .find(|e| e.uid == uid && e.id_type == id_type)
    {
        return Ok((entry.start, entry.count));
    }
    if uid < 1000 || uid == uid_t::MAX {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "UID is not eligible for automatic allocation",
        ));
    }
    let cfg = parse_login_defs()?;
    Database::open(true)?.allocate(uid, id_type, &cfg)
}

/// System users and explicitly disabled allocation are normal query outcomes.
/// All unexpected allocation failures propagate to NSS and are logged by PAM.
pub fn ensure_allocation(uid: uid_t, id_type: subid_type) -> io::Result<()> {
    let entries = read_db()?;
    if entries.iter().any(|e| e.uid == uid && e.id_type == id_type) || uid < 1000 {
        return Ok(());
    }
    let cfg = parse_login_defs()?;
    if cfg.limits(id_type).2 == 0 {
        return Ok(());
    }
    Database::open(true)?
        .allocate(uid, id_type, &cfg)
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        path::PathBuf,
        sync::{
            Arc, Barrier,
            atomic::{AtomicUsize, Ordering},
            mpsc,
        },
        time::Duration,
    };

    const U: subid_type = subid_type::IdTypeUid;
    const G: subid_type = subid_type::IdTypeGid;
    static NEXT_TEMP: AtomicUsize = AtomicUsize::new(0);

    struct TestDatabase {
        path: PathBuf,
        db: Database,
    }

    impl TestDatabase {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "subid-dyn-test-{}-{}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            let directory = File::open(&path).unwrap();
            let owner = (unsafe { libc::geteuid() }, unsafe { libc::getegid() });
            validate_directory(&directory, owner).unwrap();
            Self {
                path,
                db: Database { directory, owner },
            }
        }

        fn file(&self) -> PathBuf {
            self.path.join("allocated")
        }

        fn write(&self, text: &str) {
            fs::write(self.file(), text).unwrap();
            fs::set_permissions(self.file(), fs::Permissions::from_mode(0o644)).unwrap();
        }
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.path).unwrap();
        }
    }

    fn entry(uid: uid_t, start: c_ulong, count: c_ulong, id_type: subid_type) -> DbEntry {
        DbEntry {
            uid,
            start,
            count,
            id_type,
        }
    }

    #[test]
    fn first_fit_never_exceeds_max_before_an_old_range() {
        let cfg = SubidConfig {
            uid_min: 100,
            uid_max: 150,
            uid_count: 60,
            ..SubidConfig::default()
        };
        assert_eq!(find_free_range(&[entry(1001, 1000, 100, U)], U, &cfg), None);
        let cfg = SubidConfig {
            uid_count: 51,
            ..cfg
        };
        assert_eq!(
            find_free_range(&[entry(1001, 1000, 100, U)], U, &cfg),
            Some((100, 51))
        );
    }

    #[test]
    fn first_fit_handles_holes_and_separate_uid_gid_spaces() {
        let cfg = SubidConfig {
            uid_min: 100,
            uid_max: 199,
            uid_count: 10,
            ..SubidConfig::default()
        };
        let entries = [
            entry(1001, 120, 10, U),
            entry(1002, 90, 20, U),
            entry(1001, 110, 10, G),
        ];
        assert_eq!(find_free_range(&entries, U, &cfg), Some((110, 10)));
        let cfg = SubidConfig {
            uid_count: 20,
            ..cfg
        };
        assert_eq!(find_free_range(&entries, U, &cfg), Some((130, 20)));
    }

    #[test]
    fn first_fit_rejects_overflow_zero_and_invalid_kernel_ids() {
        for (min, max, count) in [
            (c_ulong::MAX - 5, c_ulong::MAX, 10),
            (MAX_ID - 5, MAX_ID, 7),
            (100, 200, 0),
            (0, 200, 10),
            (200, 100, 10),
        ] {
            let cfg = SubidConfig {
                uid_min: min,
                uid_max: max,
                uid_count: count,
                ..SubidConfig::default()
            };
            assert_eq!(find_free_range(&[], U, &cfg), None);
        }
        let cfg = SubidConfig {
            uid_min: MAX_ID - 5,
            uid_max: MAX_ID,
            uid_count: 6,
            ..SubidConfig::default()
        };
        assert_eq!(find_free_range(&[], U, &cfg), Some((MAX_ID - 5, 6)));
        assert_eq!(
            find_free_range(
                &[entry(1001, c_ulong::MAX - 1, 10, U)],
                U,
                &SubidConfig::default()
            ),
            None
        );
    }

    #[test]
    fn invalid_config_is_an_error_and_zero_count_disables_allocation() {
        for text in [
            "SUB_UID_COUNT nope\n",
            "SUB_UID_MIN\n",
            "SUB_UID_MAX 4294967295\n",
            "SUB_UID_MIN 600100001\n",
            "SUB_UID_COUNT 600100001\n",
            "SUB_GID_COUNT 1 extra\n",
        ] {
            assert!(parse_config(text.as_bytes()).is_err(), "{text}");
        }
        let cfg = parse_config(
            b"# comment\nUID_MIN 1000\nSUB_UID_COUNT 0 # disabled\nSUB_GID_COUNT 0\n".as_slice(),
        )
        .unwrap();
        assert_eq!(cfg.uid_count, 0);
        assert_eq!(cfg.gid_count, 0);
    }

    #[test]
    fn database_rejects_corruption_and_unterminated_records() {
        for text in [
            "1001:100000:broken:u\n",
            "1001:100000:65536:u",
            "1001:100000:65536:u1002:165536:65536:u\n",
            "1001:100000:0:u\n",
            "1001:4294967295:1:u\n",
            "4294967295:100000:1:u\n",
            "1001:100000:65536:x\n",
            "garbage\n",
            "1001:100000:65536:u\n1002:100001:1:u\n",
        ] {
            assert!(parse_db(text.as_bytes()).is_err(), "{text}");
        }
        let entries =
            parse_db(b"# comment\n\n1001:100000:65536:u\n1001:100000:65536:g\n".as_slice())
                .unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn corrupt_tail_blocks_allocation_without_discarding_bytes() {
        let db = TestDatabase::new();
        for text in ["1001:100000:65536:u", "1001:100000:broken:u\n"] {
            db.write(text);
            assert_eq!(
                db.db
                    .allocate(1002, U, &SubidConfig::default())
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidData
            );
            assert_eq!(fs::read_to_string(db.file()).unwrap(), text);
            assert!(db.db.read().is_err());
        }
    }

    #[test]
    fn concurrent_allocations_are_unique_and_idempotent() {
        let db = Arc::new(TestDatabase::new());
        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();
        for index in 0..8 {
            let db = Arc::clone(&db);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                db.db
                    .allocate(1001 + index, U, &SubidConfig::default())
                    .unwrap()
            }));
        }
        let mut ranges: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        ranges.sort_unstable();
        assert_eq!(ranges.len(), 8);
        for pair in ranges.windows(2) {
            assert!(pair[0].0 + pair[0].1 <= pair[1].0);
        }
        assert_eq!(db.db.read().unwrap().len(), 8);
        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let db = Arc::clone(&db);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                db.db.allocate(2000, G, &SubidConfig::default()).unwrap()
            }));
        }
        let ranges: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert!(ranges.iter().all(|range| range == &ranges[0]));
        assert_eq!(db.db.read().unwrap().len(), 9);
    }

    #[test]
    fn readers_wait_for_the_writer_to_finish_a_record() {
        let db = Arc::new(TestDatabase::new());
        let file = db.db.open_file(true).unwrap();
        let lock = FileLock::exclusive(&file).unwrap();
        let mut writer = &file;
        writer.write_all(b"1001:100000:").unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (tx, rx) = mpsc::channel();
        let reader_db = Arc::clone(&db);
        let reader = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            tx.send(reader_db.db.read()).unwrap();
        });
        started_rx.recv().unwrap();
        assert!(matches!(
            rx.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        writer.write_all(b"65536:u\n").unwrap();
        file.sync_all().unwrap();
        drop(lock);
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap()
                .len(),
            1
        );
        reader.join().unwrap();
    }

    #[test]
    fn symlinks_hardlinks_fifos_and_writable_files_are_rejected() {
        let db = TestDatabase::new();
        let target = db.path.join("private");
        fs::write(&target, "private data").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, db.file()).unwrap();
        assert!(db.db.open_file(true).is_err());
        assert_eq!(fs::metadata(&target).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::read_to_string(&target).unwrap(), "private data");
        fs::remove_file(db.file()).unwrap();
        fs::hard_link(&target, db.file()).unwrap();
        assert!(db.db.open_file(true).is_err());
        fs::remove_file(db.file()).unwrap();
        let name = CString::new(db.file().as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o644) }, 0);
        assert!(db.db.open_file(true).is_err());
        fs::remove_file(db.file()).unwrap();
        db.write("");
        fs::set_permissions(db.file(), fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(
            db.db.open_file(true).unwrap_err().kind(),
            ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn wrong_owner_and_writable_directory_are_rejected() {
        let db = TestDatabase::new();
        db.write("");
        let wrong_owner = Database {
            directory: File::open(&db.path).unwrap(),
            owner: (db.db.owner.0.wrapping_add(1), db.db.owner.1),
        };
        assert_eq!(
            wrong_owner.open_file(true).unwrap_err().kind(),
            ErrorKind::PermissionDenied
        );
        fs::set_permissions(&db.path, fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            validate_directory(&db.db.directory, db.db.owner)
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        // Production traversal rejects writable ancestors such as /tmp.
        assert!(open_directory(&db.path, false).is_err());
    }

    #[test]
    fn directory_traversal_rejects_symlinks() {
        let db = TestDatabase::new();
        // /proc/self is a symlink even though its parent is trusted.
        assert!(open_directory(Path::new("/proc/self"), false).is_err());
        assert!(open_directory(Path::new("relative"), false).is_err());
        assert!(open_directory(Path::new("/var/../etc"), false).is_err());
        validate_directory(&db.db.directory, db.db.owner).unwrap();
    }

    #[test]
    fn range_checks_support_adjacent_ranges_and_reject_empty_requests() {
        let entries = [
            entry(1001, 100, 10, U),
            entry(1001, 110, 10, U),
            entry(1002, 120, 10, U),
        ];
        assert!(covers_range(&entries, 1001, 105, 15, U));
        assert!(!covers_range(&entries, 1001, 105, 16, U));
        assert!(!covers_range(&entries, 1001, 105, 0, U));
        assert!(!covers_range(&entries, 1001, 105, 1, G));
        assert!(!covers_range(&entries, 1001, c_ulong::MAX, 2, U));
    }

    #[test]
    fn exhausted_disabled_and_system_allocations_are_errors() {
        let db = TestDatabase::new();
        let cfg = SubidConfig {
            uid_min: 100,
            uid_max: 109,
            uid_count: 10,
            ..SubidConfig::default()
        };
        assert_eq!(db.db.allocate(1001, U, &cfg).unwrap(), (100, 10));
        assert!(db.db.allocate(1002, U, &cfg).is_err());
        assert!(db.db.allocate(999, U, &cfg).is_err());
        let disabled = SubidConfig {
            uid_count: 0,
            ..cfg
        };
        assert!(db.db.allocate(1002, U, &disabled).is_err());
        assert_eq!(db.db.allocate(1001, U, &disabled).unwrap(), (100, 10));
        assert_eq!(db.db.read().unwrap().len(), 1);
    }

    #[test]
    fn failed_directory_sync_is_propagated() {
        let db = TestDatabase::new();
        let file = db.db.open_file(true).unwrap();
        let _lock = FileLock::exclusive(&file).unwrap();
        // A deliberately non-syncable FD injects failure after the data sync.
        let failing_sync = Database {
            directory: File::open("/dev/null").unwrap(),
            owner: db.db.owner,
        };
        assert!(
            failing_sync
                .append_locked(&file, &entry(1001, 100000, 65536, U))
                .is_err()
        );
        assert_eq!(
            fs::read_to_string(db.file()).unwrap(),
            "1001:100000:65536:u\n"
        );
    }

    #[test]
    fn ownership_failures_are_propagated_without_changing_permissions() {
        let db = TestDatabase::new();
        db.write("");
        let file = File::open(db.file()).unwrap();
        let original_mode = file.metadata().unwrap().mode();
        if unsafe { libc::geteuid() } != 0 {
            // Unmapped root in a user namespace can report EINVAL instead of EPERM.
            assert!(set_created_owner(&file, (0, 0)).is_err());
            assert_eq!(file.metadata().unwrap().mode(), original_mode);
        }
        set_created_owner(&file, db.db.owner).unwrap();
    }
}
