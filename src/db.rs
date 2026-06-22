use std::os::fd::AsRawFd;
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, ErrorKind, Write},
    str::FromStr,
};

use libc::{c_ulong, uid_t};

use crate::nss::subid_type;

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

pub const SUBID_DB_PATH: &str = "/var/db/subid/allocated";
const LOGIN_DEFS_PATH: &str = "/etc/login.defs";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

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

#[derive(Debug, Clone)]
pub struct DbEntry {
    pub uid: uid_t,
    pub start: c_ulong,
    pub count: c_ulong,
    pub id_type: subid_type,
}

// ---------------------------------------------------------------------------
// Parse /etc/login.defs
// ---------------------------------------------------------------------------

pub fn parse_login_defs() -> SubidConfig {
    let mut cfg = SubidConfig::default();
    let file = match File::open(LOGIN_DEFS_PATH) {
        Ok(f) => f,
        Err(_) => return cfg,
    };
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        let line = line.trim().to_string();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let key = parts[0];
        let val = match c_ulong::from_str(parts[1]) {
            Ok(v) => v,
            Err(_) => continue,
        };
        match key {
            "SUB_UID_MIN" => cfg.uid_min = val,
            "SUB_UID_MAX" => cfg.uid_max = val,
            "SUB_UID_COUNT" => cfg.uid_count = val,
            "SUB_GID_MIN" => cfg.gid_min = val,
            "SUB_GID_MAX" => cfg.gid_max = val,
            "SUB_GID_COUNT" => cfg.gid_count = val,
            _ => {}
        }
    }
    cfg
}

// ---------------------------------------------------------------------------
// DB file read / write
// ---------------------------------------------------------------------------

/// Read all entries from `/var/db/subid/allocated`.
/// No lock – safe for snapshot reads on the append-only file.
pub fn read_db() -> Result<Vec<DbEntry>, std::io::Error> {
    let file = match File::open(SUBID_DB_PATH) {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return Ok(Vec::new());
        }
        Err(e) => {
            return Err(e);
        }
    };
    let reader = BufReader::new(file);
    let mut entries = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() != 4 {
            continue;
        }
        let uid = match uid_t::from_str(parts[0]) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let start = match c_ulong::from_str(parts[1]) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let count = match c_ulong::from_str(parts[2]) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let id_type = match parts[3] {
            "u" => subid_type::IdTypeUid,
            "g" => subid_type::IdTypeGid,
            _ => continue,
        };
        entries.push(DbEntry {
            uid,
            start,
            count,
            id_type,
        });
    }
    Ok(entries)
}

/// Create the db directory (if missing), create the db file (if missing),
/// and set ownership to `root:root` with mode `0o644`.
pub fn ensure_db_permissions() -> Result<(), std::io::Error> {
    if let Some(parent) = std::path::Path::new(SUBID_DB_PATH).parent() {
        fs::create_dir_all(parent)?;
    }
    // Touch the file so chown/chmod have a target
    let _ = OpenOptions::new()
        .create(true)
        .write(true)
        .open(SUBID_DB_PATH)?;
    let path_c = CString::new(SUBID_DB_PATH).unwrap();
    unsafe {
        libc::chown(path_c.as_ptr(), 0, 0);
        libc::chmod(path_c.as_ptr(), 0o644);
    }
    Ok(())
}

/// Append a single allocation line to the db file.
/// The caller must hold an exclusive flock.
pub fn append_db_entry(entry: &DbEntry) -> Result<(), std::io::Error> {
    if let Some(parent) = std::path::Path::new(SUBID_DB_PATH).parent() {
        fs::create_dir_all(parent)?;
    }
    // Ensure file exists with correct permissions before appending
    ensure_db_permissions()?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(SUBID_DB_PATH)?;
    let type_char = match entry.id_type {
        subid_type::IdTypeUid => 'u',
        subid_type::IdTypeGid => 'g',
    };
    writeln!(
        file,
        "{}:{}:{}:{}",
        entry.uid, entry.start, entry.count, type_char
    )?;
    file.flush()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// File locking helpers (flock)
// ---------------------------------------------------------------------------

pub fn lock_db_exclusive(file: &File) -> Result<(), std::io::Error> {
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

pub fn unlock_db(file: &File) -> Result<(), std::io::Error> {
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Allocation helpers
// ---------------------------------------------------------------------------

/// First-fit scan over `entries` (already filtered to one `id_type`).
/// Returns `Some((start, count))` if a free range ≥ `cfg` count exists
/// inside `[cfg.min, cfg.max]`.
pub fn find_free_range(
    entries: &[DbEntry],
    id_type: subid_type,
    cfg: &SubidConfig,
) -> Option<(c_ulong, c_ulong)> {
    let (min, max, cnt) = match id_type {
        subid_type::IdTypeUid => (cfg.uid_min, cfg.uid_max, cfg.uid_count),
        subid_type::IdTypeGid => (cfg.gid_min, cfg.gid_max, cfg.gid_count),
    };

    if cnt == 0 || min > max {
        return None;
    }

    let mut occupied: Vec<(c_ulong, c_ulong)> = entries
        .iter()
        .filter(|e| e.id_type == id_type)
        .map(|e| (e.start, e.start.saturating_add(e.count)))
        .collect();
    occupied.sort_by_key(|&(s, _)| s);

    let mut candidate = min;
    for &(occ_start, occ_end) in &occupied {
        if candidate.saturating_add(cnt) <= occ_start {
            return Some((candidate, cnt));
        }
        if occ_end > candidate {
            candidate = occ_end;
        }
    }

    if candidate.saturating_add(cnt).saturating_sub(1) <= max {
        Some((candidate, cnt))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Public query / allocate helpers (uid-based, no FFI)
// ---------------------------------------------------------------------------

/// Check whether `uid` owns the range `[start, start+count)` of `id_type`.
pub fn has_range(
    uid: uid_t,
    start: c_ulong,
    count: c_ulong,
    id_type: subid_type,
) -> io::Result<bool> {
    let entries = read_db()?;
    let end = start
        .checked_add(count)
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "subid range overflow"))?;
    Ok(entries.iter().any(|e| {
        e.uid == uid
            && e.id_type == id_type
            && start >= e.start
            && end <= e.start.saturating_add(e.count)
    }))
}

/// List all `(start, count)` ranges owned by `uid` for `id_type`.
pub fn list_ranges(uid: uid_t, id_type: subid_type) -> io::Result<Vec<(c_ulong, c_ulong)>> {
    let entries = read_db()?;
    Ok(entries
        .iter()
        .filter(|e| e.uid == uid && e.id_type == id_type)
        .map(|e| (e.start, e.count))
        .collect())
}

/// Find all UIDs whose range of `id_type` covers `id`.
pub fn find_owners(id: c_ulong, id_type: subid_type) -> io::Result<Vec<uid_t>> {
    let entries = read_db()?;
    let mut owners = Vec::new();
    for e in &entries {
        if e.id_type == id_type && id >= e.start && id < e.start.saturating_add(e.count) {
            if !owners.contains(&e.uid) {
                owners.push(e.uid);
            }
        }
    }
    Ok(owners)
}

/// Allocate a subid range for `uid`+`id_type`.
///
/// Idempotent – returns the existing range when one is already present.
/// Otherwise finds a free range via first-fit and writes it to the db
/// under an exclusive `flock`.
pub fn allocate(uid: uid_t, id_type: subid_type) -> io::Result<(c_ulong, c_ulong)> {
    // ---- Step 1: check existing allocation ----
    let entries = read_db()?;
    for e in &entries {
        if e.uid == uid && e.id_type == id_type {
            return Ok((e.start, e.count));
        }
    }

    // System UIDs (< 1000) are never auto-allocated.
    // If no existing entry was found above, bail out.
    if uid < 1000 {
        return Err(io::Error::new(
            ErrorKind::Other,
            "system uid – no auto-allocation",
        ));
    }

    // ---- Step 2: read config ----
    let cfg = parse_login_defs();

    // ---- Step 3: find free range ----
    let (new_start, new_count) = find_free_range(&entries, id_type, &cfg)
        .ok_or_else(|| io::Error::new(ErrorKind::Other, "no free subid range"))?;

    // Ensure directory and file exist before locking
    ensure_db_permissions()?;

    // ---- Step 4: write to db with exclusive lock ----
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(SUBID_DB_PATH)?;

    lock_db_exclusive(&file)?;

    // Double-check under lock
    let entries2 = match read_db() {
        Ok(v) => v,
        Err(e) => {
            let _ = unlock_db(&file);
            return Err(e);
        }
    };

    for e in &entries2 {
        if e.uid == uid && e.id_type == id_type {
            let _ = unlock_db(&file);
            return Ok((e.start, e.count));
        }
    }

    // Overlap check
    for e in &entries2 {
        if e.id_type != id_type {
            continue;
        }
        let e_end = e.start.saturating_add(e.count);
        let n_end = new_start.saturating_add(new_count);
        if new_start < e_end && n_end > e.start {
            let _ = unlock_db(&file);
            return Err(io::Error::new(ErrorKind::Other, "subid range conflict"));
        }
    }

    let entry = DbEntry {
        uid,
        start: new_start,
        count: new_count,
        id_type,
    };

    if let Err(e) = append_db_entry(&entry) {
        let _ = unlock_db(&file);
        return Err(e);
    }

    let _ = unlock_db(&file);
    Ok((new_start, new_count))
}
