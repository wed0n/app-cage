use std::{ffi::OsStr, path::PathBuf, sync::RwLock};

use anyhow::{Ok, Result, anyhow};
use endpoint_sec::{
    Client, EventFork, EventOpen, EventRename, EventRenameDestinationFile, EventUnlink, Message,
};
use endpoint_sec_sys::es_auth_result_t;
use globset::GlobSet;
use roaring::RoaringBitmap;

use crate::config::Config;

// static FREAD: i32 = 0x00000001;
static FWRITE: i32 = 0x00000002;
// static FNONBLOCK: i32 = 0x00000004;
// static FAPPEND: i32 = 0x00000008;
// static FASYNC: i32 = 0x00000040;
// static FFSYNC: i32 = 0x00000080;
// static FMARK: i32 = 0x00001000;
// static FDEFER: i32 = 0x00002000;
// static FWASLOCKED: i32 = 0x00004000;
// static FWASWRITTEN: i32 = 0x00010000;
// static FNOCACHE: i32 = 0x00040000;
// static FNORDAHEAD: i32 = 0x00080000;
// static FFDSYNC: i32 = 0x00400000;
// static FNODIRECT: i32 = 0x00800000;
// static FENCRYPTED: i32 = 0x02000000;
// static FSINGLE_WRITER: i32 = 0x04000000;
// static FUNENCRYPTED: i32 = 0x10000000;
// static FEXEC: i32 = 0x40000000;

fn os_path_convert(os_path: &OsStr) -> Result<&str> {
    os_path
        .to_str()
        .ok_or(anyhow!("bad path {}", os_path.to_string_lossy()))
}

pub(super) fn handle_auth_open(
    config: &Config,
    set: &GlobSet,
    client: &mut Client,
    msg: &Message,
    event_open: EventOpen,
) -> Result<bool> {
    let mut is_responded = false;
    let path = os_path_convert(event_open.file().path())?;
    let fflag = event_open.fflag();
    if !set.is_match(path) && (fflag & FWRITE) != 0 {
        let pid = msg.process().audit_token().pid();
        if config.enforcing {
            client
                .respond_flags_result(&msg, !FWRITE as u32, true)
                .map_err(|err| anyhow!("respond open event failed: {}", err))?;
            log::info!("reject pid {} open {} as mode {}", pid, path, fflag);
            is_responded = true;
        } else {
            log::warn!(
                "pid {} open unexpected file {} as mode 0x{:02X}",
                pid,
                path,
                fflag
            );
        }
    }

    Ok(is_responded)
}

pub(super) fn handle_auth_rename(
    config: &Config,
    set: &GlobSet,
    client: &mut Client,
    msg: &Message,
    event_rename: EventRename,
) -> Result<bool> {
    let mut is_responded = false;
    let source_path = os_path_convert(event_rename.source().path())?;
    let destination_path;
    let mut new_path;
    match event_rename
        .destination()
        .ok_or(anyhow!("destination is none"))?
    {
        EventRenameDestinationFile::ExistingFile(file) => {
            destination_path = os_path_convert(file.path())?;
        }
        EventRenameDestinationFile::NewPath {
            directory,
            filename,
        } => {
            new_path = PathBuf::from(os_path_convert(directory.path())?);
            new_path.push(os_path_convert(filename)?);
            destination_path = new_path
                .to_str()
                .ok_or(anyhow!("bad new path {}", new_path.to_string_lossy()))?;
        }
    }

    if !(set.is_match(source_path) && set.is_match(destination_path)) {
        let pid = msg.process().audit_token().pid();
        if config.enforcing {
            client
                .respond_auth_result(&msg, es_auth_result_t::ES_AUTH_RESULT_DENY, true)
                .map_err(|err| anyhow!("respond rename event failed: {}", err))?;
            log::info!(
                "reject pid {} rename file {} to {}",
                pid,
                source_path,
                destination_path
            );
            is_responded = true;
        } else {
            log::warn!(
                "pid {} rename unexpected file {} to {}",
                pid,
                source_path,
                destination_path
            );
        }
    }
    Ok(is_responded)
}

pub(super) fn handle_auth_unlink(
    config: &Config,
    set: &GlobSet,
    client: &mut Client,
    msg: &Message,
    event_unlink: EventUnlink,
) -> Result<bool> {
    let mut is_responded = false;
    let path = os_path_convert(event_unlink.target().path())?;

    if !set.is_match(path) {
        let pid = msg.process().audit_token().pid();
        if config.enforcing {
            client
                .respond_auth_result(&msg, es_auth_result_t::ES_AUTH_RESULT_DENY, true)
                .map_err(|err| anyhow!("respond unlink event failed: {}", err))?;
            log::info!("reject pid {} unlink {}", pid, path);
            is_responded = true;
        } else {
            log::warn!("pid {} unlink unexpected file {}", pid, path);
        }
    }

    Ok(is_responded)
}

pub(super) fn handle_notify_fork(
    bit_map_locker: &RwLock<RoaringBitmap>,
    event_fork: EventFork,
) -> Result<()> {
    let child = event_fork.child();
    let mut bit_map = bit_map_locker
        .write()
        .map_err(|err| anyhow!("get bit map write locker in fork event failed: {}", err))?;
    let pid = child.audit_token().pid();
    bit_map.insert(pid as u32);

    Ok(())
}

pub(super) fn handle_notify_exit(bit_map_locker: &RwLock<RoaringBitmap>, pid: i32) -> Result<()> {
    let mut bit_map = bit_map_locker
        .write()
        .map_err(|err| anyhow!("get bit map write locker in exit event failed: {}", err))?;
    bit_map.remove(pid as u32);

    Ok(())
}
