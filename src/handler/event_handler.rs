use std::{ffi::OsStr, path::PathBuf, sync::RwLock};

use anyhow::{Ok, Result, anyhow};
use endpoint_sec::{
    Client, EventCreate, EventCreateDestinationFile, EventFork, EventOpen, EventRename,
    EventRenameDestinationFile, EventUnlink, Message,
};
use endpoint_sec_sys::es_auth_result_t;
use roaring::RoaringBitmap;

use crate::config::Config;
use crate::handler::flags::FWRITE;
use crate::path_matcher::PathMatcher;

fn os_path_convert(os_path: &OsStr) -> Result<&str> {
    os_path
        .to_str()
        .ok_or(anyhow!("bad path {}", os_path.to_string_lossy()))
}

pub(super) fn handle_auth_open(
    config: &Config,
    matcher: &PathMatcher,
    client: &mut Client,
    msg: &Message,
    event_open: EventOpen,
) -> Result<bool> {
    let mut is_responded = false;
    let path = os_path_convert(event_open.file().path())?;
    let fflag = event_open.fflag();
    if !matcher.is_match(path) {
        let pid = msg.process().audit_token().pid();
        if config.enforcing {
            if fflag & FWRITE != 0 {
                log::info!("reject pid {} open {} as mode 0x{:02X}", pid, path, fflag);
            }
            client
                .respond_flags_result(&msg, !FWRITE as u32, false)
                .map_err(|err| anyhow!("respond open event failed: {}", err))?;
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

pub(super) fn handle_auth_create(
    config: &Config,
    matcher: &PathMatcher,
    client: &mut Client,
    msg: &Message,
    event_create: EventCreate,
) -> Result<bool> {
    let mut is_responded = false;
    let destination_path;
    let mut new_path;
    match event_create
        .destination()
        .ok_or(anyhow!("create event destination is none"))?
    {
        EventCreateDestinationFile::ExistingFile(file) => {
            destination_path = os_path_convert(file.path())?;
        }
        EventCreateDestinationFile::NewPath {
            directory,
            filename,
            mode: _,
        } => {
            new_path = PathBuf::from(os_path_convert(directory.path())?);
            new_path.push(os_path_convert(filename)?);
            destination_path = new_path
                .to_str()
                .ok_or(anyhow!("bad new path {}", new_path.to_string_lossy()))?;
        }
    }

    if !matcher.is_match(destination_path) {
        let pid = msg.process().audit_token().pid();
        if config.enforcing {
            client
                .respond_auth_result(&msg, es_auth_result_t::ES_AUTH_RESULT_DENY, true)
                .map_err(|err| anyhow!("respond create event failed: {}", err))?;
            log::info!("reject pid {} create file {} ", pid, destination_path);
            is_responded = true;
        } else {
            log::warn!("pid {} create unexpected file {}", pid, destination_path);
        }
    }

    Ok(is_responded)
}

pub(super) fn handle_auth_rename(
    config: &Config,
    matcher: &PathMatcher,
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

    if !(matcher.is_match(source_path) && matcher.is_match(destination_path)) {
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
    matcher: &PathMatcher,
    client: &mut Client,
    msg: &Message,
    event_unlink: EventUnlink,
) -> Result<bool> {
    let mut is_responded = false;
    let path = os_path_convert(event_unlink.target().path())?;

    if !matcher.is_match(path) {
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
