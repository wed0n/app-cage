mod exec;

use std::{ffi::OsStr, path::PathBuf, sync::RwLock};

use anyhow::{Ok, Result, anyhow};
use endpoint_sec::sys::es_auth_result_t;
use endpoint_sec::{
    Client, EventCreate, EventCreateDestinationFile, EventDeleteExtAttr, EventExchangeData,
    EventFork, EventLink, EventOpen, EventRename, EventRenameDestinationFile, EventSetAcl,
    EventSetAttrlist, EventSetExtAttr, EventSetFlags, EventSetMode, EventSetOwner, EventUnlink,
    Message,
};
use roaring::RoaringBitmap;

use crate::config::Config;
use crate::handler::flags::FWRITE;
use crate::path_matcher::PathMatcher;

pub(super) use self::exec::handle_auth_exec;

fn os_str_convert(os_str: &OsStr) -> Result<&str> {
    os_str
        .to_str()
        .ok_or(anyhow!("bad path {}", os_str.to_string_lossy()))
}

fn judge_one_file(
    config: &Config,
    matcher: &PathMatcher,
    client: &mut Client,
    msg: &Message,
    event: &str,
    target: &str,
) -> Result<bool> {
    let mut is_responded = false;
    if !matcher.is_match(target) {
        let pid = msg.process().audit_token().pid();
        if config.enforcing {
            client
                .respond_auth_result(&msg, es_auth_result_t::ES_AUTH_RESULT_DENY, true)
                .map_err(|err| anyhow!("respond {} event failed: {}", event, err))?;
            log::info!("reject pid {} {} file {} ", pid, event, target);
            is_responded = true;
        } else {
            log::warn!("pid {} {} unexpected file {}", pid, event, target);
        }
    }

    Ok(is_responded)
}

fn judge_pair_files(
    config: &Config,
    matcher: &PathMatcher,
    client: &mut Client,
    msg: &Message,
    event: &str,
    source: &str,
    destination: &str,
) -> Result<bool> {
    let mut is_responded = false;
    if !(matcher.is_match(source) && matcher.is_match(destination)) {
        let pid = msg.process().audit_token().pid();
        if config.enforcing {
            client
                .respond_auth_result(&msg, es_auth_result_t::ES_AUTH_RESULT_DENY, true)
                .map_err(|err| anyhow!("respond {} event failed: {}", event, err))?;
            log::info!(
                "reject pid {} {} file {} to {} ",
                pid,
                event,
                source,
                destination
            );
            is_responded = true;
        } else {
            log::warn!(
                "pid {} {} unexpected file {} to {}",
                pid,
                event,
                source,
                destination
            );
        }
    }

    Ok(is_responded)
}

pub(super) fn handle_auth_open(
    config: &Config,
    matcher: &PathMatcher,
    client: &mut Client,
    msg: &Message,
    event_open: EventOpen,
) -> Result<bool> {
    let mut is_responded = false;
    let path = os_str_convert(event_open.file().path())?;
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
    let destination;
    let mut new_path;
    match event_create
        .destination()
        .ok_or(anyhow!("create event destination is none"))?
    {
        EventCreateDestinationFile::ExistingFile(file) => {
            destination = os_str_convert(file.path())?;
        }
        EventCreateDestinationFile::NewPath {
            directory,
            filename,
            mode: _,
        } => {
            new_path = PathBuf::from(os_str_convert(directory.path())?);
            new_path.push(os_str_convert(filename)?);
            destination = new_path
                .to_str()
                .ok_or(anyhow!("bad new path {}", new_path.to_string_lossy()))?;
        }
    }

    judge_one_file(config, matcher, client, msg, "create", destination)
}

pub(super) fn handle_auth_rename(
    config: &Config,
    matcher: &PathMatcher,
    client: &mut Client,
    msg: &Message,
    event_rename: EventRename,
) -> Result<bool> {
    let source = os_str_convert(event_rename.source().path())?;
    let destination;
    let mut new_path;
    match event_rename
        .destination()
        .ok_or(anyhow!("destination is none"))?
    {
        EventRenameDestinationFile::ExistingFile(file) => {
            destination = os_str_convert(file.path())?;
        }
        EventRenameDestinationFile::NewPath {
            directory,
            filename,
        } => {
            new_path = PathBuf::from(os_str_convert(directory.path())?);
            new_path.push(os_str_convert(filename)?);
            destination = new_path
                .to_str()
                .ok_or(anyhow!("bad new path {}", new_path.to_string_lossy()))?;
        }
    }

    judge_pair_files(config, matcher, client, msg, "rename", source, destination)
}

pub(super) fn handle_auth_link(
    config: &Config,
    matcher: &PathMatcher,
    client: &mut Client,
    msg: &Message,
    event_link: EventLink,
) -> Result<bool> {
    let source = os_str_convert(event_link.source().path())?;
    let mut new_path = PathBuf::from(os_str_convert(event_link.target_dir().path())?);
    new_path.push(os_str_convert(event_link.target_filename())?);
    let destination = new_path
        .to_str()
        .ok_or(anyhow!("bad new path {}", new_path.to_string_lossy()))?;

    judge_pair_files(config, matcher, client, msg, "link", source, destination)
}

pub(super) fn handle_auth_unlink(
    config: &Config,
    matcher: &PathMatcher,
    client: &mut Client,
    msg: &Message,
    event_unlink: EventUnlink,
) -> Result<bool> {
    let path = os_str_convert(event_unlink.target().path())?;

    judge_one_file(config, matcher, client, msg, "unlink", path)
}

pub(super) fn handle_auth_exchange_data(
    config: &Config,
    matcher: &PathMatcher,
    client: &mut Client,
    msg: &Message,
    event: EventExchangeData,
) -> Result<bool> {
    let file1 = os_str_convert(event.file1().path())?;
    let file2 = os_str_convert(event.file2().path())?;

    judge_pair_files(config, matcher, client, msg, "exchange data", file1, file2)
}

pub(super) fn handle_auth_delete_ext_attr(
    config: &Config,
    matcher: &PathMatcher,
    client: &mut Client,
    msg: &Message,
    event: EventDeleteExtAttr,
) -> Result<bool> {
    let target = os_str_convert(event.target().path())?;

    judge_one_file(config, matcher, client, msg, "delete ext attr", target)
}

pub(super) fn handle_auth_set_acl(
    config: &Config,
    matcher: &PathMatcher,
    client: &mut Client,
    msg: &Message,
    event_set_acl: EventSetAcl,
) -> Result<bool> {
    let path = os_str_convert(event_set_acl.target().path())?;

    judge_one_file(config, matcher, client, msg, "set acl", path)
}

pub(super) fn handle_auth_set_attr_list(
    config: &Config,
    matcher: &PathMatcher,
    client: &mut Client,
    msg: &Message,
    event_set_attr_list: EventSetAttrlist,
) -> Result<bool> {
    let path = os_str_convert(event_set_attr_list.target().path())?;

    judge_one_file(config, matcher, client, msg, "set attr list", path)
}

pub(super) fn handle_auth_set_ext_attr(
    config: &Config,
    matcher: &PathMatcher,
    client: &mut Client,
    msg: &Message,
    event_set_ext_attr: EventSetExtAttr,
) -> Result<bool> {
    let path = os_str_convert(event_set_ext_attr.target().path())?;

    judge_one_file(config, matcher, client, msg, "set ext attr", path)
}

pub(super) fn handle_auth_set_flags(
    config: &Config,
    matcher: &PathMatcher,
    client: &mut Client,
    msg: &Message,
    event_set_flags: EventSetFlags,
) -> Result<bool> {
    let path = os_str_convert(event_set_flags.target().path())?;

    judge_one_file(config, matcher, client, msg, "set flags", path)
}

pub(super) fn handle_auth_set_mode(
    config: &Config,
    matcher: &PathMatcher,
    client: &mut Client,
    msg: &Message,
    event_set_mode: EventSetMode,
) -> Result<bool> {
    let path = os_str_convert(event_set_mode.target().path())?;

    judge_one_file(config, matcher, client, msg, "set mode", path)
}

pub(super) fn handle_auth_set_owner(
    config: &Config,
    matcher: &PathMatcher,
    client: &mut Client,
    msg: &Message,
    event_set_owner: EventSetOwner,
) -> Result<bool> {
    let path = os_str_convert(event_set_owner.target().path())?;

    judge_one_file(config, matcher, client, msg, "set owner", path)
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
