use std::{env, sync::RwLock};

use anyhow::{Ok, Result, anyhow};
use endpoint_sec::{Client, ExpectedResponseType, Message};
use endpoint_sec_sys::{es_auth_result_t, es_event_type_t};
use globset::{Glob, GlobSetBuilder};
use log;

use crate::bitmap::make_bit_map;
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

fn default_allow_event(client: &mut Client<'_>, msg: &Message) -> Result<()> {
    let (Some(action), Some(event)) = (msg.action(), msg.event()) else {
        return Ok(());
    };
    let endpoint_sec::Action::Auth(event_id) = action else {
        return Ok(());
    };
    match event.expected_response_type() {
        Some(resp_type) => match resp_type {
            ExpectedResponseType::Auth => {
                client
                    .respond_auth_result(&msg, es_auth_result_t::ES_AUTH_RESULT_ALLOW, true)
                    .map_err(|err| {
                        anyhow!("respond auth event 0x{:02X} failed: {}", event_id, err)
                    })?;
            }
            ExpectedResponseType::Flags { flags: _ } => {
                static FULL_ACCESS: u32 = u32::MAX;
                client
                    .respond_flags_result(&msg, FULL_ACCESS, true)
                    .map_err(|err| {
                        anyhow!(
                            "respond auth flags event 0x{:02X} failed: {}",
                            event_id,
                            err
                        )
                    })?;
            }
        },
        None => log::warn!("auth event 0x{:02X} not response", event_id),
    }

    Ok(())
}

pub(super) fn get_handler_and_subscribe_events(
    config: &Config,
) -> Result<(
    impl Fn(&mut Client<'_>, Message),
    &'static [es_event_type_t],
)> {
    let bit_map = make_bit_map()?;
    let bit_map_locker = RwLock::new(bit_map);
    let mut builder = GlobSetBuilder::new();
    let mut cwd = env::current_dir()?;
    cwd.push("*.txt");
    let cwd = cwd.to_str().ok_or(anyhow!("add cwd to glob set failed"))?;
    builder.add(Glob::new(cwd)?);
    log::debug!("add cwd {} to glob set", cwd);
    for allow_path in config.whitelist.iter() {
        builder.add(Glob::new(allow_path)?);
    }
    let set = builder.build()?;

    let handler = move |client: &mut Client<'_>, msg: Message| {
        let mut execute = || -> Result<()> {
            let pid = msg.process().audit_token().pid();
            let bit_map = bit_map_locker
                .read()
                .map_err(|err| anyhow!("get bit map locker failed: {}", err))?;
            if let Some(event) = msg.event() {
                if bit_map.contains(pid as u32) {
                    match event {
                        endpoint_sec::Event::AuthOpen(event_open) => {
                            let os_path = event_open.file().path();
                            let path = os_path.to_str().ok_or(anyhow!(
                                "bad path {} in auth event",
                                os_path.to_string_lossy()
                            ))?;
                            let fflag = event_open.fflag();
                            if set.is_match(path) && fflag & FWRITE != 0 {
                                if config.enforcing {
                                    client
                                        .respond_flags_result(&msg, !FWRITE as u32, true)
                                        .map_err(|err| {
                                            anyhow!("respond open file event failed: {}", err)
                                        })?;
                                    return Ok(());
                                } else {
                                    log::warn!(
                                        "open unexpected file {} as mode 0x{:02X}",
                                        path,
                                        fflag
                                    );
                                }
                            }
                        }
                        endpoint_sec::Event::AuthMmap(event_mmap) => {
                            let os_path = event_mmap.source().path();
                            let path = os_path.to_str().ok_or(anyhow!(
                                "bad path {} in mmap event",
                                os_path.to_string_lossy()
                            ))?;
                            if set.is_match(path) {
                                log::debug!("mmap {}", path);
                            }
                        }
                        endpoint_sec::Event::AuthRename(event_rename) => {
                            let os_path = event_rename.source().path();
                            let path = os_path.to_str().ok_or(anyhow!(
                                "bad path {} in rename event",
                                os_path.to_string_lossy()
                            ))?;
                            if set.is_match(path) {
                                log::debug!("rename {}", path);
                            }
                        }
                        endpoint_sec::Event::AuthUnlink(event_unlink) => {
                            let os_path = event_unlink.target().path();
                            let path = os_path.to_str().ok_or(anyhow!(
                                "bad path {} in unlink event",
                                os_path.to_string_lossy()
                            ))?;
                            if set.is_match(path) {
                                log::debug!("unlink {}", path);
                            }
                        }
                        endpoint_sec::Event::NotifyFork(event_fork) => {
                            let child = event_fork.child();
                            drop(bit_map);
                            let mut bit_map = bit_map_locker.write().map_err(|err| {
                                anyhow!("get bit map write locker in fork event failed: {}", err)
                            })?;
                            let pid = child.audit_token().pid();
                            bit_map.insert(pid as u32);
                        }
                        endpoint_sec::Event::NotifyExit(_event_exit) => {
                            drop(bit_map);
                            let mut bit_map = bit_map_locker.write().map_err(|err| {
                                anyhow!("get bit map write locker in exit event failed: {}", err)
                            })?;
                            bit_map.remove(pid as u32);
                        }
                        _other => {}
                    }
                }
            }
            default_allow_event(client, &msg)?;

            Ok(())
        };
        if let Err(err) = execute() {
            log::error!("handle event failed: {}", err);
        }
    };
    static SUBSCRIBE_EVENTS: &[es_event_type_t] = &[
        es_event_type_t::ES_EVENT_TYPE_AUTH_OPEN,
        es_event_type_t::ES_EVENT_TYPE_AUTH_MMAP,
        es_event_type_t::ES_EVENT_TYPE_AUTH_RENAME,
        es_event_type_t::ES_EVENT_TYPE_AUTH_UNLINK,
        es_event_type_t::ES_EVENT_TYPE_NOTIFY_FORK,
        es_event_type_t::ES_EVENT_TYPE_NOTIFY_EXIT,
    ];
    Ok((handler, SUBSCRIBE_EVENTS))
}
