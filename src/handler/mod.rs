mod event_handler;

use std::{env, sync::RwLock};

use anyhow::{Ok, Result, anyhow};
use endpoint_sec::{Client, ExpectedResponseType, Message};
use endpoint_sec_sys::{es_auth_result_t, es_event_type_t};
use globset::{Glob, GlobSetBuilder};
use log;

use crate::bitmap::make_bit_map;
use crate::config::Config;
use crate::handler::event_handler::{
    handle_auth_mmap, handle_auth_open, handle_auth_rename, handle_auth_unlink, handle_notify_exit,
    handle_notify_fork,
};

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
    cwd.push("**");
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
                            if handle_auth_open(config, &set, client, &msg, event_open)? {
                                return Ok(());
                            }
                        }
                        endpoint_sec::Event::AuthMmap(event_mmap) => {
                            if handle_auth_mmap(config, &set, client, &msg, event_mmap)? {
                                return Ok(());
                            }
                        }
                        endpoint_sec::Event::AuthRename(event_rename) => {
                            if handle_auth_rename(config, &set, client, &msg, event_rename)? {
                                return Ok(());
                            }
                        }
                        endpoint_sec::Event::AuthUnlink(event_unlink) => {
                            if handle_auth_unlink(config, &set, client, &msg, event_unlink)? {
                                return Ok(());
                            }
                        }
                        endpoint_sec::Event::NotifyFork(event_fork) => {
                            drop(bit_map);
                            handle_notify_fork(&bit_map_locker, event_fork)?;
                        }
                        endpoint_sec::Event::NotifyExit(_event_exit) => {
                            drop(bit_map);
                            handle_notify_exit(&bit_map_locker, pid)?;
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
