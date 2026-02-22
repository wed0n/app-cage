mod event_handler;
#[allow(dead_code)]
mod flags;

use std::sync::RwLock;

use anyhow::{Ok, Result, anyhow};
use endpoint_sec::sys::{es_auth_result_t, es_event_type_t};
use endpoint_sec::{Client, ExpectedResponseType, Message};
use log;

use crate::bitmap::make_bitmap;
use crate::config::Config;
use crate::path_matcher::PathMatcher;

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
                    .respond_auth_result(&msg, es_auth_result_t::ES_AUTH_RESULT_ALLOW, false)
                    .map_err(|err| {
                        anyhow!("respond auth event 0x{:02X} failed: {}", event_id, err)
                    })?;
            }
            ExpectedResponseType::Flags { flags: _ } => {
                static FULL_ACCESS: u32 = u32::MAX;
                client
                    .respond_flags_result(&msg, FULL_ACCESS, false)
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
    let bit_map = make_bitmap()?;
    let bit_map_locker = RwLock::new(bit_map);
    let matcher = PathMatcher::new(&config)?;

    let handler = move |client: &mut Client<'_>, msg: Message| {
        let mut execute = || -> Result<()> {
            let mut is_responded = false;
            let pid = msg.process().audit_token().pid();
            let bit_map = bit_map_locker
                .read()
                .map_err(|err| anyhow!("get bit map locker failed: {}", err))?;
            if let Some(event) = msg.event() {
                if bit_map.contains(pid as u32) {
                    match event {
                        endpoint_sec::Event::AuthOpen(event_open) => {
                            is_responded = event_handler::handle_auth_open(
                                config, &matcher, client, &msg, event_open,
                            )?;
                        }
                        endpoint_sec::Event::AuthCreate(event_create) => {
                            is_responded = event_handler::handle_auth_create(
                                config,
                                &matcher,
                                client,
                                &msg,
                                event_create,
                            )?;
                        }
                        endpoint_sec::Event::AuthRename(event_rename) => {
                            is_responded = event_handler::handle_auth_rename(
                                config,
                                &matcher,
                                client,
                                &msg,
                                event_rename,
                            )?;
                        }
                        endpoint_sec::Event::AuthLink(event_link) => {
                            is_responded = event_handler::handle_auth_link(
                                config, &matcher, client, &msg, event_link,
                            )?;
                        }
                        endpoint_sec::Event::AuthUnlink(event_unlink) => {
                            is_responded = event_handler::handle_auth_unlink(
                                config,
                                &matcher,
                                client,
                                &msg,
                                event_unlink,
                            )?;
                        }
                        endpoint_sec::Event::AuthDeleteExtAttr(event_delete_ext_attr) => {
                            is_responded = event_handler::handle_auth_delete_ext_attr(
                                config,
                                &matcher,
                                client,
                                &msg,
                                event_delete_ext_attr,
                            )?;
                        }
                        endpoint_sec::Event::AuthExchangeData(event_exchange_data) => {
                            is_responded = event_handler::handle_auth_exchange_data(
                                config,
                                &matcher,
                                client,
                                &msg,
                                event_exchange_data,
                            )?;
                        }
                        endpoint_sec::Event::AuthSetAcl(es_event_set_acl) => {
                            is_responded = event_handler::handle_auth_set_acl(
                                config,
                                &matcher,
                                client,
                                &msg,
                                es_event_set_acl,
                            )?;
                        }
                        endpoint_sec::Event::AuthSetAttrlist(event_set_attr_list) => {
                            is_responded = event_handler::handle_auth_set_attr_list(
                                config,
                                &matcher,
                                client,
                                &msg,
                                event_set_attr_list,
                            )?;
                        }
                        endpoint_sec::Event::AuthSetExtAttr(event_set_ext_attr) => {
                            is_responded = event_handler::handle_auth_set_ext_attr(
                                config,
                                &matcher,
                                client,
                                &msg,
                                event_set_ext_attr,
                            )?;
                        }
                        endpoint_sec::Event::AuthSetFlags(event_set_flags) => {
                            is_responded = event_handler::handle_auth_set_flags(
                                config,
                                &matcher,
                                client,
                                &msg,
                                event_set_flags,
                            )?;
                        }
                        endpoint_sec::Event::AuthSetMode(event_set_mode) => {
                            is_responded = event_handler::handle_auth_set_mode(
                                config,
                                &matcher,
                                client,
                                &msg,
                                event_set_mode,
                            )?;
                        }
                        endpoint_sec::Event::AuthSetOwner(event_set_owner) => {
                            is_responded = event_handler::handle_auth_set_owner(
                                config,
                                &matcher,
                                client,
                                &msg,
                                event_set_owner,
                            )?;
                        }
                        endpoint_sec::Event::AuthExec(event_exec) => {
                            is_responded =
                                event_handler::handle_auth_exec(config, client, &msg, event_exec)?;
                        }
                        endpoint_sec::Event::NotifyFork(event_fork) => {
                            drop(bit_map);
                            event_handler::handle_notify_fork(&bit_map_locker, event_fork)?;
                        }
                        endpoint_sec::Event::NotifyExit(_event_exit) => {
                            drop(bit_map);
                            event_handler::handle_notify_exit(&bit_map_locker, pid)?;
                        }
                        _other => {}
                    }
                }
            }
            if !is_responded {
                default_allow_event(client, &msg)?;
            }

            Ok(())
        };

        if let Err(err) = execute() {
            log::error!("handle event failed: {}", err);
        }
    };
    static SUBSCRIBE_EVENTS: &[es_event_type_t] = &[
        es_event_type_t::ES_EVENT_TYPE_AUTH_OPEN,
        es_event_type_t::ES_EVENT_TYPE_AUTH_CREATE,
        es_event_type_t::ES_EVENT_TYPE_AUTH_RENAME,
        es_event_type_t::ES_EVENT_TYPE_AUTH_LINK,
        es_event_type_t::ES_EVENT_TYPE_AUTH_UNLINK,
        es_event_type_t::ES_EVENT_TYPE_AUTH_DELETEEXTATTR,
        es_event_type_t::ES_EVENT_TYPE_AUTH_EXCHANGEDATA,
        es_event_type_t::ES_EVENT_TYPE_AUTH_SETACL,
        es_event_type_t::ES_EVENT_TYPE_AUTH_SETATTRLIST,
        es_event_type_t::ES_EVENT_TYPE_AUTH_SETEXTATTR,
        es_event_type_t::ES_EVENT_TYPE_AUTH_SETFLAGS,
        es_event_type_t::ES_EVENT_TYPE_AUTH_SETMODE,
        es_event_type_t::ES_EVENT_TYPE_AUTH_SETOWNER,
        es_event_type_t::ES_EVENT_TYPE_AUTH_EXEC,
        es_event_type_t::ES_EVENT_TYPE_NOTIFY_FORK,
        es_event_type_t::ES_EVENT_TYPE_NOTIFY_EXIT,
    ];
    Ok((handler, SUBSCRIBE_EVENTS))
}
