use anyhow::{Ok, Result, anyhow};
use endpoint_sec::{Client, EventExec, Message};
use endpoint_sec_sys::es_auth_result_t;

use super::{ResponseType, os_str_convert};
use crate::config::Config;

mod prog {
    pub(super) const GH: &str = "gh";
}
mod gh_command {
    pub(super) const PR: &str = "pr";
}

mod gh_arg {
    pub(super) const REPO1: &str = "-R";
    pub(super) const REPO2: &str = "--repo";
}

pub(crate) fn handle_auth_exec(
    config: &Config,
    client: &mut Client,
    msg: &Message,
    event_exec: EventExec,
) -> Result<bool> {
    let mut is_responded = false;
    let mut response_type = ResponseType::AlwaysAllow;
    if config.gh.enable {
        let mut args = event_exec.args();
        let Some(path) = args.next() else {
            return Ok(is_responded);
        };
        let path = os_str_convert(path)?;
        let prog = path
            .split("/")
            .last()
            .ok_or(anyhow!("bad command path {}", path))?;

        match prog {
            prog::GH => {
                //todo: detect working dir.
                let (Some(command), Some(sub_command)) = (args.next(), args.next()) else {
                    return Ok(is_responded);
                };
                let (command, sub_command) =
                    (os_str_convert(command)?, os_str_convert(sub_command)?);
                match command {
                    gh_command::PR => {
                        if config.gh.pr.command_allow_set.contains(sub_command) {
                            response_type = ResponseType::Allow
                        } else {
                            response_type = ResponseType::Deny
                        }
                    }
                    _other => response_type = ResponseType::Deny,
                }
                if response_type != ResponseType::Deny {
                    loop {
                        let arg = args.next();
                        let Some(arg) = arg else {
                            break;
                        };
                        let arg = os_str_convert(arg)?;
                        if arg == gh_arg::REPO1 || arg == gh_arg::REPO2 {
                            response_type = ResponseType::Deny;
                            break;
                        }
                    }
                }
            }
            _other => {}
        }

        let should_response;
        let mut es_response_type = es_auth_result_t::ES_AUTH_RESULT_DENY;
        match response_type {
            ResponseType::Allow => {
                should_response = true;
                es_response_type = es_auth_result_t::ES_AUTH_RESULT_ALLOW;
            }
            ResponseType::Deny => should_response = true,
            ResponseType::AlwaysAllow => should_response = false,
        }
        if should_response {
            let pid = msg.process().audit_token().pid();
            if config.enforcing {
                client
                    .respond_auth_result(msg, es_response_type, false)
                    .map_err(|err| anyhow!("respond exec event failed: {}", err))?;
                log::info!("reject pid {} execute command {}", pid, prog);
                is_responded = true
            } else if es_response_type == es_auth_result_t::ES_AUTH_RESULT_DENY {
                log::warn!("pid {} execute unexpected command {}", pid, prog);
            }
        }
    }

    Ok(is_responded)
}
