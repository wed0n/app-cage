use std::path::PathBuf;

use anyhow::{Ok, Result, anyhow};
use endpoint_sec::sys::es_auth_result_t;
use endpoint_sec::{Client, EventExec, Message};

use super::os_str_convert;
use crate::config::Config;

mod prog {
    pub(super) const GH: &str = "gh";
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
    let (should_reject, prog) = judge(&config, &event_exec)?;

    if should_reject {
        let pid = msg.process().audit_token().pid();
        if config.enforcing {
            client
                .respond_auth_result(msg, es_auth_result_t::ES_AUTH_RESULT_DENY, false)
                .map_err(|err| anyhow!("respond exec event failed: {}", err))?;
            log::info!("reject pid {} execute command {}", pid, prog);
            is_responded = true
        } else {
            log::warn!("pid {} execute unexpected command {}", pid, prog);
        }
    }

    Ok(is_responded)
}

fn judge<'a>(config: &Config, event_exec: &'a EventExec) -> Result<(bool, &'a str)> {
    let mut should_reject = false;
    let mut prog = "";
    'outer: loop {
        if !config.gh.enable {
            break;
        }
        let mut args = event_exec.args();
        let Some(path) = args.next() else {
            break;
        };
        let path = os_str_convert(path)?;
        prog = path
            .split("/")
            .last()
            .ok_or(anyhow!("bad command path {}", path))?;

        match prog {
            prog::GH => {
                let (Some(command), Some(sub_command)) = (args.next(), args.next()) else {
                    break;
                };
                let (command, sub_command) =
                    (os_str_convert(command)?, os_str_convert(sub_command)?);
                match config.gh.command_allow_map.get(command) {
                    Some(allow_set) => {
                        if !allow_set.contains(sub_command) {
                            should_reject = true;
                            break;
                        }
                    }
                    None => {
                        should_reject = true;
                        break;
                    }
                }
                let cwd = PathBuf::from(
                    event_exec
                        .cwd()
                        .ok_or(anyhow!("get current working dir failed"))?
                        .path(),
                );
                if !cwd.starts_with(&config.cwd) {
                    should_reject = true;
                    break;
                }
                loop {
                    let arg = args.next();
                    let Some(arg) = arg else {
                        break;
                    };
                    let arg = os_str_convert(arg)?;
                    if arg == gh_arg::REPO1 || arg == gh_arg::REPO2 {
                        should_reject = true;
                        break 'outer;
                    }
                }
            }
            _other => {}
        }

        break;
    }

    Ok((should_reject, prog))
}
