use std::{collections::HashMap, env, sync::RwLock};

use anyhow::{Ok, Result, anyhow};
use endpoint_sec::{Client, ExpectedResponseType, Message};
use endpoint_sec_sys::{es_auth_result_t, es_event_type_t};
use globset::{Glob, GlobSetBuilder};
use log;
use roaring::RoaringBitmap;
use sysinfo::{Pid, ProcessRefreshKind, RefreshKind, System};

fn make_bit_map() -> Result<RoaringBitmap> {
    let sys = System::new_with_specifics(
        RefreshKind::nothing().with_processes(ProcessRefreshKind::nothing()),
    );

    let mut process_tree = HashMap::<Pid, Vec<Pid>>::new();
    for (_pid, process) in sys.processes().iter() {
        let pid = process.pid();
        if let Some(ppid) = process.parent() {
            match process_tree.get_mut(&ppid) {
                Some(child_vec) => {
                    child_vec.push(pid);
                }
                None => {
                    process_tree.insert(ppid, vec![pid]);
                }
            }
        }
    }

    let root_pid;
    {
        let init_pid = Pid::from(1);
        let cur_pid =
            sysinfo::get_current_pid().map_err(|err| anyhow!("get current pid failed: {}", err))?;
        let mut cur_process = sys
            .process(cur_pid)
            .ok_or(anyhow!("get current process failed"))?;
        loop {
            let parent_pid = cur_process
                .parent()
                .ok_or(anyhow!("get parent pid failed"))?;
            if parent_pid == init_pid {
                root_pid = cur_process.pid();
                break;
            }
            cur_process = sys
                .process(parent_pid)
                .ok_or(anyhow!("get parent process failed"))?;
        }
    }
    log::info!("root pid is {}", root_pid);
    let mut bit_map = RoaringBitmap::new();
    bit_map.insert(root_pid.as_u32());
    {
        struct DfsFrame {
            ppid: Pid,
            index: usize,
        }
        let mut stack = Vec::<DfsFrame>::new();
        stack.push(DfsFrame {
            ppid: root_pid,
            index: 0,
        });
        while !stack.is_empty() {
            let frame = stack.last_mut().ok_or(anyhow!("stack is empty"))?;
            match process_tree.get(&frame.ppid) {
                Some(children) => match children.get(frame.index) {
                    Some(pid) => {
                        log::debug!("insert {pid} into bitmap");
                        if !bit_map.insert(pid.as_u32()) {
                            log::warn!("{pid} is already in bitmap");
                        }
                        frame.index += 1;
                        if let Some(_) = process_tree.get(pid) {
                            stack.push(DfsFrame {
                                ppid: *pid,
                                index: 0,
                            });
                        }
                    }
                    None => {
                        stack.pop();
                    }
                },
                None => {
                    stack.pop();
                }
            }
        }
    }

    Ok(bit_map)
}

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

pub(super) fn get_handler_and_subscribe_events() -> Result<(
    impl Fn(&mut Client<'_>, Message),
    &'static [es_event_type_t],
)> {
    static FREAD: i32 = 0x00000001;
    static FWRITE: i32 = 0x00000002;
    static FNONBLOCK: i32 = 0x00000004;
    static FAPPEND: i32 = 0x00000008;
    static FASYNC: i32 = 0x00000040;
    static FFSYNC: i32 = 0x00000080;
    static FFDSYNC: i32 = 0x00400000;
    static FEXEC: i32 = 0x04000000;

    let bit_map = make_bit_map()?;
    let bit_map_locker = RwLock::new(bit_map);
    let mut builder = GlobSetBuilder::new();
    let mut cwd = env::current_dir()?;
    cwd.push("*.txt");
    let cwd = cwd.to_str().ok_or(anyhow!("add cwd to glob set failed"))?;
    builder.add(Glob::new(cwd)?);
    log::debug!("add cwd {} to glob set", cwd);
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
                            let path = event_open
                                .file()
                                .path()
                                .to_str()
                                .ok_or(anyhow!("bad path"))?;
                            let fflag = event_open.fflag();
                            if set.is_match(path) {
                                // if fflag & FWRITE != 0 {
                                log::debug!("open file {} as mode 0x{:02X}", path, fflag);
                                // }
                            }

                            // client
                            //     .respond_auth_result(&msg, es_auth_result_t::ES_AUTH_RESULT_ALLOW, true)
                            //     .map_err(|err| anyhow!("respond"))?;
                        }
                        endpoint_sec::Event::AuthMmap(_event_mmap) => {}
                        endpoint_sec::Event::AuthRename(_event_rename) => {}
                        endpoint_sec::Event::AuthUnlink(_event_unlink) => {}
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
