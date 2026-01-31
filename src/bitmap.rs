use std::collections::HashMap;

use anyhow::{Ok, Result, anyhow};
use log;
use roaring::RoaringBitmap;
use sysinfo::{Pid, ProcessRefreshKind, RefreshKind, System};

pub(super) fn make_bit_map() -> Result<RoaringBitmap> {
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
