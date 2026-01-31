use std::env;

use anyhow::{Ok, Result, anyhow};
use globset::{Glob, GlobSet, GlobSetBuilder};
use log;

use crate::config::Config;

pub(super) fn make_globset(config: &Config) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    let mut cwd = env::current_dir()?;
    cwd.push("**");
    let cwd = cwd.to_str().ok_or(anyhow!("add cwd to glob set failed"))?;
    builder.add(Glob::new(cwd)?);
    log::info!("add cwd {} to glob set", cwd);
    static INNER_WHITELIST: &[&str] = &["/dev/tty", "/dev/dtracehelper", "/dev/null", "/dev/zero"];
    for &pattern in INNER_WHITELIST {
        builder.add(Glob::new(pattern)?);
    }
    for allow_path in config.whitelist.iter() {
        builder.add(Glob::new(allow_path)?);
    }

    Ok(builder.build()?)
}
