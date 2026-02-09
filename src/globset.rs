use std::env;

use anyhow::{Ok, Result, anyhow};
use globset::{Glob, GlobSet, GlobSetBuilder};
use log;

use crate::config::Config;

fn iter_slice<T: AsRef<str>>(builder: &mut GlobSetBuilder, slice: &[T]) -> Result<()> {
    let home_dir = env::home_dir().ok_or(anyhow!("can not get home dir"))?;
    for pattern in slice {
        let pattern = pattern.as_ref();
        let real_pattern_path;
        let real_pattern;
        if pattern.starts_with("~") {
            real_pattern_path = home_dir.join(&pattern[2..]);
            real_pattern = real_pattern_path
                .to_str()
                .ok_or(anyhow!("bad path {}", pattern))?;
        } else {
            real_pattern = pattern;
        }
        log::debug!("add {} to glob set", real_pattern);
        builder.add(Glob::new(real_pattern)?);
    }

    Ok(())
}

pub(super) fn make_globset(config: &Config) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    let mut cwd = env::current_dir()?;
    cwd.push("**");
    let cwd = cwd.to_str().ok_or(anyhow!("add cwd to glob set failed"))?;
    builder.add(Glob::new(cwd)?);
    log::info!("add cwd {} to glob set", cwd);
    static INNER_WHITELIST: &[&str] = &[
        "/dev/null",
        "/dev/zero",
        "/dev/random",
        "/dev/urandom",
        "/dev/dtracehelper",
        "/dev/ptmx",
        "/dev/tty*",
        "/private/var/run/utmpx",
        "/private/var/tmp/**",
        "/private/var/folders/_l/**",
        "/private/var/spool/**"
    ];
    iter_slice(&mut builder, INNER_WHITELIST)?;
    iter_slice(&mut builder, config.whitelist.as_slice())?;
    for allow_path in config.whitelist.iter() {
        builder.add(Glob::new(allow_path)?);
    }

    Ok(builder.build()?)
}
