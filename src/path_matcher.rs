use std::env;

use anyhow::{Result, anyhow};
use path_tree::PathTree;

use crate::config::Config;

static INNER_WHITELIST: &[&str] = &[
    "/dev/dtracehelper",
    "/dev/null",
    "/dev/ptmx",
    "/dev/random",
    "/dev/tty*",
    "/dev/urandom",
    "/dev/zero",
    "/private/tmp/+",
    "/private/var/folders/_l/+",
    "/private/var/run/utmpx",
    "/private/var/spool/+",
    "/private/var/tmp/+",
    "/tmp/+",
];

fn iter_slice<T: AsRef<str>>(tree: &mut PathTree<()>, slice: &[T]) -> Result<()> {
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
        log::debug!("add {} to path matcher", real_pattern);
        let _ = tree.insert(real_pattern, ());
    }

    Ok(())
}

pub(crate) struct PathMatcher {
    matcher: PathTree<()>,
}

impl PathMatcher {
    pub(crate) fn new(config: &Config) -> Result<PathMatcher> {
        let mut tree = PathTree::<()>::new();
        let mut cwd = env::current_dir()?;
        cwd.push("+");
        let cwd = cwd
            .to_str()
            .ok_or(anyhow!("add cwd to path matcher failed"))?;
        let _ = tree.insert(cwd, ());
        iter_slice(&mut tree, INNER_WHITELIST)?;
        iter_slice(&mut tree, config.whitelist.as_slice())?;

        Ok(PathMatcher { matcher: tree })
    }

    pub(crate) fn is_match(self: &Self, path: &str) -> bool {
        match self.matcher.find(path) {
            Some(_) => true,
            None => false,
        }
    }
}
