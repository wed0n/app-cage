use std::{
    collections::{HashMap, HashSet},
    env,
    fs::File,
    io::{Read, Write},
    path::PathBuf,
    process::Command,
};

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

mod gh_command {
    pub(super) const AUTH: &str = "auth";
    pub(super) const REPO: &str = "repo";
    pub(super) const ISSUE: &str = "issue";
    pub(super) const PR: &str = "pr";
}

#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct Config {
    pub(crate) enforcing: bool,
    pub(crate) whitelist: Vec<String>,
    pub(crate) gh: GhConfig,
    #[serde(skip)]
    pub(crate) cwd: PathBuf,
}

#[derive(Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct GhConfig {
    pub(crate) enable: bool,
    pub(crate) auth: GhCommandSimpleConfig,
    pub(crate) repo: GhCommandFullConfig,
    pub(crate) issue: GhCommandFullConfig,
    pub(crate) pr: GhCommandFullConfig,
    #[serde(skip)]
    pub(crate) command_allow_map: HashMap<String, HashSet<String>>,
}

impl Default for GhConfig {
    fn default() -> Self {
        Self {
            enable: true,
            command_allow_map: Default::default(),
            auth: Default::default(),
            repo: Default::default(),
            issue: Default::default(),
            pr: Default::default(),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct GhCommandSimpleConfig {
    pub(crate) view: bool,
    pub(crate) update: bool,
}

impl Default for GhCommandSimpleConfig {
    fn default() -> Self {
        Self {
            view: true,
            update: false,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct GhCommandFullConfig {
    pub(crate) view: bool,
    pub(crate) create: bool,
    pub(crate) content: bool,
    pub(crate) maintain: bool,
}

impl Default for GhCommandFullConfig {
    fn default() -> Self {
        Self {
            view: true,
            create: false,
            content: false,
            maintain: false,
        }
    }
}

impl Config {
    pub(super) fn new() -> Result<Config> {
        let home_dir = env::home_dir().ok_or(anyhow!("can not get home dir"))?;
        let config_path = home_dir.join(".app-cage.toml");
        let mut config;
        match File::open(&config_path) {
            Ok(mut file) => {
                let mut config_str = String::new();
                file.read_to_string(&mut config_str)?;
                config = toml::from_str::<Config>(&config_str)?;
            }
            Err(err) => {
                if err.kind() == std::io::ErrorKind::NotFound {
                    config = Config::default();
                    let config_str = toml::to_string(&config)?;
                    let mut file = File::create(&config_path)?;
                    file.write(config_str.as_bytes())?;
                    let uid = env::var("SUDO_UID")?;
                    let gid = env::var("SUDO_GID")?;
                    let _ = Command::new("chown")
                        .arg(format!("{}:{}", uid, gid))
                        .arg(config_path)
                        .output()?;
                } else {
                    return Err(err.into());
                }
            }
        }

        let cwd = env::current_dir()?;
        config.cwd = cwd;

        if config.gh.enable {
            let gh = &mut config.gh;

            gh.insert_allow_set(
                gh_command::AUTH,
                gh.auth.generate_allow_set(
                    &["refresh", "status"],
                    &["login", "logout", "setup-git", "switch"],
                ),
            );
            gh.insert_allow_set(
                gh_command::REPO,
                gh.repo.generate_allow_set(
                    &["clone", "gitignore", "license", "list", "sync", "view"],
                    &["create", "fork"],
                    &["autolink", "edit"],
                    &["archive", "delete", "deploy-key", "rename", "unarchive"],
                ),
            );
            gh.insert_allow_set(
                gh_command::ISSUE,
                gh.issue.generate_allow_set(
                    &["list", "status", "view"],
                    &["create"],
                    &["comment", "develop", "edit", "pin", "unpin"],
                    &["close", "lock", "reopen", "transfer", "unlock"],
                ),
            );
            gh.insert_allow_set(
                gh_command::PR,
                gh.pr.generate_allow_set(
                    &["checkout", "checks", "diff", "list", "status", "view"],
                    &["create"],
                    &["comment", "edit", "ready", "review", "update-branch"],
                    &["close", "lock", "merge", "reopen", "revert", "unlock"],
                ),
            );
        }

        Ok(config)
    }
}

impl GhConfig {
    fn insert_allow_set(self: &mut Self, command: &str, allow_set: Option<HashSet<String>>) {
        if let Some(set) = allow_set {
            self.command_allow_map.insert(command.to_string(), set);
        }
    }
}

impl GhCommandFullConfig {
    fn generate_allow_set(
        self: &Self,
        view: &[&str],
        create: &[&str],
        content: &[&str],
        maintain: &[&str],
    ) -> Option<HashSet<String>> {
        let mut allow_set = HashSet::new();
        let allow_set_ref = &mut allow_set;
        let mut extend_allow_set = move |commands: &[&str]| {
            for command in commands {
                allow_set_ref.insert(command.to_string());
            }
        };
        if self.view {
            extend_allow_set(view);
        }
        if self.create {
            extend_allow_set(create);
        }
        if self.content {
            extend_allow_set(content);
        }
        if self.maintain {
            extend_allow_set(maintain);
        }

        if allow_set.len() > 0 {
            return Some(allow_set);
        }

        None
    }
}

impl GhCommandSimpleConfig {
    fn generate_allow_set(self: &Self, view: &[&str], update: &[&str]) -> Option<HashSet<String>> {
        let mut allow_set = HashSet::new();
        let allow_set_ref = &mut allow_set;
        let mut extend_allow_set = move |commands: &[&str]| {
            for command in commands {
                allow_set_ref.insert(command.to_string());
            }
        };
        if self.view {
            extend_allow_set(view);
        }
        if self.update {
            extend_allow_set(update);
        }

        if allow_set.len() > 0 {
            return Some(allow_set);
        }

        None
    }
}
