use std::{
    collections::HashSet,
    env,
    fs::File,
    io::{Read, Write},
    process::Command,
};

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

#[derive(Default, Deserialize, Serialize)]
pub(crate) struct Config {
    pub(crate) enforcing: bool,
    pub(crate) whitelist: Vec<String>,
    pub(crate) gh: GhConfig,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct GhConfig {
    pub(crate) enable: bool,
    pub(crate) pr: GhPrConfig,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct GhPrConfig {
    #[serde(skip)]
    pub(crate) command_allow_map: HashSet<String>,
    pub(crate) view: bool,
    pub(crate) create: bool,
    pub(crate) content: bool,
    pub(crate) maintain: bool,
}

impl Config {
    pub(super) fn new() -> Config {
        let execute = || -> Result<Config> {
            let home_dir = env::home_dir().ok_or(anyhow!("can not get home dir"))?;
            let config_path = home_dir.join(".app-cage.toml");
            match File::open(&config_path) {
                Ok(mut file) => {
                    let mut config_str = String::new();
                    file.read_to_string(&mut config_str)?;
                    let config = toml::from_str::<Config>(&config_str)?;

                    Ok(config)
                }
                Err(err) => {
                    if err.kind() == std::io::ErrorKind::NotFound {
                        let config = Config::default();
                        let config_str = toml::to_string(&config)?;
                        let mut file = File::create(&config_path)?;
                        file.write(config_str.as_bytes())?;
                        let uid = env::var("SUDO_UID")?;
                        let gid = env::var("SUDO_GID")?;
                        let _ = Command::new("chown")
                            .arg(format!("{}:{}", uid, gid))
                            .arg(config_path)
                            .output()?;

                        return Ok(config);
                    }

                    Err(err.into())
                }
            }
        };
        let mut config;
        match execute() {
            Ok(value) => config = value,
            Err(err) => {
                log::warn!("read config failed: {}", err);
                config = Config::default();
                return config;
            }
        }
        if config.gh.enable {
            let pr = &mut config.gh.pr;
            let allow_set = &mut pr.command_allow_map;
            let mut fill_allow_set = move |commands: &[&str]| {
                for command in commands {
                    allow_set.insert(command.to_string());
                }
            };
            if pr.create {
                fill_allow_set(&["create"]);
            }
            if pr.view {
                fill_allow_set(&["checkout", "checks", "diff", "list", "status", "view"]);
            }
            if pr.content {
                fill_allow_set(&["comment", "edit", "ready", "review", "update-branch"]);
            }
            if pr.maintain {
                fill_allow_set(&["close", "lock", "merge", "reopen", "revert", "unlock"]);
            }
        }

        config
    }
}
