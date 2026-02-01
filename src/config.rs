use std::{
    env,
    fs::File,
    io::{Read, Write},
    process::Command,
};

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub(super) struct Config {
    pub enforcing: bool,
    pub whitelist: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enforcing: Default::default(),
            whitelist: Default::default(),
        }
    }
}

pub(super) fn get_config() -> Config {
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
    match execute() {
        Ok(config) => config,
        Err(err) => {
            log::warn!("read config failed: {}", err);
            Config::default()
        }
    }
}
