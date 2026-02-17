mod bitmap;
mod config;
mod handler;
mod path_matcher;

use std::env;

use anyhow::{Ok, Result, anyhow};
use endpoint_sec::Client;
use log;

use crate::{config::Config, handler::get_handler_and_subscribe_events};

fn main() -> Result<()> {
    let mut log_builder = env_logger::builder();
    log_builder.format_timestamp_millis();
    if let Err(_) = env::var("RUST_LOG") {
        log_builder.filter_level(log::LevelFilter::Info);
    }
    log_builder.init();
    log::info!("logger init with level {}", log::max_level());

    let config = Config::new();
    log::info!("enforcing mode is {}", config.enforcing);
    endpoint_sec::version::set_runtime_version(13, 3, 0);
    let (handler, subscribe_events) = get_handler_and_subscribe_events(&config)?;
    let mut client = Client::new(handler).map_err(|err| anyhow!("connect failed: {}", err))?;

    client
        .subscribe(&subscribe_events)
        .map_err(|err| anyhow!("subscribe event failed: {err}"))?;
    std::thread::park();

    Ok(())
}
