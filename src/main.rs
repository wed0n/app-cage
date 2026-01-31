mod bitmap;
mod config;
mod handler;

use std::env;

use anyhow::{Ok, Result, anyhow};
use endpoint_sec::Client;
use log;

use crate::handler::get_handler_and_subscribe_events;

fn main() -> Result<()> {
    let mut log_builder = env_logger::builder();
    log_builder.format_timestamp_millis();
    if let Err(_) = env::var("RUST_LOG") {
        log_builder.filter_level(log::LevelFilter::Info);
    }
    log_builder.init();
    log::info!("logger init with level {}", log::max_level());

    let config = config::get_config();
    endpoint_sec::version::set_runtime_version(10, 15, 0);
    let (handle, subscribe_events) = get_handler_and_subscribe_events(&config)?;
    let mut client = Client::new(handle).map_err(|err| anyhow!("connect failed: {}", err))?;

    client
        .subscribe(&subscribe_events)
        .map_err(|err| anyhow!("subscribe event failed: {err}"))?;
    std::thread::park();

    Ok(())
}
