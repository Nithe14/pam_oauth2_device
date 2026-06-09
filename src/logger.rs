use dtor::dtor;
use log::LevelFilter;
use log::Log;

use simplelog::{ConfigBuilder, WriteLogger};
use std::fs::OpenOptions;
use std::sync::Once;

type DynErr = Box<dyn std::error::Error>;

static INIT: Once = Once::new();

pub struct DefaultLogger;

pub trait Logger {
    fn handle_error(fail: DynErr, msg: &'static str) {
        let mut err_msg = msg.to_string();
        let mut cur_fail: Option<&dyn std::error::Error> = Some(&*fail);
        while let Some(cause) = cur_fail {
            err_msg += &format!("\n    caused by: {}", cause);
            cur_fail = cause.source();
        }
        log::error!("{}", err_msg);
    }
}

impl Logger for DefaultLogger {}

impl DefaultLogger {
    pub fn init(log_path: &str, log_level: &str) {
        INIT.call_once(|| {
            let log_level = match log_level {
                "info" => LevelFilter::Info,
                "warn" => LevelFilter::Warn,
                "error" => LevelFilter::Error,
                "debug" => LevelFilter::Debug,
                "trace" => LevelFilter::Trace,
                _ => LevelFilter::Info,
            };

            let log_file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(log_path)
                .expect("Failed to open log file");

            let config = ConfigBuilder::new().set_time_format_rfc2822().build();
            let logger = WriteLogger::new(log_level, config, log_file);
            log::set_boxed_logger(logger).expect("Failed to init logger!");
            log::set_max_level(log_level);
        });
    }

    // Shutdowns global logger
    pub unsafe fn shutdown() {
        let logger_ptr = log::logger() as *const dyn Log;
        if !logger_ptr.is_null() {
            let boxed_logger = Box::from_raw(logger_ptr as *mut dyn Log);
            drop(boxed_logger);
        }
    }
}

// Runs just before unloading the .so module
#[dtor]
unsafe fn shutdown() {
    log::logger().flush();
    DefaultLogger::shutdown();
}
