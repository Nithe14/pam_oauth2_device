pub mod config;
pub mod error_logger;
pub mod oauth_device;
pub mod prompt;

use crate::config::read_config;
use crate::oauth_device::*;
use file_rotate::{
    compression::Compression,
    suffix::{AppendTimestamp, DateFrom, FileLimit},
    ContentLimit, FileRotate, TimeFrequency,
};
use oauth2::{TokenIntrospectionResponse, TokenResponse};
use pam::constants::{PamFlag, PamResultCode, PAM_PROMPT_ECHO_OFF};

use crate::prompt::UserPrompt;
use error_logger::{DefaultLogger, Logger};
use pam::conv::Conv;
use pam::module::{PamHandle, PamHooks};
use pam::pam_try;
use simplelog::*;
use std::collections::HashMap;
use std::ffi::CStr;

pub struct PamOAuth2Device;
pam::pam_hooks!(PamOAuth2Device);

macro_rules! or_pam_err {
    ($res:expr, $error_message:expr, $pam_error:expr) => {
        match $res {
            Ok(o) => o,
            Err(e) => {
                let mut logger = DefaultLogger;
                logger.handle_error(e, $error_message);
                return $pam_error;
            }
        }
    };
}

impl PamHooks for PamOAuth2Device {
    fn sm_authenticate(pamh: &mut PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let args = parse_args(&args);

        let default_log_path = "/tmp/pam_oauth2_device.log".to_string();
        let default_log_level = "info".to_string();
        let log_path = args.get("logs").unwrap_or(&default_log_path);
        let log_level = args.get("log_level").unwrap_or(&default_log_level);
        init_logs(&log_path, &log_level);

        let default_config = "/etc/pam_oauth2_device/config.json".to_string();
        let config = read_config(args.get("config").unwrap_or(&default_config));
        let config = or_pam_err!(
            config.map_err(|err| err.into()),
            "Failed to parse config file",
            PamResultCode::PAM_SYSTEM_ERR
        );

        let conv = match pamh.get_item::<Conv>() {
            Ok(Some(conv)) => conv,
            Ok(None) => {
                unreachable!("No conv available");
            }
            Err(err) => {
                log::error!("Couldn't get pam_conv");
                return err;
            }
        };

        let user = pam_try!(pamh.get_user(None));
        log::info!("Trying to authenticate user: {user}");

        let oauth_client = or_pam_err!(
            OAuthClient::new(&config),
            "Failed to build OAuth client",
            PamResultCode::PAM_SYSTEM_ERR
        );
        log::debug!("OAuth Client: {:?}", oauth_client);

        let device_code_resp = or_pam_err!(
            oauth_client.device_code(),
            "Failed to recive device code response",
            PamResultCode::PAM_AUTH_ERR
        );
        log::debug!("Device Code response: {:?}", device_code_resp);

        let mut user_prompt = UserPrompt::new(
            &device_code_resp,
            "Press \"ENTER\" after successful authentication: ",
        );
        if config.qr_enabled {
            log::debug!("Generate QR code...");
            user_prompt.generate_qr();
        }
        log::debug!("User prompt: {:?}", user_prompt);

        // Render user prompt
        pam_try!(conv.send(PAM_PROMPT_ECHO_OFF, &user_prompt.to_string()));

        let token = or_pam_err!(
            oauth_client.get_token(&device_code_resp),
            "Failed to recive user token",
            PamResultCode::PAM_AUTH_ERR
        );
        log::debug!("Token response: {:?}", token);

        let token = or_pam_err!(
            oauth_client.introspect(&token.access_token()),
            "Failed to introspect user token",
            PamResultCode::PAM_AUTH_ERR
        );
        log::debug!("Introspect response: {:?}", token);

        if oauth_client.validate_token(&token, &user) {
            let username = token.username().unwrap(); //it is safe cause of token validatiaon
            log::info!(
                "Authentication successful for remote user: {} -> local user: {}",
                username,
                user
            );
            return PamResultCode::PAM_SUCCESS;
        }

        log::warn!("Login failed for user: {user}");

        PamResultCode::PAM_AUTH_ERR
    }

    fn sm_setcred(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }

    fn acct_mgmt(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }
}

fn parse_args(args: &[&CStr]) -> HashMap<String, String> {
    args.iter()
        .map(|&s| {
            let s = s.to_string_lossy().into_owned();
            let mut parts = s.splitn(2, '=');
            (
                parts.next().unwrap().to_string(),
                parts.next().unwrap_or("").to_string(),
            )
        })
        .collect()
}

fn init_logs(log_path: &str, log_level: &str) {
    let log_level = match log_level {
        "info" => LevelFilter::Info,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        "none" => LevelFilter::Off,
        _ => LevelFilter::Info,
    };
    let log_file = FileRotate::new(
        log_path,
        AppendTimestamp::with_format("%Y-%m-%d", FileLimit::MaxFiles(7), DateFrom::DateYesterday),
        ContentLimit::Time(TimeFrequency::Daily),
        Compression::None,
        #[cfg(unix)]
        None,
    );
    CombinedLogger::init(vec![
        TermLogger::new(
            log_level,
            Config::default(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        ),
        WriteLogger::new(log_level, Config::default(), log_file),
    ])
    .expect("Failed to inicialize logging!");
}
