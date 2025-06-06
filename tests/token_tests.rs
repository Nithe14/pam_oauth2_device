mod test_logger;
mod utils;

use oauth2::{basic::BasicTokenType, TokenResponse};
use pam_oauth2_device::logger::Logger;
use utils::Mock;

use test_logger::{TestLogger, LOGGER};

#[test]
fn token_basic() {
    let (mut mock, oauth_client) = Mock::builder().init(None);

    mock.http_device_complete();
    mock.http_token_with_status(200);

    let device_details = oauth_client.device_code().unwrap();
    let token = oauth_client.get_token(&device_details, None).unwrap();

    assert_eq!(token.access_token().secret(), "mocking_access_token");
    assert_eq!(
        token.refresh_token().unwrap().secret(),
        "mocking_refresh_token"
    );
    assert_eq!(token.token_type(), &BasicTokenType::Bearer);
    assert_eq!(token.expires_in().unwrap().as_secs(), 86400);
}

//todo
#[test]
fn token_basic_err() {
    let (mut mock, oauth_client) = Mock::builder().init(None);
    let logger = LOGGER.lock().unwrap();

    mock.http_device_complete();
    mock.http_token_with_status(403);

    let device_details = oauth_client.device_code().unwrap();
    let token = oauth_client.get_token(&device_details, None);
    assert!(token.is_err());

    let _ = token.map_err(|err| TestLogger::handle_error(err, "Failed to recive user token"));

    assert_eq!(
        logger.msg(),
        "Failed to recive user token\n    caused by: Server returned error response: access_denied: Authorization for user is still pending."
    );
}

#[test]
fn token_other_err() {
    let (mut mock, oauth_client) = Mock::builder().init(None);
    let logger = LOGGER.lock().unwrap();

    mock.http_device_complete();
    mock.http_token_with_status(418);

    let device_details = oauth_client.device_code().unwrap();
    let token = oauth_client.get_token(&device_details, None);
    assert!(token.is_err());

    let _ = token.map_err(|err| TestLogger::handle_error(err, "Failed to recive user token"));

    assert_eq!(
        logger.msg(),
        "Failed to recive user token\n    caused by: Server returned error response: access_denied: Authorization for user is still pending."
    );
}
