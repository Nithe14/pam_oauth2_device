mod test_logger;
mod utils;

use chrono::{Duration, Utc};
use oauth2::{TokenIntrospectionResponse, TokenResponse};
use pam_oauth2_device::logger::Logger;
use utils::Mock;

use test_logger::{TestLogger, LOGGER};

#[test]
fn common_error() {
    let (mut mock, oauth_client) = Mock::builder().init(None);
    let logger = LOGGER.lock().unwrap();

    mock.http_device_complete();
    mock.http_token_with_status(200);
    mock.http_introspect_with_status(401);

    let device_details = oauth_client.device_code().unwrap();
    let token = oauth_client.get_token(&device_details, None).unwrap();
    let token = oauth_client.introspect(token.access_token());
    assert!(token.is_err());

    let _ = token.map_err(|err| TestLogger::handle_error(err, "Failed to intropsect user token"));

    assert_eq!(
        logger.msg(),
        "Failed to intropsect user token\n    caused by: Server returned error response: invalid_client: This client authentication was invalid"
    );
}

#[test]
fn other_error() {
    let (mut mock, oauth_client) = Mock::builder().init(None);
    let logger = LOGGER.lock().unwrap();
    mock.http_device_complete();
    mock.http_token_with_status(200);
    mock.http_introspect_with_status(101);

    let device_details = oauth_client.device_code().unwrap();
    let token = oauth_client.get_token(&device_details, None).unwrap();
    let token = oauth_client.introspect(token.access_token());
    assert!(token.is_err());

    let _ = token.map_err(|err| TestLogger::handle_error(err, "Failed to intropsect user token"));

    assert_eq!(
        logger.msg(),
        "Failed to intropsect user token\n    caused by: Request failed\n    caused by: client error\n    caused by: [52] Server returned nothing (no headers, no data) (Empty reply from server)"
    );
}
#[test]
fn basic_active() {
    let (mut mock, oauth_client) = Mock::builder()
        .active(true)
        .username(Some("test"))
        .scope(Some("openid profile"))
        .init(Some("openid profile"));

    mock.http_device_complete();
    mock.http_token_with_status(200);
    mock.http_introspect_with_status(200);

    let device_details = oauth_client.device_code().unwrap();
    let token = oauth_client.get_token(&device_details, None).unwrap();
    let token = oauth_client.introspect(token.access_token()).unwrap();

    assert_eq!(token.active(), true);
    assert_eq!(oauth_client.validate_token(&token, "test"), true);
}

#[test]
fn basic_inactive() {
    let (mut mock, oauth_client) = Mock::builder()
        .active(false)
        .username(Some("test"))
        .init(None);

    let logger = LOGGER.lock().unwrap();

    mock.http_device_complete();
    mock.http_token_with_status(200);
    mock.http_introspect_with_status(200);

    let device_details = oauth_client.device_code().unwrap();
    let token = oauth_client.get_token(&device_details, None).unwrap();
    let token = oauth_client.introspect(token.access_token()).unwrap();

    assert_eq!(token.active(), false);
    assert_eq!(oauth_client.validate_token(&token, "test"), false);
    assert_eq!(logger.msg(), "User token inactive!");
}

#[test]
fn invalid_username() {
    let (mut mock, oauth_client) = Mock::builder()
        .active(true)
        .username(Some("test"))
        .scope(Some("openid profile"))
        .init(Some("openid profile"));
    let logger = LOGGER.lock().unwrap();

    mock.http_device_complete();
    mock.http_token_with_status(200);
    mock.http_introspect_with_status(200);

    let device_details = oauth_client.device_code().unwrap();
    let token = oauth_client.get_token(&device_details, None).unwrap();
    let token = oauth_client.introspect(token.access_token()).unwrap();

    assert_eq!(oauth_client.validate_token(&token, "non_valid_user"), false);
    assert_eq!(
        logger.msg(),
        "Invalid username: remote: test -> local: non_valid_user"
    );
}

#[test]
fn root_user() {
    let (mut mock, oauth_client) = Mock::builder()
        .active(true)
        .username(Some("root"))
        .scope(Some("openid profile"))
        .init(Some("openid profile"));
    let logger = LOGGER.lock().unwrap();

    mock.http_device_complete();
    mock.http_token_with_status(200);
    mock.http_introspect_with_status(200);

    let device_details = oauth_client.device_code().unwrap();
    let token = oauth_client.get_token(&device_details, None).unwrap();
    let token = oauth_client.introspect(token.access_token()).unwrap();

    assert_eq!(token.active(), true);
    assert_eq!(oauth_client.validate_token(&token, "root"), false);
    assert_eq!(
        logger.msg(),
        "Invalid username: remote: root -> local: root"
    );
}

#[test]
fn empty_user() {
    let (mut mock, oauth_client) = Mock::builder()
        .active(true)
        .scope(Some("openid profile"))
        .username(None)
        .init(Some("openid profile"));
    let logger = LOGGER.lock().unwrap();

    mock.http_device_complete();
    mock.http_token_with_status(200);
    mock.http_introspect_with_status(200);

    let device_details = oauth_client.device_code().unwrap();
    let token = oauth_client.get_token(&device_details, None).unwrap();
    let token = oauth_client.introspect(token.access_token()).unwrap();

    assert_eq!(oauth_client.validate_token(&token, "test"), false);
    assert_eq!(logger.msg(), "No username provided in token");
}

#[test]
fn sufficient_scopes_all() {
    let (mut mock, oauth_client) = Mock::builder()
        .active(true)
        .scope(Some("openid profile"))
        .username(Some("test"))
        .init(Some("openid profile"));

    mock.http_device_complete();
    mock.http_token_with_status(200);
    mock.http_introspect_with_status(200);

    let device_details = oauth_client.device_code().unwrap();
    let token = oauth_client.get_token(&device_details, None).unwrap();
    let token = oauth_client.introspect(token.access_token()).unwrap();

    assert_eq!(token.active(), true);
    assert_eq!(*token.scopes().unwrap(), oauth_client.scopes());
    assert_eq!(oauth_client.validate_token(&token, "test"), true);
}

#[test]
fn sufficient_scopes_single() {
    let (mut mock, oauth_client) = Mock::builder()
        .active(true)
        .scope(Some("openid profile"))
        .username(Some("test"))
        .init(Some("profile"));

    mock.http_device_complete();
    mock.http_token_with_status(200);
    mock.http_introspect_with_status(200);

    let device_details = oauth_client.device_code().unwrap();
    let token = oauth_client.get_token(&device_details, None).unwrap();
    let token = oauth_client.introspect(token.access_token()).unwrap();

    assert_eq!(token.active(), true);
    assert_eq!(oauth_client.validate_token(&token, "test"), true);
}

#[test]
fn sufficient_scopes_unordered() {
    let (mut mock, oauth_client) = Mock::builder()
        .active(true)
        .scope(Some("openid profile"))
        .username(Some("test"))
        .init(Some("profile openid"));

    mock.http_device_complete();
    mock.http_token_with_status(200);
    mock.http_introspect_with_status(200);

    let device_details = oauth_client.device_code().unwrap();
    let token = oauth_client.get_token(&device_details, None).unwrap();
    let token = oauth_client.introspect(token.access_token()).unwrap();

    assert_eq!(token.active(), true);
    assert_eq!(oauth_client.validate_token(&token, "test"), true);
}

#[test]
fn insufficient_scopes_1() {
    let (mut mock, oauth_client) = Mock::builder()
        .active(true)
        .scope(Some("openid profile"))
        .username(Some("test"))
        .init(Some("profile openid email"));
    let logger = LOGGER.lock().unwrap();

    mock.http_device_complete();
    mock.http_token_with_status(200);
    mock.http_introspect_with_status(200);

    let device_details = oauth_client.device_code().unwrap();
    let token = oauth_client.get_token(&device_details, None).unwrap();
    let token = oauth_client.introspect(token.access_token()).unwrap();

    assert_eq!(token.active(), true);
    assert_ne!(*token.scopes().unwrap(), oauth_client.scopes());
    assert_eq!(oauth_client.validate_token(&token, "test"), false);
    assert_eq!(
        "Insuficient scopes for user test: [\"openid\", \"profile\"]",
        logger.msg()
    );
    assert_eq!(oauth_client.validate_token(&token, "non-valid-user"), false);
}

#[test]
fn insufficient_scopes_2() {
    let (mut mock, oauth_client) = Mock::builder()
        .active(true)
        .scope(Some("openid profile"))
        .username(Some("test"))
        .init(Some("test"));
    let logger = LOGGER.lock().unwrap();

    mock.http_device_complete();
    mock.http_token_with_status(200);
    mock.http_introspect_with_status(200);

    let device_details = oauth_client.device_code().unwrap();
    let token = oauth_client.get_token(&device_details, None).unwrap();
    let token = oauth_client.introspect(token.access_token()).unwrap();

    assert_eq!(token.active(), true);
    assert_ne!(*token.scopes().unwrap(), oauth_client.scopes());
    assert_eq!(oauth_client.validate_token(&token, "test"), false);
    assert_eq!(
        "Insuficient scopes for user test: [\"openid\", \"profile\"]",
        logger.msg()
    );
}

#[test]
fn empty_scope() {
    let (mut mock, oauth_client) = Mock::builder()
        .active(true)
        .username(Some("test"))
        .init(None);
    let logger = LOGGER.lock().unwrap();

    mock.http_device_complete();
    mock.http_token_with_status(200);
    mock.http_introspect_with_status(200);

    let device_details = oauth_client.device_code().unwrap();
    let token = oauth_client.get_token(&device_details, None).unwrap();
    let token = oauth_client.introspect(token.access_token()).unwrap();

    assert_eq!(oauth_client.validate_token(&token, "test"), false);
    assert_eq!(logger.msg(), "No scope provided in token");
}

#[test]
fn empty_exp() {
    let (mut mock, oauth_client) = Mock::builder()
        .active(true)
        .username(Some("test"))
        .scope(Some("openid profile"))
        .exp(None)
        .init(Some("openid profile"));
    let logger = LOGGER.lock().unwrap();

    mock.http_device_complete();
    mock.http_token_with_status(200);
    mock.http_introspect_with_status(200);

    let device_details = oauth_client.device_code().unwrap();
    let token = oauth_client.get_token(&device_details, None).unwrap();
    let token = oauth_client.introspect(token.access_token()).unwrap();

    assert_eq!(oauth_client.validate_token(&token, "test"), false);
    assert_eq!(logger.msg(), "No expiration time provided in token");
}

#[test]
fn token_expired() {
    let (mut mock, oauth_client) = Mock::builder()
        .active(true)
        .username(Some("test"))
        .scope(Some("openid profile"))
        .exp(Some(Utc::now() - Duration::seconds(3600)))
        .init(Some("openid profile"));
    let logger = LOGGER.lock().unwrap();

    mock.http_device_complete();
    mock.http_token_with_status(200);
    mock.http_introspect_with_status(200);

    let device_details = oauth_client.device_code().unwrap();
    let token = oauth_client.get_token(&device_details, None).unwrap();
    let token = oauth_client.introspect(token.access_token()).unwrap();

    assert_eq!(oauth_client.validate_token(&token, "test"), false);
    assert_eq!(logger.msg(), "Token has expired for user test");
}
