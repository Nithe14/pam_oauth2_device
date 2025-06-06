mod test_logger;
mod utils;
use pam_oauth2_device::config::Messages;
use pam_oauth2_device::logger::Logger;
use pam_oauth2_device::prompt::{qr_code, UserPrompt};

use test_logger::{TestLogger, LOGGER};
use utils::Mock;

#[test]
fn device_basic_uri() {
    let (mut mock, oauth_client) = Mock::builder().init(None);

    mock.http_device_basic();

    let resp = oauth_client.device_code().unwrap();

    let mut prompt = UserPrompt::new(&resp, &Messages::default());

    assert_eq!(resp.device_code().secret(), "mocking_device_code");
    assert_eq!(resp.user_code().secret(), "mocking_user_code");
    assert_eq!(resp.verification_uri().to_string(), "https://mocking.uri/");
    assert_eq!(resp.expires_in().as_secs(), 3600);
    assert_eq!(resp.interval().as_secs(), 5);

    // No QR code generated
    assert_eq!(prompt.to_string(), "\nOpen the following link in your web browser:\nhttps://mocking.uri/\nOnce you're in, enter the following code:\nmocking_user_code\nPress \"ENTER\" after successful authentication...");

    prompt.generate_qr();

    // With QR code generated
    assert_eq!(
        prompt.to_string(),
        format!(
            "\n{}\n{}",
            qr_code(&"https://mocking.uri/".to_string()).unwrap(),
            "Scan the QR code above or open the following link in your web browser:\nhttps://mocking.uri/\nOnce you're in, enter the following code:\nmocking_user_code\nPress \"ENTER\" after successful authentication..."
        )
    );
}

#[test]
fn device_uri_complete() {
    let (mut mock, oauth_client) = Mock::builder().init(None);
    mock.http_device_complete();

    let resp = oauth_client.device_code().unwrap();

    let mut prompt = UserPrompt::new(&resp, &Messages::default());

    assert_eq!(resp.device_code().secret(), "mocking_device_code");
    assert_eq!(resp.user_code().secret(), "mocking_user_code");
    assert_eq!(resp.verification_uri().to_string(), "https://mocking.uri/");
    assert_eq!(
        resp.verification_uri_complete().unwrap().secret(),
        "https://mocking.uri/mocking_user_code"
    );
    assert_eq!(resp.expires_in().as_secs(), 3600);
    assert_eq!(resp.interval().as_secs(), 5);

    // No QR code generated
    assert_eq!(
        prompt.to_string(),
        "\nOpen the following link in your web browser:\nhttps://mocking.uri/mocking_user_code\nPress \"ENTER\" after successful authentication..."
    );

    prompt.generate_qr();
    // With QR code generated
    assert_eq!(
        prompt.to_string(),
        format!(
            "\n{}\nScan the QR code above or open the following link in your web browser:\nhttps://mocking.uri/mocking_user_code\nPress \"ENTER\" after successful authentication...",
            qr_code(&"https://mocking.uri/mocking_user_code".to_string()).unwrap()
        )
    );
}

#[test]
fn err_500_device() {
    let (mut mock, oauth_client) = Mock::builder().init(None);
    let logger = LOGGER.lock().unwrap();

    mock.server
        .mock("POST", "/device")
        .with_status(500)
        .with_body(
            r#"{
        "error": "500 Internal Server Error" 
    }
        "#,
        )
        .create();

    let resp = oauth_client.device_code();
    assert!(resp.is_err());
    let _ = resp.map_err(|err| TestLogger::handle_error(err, "Failed to get device code"));
    assert_eq!(
        logger.msg(),
        "Failed to get device code\n    caused by: Server returned error response: 500 Internal Server Error"
    );
}
