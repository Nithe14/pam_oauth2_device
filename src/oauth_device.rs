use std::time::Duration;

use crate::config::Config;
use chrono::{DateTime, Utc};
use oauth2::basic::{BasicClient, BasicTokenResponse};
use oauth2::{
    AccessToken, AuthUrl, ClientId, ClientSecret, DeviceAuthorizationUrl, IntrospectionUrl,
    RedirectUrl, Scope, TokenIntrospectionResponse, TokenUrl,
};
use oauth2::{CurlHttpClient as http_client, EndpointSet};
use oauth2::{EndpointNotSet, StandardDeviceAuthorizationResponse};

type DynErr = Box<dyn std::error::Error>;

#[derive(Debug)]
pub struct OAuthClient {
    client: BasicClient<
        EndpointSet,    //HasAuthUrl
        EndpointSet,    //HasDeviceAuthUrl
        EndpointSet,    //HasIntrospectionUrl
        EndpointNotSet, //HasRevocationUrl
        EndpointSet,    //HasTokenUrl
    >,
    scopes: Vec<Scope>,
}

impl OAuthClient {
    pub fn new(c: &Config) -> Result<Self, DynErr> {
        let client_id = ClientId::new(c.client_id.clone());
        let client_secret = ClientSecret::new(c.client_secret.clone());
        let auth_url = AuthUrl::from_url(c.oauth_auth_url.clone());
        let token_url = TokenUrl::from_url(c.oauth_token_url.clone());
        let device_url = DeviceAuthorizationUrl::from_url(c.oauth_device_url.clone());
        let introspect_url = IntrospectionUrl::from_url(c.oauth_token_introspect_url.clone());
        let redirect_url = RedirectUrl::new("urn:ietf:wg:oauth:2.0:oob".to_string())?;
        let scopes = c
            .scopes
            .split_whitespace()
            .map(|s| Scope::new(s.to_string()))
            .collect();

        let client = BasicClient::new(client_id)
            .set_client_secret(client_secret)
            .set_auth_uri(auth_url)
            .set_token_uri(token_url)
            .set_device_authorization_url(device_url)
            .set_introspection_url(introspect_url)
            .set_redirect_uri(redirect_url);

        Ok(Self { client, scopes })
    }

    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    pub fn device_code(&self) -> Result<StandardDeviceAuthorizationResponse, DynErr> {
        let details: StandardDeviceAuthorizationResponse = self
            .client
            .exchange_device_code()
            .add_scopes(self.scopes.clone())
            .request(&http_client)?;
        Ok(details)
    }

    pub fn get_token(
        &self,
        details: &StandardDeviceAuthorizationResponse,
        timeout: Option<Duration>,
    ) -> Result<BasicTokenResponse, DynErr> {
        let token = self.client.exchange_device_access_token(details).request(
            &http_client,
            std::thread::sleep,
            timeout,
        )?;
        Ok(token)
    }

    pub fn introspect(
        &self,
        token: &AccessToken,
    ) -> Result<impl TokenIntrospectionResponse, DynErr> {
        let introspect = self.client.introspect(token).request(&http_client)?;
        Ok(introspect)
    }

    pub fn validate_token(
        &self,
        token: &impl TokenIntrospectionResponse,
        local_user: &str,
    ) -> bool {
        if !token.active() {
            log::warn!("User token inactive!");
            return false;
        }

        let username_valid = token.username().map_or_else(
            || {
                log::warn!("No username provided in token");
                false
            },
            |remote_username| valid_user(remote_username, local_user),
        );

        let scope_valid = token.scopes().map_or_else(
            || {
                log::warn!("No scope provided in token");
                false
            },
            |token_scopes| valid_scopes(&self.scopes, &token_scopes, &local_user),
        );

        let exp_valid = token.exp().map_or_else(
            || {
                log::warn!("No expiration time provided in token");
                false
            },
            |exp| valid_exp(exp, local_user),
        );

        username_valid && scope_valid && exp_valid
    }
}

fn valid_user(remote_username: &str, local_username: &str) -> bool {
    //remote user cannot be root
    if remote_username == local_username && remote_username != "root" {
        return true;
    }
    log::warn!(
        "Invalid username: remote: {} -> local: {}",
        remote_username,
        &local_username
    );
    false
}

fn valid_scopes(required_scopes: &[Scope], token_scopes: &[Scope], user: &str) -> bool {
    // Scopes order doesn't matter according to RFC 6749
    if required_scopes.iter().all(|s| token_scopes.contains(s)) {
        return true;
    }
    let display_scopes = token_scopes
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<String>>();
    log::warn!(
        "Insuficient scopes for user {}: {:?}",
        &user,
        display_scopes
    );
    false
}

fn valid_exp(exp: DateTime<Utc>, user: &str) -> bool {
    if exp <= Utc::now() {
        log::warn!("Token has expired for user {}", &user);
    }

    exp > Utc::now()
}
