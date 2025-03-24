# PAM module for OAuth 2.0 Device Authorization Grant 
This PAM module authenticates users using [OAuth 2.0 Device Authorization Grant](https://oauth.net/2/device-flow/). It doesn't have built-in LDAP integration, so **users must be present** in the system before they can log in via this module. It works well alongside SSSD. The module communicates with the Authorization Server to obtain user prompt data, attempt to retrieve a user `access_token`, and introspect the obtained token. Since the client module needs to introspect the access token via the Authorization Server introspection endpoint, this endpoint must be implemented on the server side. If the token is valid then the user is authenticated. The module validates the following fields in the Token Information Response:
- `active`: Must be true.
- `username`: The username from the `access_token` must match the requested PAM username. The use of "root" as a remote username is prohibited and and will consistently result in failure.
- `scope`: The scopes must match those requested in the module configuration file. The order of scopes doesn't matter.
- `exp`: The expiration date is compared to the current system date converted to UTC.

Only the `auth` PAM module type is implemented in this repo. The `account` type will consistently return success for testing purposes.

This code relies heavily on two libraries:
- [pam-bindings](https://github.com/Nithe14/pam-rs.git) - My own fork of Rust interface to the PAM framework (See [original crate](https://crates.io/crates/pam-bindings) for more details)
- [oauth2](https://docs.rs/oauth2/latest/oauth2/) - A dedicated, strongly-typed Rust OAuth2 client library

**Tested only with AlmaLinux 9.\* and Keycloak.**

##  Requirements
- rustc >= 1.81.0
- cargo
- gcc
- libpam-devel
- openssl-devel

```shell
#RPMs
dnf install rustc cargo gcc pam-devel openssl-devel

#Debian
apt install rustc cargo build-essential libpam-dev libssl-dev
```
## Installation
You can install it with provided RPM:
```shell
rpm -i rpm/pam_oauth2_device.so-0.1.1-1.x86_64.rpm
```

You can use the provided Makefile:
```shell
make all
```
This command will test, build, and install the module. Installation primarily involves copying the compiled `libpam_oauth2_device.so` to the PAM modules path and creating example configurations.

Alternatively, you can test and build it manually:

```shell
cargo test [--release]
cargo build [--release]
```
The module file should then be located at either `target/debug/libpam_oauth2_device.so` or `target/release/libpam_oauth2_device.so`, and it can be copy to the PAM modules path (`/lib64/security/`).

## Configuration
#### Arguments
The module requires a configuration file. You can specify the path to this file using the `config` keyword, as that's how the parser works. Please refer to the example below:
```conf
auth       sufficient   pam_oauth2_device.so config=/etc/pam_oauth2_device/config.json
```
The `config` argument specifies configuration path and is not required, but it is recommended to set up. Otherwise, the default configuration path (`/etc/pam_oauth2_device/config.json`) will be used.

Module also parses two optional arguments:
- `logs`: Specifies the logging path (default: `/tmp/pam_oauth2_device`),
- `log_level`: Specifies the logging level filter (default: `info`). Possible options: `info`, `warn`, `error`, `debug`, `trace`, and `none`.

These **cannot** be configured via a configuration file, as logging is initialized beforehand and operates independently of config parsing.

Example: 
```conf
auth       sufficient   pam_oauth2_device.so config=/etc/pam_oauth2_device/config.json logs=/var/log/pam_oauth2_device/log log_level=warn
```
#### Config file

The configuration file (`config.json`) must be a valid JSON file with all required fields properly set:
| Field                        | Description                                 | Required | Default Value        |
| ---------------------------- | ------------------------------------------- | ---------| ---------------------|
| `client_id`                  | OAuth 2.0 client_id                         | Yes      | -                    |
| `client_secret`              | OAuth 2.0 client_secret                     | Yes      | -                    |
| `oauth_auth_url`             | OAuth 2.0 Authorization endpoint URL        | Yes      | -                    |
| `oauth_device_url`           | OAuth 2.0 Device Authorization endpoint URL | Yes      | -                    |
| `oauth_token_url`            | OAuth 2.0 Token endpoint URL                | Yes      | -                    |
| `oauth_token_introspect_url` | OAuth 2.0 Token Introspection endpoint URL  | Yes      | -                    |
| `oauth_device_token_polling_timeout` | Time in seconds specifying the polling token timeout  | No      | null                    |
| `scope`                      | OAuth 2.0 Access Scopes (optional)          | No       | `openid profile`     |
| `qr_enabled`                 | If set to true, a QR code will be generated from either verification_uri_complete or verification_uri (optional) | No       | `true`               |
| `messages`                   | An object containing the contents of messages displayed to the user | No       | {...} |
| `messages.prompt_complete`   | Content of prompt message if the `verification_uri_complete` is returned by OAuth server and QR code is displayed | No | shown in `example-config.json` |
| `messages.prompt_no_qr_complete`   | The same as `prompt_complete` but when the QR code is not displayed | No | shown in `example-config.json` |
| `messages.prompt_incomplete`   | Content of prompt message if the `verification_uri_complete` is **not** returned by OAuth server and QR code is displayed | No | shown in `example-config.json` |
| `messages.prompt_no_qr_incomplete`   | The same as `prompt_incomplete` but when the QR code is not displayed | No | shown in `example-config.json` |
| `messages.prompt_code`   | Content of prompt message that is prited before `user_code` if the `verification_uri_complete` has not been returned form the server  | No | shown in `example-config.json` |
| `messages.prompt_enter`   | Content of the prompt message encouraging the user to press enter after authentication | No | shown in `example-config.json` |


Look at [example-config.json](./example-config.json).

### Redirect URI
The redirect URI is hardcoded as a `urn:ietf:wg:oauth:2.0:oob` value because the PAM module is Out of Band. You need to configure this redirect URI in your OAuth client settings.

## Testing
If you installed the module using the Makefile, you should find a testing utility at `target/pam_test` and an example PAM configuration at `/etc/pam.d/device-flow-auth`. Ensure you create the configuration file at `/etc/pam_oauth2_device/config.json`. You can use the following command to test the module:
```shell
                                 # Just the name of PAM config under /etc/pam.d/. Not a path!
./target/pam_test <pam-username> device-flow-auth 
```
Make sure to replace `<pam-username>` with the actual username configured in your system.

## SElinux config
Setting one of this booleans should be sufficient: `authlogin_yubikey` or `nis_enabled`.
```shell
setsebool -P authlogin_yubikey 1
# OR
setsebool -P nis_enabled 1
```

## SSHD example
This `sshd_config`  params are required:
```conf
ChallengeResponseAuthentication yes
UsePAM yes
```
An example of `/etc/pam.d/sshd`:
```conf
#%PAM-1.0
auth       sufficient   pam_oauth2_device.so config=/etc/pam_oauth2_device/config.json logs=/var/log/pam_oauth2_device/log log_level=info
auth       include      postlogin

#the rest of the file...
```
