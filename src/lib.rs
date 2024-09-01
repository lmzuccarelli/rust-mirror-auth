use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use custom_logger::*;
use mirror_error::MirrorError;
use reqwest::StatusCode;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;
use std::str;
use urlencoding::encode;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Token {
    pub token: Option<String>,
    #[serde(rename = "access_token")]
    pub access_token: Option<String>,
    #[serde(rename = "expires_in")]
    pub expires_in: Option<i64>,
    #[serde(rename = "issued_at")]
    pub issued_at: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Root {
    pub auths: HashMap<String, Provider>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Provider {
    pub auth: String,
    pub email: Option<String>,
}

#[derive(Clone)]
pub struct ImplTokenInterface {}

#[async_trait]
pub trait TokenInterface {
    async fn get_credentials(
        &self,
        log: &Logging,
        file: Option<String>,
    ) -> Result<String, MirrorError>;
    async fn get_auth_json(&self, url: String, auth: String) -> Result<String, MirrorError>;
    // this allows us to inject file read errors for testing
    async fn read_file(&self, file: String) -> Result<String, MirrorError>;
}

#[async_trait]
impl TokenInterface for ImplTokenInterface {
    // read the credentials from set path (see podman credential reference)
    async fn get_credentials(
        &self,
        log: &Logging,
        file: Option<String>,
    ) -> Result<String, MirrorError> {
        // using $XDG_RUNTIME_DIR envar
        let xdg = match env::var_os("XDG_RUNTIME_DIR") {
            Some(v) => v.into_string().unwrap(),
            None => {
                log.error("$XDG_RUNTIME_DIR envar not set");
                "".to_string()
            }
        };
        let auth_data: String;
        let auth_file: String;
        if file.is_some() {
            auth_file = format!("{}", file.unwrap());
        } else {
            auth_file = format!("{}/containers/auth.json", xdg);
        }
        let exists = Path::new(&auth_file).exists();
        if exists {
            auth_data = self.read_file(auth_file.clone()).await?;
        } else {
            // try $HOME/.docker/config
            let docker_env = match env::var_os("HOME") {
                Some(v) => v.into_string().unwrap(),
                None => {
                    log.error("$HOME envar not set");
                    "".to_string()
                }
            };
            let docker_auth = format!("{}/.docker/config.json", docker_env);
            let exists = Path::new(&docker_auth).exists();
            if exists {
                auth_data = self.read_file(docker_auth).await?;
            } else {
                return Err(MirrorError::new(
                    "[get_credentials] could not locate $HOME/.docker/config.json",
                ));
            }
        }
        Ok(auth_data)
    }

    /// async api call with basic auth
    async fn get_auth_json(&self, url: String, auth: String) -> Result<String, MirrorError> {
        let client = reqwest::Client::new();
        let res = client
            .get(&url)
            .header("Authorization", format!("Basic {}", auth.clone()))
            .header("User-Agent", "rust-mirror-auth")
            .send()
            .await;
        if res.as_ref().unwrap().status() != StatusCode::OK {
            return Err(MirrorError::new(&format!(
                "[get_auth_json] api call {} {}",
                url.clone(),
                res.unwrap().status()
            )));
        }
        let body = res.unwrap().text().await;
        if body.is_err() {
            return Err(MirrorError::new(&format!(
                "[get_auth_json] reading body {}",
                body.err().unwrap().to_string().to_lowercase()
            )));
        }
        Ok(body.unwrap())
    }

    async fn read_file(&self, file: String) -> Result<String, MirrorError> {
        let res = fs::read_to_string(file.clone());
        if res.is_err() {
            return Err(MirrorError::new(&format!(
                "[read_file] {}",
                res.as_ref().unwrap().to_string().to_lowercase()
            )));
        }
        Ok(res.unwrap())
    }
}

/// process all relative functions in this module to actually get the token
pub async fn get_token<T: TokenInterface>(
    t_impl: T,
    log: &Logging,
    name: String,
    namespace: String,
    enabled: bool,
) -> Result<String, MirrorError> {
    if !enabled {
        return Ok("".to_string());
    }
    // get creds from $XDG_RUNTIME_DIR
    let creds = t_impl.get_credentials(log, None).await?;
    // parse the json data
    let auth = parse_json_creds(creds.clone(), name.clone())?;
    // decode to base64
    let res_bytes = general_purpose::STANDARD.decode(auth.clone());
    if res_bytes.is_err() {
        return Err(MirrorError::new(&format!(
            "[get_token] base64 decode {}",
            res_bytes.as_ref().err().unwrap().to_string().to_lowercase()
        )));
    };
    let s = match str::from_utf8(&res_bytes.as_ref().unwrap()) {
        Ok(v) => v,
        Err(e) => {
            return Err(MirrorError::new(&format!(
                "[get_token] get auth json {}",
                e.to_string().to_lowercase()
            )));
        }
    };

    // get user from json
    let (user, _) = s.split_once(":").unwrap();
    let token_url = match name.as_str() {
                "registry.redhat.io" => format!(
                "https://sso.redhat.com/auth/realms/rhcc/protocol/redhat-docker-v2/auth?service=docker-registry&client_id=curl&scope={}",encode("repository:rhel:pull")
                ),
                "quay.io" => {
                    format!("https://quay.io/v2/auth?account={}&service={}&scope={}",
                        encode(user),
                        "quay%2Eio",
                        encode("repository:openshift-release-dev/ocp-v4.0-art-dev:pull"))
                }
                "registry.ci.openshift.org" => {
                    format!(
                        "https://registry.ci.openshift.org/openshift/token?&account={}&scope={}",
                        encode(user),
                        encode("repository:ocp/release:pull"))
                }
                &_ => {
                    // used for quay.io on prem
                    let scope_pull_push = format!("repository:{}:pull,push",namespace);
                    let scope_pull = format!("repository:{}:pull",namespace);
                    format!("https://{}/v2/auth?account={}&scope={}&scope={}&service={}",
                        name,
                        encode(user),
                        encode(&scope_pull_push),
                        encode(&scope_pull),
                        encode(&name))
                }
            };

    // call the realm url to get a token with the creds
    let res = t_impl.get_auth_json(token_url, auth.to_string()).await?;
    let result = res.clone();
    // if all goes well we should have a valid token
    let token = parse_json_token(result)?;
    Ok(token.clone())
}

/// parse the json credentials to a struct
pub fn parse_json_creds(data: String, mode: String) -> Result<String, MirrorError> {
    // parse the string of data into serde_json::Root.
    let res = serde_json::from_str(&data);
    if res.is_err() {
        return Err(MirrorError::new(&format!(
            "[parse_json_creds] {}",
            res.err().unwrap().to_string().to_lowercase()
        )));
    }
    let creds: Root = res.unwrap();
    let provider = &creds.auths[&mode];
    Ok(provider.auth.clone())
}

/// parse the json from the api call
pub fn parse_json_token(data: String) -> Result<String, MirrorError> {
    // parse the string of data into serde_json::Token.
    let res = serde_json::from_str(&data);
    if res.is_err() {
        return Err(MirrorError::new(&format!(
            "[parse_json_token] {}",
            res.err().unwrap().to_string().to_lowercase()
        )));
    }
    let root: Token = res.unwrap();
    if root.token.is_some() {
        return Ok(root.token.unwrap());
    }
    if root.access_token.is_some() {
        return Ok(root.access_token.unwrap());
    }
    return Err(MirrorError::new(
        "[parse_json_token] could not parse access_token or token fields",
    ));
}

#[cfg(test)]
mod tests {
    // this brings everything from parent's scope
    use super::*;
    use serial_test::serial;

    macro_rules! aw {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
    }

    #[derive(Clone)]
    struct Fake {}

    fn setup_mock() -> Fake {
        #[async_trait]
        impl TokenInterface for Fake {
            async fn get_credentials(
                &self,
                _log: &Logging,
                _file: Option<String>,
            ) -> Result<String, MirrorError> {
                let json_data = r#"{ 
                  "auths":{
                    "registry.redhat.io": {
                      "auth":"aGVsbG86d29ybGQK"
                    },
                    "quay.io": {
                      "auth":"aGVsbG86d29ybGQK"
                    },
                    "registry.ci.openshift.org": {
                      "auth":"aGVsbG86d29ybGQK"
                    },
                    "other": {
                      "auth":"aGVsbG86d29ybGQK"
                    },
                    "broken" : {
                        "auth" : "broken"
                    }
                  }
                }"#;
                Ok(json_data.to_string())
            }
            async fn get_auth_json(
                &self,
                _url: String,
                _auth: String,
            ) -> Result<String, MirrorError> {
                let result = r#"{
                    "token": "test",
                    "access_token": "aebcdef1234567890",
                    "expires_in":300,
                    "issued_at":"2023-10-20T13:23:31Z"
                }"#;
                Ok(result.to_string())
            }
            async fn read_file(&self, _file: String) -> Result<String, MirrorError> {
                Ok("ok".to_string())
            }
        }
        let fake = Fake {};
        fake
    }

    #[test]
    #[serial]
    fn test_get_token_pass() {
        let log = &Logging {
            log_level: Level::TRACE,
        };

        let fake = setup_mock();
        let res = aw!(get_token(
            fake.clone(),
            log,
            "registry.redhat.io".to_string(),
            "".to_string(),
            true
        ));
        assert_eq!(res.is_ok(), true);

        let res_q = aw!(get_token(
            fake.clone(),
            log,
            "quay.io".to_string(),
            "".to_string(),
            true
        ));
        assert_eq!(res_q.is_ok(), true);

        let res_r = aw!(get_token(
            fake.clone(),
            log,
            "registry.ci.openshift.org".to_string(),
            "".to_string(),
            true
        ));
        assert_eq!(res_r.is_ok(), true);

        let res_o = aw!(get_token(
            fake.clone(),
            log,
            "other".to_string(),
            "".to_string(),
            true
        ));
        assert_eq!(res_o.is_ok(), true);

        let res_o = aw!(get_token(
            fake.clone(),
            log,
            "broken".to_string(),
            "".to_string(),
            true
        ));
        assert_eq!(res_o.is_err(), true);

        let res_o = aw!(get_token(
            fake.clone(),
            log,
            "none".to_string(),
            "".to_string(),
            false
        ));
        assert_eq!(res_o.is_ok(), true);
    }

    #[test]
    fn parse_json_creds_fail() {
        let data = "{".to_string();
        let res = parse_json_creds(data, "other".to_string());
        assert_eq!(res.is_err(), true);
    }

    #[test]
    fn parse_json_token_fail() {
        let data = "{".to_string();
        let res = parse_json_token(data);
        assert_eq!(res.is_err(), true);
    }

    #[test]
    fn parse_json_token_invalid_token_fail() {
        let data = r#"{
                    "none": "aebcdef1234567890",
                    "expires_in":300,
                    "issued_at":"2023-10-20T13:23:31Z"
                }"#;
        let res = parse_json_token(data.to_string());
        assert_eq!(res.is_err(), true);
    }

    #[test]
    fn parse_json_token_pass() {
        let data = r#"{
                    "access_token": "aebcdef1234567890",
                    "expires_in":300,
                    "issued_at":"2023-10-20T13:23:31Z"
                }"#;
        let res = parse_json_token(data.to_string());
        assert_eq!(res.is_ok(), true);
    }

    #[test]
    fn get_auth_json_pass() {
        let mut server = mockito::Server::new();
        let url = server.url();

        let t_impl = ImplTokenInterface {};
        // Create a mock server
        server
            .mock("GET", "/v2/auth")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                "{
                    \"token\": \"test\",
                    \"access_token\": \"aebcdef1234567890\",
                    \"expires_in\":300,
                    \"issued_at\":\"2023-10-20T13:23:31Z\"
                }",
            )
            .create();

        server
            .mock("GET", "/v2/error")
            .with_status(500)
            .with_header("content-type", "application/json")
            .create();

        let res = aw!(t_impl.get_auth_json(format!("{}/v2/auth", url), "auth".to_string()));
        assert_eq!(res.is_ok(), true);

        let res = aw!(t_impl.get_auth_json(format!("{}/v2/error", url), "auth".to_string()));
        assert_eq!(res.is_err(), true);
    }

    #[test]
    fn get_credentials_file_pass() {
        let log = &Logging {
            log_level: Level::TRACE,
        };
        let t_impl = ImplTokenInterface {};
        let res = aw!(t_impl.get_credentials(log, Some("tests/containers/auth.json".to_string())));
        assert_eq!(res.is_ok(), true);
    }

    #[test]
    fn get_credentials_file_fail() {
        let log = &Logging {
            log_level: Level::TRACE,
        };
        let t_impl = ImplTokenInterface {};
        let res_f = aw!(t_impl.get_credentials(log, Some("nada".to_string())));
        assert_eq!(res_f.is_ok(), true);
    }

    #[test]
    fn get_credentials_xdg_pass() {
        let log = &Logging {
            log_level: Level::TRACE,
        };
        unsafe {
            env::set_var("XDG_RUNTIME_DIR", "tests");
        }
        let t_impl = ImplTokenInterface {};
        let res_f = aw!(t_impl.get_credentials(log, None));
        assert_eq!(res_f.is_ok(), true);
    }
}
