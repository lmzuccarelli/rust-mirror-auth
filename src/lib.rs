use base64::{engine::general_purpose, Engine as _};
use custom_logger::*;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;
use std::str;
use urlencoding::encode;

mod error;

use crate::error::handler::*;

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

// read the credentials from set path (see podman credential reference)
pub fn get_credentials(log: &Logging) -> Result<String, Box<dyn std::error::Error>> {
    // Create a path to the desired file
    // using $XDG_RUNTIME_DIR envar

    let xdg = match env::var_os("XDG_RUNTIME_DIR") {
        Some(v) => v.into_string().unwrap(),
        None => {
            log.error("$XDG_RUNTIME_DIR envar not set");
            "".to_string()
        }
    };

    let auth_file = format!("{}/containers/auth.json", xdg);
    let mut exists = Path::new(&auth_file).exists();
    let mut auth_data: String = String::new();
    if exists {
        let data = fs::read_to_string(auth_file);
        if data.is_err() {
            exists = false;
            log.warn(&format!(
                "$XDG_RUNTIME_DIR/containers/auth.json {:?}",
                data.as_ref().err().unwrap().to_string().to_lowercase()
            ));
        }
        log.debug("using auth file $XDG_RUNTIME_DIR/containers/auth.json");
        auth_data = data.unwrap();
    }
    if !exists {
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
            let data = fs::read_to_string(docker_auth);
            if data.is_err() {
                return Err(Box::new(MirrorError::new(&format!(
                    "$HOME/.docker/config.json {:?}",
                    data.err().unwrap().to_string().to_lowercase()
                ))));
            }
            log.debug("using auth file $HOME/.docker/config.json");
            auth_data = data.unwrap();
        } else {
            return Err(Box::new(MirrorError::new(
                "could not locate $HOME/.docker/config.json",
            )));
        }
    }
    Ok(auth_data)
}

/// parse the json credentials to a struct
pub fn parse_json_creds(data: String, mode: String) -> Result<String, Box<dyn std::error::Error>> {
    // parse the string of data into serde_json::Root.
    let creds: Root = serde_json::from_str(&data)?;
    let provider = &creds.auths[&mode];
    Ok(provider.auth.clone())
}

/// parse the json from the api call
pub fn parse_json_token(data: String, mode: String) -> Result<String, Box<dyn std::error::Error>> {
    // parse the string of data into serde_json::Token.
    let root: Token = serde_json::from_str(&data)?;
    if &mode == "quay.io" {
        if root.token.is_some() {
            return Ok(root.token.unwrap());
        } else {
            return Err(Box::new(MirrorError::new(
                "could not parse token for quay.io",
            )));
        }
    } else {
        if root.access_token.is_some() {
            return Ok(root.access_token.unwrap());
        } else {
            return Err(Box::new(MirrorError::new(&format!(
                "could not parse access_token for {}",
                mode
            ))));
        }
    }
}

/// update quay.io account and urlencode
fn update_url(url: String, account: String) -> String {
    let service = "quay%2Eio";
    let scope = "repository%3Aopenshift-release-dev%2Focp-v4.0-art-dev%3Apull";
    let account_encoded = encode(&account).to_string();
    let result = format!(
        "https://{}account={}&service={}&scope={}",
        &url, &account_encoded, &service, &scope
    );
    result
}

/// async api call with basic auth
pub async fn get_auth_json(
    url: String,
    user: String,
    password: String,
) -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let pwd: Option<String> = Some(password);
    let body = client
        .get(&url)
        .basic_auth(user, pwd)
        .header("User-Agent", "rust auth api caller")
        .send()
        .await?
        .text()
        .await?;
    Ok(body)
}

/// process all relative functions in this module to actually get the token
pub async fn get_token(log: &Logging, name: String) -> Result<String, Box<dyn std::error::Error>> {
    // get creds from $XDG_RUNTIME_DIR
    let creds = get_credentials(log);
    // go style error handling
    if creds.is_err() {
        return Err(Box::new(MirrorError::new(&format!(
            "get_credentials {}",
            creds.err().unwrap().to_string().to_lowercase()
        ))));
    }
    // parse the json data
    let auth = parse_json_creds(creds.as_ref().unwrap().to_string(), name.clone());
    // go style error handling
    if auth.is_err() {
        //log.error(&format!("{:#?}", auth.err()));
        return Err(Box::new(MirrorError::new(&format!(
            "parse_json_creds {}",
            auth.err().unwrap().to_string().to_lowercase()
        ))));
    }

    // decode to base64
    let bytes = general_purpose::STANDARD.decode(auth.unwrap()).unwrap();

    let s = match str::from_utf8(&bytes) {
        Ok(v) => v,
        Err(e) => panic!("invalid UTF-8 sequence: {}", e),
    };
    // get user and password form json
    let (user, pwd) = s.split_once(":").unwrap();
    let token_url = match name.as_str() {
        "registry.redhat.io" => "https://sso.redhat.com/auth/realms/rhcc/protocol/redhat-docker-v2/auth?service=docker-registry&client_id=curl&scope=repository:rhel:pull".to_string(),
        "quay.io" => {
            update_url("quay.io/v2/auth?".to_string(),user.to_string())
        },
        "registry.ci.openshift.org" => format!("https://registry.ci.openshift.org/openshift/token?account={}scope=repository%3Aocp%2Frelease%3Apull",encode(user)),
        &_ => {
            // used for testing
            // return for the mockito server
            let mut hld = name.split("/");
            let url = hld.nth(0).unwrap();
            String::from("http://".to_string() + url + "/auth")
        },
    };
    // call the realm url to get a token with the creds
    let res = get_auth_json(token_url, user.to_string(), pwd.to_string()).await;
    // go style error handling
    if res.is_err() {
        return Err(Box::new(MirrorError::new(&format!(
            "get_auth_json {:#?}",
            res.err().unwrap().to_string().to_lowercase()
        ))));
    }
    let result = res.unwrap();
    // if all goes well we should have a valid token
    let token = parse_json_token(result, name.clone());
    // go style error handling
    if token.is_err() {
        return Err(Box::new(MirrorError::new(&format!(
            "get_auth_json {:#?}",
            token.err().unwrap().to_string().to_lowercase()
        ))));
    }
    // we can now safely unwrap
    Ok(token.unwrap())
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

    #[test]
    #[serial]
    fn test_get_token_redhat_pass() {
        //env::set_var("XDG_RUNTIME_DIR", "/run/user/1000");
        let log = &Logging {
            log_level: Level::DEBUG,
        };
        let res = aw!(get_token(log, String::from("registry.redhat.io"),));
        assert!(res.is_err() == false);
    }
    #[test]
    #[serial]
    fn test_get_token_quay_pass() {
        //env::set_var("XDG_RUNTIME_DIR", "/run/user/1000");
        let log = &Logging {
            log_level: Level::DEBUG,
        };
        let res = aw!(get_token(log, String::from("quay.io"),));
        assert!(res.is_err() == false);
    }
    #[test]
    #[serial]
    fn test_get_token_quay_pass_no_xdg() {
        //env::set_var("XDG_RUNTIME_DIR", "nada");
        let log = &Logging {
            log_level: Level::DEBUG,
        };
        let res = aw!(get_token(log, String::from("quay.io"),));
        //env::set_var("XDG_RUNTIME_DIR", "/run/user/1000");
        // should pass as it pick up $HOME/.docker/config/json
        assert!(res.is_err() == false);
    }
    #[test]
    #[serial]
    fn test_parse_json_creds_pass() {
        let log = &Logging {
            log_level: Level::DEBUG,
        };
        // set to pick up local path tests/containers/auth.json
        //env::set_var("XDG_RUNTIME_DIR", "tests/");
        let data = get_credentials(log).unwrap();
        let res = parse_json_creds(data, String::from("registry.redhat.io"));
        //env::set_var("XDG_RUNTIME_DIR", "/run/user/1000");
        assert!(res.is_ok());
    }
    #[test]
    #[serial]
    fn test_parse_json_creds_registry_connect_pass() {
        let log = &Logging {
            log_level: Level::DEBUG,
        };
        // set to pick up local path tests/containers/auth.json
        //env::set_var("XDG_RUNTIME_DIR", "tests/");
        let data = get_credentials(log).unwrap();
        let res = parse_json_creds(data, String::from("registry.connect.redhat.com"));
        //env::set_var("XDG_RUNTIME_DIR", "/run/user/1000");
        assert!(res.is_ok());
    }
}
