#![allow(clippy::let_unit_value)]

use std::fmt;

use minijinja::value::{from_args, Kwargs, Object, Value};
use minijinja::{Environment, Error, State};

use vaultrs::auth::approle::role::{self, secret};
use vaultrs::client::{VaultClient, VaultClientSettingsBuilderError};
use vaultrs::kv2;

use vaultrs_login::engines::approle::AppRoleLogin;
use vaultrs_login::LoginClient;

pub struct MinijinjaVaultClient(VaultClient);

impl fmt::Display for MinijinjaVaultClient {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "vaultclient")
    }
}

impl fmt::Debug for MinijinjaVaultClient {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "vaultclient")
    }
}

impl Object for MinijinjaVaultClient {
    fn call_method(&self, _state: &State, name: &str, args: &[Value]) -> Result<Value, Error> {
        // use the client on self to get the secret from a kv2 endpoint

        match name {
            "list" => self.list(args),
            "get" => self.get(args),
            _ => Err(Error::new(
                minijinja::ErrorKind::UnknownMethod,
                format!("method {} not found", name),
            )),
        }
    }
}

impl MinijinjaVaultClient {
    pub fn list(&self, args: &[Value]) -> Result<Value, Error> {
        let (mount, path): (&str, &str) = from_args(args)?;
        let rt = tokio::runtime::Runtime::new().unwrap();
        let secret = rt
            .block_on(kv2::list(&self.0, mount, path))
            .expect("list operation failed");
        Ok(Value::from_iter(secret))
    }

    pub fn get(&self, args: &[Value]) -> Result<Value, Error> {
        let (mount, path, key): (&str, &str, &str) = from_args(args)?;
        let rt = tokio::runtime::Runtime::new().unwrap();
        let secret = rt
            .block_on(kv2::read::<serde_json::Value>(&self.0, mount, path))
            .expect("Failed to read secret");
        Ok(Value::from_safe_string(
            secret.get(key).expect("key does not exist").to_string(),
        ))
    }
}

pub fn make_vault_client(_state: &State, args: Vec<Value>) -> Result<Value, Error> {
    let (_, kwargs): (&[Value], Kwargs) = from_args(&args)?;

    let addr: Option<&str> = kwargs.get("address")?;
    let addr = addr
        .map(|s| s.to_string())
        .unwrap_or_else(|| std::env::var("VAULT_ADDR").expect("VAULT_ADDR not set"));

    let role_id: Option<&str> = kwargs.get("role_id")?;
    let role_id = role_id
        .map(|s| s.to_string())
        .unwrap_or_else(|| std::env::var("VAULT_ROLE_ID").expect("VAULT_ROLE_ID not set"));

    let secret_id: Option<&str> = kwargs.get("secret_id")?;
    let secret_id = secret_id
        .map(|s| s.to_string())
        .unwrap_or_else(|| std::env::var("VAULT_SECRET_ID").expect("VAULT_SECRET_ID not set"));

    let verify: Option<bool> = kwargs.get("verify")?;
    let verify = verify.unwrap_or_else(|| {
        std::env::var("VAULT_SKIP_VERIFY")
            .map(|s| s == "false")
            .unwrap_or(true)
    });

    let mut settings = vaultrs::client::VaultClientSettingsBuilder::default();
    settings.address(addr);
    settings.verify(verify);

    let the_settings = settings
        .build()
        .map_err(VaultClientSettingsBuilderError::from)
        .expect("failed to build settings");

    // Use one of the login flows to obtain a token for the client
    let login = AppRoleLogin {
        role_id: role_id.to_string(),
        secret_id: secret_id.to_string(),
    };

    let rt = tokio::runtime::Runtime::new().expect("failed to create runtime");
    let mut client = VaultClient::new(the_settings).expect("failed to create client");

    rt.block_on(client.login("approle", &login))
        .expect("fauled to login");

    Ok(Value::from_object(MinijinjaVaultClient(client)))
}
