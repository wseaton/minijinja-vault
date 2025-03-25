#![allow(clippy::let_unit_value)]

use std::sync::Arc;
use std::{fmt, io};

use minijinja::value::{from_args, Kwargs, Object, Value};
use minijinja::{Error, State};

use tokio::runtime::{Builder as RuntimeBuilder, Runtime};
use tracing::{debug, error, info};
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use vaultrs::kv2;

use vaultrs_login::engines::{approle::AppRoleLogin, oidc::OIDCLogin};
use vaultrs_login::method::{default_mount, Method};
use vaultrs_login::LoginClient;

pub enum VaultLogin {
    AppRole(AppRoleLogin),
    OIDC(OIDCLogin),
}

pub struct MinijinjaVaultClient {
    pub vault: VaultClient,
    runtime: Runtime,
}

impl MinijinjaVaultClient {
    // helper function to create a new instance of the client in rust code
    pub fn new(client: VaultClient) -> Self {
        let runtime = get_runtime().expect("failed to create runtime");
        MinijinjaVaultClient {
            vault: client,
            runtime,
        }
    }

    pub fn try_new(client: VaultClient) -> Result<Self, io::Error> {
        let runtime = get_runtime()?;
        Ok(MinijinjaVaultClient {
            vault: client,
            runtime,
        })
    }
}

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
    fn call_method(
        self: &Arc<Self>,
        _state: &State,
        name: &str,
        args: &[Value],
    ) -> Result<Value, Error> {
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
        let secret = self
            .runtime
            .block_on(kv2::list(&self.vault, mount, path))
            .expect("list operation failed");
        Ok(Value::from_iter(secret))
    }

    pub fn get(&self, args: &[Value]) -> Result<Value, Error> {
        let (mount, path): (&str, &str) = from_args(args)?;
        let secret = self
            .runtime
            .block_on(kv2::read::<Value>(&self.vault, mount, path))
            .expect("Failed to read secret");
        Ok(secret)
    }
}

fn get_value(kwargs: &Kwargs, key: &str, env_var: &str) -> Result<String, Error> {
    let value: Option<&str> = kwargs.get(key)?;
    Ok(value.map(|s| s.to_string()).unwrap_or_else(|| {
        std::env::var(env_var).unwrap_or_else(|_| panic!("{} not set", env_var))
    }))
}

/// This function creates a new instance of the vault client from inside of the template
pub fn make_vault_client(options: Kwargs) -> Result<Value, Error> {
    debug!("kwargs: {:#?}", &options);
    let (mount, login) = match options.get("login") {
        Ok(Some("oidc")) => {
            let mount = default_mount(&Method::OIDC);
            // Parse OIDC port from kwargs or environment variable
            let port = std::env::var("VAULT_OIDC_PORT")
                .unwrap_or("8250".to_string())
                .parse::<u16>()
                .map_err(|e| {
                    Error::new(
                        minijinja::ErrorKind::InvalidOperation,
                        format!("failed to parse port: {}", e),
                    )
                })?;

            // Get OIDC role or use empty string as default
            let role = Some(std::env::var("VAULT_OIDC_ROLE").unwrap_or_else(|_| "".to_string()));
            (
                mount,
                VaultLogin::OIDC(OIDCLogin {
                    port: Some(port),
                    role,
                }),
            )
        }
        Ok(Some("app_role")) => {
            let mount = default_mount(&Method::APPROLE);
            (
                mount,
                VaultLogin::AppRole(AppRoleLogin {
                    role_id: get_value(&options, "role_id", "VAULT_ROLE_ID")?,
                    secret_id: get_value(&options, "secret_id", "VAULT_SECRET_ID")?,
                }),
            )
        }
        Ok(Some(other)) => {
            return Err(Error::new(
                minijinja::ErrorKind::InvalidOperation,
                format!("unknown login method: {}", other),
            ))
        }
        Ok(None) => {
            return Err(Error::new(
                minijinja::ErrorKind::InvalidOperation,
                "unknown login method: [EMPTY]".to_string(),
            ))
        }
        Err(e) => {
            return Err(Error::new(
                minijinja::ErrorKind::InvalidOperation,
                format!("failed to generate login: {e}",),
            ))
        }
    };

    let addr = get_value(&options, "address", "VAULT_ADDR")?;

    let verify: Option<bool> = options.get("verify")?;
    let verify = verify.unwrap_or_else(|| {
        std::env::var("VAULT_SKIP_VERIFY")
            .map(|s| s == "false")
            .unwrap_or(true)
    });

    let mut settings = VaultClientSettingsBuilder::default();
    settings.address(addr);
    settings.verify(verify);

    let the_settings = settings.build().expect("failed to build settings");

    let rt = get_runtime().map_err(|e| {
        Error::new(
            minijinja::ErrorKind::WriteFailure,
            format!("failed to create runtime: {}", e),
        )
    })?;
    let mut client = VaultClient::new(the_settings).expect("failed to create client");

    match login {
        VaultLogin::AppRole(login) => rt
            .block_on(client.login(&mount, &login))
            .expect("failed to login"),
        VaultLogin::OIDC(login) => {
            // Login with OIDC in a blocking manner
            info!("Logging in with OIDC");
            let cb = rt
                .block_on(client.login_multi("oidc", login))
                .expect("failed to get OIDC login callback");

            tracing::debug!("OIDC callback: {:?}", cb);
            if webbrowser::open(cb.url.as_str()).is_err() {
                error!("Failed to open browser, please navigate to: {}", cb.url);
            }

            info!("Waiting for OIDC callback...");
            rt.block_on(client.login_multi_callback("oidc", cb))
                .expect("failed to complete OIDC callback");

            info!("OIDC login completed successfully");
        }
    }

    Ok(Value::from_object(MinijinjaVaultClient::new(client)))
}

fn get_runtime() -> io::Result<Runtime> {
    RuntimeBuilder::new_current_thread().enable_all().build()
}
