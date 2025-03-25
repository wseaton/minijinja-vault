use std::sync::Arc;

use minijinja::{context, value::Kwargs, Environment, Value};
use minijinja_vault::{make_vault_client, MinijinjaVaultClient};

use dotenv::dotenv;
use tracing::{error, info};

fn main() {
    dotenv().ok();
    tracing_subscriber::fmt::init();

    // example of how you can bootstrap the environment w/ variables and a client, 
    // this is the optimal way to use the library if you are going to be repeatedly
    // rendering templates with the same client
    let mut env = Environment::new();
    env.add_global("mount", "apps");
    env.add_global("path", std::env::args().nth(1).unwrap_or("myapp".to_string()));
    let kwargs = Kwargs::from_iter([
        ("login", Value::from("oidc".to_string())
    )]);
    let client = make_vault_client(kwargs).unwrap();
    env.add_global("vault", client);

    match env.render_str(
        r#"
{# Create a fancy CLI display of Vault secrets #}
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃           VAULT CONTENTS EXPLORER          ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
{%- set paths = vault.list(mount, path) %}
📂 Available Paths in apps/accountai:
{% for item in paths -%}
    {% if loop.index is even -%}
    ├── 🔹 {{ item|upper }}
    {%- else -%}
    ├── 🔸 {{ item|lower }}
    {%- endif %}
{% endfor -%}
└── End of listing

📊 SUMMARY:
    • Total paths: {{ paths|length }}
    {%- if paths|length > 5 %}
    • Status: 🟢 Many paths available!
    {%- else %}
    • Status: 🟡 Only a few paths found.
    {%- endif %}

{%- if paths|length == 0 %}
⚠️  WARNING: No paths were found!
{%- endif %}
        "#,
                context! {},
        ) {
                Ok(output) => println!("rendered output: {output}"),
                Err(e) => {
                        error!("{e:#?}");
                }
        };
}