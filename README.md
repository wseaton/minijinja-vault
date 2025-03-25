# MiniJinja Vault Plugin

A Rust library that integrates MiniJinja templating with HashiCorp Vault at render time.

Currently supported auth methods:

- OIDC
- AppRole

## Structure

This workspace contains:

- `minijinja-vault`: The core library
- `examples`: Example applications showing usage

## Running the Example

```
cd examples/cli
cargo run
```

Make sure to set the required environment variables or create a `.env` file. The example assumes you have a running Vault instance to connect to.
