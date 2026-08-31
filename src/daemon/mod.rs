pub mod auth;
pub mod clipboard;
pub mod server;
pub mod tls;

use crate::config::Config;
use server::AppState;
use tracing::info;

pub async fn run(config: Config) -> anyhow::Result<()> {
    info!("Starting clipperd daemon...");

    let clipboard_state = clipboard::new_shared_state();

    let state_clone = clipboard_state.clone();
    tokio::spawn(async move {
        clipboard::poll_clipboard(state_clone).await;
    });

    // The effective key and token: external files when configured, else inline.
    let key_pem = config.effective_key_pem()?;
    let token = config.effective_token()?;

    let app_state = AppState {
        clipboard: clipboard_state,
        token,
    };

    server::run_https_server(
        app_state,
        config.port,
        &config.cert_pem,
        &key_pem,
        config.bind_ip.clone(),
    )
    .await?;

    Ok(())
}
