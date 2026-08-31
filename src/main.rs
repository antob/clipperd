mod config;
mod daemon;
mod setup;

use clap::{Parser, Subcommand};
use rand::Rng;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "clipperd",
    about = "Seamless clipboard sync between iPhone and Linux",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate keys (first run) and start the pairing wizard
    Setup {
        /// Port for the HTTPS daemon (default: 7171)
        #[arg(long, default_value_t = 7171)]
        port: u16,

        /// IP address to bind the daemon and setup server to, and to embed in
        /// the server certificate. Defaults to the auto-detected LAN IP.
        #[arg(long)]
        bind_ip: Option<std::net::IpAddr>,

        /// Certificate name(s): the CN and additional SANs, used when creating
        /// the certificate. Repeatable. Each value may be a hostname or an IP.
        /// Defaults to the detected LAN IP when omitted.
        #[arg(long, action = clap::ArgAction::Append)]
        cert_name: Vec<String>,

        /// Print the config that setup would generate to stdout and exit,
        /// without writing anything to disk or starting the setup server.
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },

    /// Run the clipboard sync daemon
    Run,

    /// Show daemon status and configuration
    Status,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("clipperd=info,warn")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Setup {
            port,
            bind_ip,
            cert_name,
            dry_run,
        } => cmd_setup(port, bind_ip, cert_name, dry_run).await,
        Commands::Run => cmd_run().await,
        Commands::Status => cmd_status(),
    }
}

async fn cmd_setup(
    port: u16,
    bind_ip: Option<std::net::IpAddr>,
    cert_name: Vec<String>,
    dry_run: bool,
) -> anyhow::Result<()> {
    // Reject unspecified addresses: they are unusable as a connect host for the
    // iPhone and would produce a mismatch between the bind and the cert/QR.
    if let Some(ip) = bind_ip {
        if ip.is_unspecified() {
            anyhow::bail!(
                "--bind-ip cannot be 0.0.0.0/:: (unspecified has no single connect \
                 address for the iPhone). Pass a concrete interface IP."
            );
        }
    }

    // Passing an identity-changing flag regenerates the cert (keeping the
    // token so iOS Shortcuts stay valid). Otherwise reuse existing credentials.
    let regenerate = bind_ip.is_some() || !cert_name.is_empty();
    let configured = config::Config::is_configured();
    let existing = if configured {
        Some(config::Config::load()?)
    } else {
        None
    };

    let hostname = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "clipperd-host".to_string());

    // Bind IP: explicit flag wins, else auto-detect the LAN IP. This single
    // value drives the daemon/setup bind, the cert IP SAN, the QR, the setup
    // URL, and the iOS Shortcut host URL.
    let auto_ip: std::net::IpAddr = local_ip_address::local_ip()
        .unwrap_or_else(|_| "127.0.0.1".parse().unwrap());
    let bind_addr = bind_ip.unwrap_or(auto_ip);
    let host = bind_addr.to_string();

    let (cfg, fingerprint) = if !configured || regenerate {
        if !dry_run {
            println!("🔐 Generating keys and certificate...");
        }

        let certs = daemon::tls::generate_certs(&hostname, bind_addr, &cert_name)?;
        let fingerprint = daemon::tls::cert_fingerprint(&certs.ca_cert_pem)?;

        // Preserve how the token was configured across a re-setup (inline value
        // or external token_file) so iOS Shortcuts stay valid and externalized
        // tokens are never de-externalized or rotated. Only a first-time setup
        // generates a fresh random inline token.
        let (token, token_file) = match &existing {
            Some(c) => (c.token.clone(), c.token_file.clone()),
            None => (Some(hex::encode(rand::rng().random::<[u8; 32]>())), None),
        };

        let cfg = config::Config {
            token,
            token_file,
            port,
            bind_ip: bind_ip.map(|ip| ip.to_string()),
            cert_names: cert_name.clone(),
            cert_pem: certs.cert_pem.clone(),
            key_pem: Some(certs.key_pem.clone()),
            ca_cert_pem: certs.ca_cert_pem.clone(),
            key_pem_file: None,
        };

        if !dry_run {
            cfg.save()?;
            println!(
                "✅ Config saved to {}",
                config::Config::config_path().display()
            );
            println!();
            println!("🌐 Bind address: {}", host);
            if !cert_name.is_empty() {
                println!("   Cert names: {}", cert_name.join(", "));
            }
            println!();
        }

        (cfg, fingerprint)
    } else {
        if !dry_run {
            println!("ℹ  Config already exists — reusing existing keys and token.");
            println!(
                "   (Delete {} to generate fresh credentials.)",
                config::Config::config_path().display()
            );
            println!();
        }
        let cfg = existing.expect("configured checked");
        let fingerprint = daemon::tls::cert_fingerprint(&cfg.ca_cert_pem)?;
        (cfg, fingerprint)
    };

    // Dry run: emit the config that setup would produce and exit without
    // writing to disk or starting the setup server. Only the serialized config
    // goes to stdout so it can be piped or redirected cleanly.
    if dry_run {
        let toml_str = toml::to_string_pretty(&cfg)?;
        print!("{}", toml_str);
        return Ok(());
    }

    println!("📱 CA Certificate Fingerprint:");
    println!("   {}", fingerprint);
    println!();

    // The setup server, QR, and Shortcuts all share the same host (the bind
    // IP or the detected fallback), so they can never disagree. The token uses
    // the effective value so an externalized token_file stays in sync with the
    // daemon.
    let token = cfg.effective_token()?;
    let setup_state = setup::build_setup_state(&cfg.ca_cert_pem, &token, cfg.port, &host)?;

    let port = cfg.port;
    let setup_url = format!("http://{}:{}/setup", host, port);

    // Print QR code
    println!("📷 Scan this QR code on your iPhone:");
    println!();
    print_qr(&setup_url);
    println!();
    println!("   Or open:  {}", setup_url);
    println!();
    println!("📡 Starting setup server... (Ctrl+C when done)");
    println!();

    let router = setup::setup_router(setup_state);
    daemon::server::run_setup_server(port, router, Some(host)).await?;

    Ok(())
}

async fn cmd_run() -> anyhow::Result<()> {
    let config = config::Config::load()?;
    info!("Loaded config, port={}", config.port);
    daemon::run(config).await
}

fn cmd_status() -> anyhow::Result<()> {
    if !config::Config::is_configured() {
        println!("Not configured. Run `clipperd setup` first.");
        return Ok(());
    }

    let config = config::Config::load()?;
    let ip = local_ip_address::local_ip()
        .unwrap_or_else(|_| "127.0.0.1".parse().unwrap());

    println!("Clipperd Status");
    println!("──────────────────");
    println!("Config:   {}", config::Config::config_path().display());
    println!("LAN IP:   {}", ip);
    println!("Port:     {}", config.port);
    match &config.bind_ip {
        Some(bind) => println!("URL:      https://{}:{}", bind, config.port),
        None => println!("URL:      https://{}:{}", ip, config.port),
    }
    match &config.bind_ip {
        Some(bind) => println!("Bind IP:  {}", bind),
        None => println!("Bind IP:  (auto-detected)"),
    }
    if !config.cert_names.is_empty() {
        println!("Cert:     {}", config.cert_names.join(", "));
    }

    let fingerprint = daemon::tls::cert_fingerprint(&config.ca_cert_pem)
        .unwrap_or_else(|_| "error".to_string());
    println!("Cert CA:  {}", fingerprint);

    let health_url = format!("https://{}:{}/health", ip, config.port);
    println!("Health:   {}", health_url);

    Ok(())
}

fn print_qr(url: &str) {
    use qrcode::{QrCode, render::unicode};
    match QrCode::new(url.as_bytes()) {
        Ok(code) => {
            let rendered = code.render::<unicode::Dense1x2>()
                .dark_color(unicode::Dense1x2::Dark)
                .light_color(unicode::Dense1x2::Light)
                .build();
            println!("{}", rendered);
        }
        Err(e) => {
            eprintln!("QR generation failed: {}", e);
        }
    }
}
