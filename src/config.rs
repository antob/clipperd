use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Inline auth token. Optional so a config may rely on `token_file` alone.
    #[serde(default)]
    pub token: Option<String>,
    /// Optional path to a file holding the auth token (read-only). When set,
    /// the daemon and setup flow load the token from this file instead of the
    /// inline `token`. Relative paths resolve against the config directory.
    /// Surrounding whitespace is trimmed. Clipperd never writes this file and
    /// never rotates an externalized token.
    #[serde(default)]
    pub token_file: Option<String>,
    pub port: u16,
    pub cert_pem: String,
    /// Inline PKCS#8 private key PEM. Optional so a config may rely on
    /// `key_pem_file` alone.
    #[serde(default)]
    pub key_pem: Option<String>,
    pub ca_cert_pem: String,
    /// Optional explicit IP the daemon and setup server should bind to, and the
    /// address used in the QR / setup URL / iOS Shortcuts. When unset, the
    /// daemon auto-detects the LAN IP.
    #[serde(default)]
    pub bind_ip: Option<String>,
    /// Certificate identity: the CN and any additional SANs (hostnames and/or
    /// IPs). Empty means fall back to the detected LAN IP as the cert identity.
    #[serde(default)]
    pub cert_names: Vec<String>,
    /// Optional path to a PKCS#8 PEM private key file (read-only). When set, the
    /// daemon loads the key from this file instead of `key_pem`. Relative paths
    /// resolve against the config directory. Clipperd never writes this file.
    #[serde(default)]
    pub key_pem_file: Option<String>,
}

impl Config {
    pub fn config_dir() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(".config").join("clipperd")
    }

    pub fn config_path() -> PathBuf {
        Self::config_dir().join("config.toml")
    }

    pub fn load() -> anyhow::Result<Self> {
        let path = Self::config_path();
        let content = std::fs::read_to_string(&path)
            .map_err(|_| anyhow::anyhow!("Config not found at {}. Run `clipperd setup` first.", path.display()))?;
        Ok(toml::from_str(&content)?)
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let dir = Self::config_dir();
        std::fs::create_dir_all(&dir)?;
        let content = toml::to_string_pretty(self)?;
        // Restrict permissions: owner read/write only
        let path = Self::config_path();
        std::fs::write(&path, content)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    pub fn is_configured() -> bool {
        Self::config_path().exists()
    }

    /// Resolve a private key PEM or token from an optional external file, falling
    /// back to the inline value. Relative paths anchor to the config dir.
    /// A present-but-unreadable file is a hard error. When `trim` is set, both
    /// the file content and the inline fallback are trimmed of whitespace.
    fn read_external_value(
        field_name: &str,
        path_opt: &Option<String>,
        inline: Option<&str>,
        trim: bool,
    ) -> anyhow::Result<String> {
        let value = match path_opt {
            Some(path) => {
                let full = if std::path::Path::new(path).is_absolute() {
                    std::path::PathBuf::from(path)
                } else {
                    Self::config_dir().join(path)
                };
                std::fs::read_to_string(&full).map_err(|e| {
                    anyhow::anyhow!(
                        "{} set but could not read {}: {}",
                        field_name,
                        full.display(),
                        e
                    )
                })?
            }
            None => inline.map(|s| s.to_string()).ok_or_else(|| {
                anyhow::anyhow!(
                    "no {} configured: set either the inline value or {} pointing to a file",
                    field_name,
                    field_name
                )
            })?,
        };
        Ok(if trim { value.trim().to_string() } else { value })
    }

    /// Resolve the effective private key PEM: the contents of `key_pem_file`
    /// when set (relative paths anchored to the config dir), else the inline
    /// `key_pem`. A present-but-unreadable key file is a hard error.
    pub fn effective_key_pem(&self) -> anyhow::Result<String> {
        Self::read_external_value(
            "key_pem_file",
            &self.key_pem_file,
            self.key_pem.as_deref(),
            false,
        )
    }

    /// Resolve the effective auth token: the contents of `token_file` when set
    /// (relative paths anchored to the config dir), else the inline `token`.
    /// The value is trimmed of surrounding whitespace so a trailing newline
    /// (from echo/editors) doesn't silently break auth.
    /// A present-but-unreadable token file is a hard error.
    pub fn effective_token(&self) -> anyhow::Result<String> {
        Self::read_external_value("token", &self.token_file, self.token.as_deref(), true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn cfg(token_file: Option<&str>, key_file: Option<&str>) -> Config {
        Config {
            token: Some("inline-token".to_string()),
            token_file: token_file.map(|s| s.to_string()),
            port: 7171,
            cert_pem: "cert".into(),
            key_pem: Some("INLINE".to_string()),
            ca_cert_pem: "ca".into(),
            bind_ip: None,
            cert_names: vec![],
            key_pem_file: key_file.map(|s| s.to_string()),
        }
    }

    /// Write a uniquely-named temp file and return its path. A per-call counter
    /// keeps every test filepath distinct, since tests run in parallel threads and
    /// a pid+name-derived name would collide across tests and be torn down early.
    fn write_temp(name: &str, contents: &[u8]) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!("clipperd-{}-{}-{}", std::process::id(), n, name));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(contents).unwrap();
        p
    }

    #[test]
    fn no_key_file_returns_inline_key() {
        let c = cfg(None, None);
        assert_eq!(c.effective_key_pem().unwrap(), "INLINE");
    }

    #[test]
    fn absolute_key_file_is_read() {
        let p = write_temp("key", b"---- FILE KEY ----");
        let c = cfg(None, Some(p.to_str().unwrap()));
        assert_eq!(c.effective_key_pem().unwrap(), "---- FILE KEY ----");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn missing_key_file_is_an_error() {
        let c = cfg(None, Some("/nonexistent/clipperd/no/key.pem"));
        assert!(c.effective_key_pem().is_err());
    }

    #[test]
    fn no_token_file_returns_inline_token() {
        let c = cfg(None, None);
        assert_eq!(c.effective_token().unwrap(), "inline-token");
    }

    #[test]
    fn absolute_token_file_is_read() {
        let p = write_temp("token", b"file-token-abc");
        let c = cfg(Some(p.to_str().unwrap()), None);
        assert_eq!(c.effective_token().unwrap(), "file-token-abc");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn token_file_trailing_newline_is_trimmed() {
        let p = write_temp("token", b"token-with-newline\n\n");
        let c = cfg(Some(p.to_str().unwrap()), None);
        assert_eq!(c.effective_token().unwrap(), "token-with-newline");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn missing_token_file_is_an_error() {
        let c = cfg(Some("/nonexistent/clipperd/no/token.txt"), None);
        assert!(c.effective_token().is_err());
    }

    #[test]
    fn config_parses_with_token_file_and_no_token() {
        // The regression: a config relying solely on token_file must load even
        // though the token field is absent.
        let toml_str = "token_file = \"/run/secrets/token\"\n\
             port = 7171\n\
             cert_pem = \"cert\"\n\
             key_pem = \"key\"\n\
             ca_cert_pem = \"ca\"\n";
        let c: Config = toml::from_str(toml_str).expect("config with token_file only must parse");
        assert_eq!(c.token, None);
        assert_eq!(c.token_file.as_deref(), Some("/run/secrets/token"));
        // Missing inline token but token_file set → effective_token is a hard
        // read error (from the file), not a "missing field" parse error.
        assert!(c.effective_token().is_err());
    }

    #[test]
    fn effective_token_errors_when_neither_set() {
        let c = cfg(None, None);
        // token is Some(inline) in the helper; simulate absence by clearing it.
        let mut c = c;
        c.token = None;
        c.token_file = None;
        assert!(c.effective_token().is_err());
    }

    #[test]
    fn config_parses_with_key_pem_file_and_no_key_pem() {
        // Regression (mirrors token_file): a config relying solely on
        // key_pem_file must load even though the key_pem field is absent.
        let p = write_temp("keyfile", b"---- BEGIN PRIVATE KEY ----");
        let toml_str = format!(
            "token = \"t\"\n\
             port = 7171\n\
             cert_pem = \"cert\"\n\
             key_pem_file = \"{}\"\n\
             ca_cert_pem = \"ca\"\n",
            p.display()
        );
        let c: Config =
            toml::from_str(&toml_str).expect("config with key_pem_file only must parse");
        assert_eq!(c.key_pem, None);
        assert_eq!(c.effective_key_pem().unwrap(), "---- BEGIN PRIVATE KEY ----");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn effective_key_pem_errors_when_neither_set() {
        let mut c = cfg(None, None);
        c.key_pem = None;
        c.key_pem_file = None;
        assert!(c.effective_key_pem().is_err());
    }
}
