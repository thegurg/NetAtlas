//! Configuration and XDG path resolution.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

const APP_DIR: &str = "netatlas";
const DEFAULT_MAX_HOSTS: usize = 1024;
const DEFAULT_CONCURRENCY: usize = 64;
const DEFAULT_TIMEOUT_MS: u64 = 1_000;
const DEFAULT_DNS_TIMEOUT_MS: u64 = 1_500;

#[derive(Debug, Clone)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
}

impl Paths {
    pub fn discover() -> Result<Self> {
        let home = std::env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .context("HOME is not set; cannot resolve NetAtlas data paths")?;

        let config_root = std::env::var_os("XDG_CONFIG_HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".config"));
        let data_root = std::env::var_os("XDG_DATA_HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local/share"));

        Ok(Self {
            config_dir: config_root.join(APP_DIR),
            data_dir: data_root.join(APP_DIR),
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
struct ConfigFile {
    db_path: Option<PathBuf>,
    max_hosts: usize,
    concurrency: usize,
    timeout_ms: u64,
    dns_timeout_ms: u64,
}

impl Default for ConfigFile {
    fn default() -> Self {
        Self {
            db_path: None,
            max_hosts: DEFAULT_MAX_HOSTS,
            concurrency: DEFAULT_CONCURRENCY,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            dns_timeout_ms: DEFAULT_DNS_TIMEOUT_MS,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub paths: Paths,
    pub db_path: PathBuf,
    pub max_hosts: usize,
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub dns_timeout_ms: u64,
}

impl Config {
    pub fn load(db_override: Option<PathBuf>) -> Result<Self> {
        let paths = Paths::discover()?;
        std::fs::create_dir_all(&paths.config_dir)
            .with_context(|| format!("creating config directory {}", paths.config_dir.display()))?;
        std::fs::create_dir_all(&paths.data_dir)
            .with_context(|| format!("creating data directory {}", paths.data_dir.display()))?;

        let config_path = paths.config_dir.join("config.toml");
        let file = if config_path.exists() {
            let contents = std::fs::read_to_string(&config_path)
                .with_context(|| format!("reading {}", config_path.display()))?;
            toml::from_str::<ConfigFile>(&contents)
                .with_context(|| format!("parsing {}", config_path.display()))?
        } else {
            ConfigFile::default()
        };

        let db_path = match db_override.or(file.db_path.clone()) {
            Some(path) if path.is_absolute() => path,
            Some(path) => paths.config_dir.join(path),
            None => paths.data_dir.join("netatlas.db"),
        };

        let config = Self {
            paths,
            db_path,
            max_hosts: file.max_hosts,
            concurrency: file.concurrency,
            timeout_ms: file.timeout_ms,
            dns_timeout_ms: file.dns_timeout_ms,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn config_file_path(&self) -> PathBuf {
        self.paths.config_dir.join("config.toml")
    }

    pub fn validate(&self) -> Result<()> {
        if !(1..=65_536).contains(&self.max_hosts) {
            bail!("max_hosts must be between 1 and 65536");
        }
        if !(1..=1_024).contains(&self.concurrency) {
            bail!("concurrency must be between 1 and 1024");
        }
        if !(100..=60_000).contains(&self.timeout_ms) {
            bail!("timeout_ms must be between 100 and 60000");
        }
        if !(100..=60_000).contains(&self.dns_timeout_ms) {
            bail!("dns_timeout_ms must be between 100 and 60000");
        }
        Ok(())
    }

    pub fn ensure_db_parent(&self) -> Result<()> {
        if let Some(parent) = self.db_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating database directory {}", parent.display()))?;
        }
        Ok(())
    }
}

/// Resolve the default database path for a data directory. Used by tests.
pub fn default_db_path(data_dir: &Path) -> PathBuf {
    data_dir.join("netatlas.db")
}

#[cfg(test)]
mod tests {
    use super::{Config, ConfigFile, Paths};
    use std::path::PathBuf;

    #[test]
    fn parses_partial_config() {
        let parsed: ConfigFile = toml::from_str(
            r#"
            max_hosts = 256
            concurrency = 32
            "#,
        )
        .unwrap();
        assert_eq!(parsed.max_hosts, 256);
        assert_eq!(parsed.concurrency, 32);
        assert_eq!(parsed.timeout_ms, 1_000);
    }

    #[test]
    fn rejects_invalid_values() {
        let config = Config {
            paths: Paths {
                config_dir: PathBuf::from("/tmp/config"),
                data_dir: PathBuf::from("/tmp/data"),
            },
            db_path: PathBuf::from("/tmp/data/netatlas.db"),
            max_hosts: 0,
            concurrency: 64,
            timeout_ms: 1_000,
            dns_timeout_ms: 1_500,
        };
        assert!(config.validate().is_err());
    }
}
