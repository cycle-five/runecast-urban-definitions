//! Service configuration from the environment. Fail-closed: the three
//! secrets are required and must be non-empty.

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};

use crate::source::SshConfig;

#[derive(Clone)]
pub struct Config {
    pub ticket_key: String,
    pub internal_token: String,
    pub metrics_token: String,
    pub backend_internal_url: String,
    pub bind_addr: String,
    /// `None` when `DUMP_SSH_HOST` is unset or empty: the dump is never loaded.
    pub dump_source: Option<SshConfig>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let required = |name: &str| {
            get(name)
                .filter(|v| !v.is_empty())
                .ok_or_else(|| anyhow!("{name} is required"))
        };
        let optional = |name: &str, default: &str| {
            get(name)
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| default.to_string())
        };
        let dump_source = match get("DUMP_SSH_HOST").filter(|v| !v.is_empty()) {
            None => None,
            Some(host) => {
                let port = optional("DUMP_SSH_PORT", "22")
                    .parse::<u16>()
                    .context("DUMP_SSH_PORT must be a port number")?;
                Some(SshConfig {
                    user: required("DUMP_SSH_USER")?,
                    port,
                    key: PathBuf::from(optional("DUMP_SSH_KEY", "/run/muninn/id_ed25519")),
                    known_hosts: PathBuf::from(optional(
                        "DUMP_SSH_KNOWN_HOSTS",
                        "/run/muninn/known_hosts",
                    )),
                    host_key_alias: optional("DUMP_SSH_HOST_KEY_ALIAS", &host),
                    host,
                })
            }
        };
        Ok(Self {
            ticket_key: required("URBAN_DEFINITIONS_KEY")?,
            internal_token: required("INTERNAL_TOKEN")?,
            metrics_token: required("METRICS_AUTH_TOKEN")?,
            backend_internal_url: optional("BACKEND_INTERNAL_URL", "http://backend:3001"),
            bind_addr: optional("BIND_ADDR", "0.0.0.0:3003"),
            dump_source,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| map.get(k).cloned()
    }

    const ALL: [(&str, &str); 3] = [
        ("URBAN_DEFINITIONS_KEY", "k"),
        ("INTERNAL_TOKEN", "i"),
        ("METRICS_AUTH_TOKEN", "m"),
    ];

    #[test]
    fn defaults_apply() {
        let c = Config::from_lookup(env(&ALL)).unwrap();
        assert_eq!(c.backend_internal_url, "http://backend:3001");
        assert_eq!(c.bind_addr, "0.0.0.0:3003");
    }

    fn with(extra: &[(&'static str, &'static str)]) -> Result<Config> {
        let mut pairs: Vec<(&str, &str)> = ALL.to_vec();
        pairs.extend_from_slice(extra);
        Config::from_lookup(env(&pairs))
    }

    #[test]
    fn dump_source_is_off_without_a_host() {
        assert!(with(&[]).unwrap().dump_source.is_none());
        assert!(with(&[("DUMP_SSH_HOST", ""), ("DUMP_SSH_USER", "u")])
            .unwrap()
            .dump_source
            .is_none());
    }

    #[test]
    fn dump_source_defaults() {
        let c = with(&[("DUMP_SSH_HOST", "h.example"), ("DUMP_SSH_USER", "u")]).unwrap();
        let s = c.dump_source.unwrap();
        assert_eq!(s.host, "h.example");
        assert_eq!(s.user, "u");
        assert_eq!(s.port, 22);
        assert_eq!(s.key, std::path::PathBuf::from("/run/muninn/id_ed25519"));
        assert_eq!(
            s.known_hosts,
            std::path::PathBuf::from("/run/muninn/known_hosts")
        );
        assert_eq!(s.host_key_alias, "h.example");
    }

    #[test]
    fn dump_source_needs_a_user_and_a_numeric_port() {
        assert!(with(&[("DUMP_SSH_HOST", "h")]).is_err());
        assert!(with(&[("DUMP_SSH_HOST", "h"), ("DUMP_SSH_USER", "")]).is_err());
        assert!(with(&[
            ("DUMP_SSH_HOST", "h"),
            ("DUMP_SSH_USER", "u"),
            ("DUMP_SSH_PORT", "ssh")
        ])
        .is_err());
        assert!(with(&[
            ("DUMP_SSH_HOST", "h"),
            ("DUMP_SSH_USER", "u"),
            ("DUMP_SSH_PORT", "70000")
        ])
        .is_err());
        let c = with(&[
            ("DUMP_SSH_HOST", "h"),
            ("DUMP_SSH_USER", "u"),
            ("DUMP_SSH_PORT", "1596"),
            ("DUMP_SSH_HOST_KEY_ALIAS", "muninn"),
        ])
        .unwrap();
        let s = c.dump_source.unwrap();
        assert_eq!((s.port, s.host_key_alias.as_str()), (1596, "muninn"));
    }

    #[test]
    fn each_secret_is_required_and_non_empty() {
        for (missing, (name, _)) in ALL.iter().enumerate() {
            let pairs: Vec<_> = ALL
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != missing)
                .map(|(_, p)| *p)
                .collect();
            assert!(Config::from_lookup(env(&pairs)).is_err());
            let mut blank: Vec<_> = pairs.clone();
            blank.push((name, ""));
            assert!(Config::from_lookup(env(&blank)).is_err());
        }
    }
}
