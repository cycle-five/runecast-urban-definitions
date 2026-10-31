//! Service configuration from the environment. Fail-closed: the three
//! secrets are required and must be non-empty.

use anyhow::{anyhow, Result};

#[derive(Clone)]
pub struct Config {
    pub ticket_key: String,
    pub internal_token: String,
    pub metrics_token: String,
    pub backend_internal_url: String,
    pub bind_addr: String,
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
        Ok(Self {
            ticket_key: required("URBAN_DEFINITIONS_KEY")?,
            internal_token: required("INTERNAL_TOKEN")?,
            metrics_token: required("METRICS_AUTH_TOKEN")?,
            backend_internal_url: optional("BACKEND_INTERNAL_URL", "http://backend:3001"),
            bind_addr: optional("BIND_ADDR", "0.0.0.0:3003"),
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
