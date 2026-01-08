use std::env;
use tracing::debug;

#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub log_level: String,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            host: env::var("NOX_GATEWAY_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: env::var("NOX_GATEWAY_PORT")
                .unwrap_or_else(|_| "3000".to_string())
                .parse()
                .unwrap_or(3000),
            log_level: env::var("NOX_GATEWAY_LOG_LEVEL").unwrap_or_else(|_| "info".to_string()),
        }
    }

    pub fn bind_addr(&self) -> String {
        let addr = format!("{}:{}", self.host, self.port);
        debug!("Binding address: {}", addr);
        addr
    }
}
