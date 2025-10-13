use std::env;

use app::configs::Configs;

const DEFAULT_LISTEN_ADDRESS: &'static str = "0.0.0.0:3232";

#[derive(Debug, Clone)]
pub struct HttpServerConfigs {
    pub(crate) listen_address: String
}

impl Configs for HttpServerConfigs {
    fn load() -> Result<Self, std::env::VarError> {
        Ok(HttpServerConfigs { 
            listen_address: env::var("LISTEN_ADDRESS")
                .unwrap_or(DEFAULT_LISTEN_ADDRESS.to_string())
        })
    }
}