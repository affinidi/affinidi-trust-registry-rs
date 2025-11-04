use affinidi_tdk::secrets_resolver::secrets::Secret;
use serde::{Deserialize, Serialize};
use serde_json;
use std::{collections::HashMap, env, fs};

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub alias: String,
    pub secrets: Vec<Secret>,
}

pub fn load_file(path: &str) -> Result<HashMap<String, ServiceConfig>, Box<dyn std::error::Error>> {

    let file_content = fs::read_to_string(path)?;

    let service_configs: HashMap<String, ServiceConfig> =
        serde_json::from_str::<HashMap<String, ServiceConfig>>(&file_content)?;

    Ok(service_configs)
}


pub fn load_user_config() -> Result<HashMap<String, ServiceConfig>, Box<dyn std::error::Error>> {
    let service_config_path = match env::var("SERVICE_CONFIG_PATH") {
        Ok(service_config_path) => service_config_path,
        Err(_) => "./conf/user_config.json".to_string(),
    };

    let services_configs = match load_file(service_config_path.as_str()) {
        Ok(sc) => sc,
        Err(err) => {
            return Err(err);
        }
    };

    Ok(services_configs)
}
