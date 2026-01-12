use std::{env, fs::File, time::Duration};
use tokio::time::timeout;

#[tokio::test]
async fn test_start_server() {
    dotenvy::from_filename(".env.test").ok();
    let temp_file = std::env::temp_dir().join("integration_test_data.csv");
    File::create(temp_file.clone()).unwrap();

    println!("loaded data");
    if env::var("TR_STORAGE_BACKEND").unwrap_or("csv".to_owned()) == "csv" {
        unsafe {
            env::set_var("FILE_STORAGE_PATH", temp_file.to_str().unwrap());
        }
    }
    unsafe {
        std::env::set_var("LISTEN_ADDRESS", "0.0.0.0:3234");
    }
    let result = timeout(Duration::from_secs(10), trust_registry::server::start()).await;

    assert!(
        result.is_err(),
        "Server should run without errors for 10 seconds"
    );
}
