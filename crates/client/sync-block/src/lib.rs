use std::path::Path;
use std::time::Instant;

use base64::engine::general_purpose;
use base64::Engine as _;
use hyper::header::HeaderValue;
use hyper::{body, Body, Client, Request, StatusCode};
use mc_config::config_map;
use once_cell::sync::OnceCell;
use rocksdb::{IteratorMode, DB};
use serde_json::{json, Value};
use tokio::time::{sleep, Duration};

// Create a global instance of SyncDB that can be accessed from other modules.
// pub static SYNC_DB: OnceCell<Result<SyncDB, Box<dyn std::error::Error + Send + Sync>>> =
// OnceCell::default();
static SYNC_DB: OnceCell<SyncDB> = OnceCell::new();

pub fn get_sync_db() -> Result<&'static SyncDB, Box<dyn std::error::Error + Send + Sync>> {
    SYNC_DB.get_or_try_init(SyncDB::new_sync_db)
}

// Define a struct to hold the DB instance.
pub struct SyncDB {
    db: DB,
}

impl SyncDB {
    // Constructor to open the database.
    fn new() -> Result<SyncDB, Box<dyn std::error::Error + Send + Sync>> {
        Ok(SyncDB { db: DB::open_default(Path::new("epool"))? })
    }

    fn new_sync_db() -> Result<SyncDB, Box<dyn std::error::Error + Send + Sync>> {
        let db = SyncDB::new().map_err(|e| {
            log::error!("Failed to init sync database: {e:?}");
            e
        })?;

        // Perform write operations here
        db.write("sync".to_string(), "0".to_string()).map_err(|e| {
            log::error!("Failed to write sync: {e:?}");
            e
        })?;
        db.write("sync_target".to_string(), "0".to_string())?;
        db.write("synced_da_block_height".to_string(), "0".to_string())?;

        Ok(db)
    }

    // Method to perform a read operation.
    fn read(&self, key: String) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // Serialize key to bytes
        let key_bytes = key.as_bytes();

        // Handle the None case.
        let value_vec = self.db.get(key_bytes)?.ok_or("No value found for the given key")?;

        Ok(String::from_utf8(value_vec)?)
    }

    // Method to perform a write operation.
    pub fn write(&self, key: String, value: String) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.db.put(key.as_bytes(), value.as_bytes())?)
    }

    fn _clear(&self) {
        // Create an iterator starting at the first key.
        let iter = self.db.iterator(IteratorMode::Start);

        // Iterate through all key-value pairs and print them.
        for key_val in iter.flatten() {
            if let Err(e) = self.db.delete(key_val.0) {
                log::error!("Failed to delete key: {e:?}");
            }
        }
    }

    fn display_all(&self) {
        // Create an iterator starting at the first key.
        let iter = self.db.iterator(IteratorMode::Start);

        // Iterate through all key-value pairs and print them.
        for (i, entry) in iter.enumerate() {
            match entry {
                Ok((key, value)) => {
                    log::info!("key: {:?} value: {:?}", key, value);
                }
                Err(err) => {
                    log::error!("There is no [{i}] key-value pair. - {err:?}")
                }
            }
        }
    }

    fn get_next_entry(&self, start_key: String) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
        // Serialize key to bytes. The process is 2-step since u64 does not directly support as_ref()
        let key_bytes = start_key.as_bytes();

        // Create an iterator starting from the key after the specified start_key.
        let mut iter = self.db.iterator(IteratorMode::From(key_bytes, rocksdb::Direction::Forward));
        iter.next().ok_or("No next entry found".into()).and_then(|next_entry| {
            let key_val = next_entry?;
            let key = String::from_utf8(key_val.0.into())?;
            let val = String::from_utf8(key_val.1.into())?;
            Ok((key, val))
        })
    }
}

// Convert bytes to base64
fn encode_data_to_base64(original: String) -> String {
    general_purpose::STANDARD.encode(original.as_bytes())
}

async fn send_request(
    da_auth: String,
    rpc_request: serde_json::Value,
    method: &str,
    da_host: String,
) -> Result<hyper::Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
    let request_builder = Request::builder()
        .method(method)
        .uri(da_host)
        .header("Authorization", da_auth.clone()) // Clone da_auth here
        .header("Content-Type", "application/json")
        .header("timeout", HeaderValue::from_static("100"))
        .body(Body::from(rpc_request.to_string()))?;

    let client = Client::new();
    let response = client.request(request_builder).await?;
    if response.status() != StatusCode::OK {
        return Err(format!("Request failed with status code: {}", response.status()).into());
    }

    Ok(response)
}

async fn parse_response(response: hyper::Response<Body>) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let response_body = body::to_bytes(response.into_body()).await?;
    let parsed_response: Value = serde_json::from_slice(&response_body)?;
    let res = parsed_response.get("result").ok_or_else(|| {
        Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, "Result not found in response"))
            as Box<dyn std::error::Error + Send + Sync>
    })?;

    Ok(res.to_string())
}

async fn submit_to_da(data: String) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let config_map = config_map();
    let da_host = config_map.get_string("host")?;
    let da_namespace = config_map.get_string("namespace")?;
    let da_auth_token = config_map.get_string("auth_token")?;
    let da_auth = format!("Bearer {}", da_auth_token);

    let encoded_data = encode_data_to_base64(data);

    let rpc_request = json!({
        "id": 1,
        "jsonrpc": "2.0",
        "method": "blob.Submit",
        "params": [
            [
                {
                    "namespace": da_namespace,
                    "data": encoded_data,
                }
            ]
        ],
    });

    let response = send_request(da_auth, rpc_request, "POST", da_host).await?;
    parse_response(response).await
}

async fn retrieve_from_da(data: String) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let config_map = config_map();
    let da_host = config_map.get_string("host")?;
    let da_namespace = config_map.get_string("namespace")?;
    let da_auth_token = config_map.get_string("auth_token")?;
    let da_auth = format!("Bearer {}", da_auth_token);

    let block_height: u64 = data.parse()?;

    let rpc_request = json!({
        "id": 1,
        "jsonrpc": "2.0",
        "method": "blob.GetAll",
        "params": [
            block_height,
            [
                da_namespace
            ]
        ],
    });

    let response = send_request(da_auth, rpc_request, "POST", da_host).await?;
    parse_response(response).await
}

pub async fn sync_with_da() {
    log::info!(
        "
        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&&####&&@@@@@@@#&@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
        @@@@@@@@@@@@@@@@@&P?777J5B&@@@@@#G5?!~^^::::::^^~!?5BJ!@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
        @@@@@@@@@@@@@@@@B: :7?7~^:^!J5?~::~7J5PGB####BGP5J7~  :75#@@@@@@@@@@@@@@@@@@@@@@@@@@@@
        @@@@@@@@@@@@@@@@7  G@@@@@B7  .  7B@@@@@@@@@@@@@@@@@Y.55!:.~Y#@@@@@@@@@@@@@@@@@@@@@@@@@
        @@@@@@@@@@@@@@@@J  J@@@B7..7G&#57~!Y#@@@@@@@@@@@@@Y Y@@@&G7..7B@@@@@@@@@@@@@@@@@@@@@@@
        @@@@@@@@@@@@@@@@#:  5#7 :Y#@@@@@@&G?!7P&@@@@@@@@@Y ?@@@@@@@&Y: 7B@@@@@@@@@@@@@@@@@@@@@
        @@@@@@@@@@@@@@@@@G. ...J&@@@@@@@@@@@&GJ!JB@@#PJJ7 ~@@@@@@@@@@&Y..Y@@@@@@@@@@@@@@@@@@@@
        @@@@@@@@@@@@@@@@@@5   !&@@@@@@@@@@@@@@@&P??7.     .?&@@@@@@@@@@#~ !&@@@@@@@@@@@@@@@@@@
        @@@@@@@@@@@@@@@@@&! .  ^G@@@@@@@@@@@@@&&@@J         Y@@@@@@@@@@@@7 ~&@@@@@@@@@@@@@@@@@
        @@@@@@@@@@@@@@@@@7 !G:   ?P5YYJJJJJYYYJJJY?         !YJYYY55PGBB#&7 !@@@@@@@@@@@@@@@@@
        @@@@@@@@@@@@@&BP?  ^!~~    !GBB###&&&&&@@@@G:     .P&##BBGP5YJ?7!!~  ?PB&@@@@@@@@@@@@@
        @@@@@@@@@&P?^::^  ?##&@5.   ~G@@@@@@@@@@@@@5. ?GBBJ?G@@@@@@@@@@@&&#J  ~^:~?P&@@@@@@@@@
        @@@@@@@&J: ~JG&B..B@@@@@#!    !G@@@@@@@@@@Y  !@@@@@#J7G@@@@@@@@@@@@#. B&BY! :J&@@@@@@@
        @@@@@@@7 .G@@@@P .#@@@@@@@5:    7B@@@@@@@Y  ^&@@@@@@@B?7G@@@@@@@@@@&: P@@@@B: 7@@@@@@@
        @@@@@@@J  ?G&@@G .#@@@@@@@@&?.   .7B@@@@Y  :#@@@@@@@@@@G7?#@@@@@@@@&: G@@&B?  J@@@@@@@
        @@@@@@@@P~  :!JY. G@@@@@@@@@@#7.   .7B@Y  .G@@@@@@@@@@@@@P!J&@@@@@@G  YY!:  ~P@@@@@@@@
        @@@@@@@@@@BY!:    .^~7?JY5PGGBB5~    .~   Y@&&&&&&&####BBBP^^YYJ7!~:    :!YB@@@@@@@@@@
        @@@@@@@@@@@@@&BPJ. ..          ..         :::::::::....          .. .JPB&@@@@@@@@@@@@@
        @@@@@@@@@@@@@@@@@Y :GBP5J?!~^:...                    ..:^^~7?J7 ?G: J@@@@@@@@@@@@@@@@@
        @@@@@@@@@@@@@@@@@@J :B@@@@@@@&&##BB7   .     :?PGGGBB##&&@@@@@@Y.: J@@@@@@@@@@@@@@@@@@
        @@@@@@@@@@@@@@@@@@@5. Y@@@@@@@@@@@5   :BG7:   .!5&@@@@@@@@@@@@@5  :#@@@@@@@@@@@@@@@@@@
        @@@@@@@@@@@@@@@@@@@@B~ ~G@@@@@@@@5   .G@@@#5!.   :7G&@@@@@@@@G~ !Y ^#@@@@@@@@@@@@@@@@@
        @@@@@@@@@@@@@@@@@@@@@@P^ ~5&@@@@Y    5@@@@@@@#Y~.   ^JG&@@&P~ ^5@@J ~&@@@@@@@@@@@@@@@@
        @@@@@@@@@@@@@@@@@@@@@@@&P!.:7P&5    J@@@@@@@@@@@#5!:   ^??:.!G@@@@&: 5@@@@@@@@@@@@@@@@
        @@@@@@@@@@@@@@@@@@@@@@@@@@#Y~::    !@@@@@@@@@@@@@@&B?.     :JPB#&&G. Y@@@@@@@@@@@@@@@@
        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@J     :~!7JJYYYYJJ7!^::^!JGGY7^.  .:: .?&@@@@@@@@@@@@@@@@
        @@@@@@@@@@@@@@@@@@@@@@@@@@@@P    :BG5Y?77!~~!77?Y5G#&@@@@@@&#BGP55G#@@@@@@@@@@@@@@@@@@
        @@@@@@@@@@@@@@@@@@@@@@@@@@@@G^..^B@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@&##&@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    "
    );
    let mut da_failed = false;
    let mut start_time = Instant::now();
    let mut previous_block_height: u64 = 0;
    'sync: loop {
        sleep(Duration::from_millis(3000)).await;

        // Initialize(if needed) or get a global instance of SyncDB that can be accessed from other modules.
        let db = match get_sync_db() {
            Ok(sync_db) => sync_db,
            Err(_) => continue 'sync,
        };

        let sync = match db.read("sync".to_string()) {
            Ok(sync) => sync,
            Err(e) => {
                log::error!("Failed to read sync: {e:?}");
                continue 'sync;
            }
        };
        let sync_target = match db.read("sync_target".to_string()) {
            Ok(sync_target) => sync_target,
            Err(e) => {
                log::error!("Failed to read sync_target: {e:?}");
                continue 'sync;
            }
        };

        log::info!("sync_target: {sync_target:?} and sync {sync:?}");
        if sync_target != sync {
            db.display_all();
            let (next_sync, next_txs) = match db.get_next_entry(sync) {
                Ok((next_sync, next_txs)) => (next_sync, next_txs),
                Err(e) => {
                    log::error!("Failed to get next entry: {e:?}");
                    continue 'sync;
                }
            };
            if !da_failed {
                let block_height = submit_to_da(next_txs).await;
                match block_height {
                    Ok(block_height) => {
                        log::info!(
                            "<------------------------------------DA BLOCK \
                             HEIGHT------------------------------------------>: {}",
                            block_height
                        );
                        match db.write("sync".to_string(), next_sync) {
                            Ok(_) => {}
                            Err(e) => {
                                log::error!("Failed to write sync: {e:?}");
                                continue 'sync;
                            }
                        }
                        match db.write("synced_da_block_height".to_string(), block_height) {
                            Ok(_) => {}
                            Err(e) => {
                                log::error!("Failed to write synced_da_block_height: {e:?}");
                                continue 'sync;
                            }
                        }
                    }
                    Err(err) => {
                        da_failed = true;
                        start_time = Instant::now();
                        match db.read("synced_da_block_height".to_string()) {
                            Ok(synced_da_block_height) => match synced_da_block_height.parse() {
                                Ok(height) => previous_block_height = height,
                                Err(e) => {
                                    log::error!("Failed to parse synced_da_block_height: {e:?}");
                                    continue 'sync;
                                }
                            },
                            Err(e) => {
                                log::error!("Failed to read synced_da_block_height: {e:?}");
                                continue 'sync;
                            }
                        }
                        log::error!("Failed to submit to DA with error: {:?}, trying to retrieve", err);
                    }
                }
            } else {
                previous_block_height += 1;
                match retrieve_from_da(previous_block_height.to_string()).await {
                    Ok(_) => {
                        match db.write("synced_da_block_height".to_string(), previous_block_height.to_string()) {
                            Ok(_) => {}
                            Err(e) => {
                                log::error!("Failed to write synced_da_block_height: {e:?}");
                                continue 'sync;
                            }
                        }
                        match db.write("sync".to_string(), next_sync) {
                            Ok(_) => {}
                            Err(e) => {
                                log::error!("Failed to write sync: {e:?}");
                                continue 'sync;
                            }
                        }
                        da_failed = false;
                    }
                    Err(e) => {
                        if start_time.elapsed().as_secs() > 24 * 60 * 60 {
                            panic!("Total time exceeded 24 hours");
                        };
                        log::error!("Failed to retrieve: {e:?}, incrementing the block_height");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use mc_config::init_config;

    use super::*;

    #[test]
    fn encoding() {
        assert_eq!(encode_data_to_base64(" ".to_string()), "IA==");
        assert_eq!(encode_data_to_base64("Bye World".to_string()), "QnllIFdvcmxk");
    }

    #[test]
    fn submission_to_da() {
        use tokio::runtime::Runtime;

        // Create the runtime
        let rt = match Runtime::new() {
            Ok(rt) => {
                println!("Successfully created runtime");
                rt
            }
            Err(err) => {
                eprintln!("Error in creating runtime: {}", err);
                return;
            }
        };
        let data_to_store = "Bye World".to_string();
        let encoded_data_to_store = encode_data_to_base64("Bye World".to_string());

        rt.block_on(async {
            let home_path = std::env::var("HOME").unwrap_or(std::env::var("USERPROFILE").unwrap_or(".".into()));
            init_config(&format!("{}/.madara", home_path));

            let block_height = submit_to_da(data_to_store).await;
            match block_height {
                Ok(block_height) => {
                    let retrieved_from_da = retrieve_from_da(block_height).await;
                    match retrieved_from_da {
                        Ok(encoded_data_from_da) => {
                            assert_eq!(encoded_data_to_store, encoded_data_from_da);
                        }
                        Err(err) => eprintln!("Failed to retrieve from DA with error: {:?}", err),
                    }
                }
                Err(err) => eprintln!("Failed to store to DA with error: {:?}", err),
            }
        });
    }
}
