use std::path::Path;
use std::time::Instant;

use base64::engine::general_purpose;
use base64::Engine as _;
use hyper::header::HeaderValue;
use hyper::{body, Body, Client, Request, StatusCode};
use lazy_static::lazy_static;
use mc_config::config_map;
use rocksdb::{Error, IteratorMode, DB};
use serde_json::{json, Value};
use tokio;
use tokio::time::{sleep, Duration};

// Import Lazy from the lazy_static crate
// Import the Error type from rocksdb crate
// Define a struct to hold the DB instance.
pub struct SyncDB {
    db: DB,
}

impl SyncDB {
    // Constructor to open the database.
    fn open() -> Result<SyncDB, Error> {
        let path = Path::new("epool");
        let db = DB::open_default(&path)?;
        Ok(SyncDB { db })
    }

    // Method to perform a read operation.
    fn read(&self, key: String) -> String {
        // Serialize key to bytes
        let key_bytes = key.as_bytes();

        // Use the 'get' method to retrieve the value.
        let result_of_get = self.db.get(key_bytes);

        let option = match result_of_get {
            Ok(val) => val,
            Err(err) => {
                eprintln!("Failed to read from DB: {:?}", err);
                None
            }
        };

        // Handle the None case.
        let value_vec = match option {
            Some(val) => val,
            None => Vec::new(),
        };
        let value = String::from_utf8(value_vec).unwrap();

        value
    }

    // Method to perform a write operation.
    pub fn write(&self, key: String, value: String) {
        // Serialize key to bytes
        let key_bytes = key.as_bytes();

        // Serialize value for storing in DB
        let value_bytes = value.as_bytes();
        let result_of_put = self.db.put(key_bytes, value_bytes);
        match result_of_put {
            Ok(()) => {}
            Err(err) => eprintln!("Failed to write to DB: {:?}", err),
        };
    }

    fn clear(&self) {
        // Create an iterator starting at the first key.
        let iter = self.db.iterator(IteratorMode::Start);

        // Iterate through all key-value pairs and print them.
        for result in iter {
            let deleted = self.db.delete(result.unwrap().0);
            match deleted {
                Ok(()) => {}
                Err(err) => {
                    eprintln!("Failed to delete, error: {:?}", err);
                }
            }
        }
    }

    fn display_all(&self) {
        // Create an iterator starting at the first key.
        let iter = self.db.iterator(IteratorMode::Start);

        // Iterate through all key-value pairs and print them.
        for result in iter {
            match result {
                Ok((key, value)) => {
                    println!("key: {:?} value: {:?}", key, value);
                }
                Err(err) => {
                    eprintln!("There is an error! {:?}", err);
                }
            }
        }
    }

    fn get_next_entry(&self, start_key: String) -> (String, String) {
        // Serialize key to bytes. The process is 2-step since u64 does not directly support as_ref()
        let key_bytes = start_key.as_bytes();

        // Create an iterator starting from the key after the specified start_key.
        let mut iter = self.db.iterator(IteratorMode::From(key_bytes, rocksdb::Direction::Forward));

        // Iterate to get the next entry.
        let key_vec = iter.next().unwrap().unwrap().0.into_vec();
        let value_vec = iter.next().unwrap().unwrap().1.into_vec();
        let key = String::from_utf8(key_vec).unwrap();
        let value = String::from_utf8(value_vec).unwrap();
        return (key, value);
    }
}

// Create a global instance of SyncDB that can be accessed from other modules.
lazy_static! {
    pub static ref SYNC_DB: SyncDB = {
        let db = SyncDB::open().unwrap_or_else(|err| {
            eprintln!("Failed to open database: {:?}", err);
            std::process::exit(1); // Exit the program on error
        });

        db.clear();

        // Perform write operations here
        db.write("sync".to_string(), "0".to_string());
        db.write("sync_target".to_string(), "0".to_string());
        db.write("synced_da_block_height".to_string(),"0".to_string());

        db // Return the initialized SyncDB
    };
}

fn encode_data_to_base64(original: String) -> String {
    // Convert string to bytes
    let bytes = original.as_bytes();
    // Convert bytes to base64
    let base64_str: String = general_purpose::STANDARD.encode(&bytes);
    base64_str
}

async fn submit_to_da(data: String) -> Result<String, Box<dyn std::error::Error>> {
    let config_map = config_map();
    let da_host = config_map.get_string("host").unwrap();
    let da_namespace = config_map.get_string("namespace").unwrap();
    let da_auth_token = config_map.get_string("auth_token").unwrap();
    let da_auth = format!("Bearer {}", da_auth_token);

    let encoded_data = encode_data_to_base64(data);

    let client = Client::new();

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

    // Create a mutable request builder
    let request_builder = Request::builder()
        .method("POST")
        .uri(da_host)
        .header("Authorization", da_auth.clone()) // Clone da_auth here
        .header("Content-Type", "application/json")
        .header("timeout", HeaderValue::from_static("100"))
        .body(Body::from(rpc_request.to_string()))?;

    // Send the request and await the response
    let response = client.request(request_builder).await?;

    if response.status() != StatusCode::OK {
        return Err(format!("Request failed with status code: {}", response.status()).into());
    }

    let response_body = body::to_bytes(response.into_body()).await?;
    let parsed: Value = serde_json::from_slice(&response_body)?;

    if let Some(result_value) = parsed.get("result") {
        Ok(result_value.to_string())
    } else {
        Err("Result not found in response".into()) // Or create a custom error type
    }
}

async fn retrieve_from_da(data: String) -> Result<String, Box<dyn std::error::Error>> {
    let config_map = config_map();
    let da_host = config_map.get_string("host").unwrap();
    let da_namespace = config_map.get_string("namespace").unwrap();
    let da_auth_token = config_map.get_string("auth_token").unwrap();
    let da_auth = format!("Bearer {}", da_auth_token);

    let block_height: u64 = data.parse().unwrap();

    let client = Client::new();

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

    // Create a mutable request builder
    let request_builder = Request::builder()
        .method("POST")
        .uri(da_host)
        .header("Authorization", da_auth.clone()) // Clone da_auth here
        .header("Content-Type", "application/json")
        .header("timeout", HeaderValue::from_static("100"))
        .body(Body::from(rpc_request.to_string()))?;

    // Send the request and await the response
    let response = client.request(request_builder).await?;

    if response.status() != StatusCode::OK {
        return Err(format!("Request failed with status code: {}", response.status()).into());
    }

    let response_body = body::to_bytes(response.into_body()).await?;
    let parsed: Value = serde_json::from_slice(&response_body)?;

    if let Some(result_value) = parsed.get("result") {
        Ok(result_value.to_string())
    } else {
        Err("Result not found in response".into()) // Or create a custom error type
    }
}
pub async fn sync_with_da() {
    println!(
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
    loop {
        sleep(Duration::from_millis(3000)).await;
        let sync = SYNC_DB.read("sync".to_string());
        let sync_target = SYNC_DB.read("sync_target".to_string());

        println!("sync_target: {:?} and sync {:?}", sync_target, sync);
        if sync_target != sync {
            SYNC_DB.display_all();
            let (next_sync, next_txs) = SYNC_DB.get_next_entry(sync);
            if !da_failed {
                let block_height = submit_to_da(next_txs).await;
                match block_height {
                    Ok(block_height) => {
                        println!(
                            "<------------------------------------DA BLOCK \
                             HEIGHT------------------------------------------>: {}",
                            block_height
                        );
                        SYNC_DB.write("sync".to_string(), next_sync);
                        SYNC_DB.write("synced_da_block_height".to_string(), block_height);
                    }
                    Err(err) => {
                        da_failed = true;
                        start_time = Instant::now();
                        previous_block_height = SYNC_DB.read("synced_da_block_height".to_string()).parse().unwrap();
                        eprintln!("Failed to submit to DA with error: {:?}, trying to retrieve", err);
                    }
                }
            } else {
                previous_block_height += 1;
                let retrieved_from_da = retrieve_from_da(previous_block_height.to_string()).await;
                match retrieved_from_da {
                    Ok(_) => {
                        SYNC_DB.write("synced_da_block_height".to_string(), previous_block_height.to_string());
                        SYNC_DB.write("sync".to_string(), next_sync);
                        da_failed = false;
                    }
                    Err(err) => {
                        if start_time.elapsed().as_secs() > 24 * 60 * 60 {
                            panic!("Total time exceeded 24 hours");
                        };
                        eprintln!("Failed to retrieve: {:?}, incrementing the block_height", err);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
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
