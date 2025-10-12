// Substrate chain querying for ISMP messages
// Supports: Bifrost, Polkadot Asset Hub

use serde_json::Value;
use std::error::Error;

/// Substrate chain configuration
pub struct SubstrateChain {
    pub name: &'static str,
    pub rpc_url: &'static str,
    pub chain_id: &'static str,
}

/// Available Substrate chains
pub const SUBSTRATE_CHAINS: &[SubstrateChain] = &[
    SubstrateChain {
        name: "bifrost",
        rpc_url: "wss://bifrost-polkadot.api.onfinality.io/public-ws",
        chain_id: "POLKADOT-2030",
    },
    SubstrateChain {
        name: "polkadot_asset_hub",
        rpc_url: "wss://polkadot-asset-hub-rpc.polkadot.io",
        chain_id: "POLKADOT-1000",
    },
];

/// Source transaction data from Substrate
#[derive(Debug, Clone)]
pub struct SubstrateSourceTxData {
    pub chain: String,
    pub tx_hash: String,
    pub block_number: u64,
    pub timestamp: i64,
    pub extrinsic_index: u32,
}

/// Find a commitment on Substrate chains
pub async fn find_substrate_commitment(
    commitment: &str,
    source_chain: Option<&str>,
) -> Result<Option<SubstrateSourceTxData>, Box<dyn Error>> {
    let chains = if let Some(chain) = source_chain {
        SUBSTRATE_CHAINS
            .iter()
            .filter(|c| c.name == chain)
            .collect::<Vec<_>>()
    } else {
        SUBSTRATE_CHAINS.iter().collect::<Vec<_>>()
    };

    for chain in chains {
        println!("   Searching {}...", chain.name);
        
        match scan_substrate_chain(chain, commitment).await {
            Ok(Some(data)) => {
                println!("   ✅ Found on {}!", chain.name);
                return Ok(Some(data));
            }
            Ok(None) => {
                // Not found, continue to next chain
            }
            Err(e) => {
                println!("   ⚠️  Error scanning {}: {}", chain.name, e);
            }
        }
    }

    Ok(None)
}

/// Scan a specific Substrate chain for a commitment
async fn scan_substrate_chain(
    chain: &SubstrateChain,
    commitment: &str,
) -> Result<Option<SubstrateSourceTxData>, Box<dyn Error>> {
    // For now, use RPC calls to query recent blocks
    // In production, you'd use subxt to subscribe to events
    
    // Get the current block number first
    let client = reqwest::Client::new();
    
    // Convert WSS to HTTPS for REST API (many Substrate nodes support both)
    let http_url = chain.rpc_url.replace("wss://", "https://").replace("ws://", "http://");
    let http_url = if http_url.ends_with("/public-ws") {
        http_url.replace("/public-ws", "")
    } else {
        http_url
    };
    
    // Get finalized head
    let response = client
        .post(&http_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "chain_getFinalizedHead",
            "params": [],
            "id": 1
        }))
        .send()
        .await?;
    
    if !response.status().is_success() {
        return Err(format!("HTTP error: {}", response.status()).into());
    }
    
    let result: Value = response.json().await?;
    let finalized_hash = result["result"]
        .as_str()
        .ok_or("No finalized head found")?;
    
    // Get the block number for this hash
    let response = client
        .post(&http_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "chain_getBlock",
            "params": [finalized_hash],
            "id": 1
        }))
        .send()
        .await?;
    
    let block_data: Value = response.json().await?;
    let block_number = block_data["result"]["block"]["header"]["number"]
        .as_str()
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0);
    
    if block_number == 0 {
        return Err("Could not determine current block number".into());
    }
    
    println!("      Current block: {}", block_number);
    println!("      Searching last 7200 blocks (~24 hours)");
    
    // Search last 7200 blocks (approximately 24 hours for Substrate chains with 12s block time)
    let search_depth = 7200;
    let start_block = block_number.saturating_sub(search_depth);
    
    // For efficiency, we'll search in chunks of 100 blocks
    let chunk_size = 100;
    let mut current_block = block_number;
    
    while current_block > start_block {
        let chunk_start = current_block.saturating_sub(chunk_size);
        
        // Get block hash for this range
        for block_num in (chunk_start..current_block).rev() {
            // Get block hash
            let hash_response = client
                .post(&http_url)
                .json(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "chain_getBlockHash",
                    "params": [block_num],
                    "id": 1
                }))
                .send()
                .await?;
            
            let hash_result: Value = hash_response.json().await?;
            if let Some(block_hash) = hash_result["result"].as_str() {
                // Check events in this block
                if let Some(tx_data) = check_substrate_block_for_commitment(
                    &client,
                    &http_url,
                    block_hash,
                    block_num,
                    commitment,
                    chain.name,
                )
                .await?
                {
                    return Ok(Some(tx_data));
                }
            }
        }
        
        current_block = chunk_start;
        
        // Safety: don't search forever
        if current_block <= start_block {
            break;
        }
    }
    
    Ok(None)
}

/// Check a specific Substrate block for ISMP PostRequest events with matching commitment
async fn check_substrate_block_for_commitment(
    client: &reqwest::Client,
    rpc_url: &str,
    block_hash: &str,
    block_number: u64,
    commitment: &str,
    chain_name: &str,
) -> Result<Option<SubstrateSourceTxData>, Box<dyn Error>> {
    // Get events for this block using state_getStorage
    // The events are stored at System.Events storage key
    // For simplicity, we'll use system_events query
    
    let response = client
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "state_getStorage",
            "params": ["0x26aa394eea5630e07c48ae0c9558cef780d41e5e16056765bc8461851072c9d7", block_hash],
            "id": 1
        }))
        .send()
        .await?;
    
    let events_result: Value = response.json().await?;
    
    if let Some(events_hex) = events_result["result"].as_str() {
        // Decode events (simplified - in production use SCALE codec)
        // Look for ISMP PostRequest events containing our commitment
        
        // For now, we'll do a simple hex search
        let events_data = events_hex.trim_start_matches("0x");
        let commitment_hex = commitment.trim_start_matches("0x");
        
        if events_data.contains(commitment_hex) {
            println!("      🎯 Found commitment in block {}!", block_number);
            
            // Get block timestamp
            let timestamp = chrono::Utc::now().timestamp(); // Simplified
            
            // Get extrinsics to find the transaction hash
            let block_response = client
                .post(rpc_url)
                .json(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "chain_getBlock",
                    "params": [block_hash],
                    "id": 1
                }))
                .send()
                .await?;
            
            let block_data: Value = block_response.json().await?;
            
            // Get first extrinsic hash (simplified)
            let tx_hash = if let Some(extrinsics) = block_data["result"]["block"]["extrinsics"].as_array() {
                if let Some(first_ext) = extrinsics.first() {
                    // Compute hash of extrinsic (simplified - just use block hash for now)
                    block_hash.to_string()
                } else {
                    block_hash.to_string()
                }
            } else {
                block_hash.to_string()
            };
            
            return Ok(Some(SubstrateSourceTxData {
                chain: chain_name.to_string(),
                tx_hash,
                block_number,
                timestamp,
                extrinsic_index: 0,
            }));
        }
    }
    
    Ok(None)
}

/// Parse Substrate ISMP event to extract message details
pub async fn parse_substrate_post_request(
    source_data: &SubstrateSourceTxData,
) -> Result<SubstratePostRequestData, Box<dyn Error>> {
    // This would normally use SCALE codec to decode the event
    // For now, return placeholder data
    
    Ok(SubstratePostRequestData {
        commitment: "".to_string(), // Will be filled from search
        dest_state_machine: "UNKNOWN".to_string(),
        amount: 0,
        source_address: "0x0000000000000000000000000000000000000000".to_string(),
    })
}

/// Parsed PostRequest data from Substrate
#[derive(Debug, Clone)]
pub struct SubstratePostRequestData {
    pub commitment: String,
    pub dest_state_machine: String,
    pub amount: u128,
    pub source_address: String,
}

