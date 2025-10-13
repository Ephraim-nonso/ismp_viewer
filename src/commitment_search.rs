// ============================================================================
// Commitment Search Module
// Implements commitment-based message tracking across multiple blockchains
// ============================================================================

use chrono::{DateTime, Utc, Duration};
use ethers::prelude::*;
use hex;
use std::str::FromStr;

// Import from main backend
use super::{CrossChainMessage, MessageStatus, COMMITMENT_CACHE, get_24h_block_range};
use super::substrate_search::{find_substrate_commitment, SubstrateSourceTxData};

// ============================================================================
// Helper Structures
// ============================================================================

#[derive(Debug, Clone)]
pub struct SourceTxData {
    pub chain: String,
    pub tx_hash: String,
    pub from_address: String,
    pub timestamp: DateTime<Utc>,
    pub log_data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PostRequestData {
    pub commitment: String,
    pub amount: String,
    pub dest_state_machine: String,
    pub timeout: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct DeliveryStatus {
    pub status: MessageStatus,
    pub tx_hash: Option<String>,
    pub timestamp: Option<DateTime<Utc>>,
    pub relayer: Option<String>,
}

impl DeliveryStatus {
    pub fn pending() -> Self {
        DeliveryStatus {
            status: MessageStatus::Pending,
            tx_hash: None,
            timestamp: None,
            relayer: None,
        }
    }
}

// ============================================================================
// Main Query Function
// ============================================================================

pub async fn query_by_commitment(commitment: &str, source_chain: Option<&str>) -> Result<CrossChainMessage, String> {
    println!("🔍 Searching for commitment: {}", commitment);
    if let Some(chain) = source_chain {
        println!("   🎯 Source chain provided: {} (faster search!)", chain);
    }
    
    // 1. Check cache
    if let Ok(cache) = COMMITMENT_CACHE.lock() {
        if let Some(cached_msg) = cache.get(commitment) {
            println!("✅ Found in cache!");
            return Ok(cached_msg.clone());
        }
    }
    
    // 2. Search for source transaction (specific chain if provided, all chains if not)
    let source_data = find_source_transaction(commitment, source_chain).await?;
    
    // 3. Parse PostRequest event
    let post_request = parse_post_request_event(&source_data)?;
    
    // 4. Check delivery status on destination
    let dest_chain_name = map_state_machine_to_chain(&post_request.dest_state_machine);
    let delivery_status = check_delivery_status(&post_request.dest_state_machine, commitment).await?;
    
    // 5. Build message with metrics
    let transit_time = calculate_transit_time(&source_data.timestamp, &delivery_status.timestamp);
    let relayer_fee = calculate_relayer_fee(&post_request.amount);
    
    let message = CrossChainMessage {
        commitment: commitment.to_string(),
        source_chain: source_data.chain.clone(),
        source_tx_hash: source_data.tx_hash.clone(),
        source_address: source_data.from_address.clone(),
        source_timestamp: source_data.timestamp,
        dest_chain: dest_chain_name,
        dest_tx_hash: delivery_status.tx_hash.clone(),
        dest_address: "TBD".to_string(), // TODO: Parse from event
        dest_timestamp: delivery_status.timestamp,
        request_type: "PostRequest".to_string(),
        status: delivery_status.status.clone(),
        amount: Some(post_request.amount.clone()),
        transit_time,
        relayer: delivery_status.relayer.clone(),
        relayer_fee,
        nonce: 0, // TODO: Parse from event
        timeout_timestamp: post_request.timeout,
    };
    
    // 6. Cache result
    if let Ok(mut cache) = COMMITMENT_CACHE.lock() {
        cache.insert(commitment.to_string(), message.clone());
    }
    
    Ok(message)
}

// ============================================================================
// Find Source Transaction
// ============================================================================

async fn find_source_transaction(commitment: &str, source_chain: Option<&str>) -> Result<SourceTxData, String> {
    // If source chain is Substrate (Bifrost or Polkadot Asset Hub), search Substrate first
    let substrate_chains = vec!["bifrost", "polkadot_asset_hub"];
    let is_substrate_source = source_chain.map(|s| substrate_chains.contains(&s)).unwrap_or(false);
    
    // Try Substrate chains first if specified or if searching all chains
    if is_substrate_source || source_chain.is_none() {
        match find_substrate_commitment(commitment, source_chain).await {
            Ok(Some(substrate_data)) => {
                // Convert SubstrateSourceTxData to SourceTxData
                return Ok(convert_substrate_to_source_tx_data(substrate_data));
            },
            Ok(None) => {
                // Not found on Substrate, continue to EVM if searching all chains
                if is_substrate_source {
                    // If user specified Substrate but we didn't find it, return error
                    return Err(format!("Commitment {} not found on {} (searched last ~14 days for Substrate, ~3-4 hours for EVM)", 
                        commitment, source_chain.unwrap()));
                }
            },
            Err(e) => {
                println!("   ⚠️  Substrate search error: {}", e);
                // Continue to EVM chains
            }
        }
    }
    
    // Search EVM chains
    let evm_chains = if let Some(source) = source_chain {
        // If source is provided and not Substrate, only search that chain!
        if substrate_chains.contains(&source) {
            vec![] // Already searched above
        } else {
            vec![source]
        }
    } else {
        // Otherwise search all EVM chains
        vec![
            "ethereum", "arbitrum", "optimism", "base", "bsc",
            "gnosis", "scroll", "soneium", "polygon", "unichain"
        ]
    };
    
    for chain in evm_chains {
        println!("   Searching {}...", chain);
        
        match scan_chain_for_commitment(chain, commitment).await {
            Ok(Some(tx_data)) => {
                println!("   ✅ Found on {}!", chain);
                return Ok(tx_data);
            },
            Ok(None) => continue,
            Err(e) => {
                println!("   ⚠️  Error scanning {}: {}", chain, e);
                continue;
            }
        }
    }
    
    if let Some(source) = source_chain {
        Err(format!("Commitment {} not found on {} (searched last ~3-4 hours)", commitment, source))
    } else {
        Err(format!("Commitment {} not found on any supported chain", commitment))
    }
}

// Convert Substrate source data to unified SourceTxData
fn convert_substrate_to_source_tx_data(substrate_data: SubstrateSourceTxData) -> SourceTxData {
    SourceTxData {
        chain: substrate_data.chain,
        tx_hash: substrate_data.tx_hash,
        from_address: "Substrate".to_string(), // Substrate doesn't use Ethereum-style addresses
        timestamp: DateTime::<Utc>::from_timestamp(substrate_data.timestamp, 0)
            .unwrap_or_else(|| Utc::now()),
        log_data: vec![], // We'll populate this from the commitment
    }
}

// ============================================================================
// Scan Chain for Commitment
// ============================================================================

const EVENT_POST_REQUEST: &str = "0x07d0e7e31f460a5025fe4913407d890186747d91632fe9d1ef4666cc5e01d02d";

async fn scan_chain_for_commitment(
    chain: &str,
    commitment: &str
) -> Result<Option<SourceTxData>, String> {
    let rpc_url = get_rpc_url(chain);
    let provider = Provider::<Http>::try_from(rpc_url)
        .map_err(|e| format!("Failed to create provider: {}", e))?;
    
    // Get current block
    let current_block = provider.get_block_number().await
        .map_err(|e| format!("Failed to get block number: {}", e))?;
    
    // Use chunked scanning to search further back without hitting RPC limits
    let chunk_size = match chain {
        "ethereum" => 1000,   // Llamarpc max
        "bsc" => 5000,        // BSC limit
        _ => 10000,           // Most chains can handle 10k
    };
    
    // Search last 24 hours in chunks (about 20-30 chunks total)
    let total_blocks_to_search = get_24h_block_range(chain) * 8; // 8x = more coverage
    let num_chunks = (total_blocks_to_search / chunk_size).min(30); // Max 30 chunks
    
    println!("      Searching {} chunks of {} blocks ({} total blocks)", num_chunks, chunk_size, num_chunks * chunk_size);
    
    let topic0 = H256::from_str(EVENT_POST_REQUEST)
        .map_err(|e| format!("Invalid event signature: {}", e))?;
    
    // Search in chunks from most recent backwards
    for i in 0..num_chunks {
        let to_block = current_block.saturating_sub(U64::from(i * chunk_size));
        let from_block = to_block.saturating_sub(U64::from(chunk_size));
        
        if i == 0 || i % 5 == 0 {
            println!("      Chunk {}/{}: blocks {} to {}", i+1, num_chunks, from_block, to_block);
        }
        
        // Some chains (BSC, Unichain) require specifying contract address
        let filter = if chain == "bsc" || chain == "unichain" {
            // BSC and Unichain require address filter
            let handler_address = if chain == "bsc" {
                "0xFd413e3AFe560182C4471F4d143A96d3e259B6dE" // BSC Handler
            } else {
                "0x85F82D70ceED45ca0D1b154C297946BabCf4d344" // Unichain Handler
            };
            
            Filter::new()
                .from_block(from_block)
                .to_block(to_block)
                .address(vec![handler_address.parse().unwrap()])
                .topic0(vec![topic0])
        } else {
            Filter::new()
                .from_block(from_block)
                .to_block(to_block)
                .topic0(vec![topic0])
        };
        
        let logs = match provider.get_logs(&filter).await {
            Ok(logs) => logs,
            Err(e) => {
                if i == 0 {
                    println!("      ⚠️  Error in first chunk: {}", e);
                }
                continue; // Skip this chunk, try next
            }
        };
        
        if !logs.is_empty() && i % 5 == 0 {
            println!("      Found {} events in chunk {}", logs.len(), i+1);
        }
        
        // Search for matching commitment in this chunk's events
        let commitment_bytes = hex::decode(&commitment[2..])
            .map_err(|e| format!("Invalid commitment hex: {}", e))?;
        
        for log in logs {
            let mut found = false;
            
            // Check if commitment is in indexed topics (some events index the commitment)
            for topic in &log.topics {
                if topic.as_bytes() == commitment_bytes.as_slice() {
                    println!("      🎯 Match found in topics (indexed)!");
                    found = true;
                    break;
                }
            }
            
            // Check if data contains our commitment (at offset 96 bytes, chunk [3])
            if !found {
                let data = log.data.to_vec();
                if data.len() >= 128 {
                    let chunk_3 = &data[96..128]; // commitment is in chunk [3]
                    if chunk_3 == commitment_bytes.as_slice() {
                        println!("      🎯 Match found in data field!");
                        found = true;
                    }
                }
            }
            
            if found {
                // Get full transaction details
                let data = log.data.to_vec();
                let tx_hash = log.transaction_hash.ok_or("No tx hash")?;
                let tx = provider.get_transaction(tx_hash).await
                    .map_err(|e| format!("Failed to get tx: {}", e))?
                    .ok_or("Tx not found")?;
                let receipt = provider.get_transaction_receipt(tx_hash).await
                    .map_err(|e| format!("Failed to get receipt: {}", e))?
                    .ok_or("Receipt not found")?;
                let block_num = receipt.block_number.ok_or("No block number")?;
                let block = provider.get_block(block_num).await
                    .map_err(|e| format!("Failed to get block: {}", e))?
                    .ok_or("Block not found")?;
                
                return Ok(Some(SourceTxData {
                    chain: chain.to_string(),
                    tx_hash: format!("0x{}", hex::encode(tx_hash.as_bytes())),
                    from_address: format!("0x{}", hex::encode(tx.from.as_bytes())),
                    timestamp: DateTime::from_timestamp(block.timestamp.as_u64() as i64, 0)
                        .unwrap_or_else(|| Utc::now()),
                    log_data: data,
                }));
            }
        }
    }
    
    // Not found in any chunk
    Ok(None)
}

// ============================================================================
// Parse PostRequest Event
// ============================================================================

fn parse_post_request_event(source_data: &SourceTxData) -> Result<PostRequestData, String> {
    // Event data structure:
    // [0-31]: internal_hash
    // [32-63]: offset pointer
    // [64-95]: amount
    // [96-127]: commitment ✅
    // [128-159]: reserved
    // [160-191]: dest_length
    // [192+]: dest_state_machine string
    
    let data = &source_data.log_data;
    if data.len() < 224 {
        return Err(format!("Event data too short: {} bytes", data.len()));
    }
    
    // Extract amount (bytes 64-95)
    let amount_bytes = &data[64..96];
    let amount = U256::from_big_endian(amount_bytes);
    let amount_str = format_amount(amount);
    
    // Extract commitment (bytes 96-127)
    let commitment = format!("0x{}", hex::encode(&data[96..128]));
    
    // Extract destination length (bytes 160-191)
    let dest_len = u32::from_be_bytes([
        data[188], data[189], data[190], data[191]
    ]) as usize;
    
    if data.len() < 192 + dest_len {
        return Err(format!("Dest string truncated: need {} bytes", 192 + dest_len));
    }
    
    // Extract destination state machine (bytes 192+)
    let dest_bytes = &data[192..192 + dest_len];
    let dest_state_machine = String::from_utf8(dest_bytes.to_vec())
        .map_err(|e| format!("Invalid UTF-8 in dest: {}", e))?;
    
    Ok(PostRequestData {
        commitment,
        amount: amount_str,
        dest_state_machine,
        timeout: None,
    })
}

// ============================================================================
// Check Delivery Status
// ============================================================================

async fn check_delivery_status(
    dest_state_machine: &str,
    commitment: &str
) -> Result<DeliveryStatus, String> {
    match dest_state_machine {
        "POLKADOT-2030" => check_bifrost_delivery(commitment).await,
        "POLKADOT-1000" => check_asset_hub_delivery(commitment).await,
        _ if dest_state_machine.starts_with("EVM-") => {
            // TODO: Implement EVM destination checking
            Ok(DeliveryStatus::pending())
        },
        _ => Ok(DeliveryStatus::pending()),
    }
}

async fn check_bifrost_delivery(_commitment: &str) -> Result<DeliveryStatus, String> {
    // TODO: Implement using subxt
    // For now, return pending
    Ok(DeliveryStatus::pending())
}

async fn check_asset_hub_delivery(_commitment: &str) -> Result<DeliveryStatus, String> {
    // TODO: Implement using subxt
    Ok(DeliveryStatus::pending())
}

// ============================================================================
// Helper Functions
// ============================================================================

fn get_rpc_url(chain: &str) -> &'static str {
    match chain {
        "ethereum" => "https://eth.llamarpc.com",
        "arbitrum" => "https://arb1.arbitrum.io/rpc",
        "optimism" => "https://mainnet.optimism.io",
        "base" => "https://mainnet.base.org",
        "bsc" => "https://bsc-rpc.publicnode.com",
        "gnosis" => "https://rpc.gnosischain.com",
        "scroll" => "https://rpc.scroll.io",
        "soneium" => "https://rpc.soneium.org",
        "polygon" => "https://polygon-rpc.com",
        "unichain" => "https://unichain-rpc.publicnode.com",
        _ => "https://eth.llamarpc.com", // fallback
    }
}

fn map_state_machine_to_chain(state_machine: &str) -> String {
    match state_machine {
        "POLKADOT-1000" => "Polkadot Asset Hub".to_string(),
        "POLKADOT-2030" => "Bifrost".to_string(),
        "EVM-1" => "Ethereum".to_string(),
        "EVM-42161" => "Arbitrum".to_string(),
        "EVM-10" => "Optimism".to_string(),
        "EVM-8453" => "Base".to_string(),
        "EVM-56" => "BSC".to_string(),
        "EVM-100" => "Gnosis Chain".to_string(),
        "EVM-534352" => "Scroll".to_string(),
        "EVM-1868" => "Soneium".to_string(),
        "EVM-137" => "Polygon".to_string(),
        "EVM-130" => "Unichain".to_string(),
        _ if state_machine.starts_with("POLKADOT-") => {
            let id = &state_machine[9..];
            format!("Polkadot Parachain {}", id)
        },
        _ if state_machine.starts_with("EVM-") => {
            let id = &state_machine[4..];
            format!("EVM Chain {}", id)
        },
        _ => state_machine.to_string(),
    }
}

fn format_amount(amount: U256) -> String {
    // Convert from wei to readable format
    // Assuming 18 decimals (adjust if needed)
    let divisor = U256::from(10).pow(U256::from(18));
    let whole = amount / divisor;
    let remainder = amount % divisor;
    
    // Get first 2 decimal places
    let decimals = (remainder * U256::from(100)) / divisor;
    
    format!("{}.{:02}", whole, decimals.as_u64())
}

fn calculate_transit_time(
    source_time: &DateTime<Utc>,
    dest_time: &Option<DateTime<Utc>>
) -> Option<String> {
    if let Some(dest) = dest_time {
        let duration = dest.signed_duration_since(*source_time);
        Some(format_duration(duration))
    } else {
        None
    }
}

fn format_duration(duration: Duration) -> String {
    let seconds = duration.num_seconds();
    if seconds < 0 {
        return "0s".to_string();
    }
    
    if seconds < 60 {
        format!("{}s", seconds)
    } else if seconds < 3600 {
        format!("{}m {}s", seconds / 60, seconds % 60)
    } else {
        format!("{}h {}m", seconds / 3600, (seconds % 3600) / 60)
    }
}

fn calculate_relayer_fee(amount: &str) -> Option<String> {
    // Parse amount and calculate ~0.1% fee
    if let Ok(amt) = amount.parse::<f64>() {
        let fee = amt * 0.001;
        Some(format!("{:.2}", fee))
    } else {
        None
    }
}

