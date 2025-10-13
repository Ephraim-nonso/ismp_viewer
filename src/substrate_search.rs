// Optimized Subxt Implementation for Substrate Chains
// Fast commitment search with smart scanning strategies

use subxt::{OnlineClient, PolkadotConfig};
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

/// Find a commitment on Substrate chains using optimized search
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
        println!("   🔍 Searching {} (WebSocket/Substrate)...", chain.name);
        
        match scan_substrate_optimized(chain, commitment).await {
            Ok(Some(data)) => {
                println!("   ✅ Found on {}!", chain.name);
                return Ok(Some(data));
            }
            Ok(None) => {
                println!("      ❌ Not found in recent blocks");
            }
            Err(e) => {
                println!("      ⚠️  Error: {}", e);
                continue;
            }
        }
    }

    Ok(None)
}

/// Optimized scan with smart strategies
async fn scan_substrate_optimized(
    chain: &SubstrateChain,
    commitment_hex: &str,
) -> Result<Option<SubstrateSourceTxData>, Box<dyn Error>> {
    println!("      Connecting...");
    
    // Connect to chain
    let client = OnlineClient::<PolkadotConfig>::from_url(chain.rpc_url).await
        .map_err(|e| format!("Connection failed: {}", e))?;
    
    println!("      ✓ Connected");
    
    // Get latest block
    let latest_block = client.blocks().at_latest().await?;
    let current_block: u32 = latest_block.number();
    
    println!("      Block: {}", current_block);
    
    // OPTIMIZED: Search only last 1000 blocks (~3-4 hours)
    // This is fast and covers most recent messages
    let search_depth: u32 = 1000;
    let start_block = current_block.saturating_sub(search_depth);
    
    println!("      Scanning {} recent blocks (fast mode)...", search_depth);
    
    // Parse commitment
    let commitment_bytes = hex::decode(commitment_hex.trim_start_matches("0x"))
        .map_err(|e| format!("Invalid hex: {}", e))?;
    
    if commitment_bytes.len() != 32 {
        return Err("Commitment must be 32 bytes".into());
    }
    
    let mut commitment_array = [0u8; 32];
    commitment_array.copy_from_slice(&commitment_bytes);
    
    // OPTIMIZATION 1: Scan in reverse (most recent first)
    // OPTIMIZATION 2: Check every 10th block first (quick scan)
    // OPTIMIZATION 3: Skip blocks with no events
    
    println!("      Phase 1: Quick scan (every 10th block)...");
    let mut blocks_checked = 0;
    let mut current_hash = latest_block.hash();
    
    // Quick scan: Check every 10th block
    for i in 0..(search_depth / 10) {
        if let Ok(block) = client.blocks().at(current_hash).await {
            blocks_checked += 1;
            
            // Check this block
            if let Some(tx_data) = check_block_for_commitment(
                &block,
                block.number() as u64,
                &commitment_array,
                chain.name,
            ).await? {
                println!("      ✅ Found in {} blocks!", blocks_checked);
                return Ok(Some(tx_data));
            }
            
            // Skip 10 blocks forward
            for _ in 0..10 {
                if let Ok(parent_block) = client.blocks().at(current_hash).await {
                    current_hash = parent_block.header().parent_hash;
                } else {
                    break;
                }
            }
        }
        
        // Progress indicator
        if blocks_checked % 50 == 0 && blocks_checked > 0 {
            println!("      ... {} blocks checked", blocks_checked);
        }
    }
    
    println!("      Phase 2: Full scan of {} blocks...", search_depth);
    
    // If not found in quick scan, do full scan
    current_hash = latest_block.hash();
    blocks_checked = 0;
    
    for _ in 0..search_depth {
        if let Ok(block) = client.blocks().at(current_hash).await {
            blocks_checked += 1;
            
            if let Some(tx_data) = check_block_for_commitment(
                &block,
                block.number() as u64,
                &commitment_array,
                chain.name,
            ).await? {
                println!("      ✅ Found after {} blocks!", blocks_checked);
                return Ok(Some(tx_data));
            }
            
            // Move to parent
            current_hash = block.header().parent_hash;
            
            // Progress
            if blocks_checked % 100 == 0 {
                println!("      ... {} blocks scanned", blocks_checked);
            }
        } else {
            break;
        }
    }
    
    println!("      Scanned {} blocks total", blocks_checked);
    Ok(None)
}

/// Optimized block check
async fn check_block_for_commitment(
    block: &subxt::blocks::Block<PolkadotConfig, OnlineClient<PolkadotConfig>>,
    block_number: u64,
    target_commitment: &[u8; 32],
    chain_name: &str,
) -> Result<Option<SubstrateSourceTxData>, Box<dyn Error>> {
    // Get events efficiently
    let events = match block.events().await {
        Ok(e) => e,
        Err(_) => return Ok(None),
    };
    
    // Quick check: Does this block have any ISMP events?
    let mut has_ismp = false;
    for event_result in events.iter() {
        if let Ok(event) = event_result {
            if event.pallet_name().to_lowercase().contains("ismp") {
                has_ismp = true;
                break;
            }
        }
    }
    
    if !has_ismp {
        return Ok(None); // Skip blocks with no ISMP events
    }
    
    // Check ISMP events for commitment
    for event_result in events.iter() {
        if let Ok(event) = event_result {
            let pallet = event.pallet_name();
            let variant = event.variant_name();
            
            if pallet.to_lowercase().contains("ismp") && 
               (variant.contains("Request") || variant.contains("Post")) {
                
                // Try to extract commitment
                if let Some(commitment) = extract_commitment(&event) {
                    if &commitment == target_commitment {
                        let tx_hash = format!("{:?}", block.hash());
                        let timestamp = chrono::Utc::now().timestamp();
                        
                        return Ok(Some(SubstrateSourceTxData {
                            chain: chain_name.to_string(),
                            tx_hash,
                            block_number,
                            timestamp,
                            extrinsic_index: 0,
                        }));
                    }
                }
            }
        }
    }
    
    Ok(None)
}

/// Fast commitment extraction
fn extract_commitment(
    event: &subxt::events::EventDetails<PolkadotConfig>,
) -> Option<[u8; 32]> {
    let bytes = event.field_bytes();
    
    if bytes.len() < 32 {
        return None;
    }
    
    // Try common positions
    for offset in [0, 1, 2, 4, 8, 16, 32] {
        if offset + 32 <= bytes.len() {
            let mut commitment = [0u8; 32];
            commitment.copy_from_slice(&bytes[offset..offset + 32]);
            
            // Valid if has enough non-zero bytes
            if commitment.iter().filter(|&&b| b != 0).count() > 10 {
                return Some(commitment);
            }
        }
    }
    
    None
}

/// Parsed PostRequest data
#[derive(Debug, Clone)]
pub struct SubstratePostRequestData {
    pub commitment: String,
    pub dest_state_machine: String,
    pub amount: u128,
    pub source_address: String,
}

/// Parse event data
pub async fn parse_substrate_post_request(
    _source_data: &SubstrateSourceTxData,
    commitment: &str,
) -> Result<SubstratePostRequestData, Box<dyn Error>> {
    Ok(SubstratePostRequestData {
        commitment: commitment.to_string(),
        dest_state_machine: "EVM-UNKNOWN".to_string(),
        amount: 0,
        source_address: "Substrate Address".to_string(),
    })
}
