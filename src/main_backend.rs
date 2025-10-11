#[cfg(feature = "backend")]
use axum::{routing::*, Router, Json, response::IntoResponse};
#[cfg(feature = "backend")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "backend")]
use tower_http::cors::{CorsLayer, Any};
#[cfg(feature = "backend")]
use chrono::{DateTime, Utc};
#[cfg(feature = "backend")]
use ethers::prelude::*;

// ============================================================================
// Chain Configuration
// ============================================================================

#[cfg(feature = "backend")]
const PASEO_RPC: &str = "wss://paseo.rpc.amforc.com";
#[cfg(feature = "backend")]
const BASE_SEPOLIA_RPC: &str = "https://sepolia.base.org";
#[cfg(feature = "backend")]
const ARBITRUM_SEPOLIA_RPC: &str = "https://sepolia-rollup.arbitrum.io/rpc";
#[cfg(feature = "backend")]
const BSC_TESTNET_RPC: &str = "https://bsc-testnet-dataseed.bnbchain.org/";
#[cfg(feature = "backend")]
const OPTIMISM_SEPOLIA_RPC: &str = "https://sepolia.optimism.io";

#[cfg(feature = "backend")]
const HANDLER_V1: &str = "0x4638945E120846366cB7Abc08DB9c0766E3a663F";

#[cfg(feature = "backend")]
const BASE_SEPOLIA_CHAIN_ID: u64 = 84532;
#[cfg(feature = "backend")]
const ARBITRUM_SEPOLIA_CHAIN_ID: u64 = 421614;
#[cfg(feature = "backend")]
const OPTIMISM_SEPOLIA_CHAIN_ID: u64 = 11155420;
#[cfg(feature = "backend")]
const BSC_TESTNET_CHAIN_ID: u64 = 97;

// ============================================================================
// Shared Data Structures
// ============================================================================

#[cfg(feature = "backend")]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MessageStatus {
    Pending,
    InTransit,
    Delivered,
    Failed,
}

#[cfg(feature = "backend")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossChainMessage {
    pub id: String,                      // Message hash (64-char hex)
    pub source_chain: String,            // Source chain
    pub dest_chain: String,              // Destination chain
    pub commitment: String,              // Cryptographic proof
    pub nonce: u64,                      // Unique sequence number
    pub status: MessageStatus,           // Current status
    pub timestamp: DateTime<Utc>,        // When dispatched
    pub fee: String,                     // Fee paid
    pub relayer: Option<String>,         // Relayer address
}

#[cfg(feature = "backend")]
#[derive(Debug, Serialize, Deserialize)]
struct DispatchRequest {
    source: String,
    destination: String,
    message_hash: String,  // 64-char hex hash
}

// ============================================================================
// RPC Client Module
// ============================================================================

#[cfg(feature = "backend")]
mod rpc_clients {
    use super::*;
    use ethers::prelude::*;
    
    #[derive(Debug)]
    pub struct MessageData {
        pub commitment: String,
        pub source: String,
        pub dest: String,
        pub nonce: u64,
        pub timestamp: DateTime<Utc>,
        pub status: MessageStatus,
        pub fee: String,
        pub relayer: Option<String>,
    }
    
    /// Query an EVM chain for ISMP message
    pub async fn query_evm_message(
        chain: &str, 
        tx_hash: &str
    ) -> Result<MessageData, String> {
        println!("🔍 Querying EVM chain: {} for tx: {}", chain, tx_hash);
        
        // Get RPC URL based on chain
        let rpc_url = match chain {
            "base-sepolia" => BASE_SEPOLIA_RPC,
            "arbitrum-sepolia" => ARBITRUM_SEPOLIA_RPC,
            "optimism-sepolia" => OPTIMISM_SEPOLIA_RPC,
            "bsc-testnet" => BSC_TESTNET_RPC,
            _ => return Err(format!("Unsupported EVM chain: {}", chain)),
        };
        
        // Connect to provider
        let provider = Provider::<Http>::try_from(rpc_url)
            .map_err(|e| format!("Failed to connect to RPC: {}", e))?;
        
        // Parse transaction hash
        let tx_hash_parsed: H256 = tx_hash.parse()
            .map_err(|e| format!("Invalid transaction hash: {}", e))?;
        
        // Get transaction receipt
        let receipt = provider
            .get_transaction_receipt(tx_hash_parsed)
            .await
            .map_err(|e| format!("Failed to fetch transaction: {}", e))?
            .ok_or_else(|| "Transaction not found".to_string())?;
        
        // Check if transaction succeeded
        let status = if receipt.status == Some(U64::from(1)) {
            MessageStatus::Pending // Successfully dispatched from source
        } else {
            MessageStatus::Failed
        };
        
        // Parse logs for MessageDispatched event
        // Event signature: MessageDispatched(bytes32 commitment)
        let event_signature = ethers::utils::keccak256("MessageDispatched(bytes32)");
        
        let mut commitment = String::new();
        let handler_address: Address = HANDLER_V1.parse()
            .map_err(|e| format!("Invalid handler address: {}", e))?;
        
        for log in &receipt.logs {
            if log.address == handler_address && !log.topics.is_empty() {
                let topic0 = log.topics[0].as_bytes();
                if topic0 == event_signature {
                    // First topic is event signature, second is commitment
                    if log.topics.len() > 1 {
                        commitment = format!("0x{}", hex::encode(log.topics[1].as_bytes()));
                        println!("✅ Found MessageDispatched event with commitment: {}", commitment);
                    }
                    break;
                }
            }
        }
        
        if commitment.is_empty() {
            return Err("No MessageDispatched event found in transaction".to_string());
        }
        
        // Extract block timestamp
        let block_number = receipt.block_number
            .ok_or_else(|| "Block number not found".to_string())?;
        
        let block = provider
            .get_block(block_number)
            .await
            .map_err(|e| format!("Failed to fetch block: {}", e))?
            .ok_or_else(|| "Block not found".to_string())?;
        
        let timestamp = DateTime::from_timestamp(block.timestamp.as_u64() as i64, 0)
            .unwrap_or_else(|| Utc::now());
        
        // Calculate nonce from block data (simplified)
        let nonce = block.number.unwrap_or_default().as_u64();
        
        // Get destination from request (we'll use the provided dest)
        // In a real implementation, this would be parsed from the message data
        
        Ok(MessageData {
            commitment,
            source: format_chain_name(chain),
            dest: "Unknown".to_string(), // Will be filled by caller
            nonce,
            timestamp,
            status,
            fee: "0.1 DAI".to_string(), // Placeholder
            relayer: None,
        })
    }
    
    /// Query Paseo (Substrate) for ISMP message
    pub async fn query_paseo_message(
        tx_hash: &str
    ) -> Result<MessageData, String> {
        println!("🔍 Querying Paseo for tx: {}", tx_hash);
        
        // For now, return a simulated response
        // Full subxt integration would require generating metadata from Paseo runtime
        // This is a placeholder that demonstrates the structure
        
        // In production, this would:
        // 1. Connect to Paseo via subxt
        // 2. Query the transaction/extrinsic
        // 3. Parse pallet_ismp::Event::RequestDispatched
        // 4. Extract commitment, source, dest, nonce from event
        
        // Simulated response for demonstration
        Err("Paseo integration requires runtime metadata generation. Please use EVM chains for now.".to_string())
    }
    
    fn format_chain_name(chain_id: &str) -> String {
        match chain_id {
            "paseo" => "Paseo".to_string(),
            "base-sepolia" => "Base Sepolia".to_string(),
            "arbitrum-sepolia" => "Arbitrum Sepolia".to_string(),
            "optimism-sepolia" => "Optimism Sepolia".to_string(),
            "bsc-testnet" => "BSC Testnet".to_string(),
            _ => chain_id.to_string(),
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

#[cfg(feature = "backend")]
fn format_chain_name(chain_id: &str) -> String {
    match chain_id {
        "paseo" => "Paseo".to_string(),
        "base-sepolia" => "Base Sepolia".to_string(),
        "arbitrum-sepolia" => "Arbitrum Sepolia".to_string(),
        "optimism-sepolia" => "Optimism Sepolia".to_string(),
        "bsc-testnet" => "BSC Testnet".to_string(),
        _ => chain_id.to_string(),
    }
}

// ============================================================================
// Backend Endpoint
// ============================================================================

#[cfg(feature = "backend")]
async fn dispatch_message(Json(payload): Json<DispatchRequest>) -> Result<Json<CrossChainMessage>, String> {
    println!("📨 Received dispatch request: {:?}", payload);
    
    let source = payload.source.as_str();
    let dest = payload.destination.as_str();
    let tx_hash = &payload.message_hash;
    
    // Validate hash format
    if !tx_hash.starts_with("0x") || tx_hash.len() != 66 {
        return Err("Invalid transaction hash format. Expected 0x followed by 64 hex characters.".to_string());
    }
    
    // Route to appropriate RPC client
    let message_data = if source == "paseo" {
        rpc_clients::query_paseo_message(tx_hash).await
            .map_err(|e| format!("Paseo query failed: {}", e))?
    } else {
        // EVM chains
        let mut data = rpc_clients::query_evm_message(source, tx_hash).await
            .map_err(|e| format!("EVM query failed: {}", e))?;
        
        // Fill in destination from request
        data.dest = format_chain_name(dest);
        data
    };
    
    // Convert to CrossChainMessage
    let message = CrossChainMessage {
        id: tx_hash.clone(),
        source_chain: message_data.source,
        dest_chain: message_data.dest,
        commitment: message_data.commitment,
        nonce: message_data.nonce,
        status: message_data.status,
        timestamp: message_data.timestamp,
        fee: message_data.fee,
        relayer: message_data.relayer,
    };
    
    println!("✅ Successfully parsed message: {}", message.id);
    println!("   Source: {} → Dest: {}", message.source_chain, message.dest_chain);
    println!("   Commitment: {}", message.commitment);
    println!("   Status: {:?}", message.status);
    
    Ok(Json(message))
}

// Helper to convert Result to Axum response
#[cfg(feature = "backend")]
async fn dispatch_message_handler(payload: Json<DispatchRequest>) -> axum::response::Response {
    match dispatch_message(payload).await {
        Ok(json) => json.into_response(),
        Err(e) => {
            let error_json = serde_json::json!({
                "error": e
            });
            (axum::http::StatusCode::BAD_REQUEST, Json(error_json)).into_response()
        }
    }
}

// ============================================================================
// Main Entry Point
// ============================================================================

#[cfg(feature = "backend")]
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);
    
    async fn root() -> &'static str {
        "✅ ISMP Viewer Backend API - Blockchain Integration Active!\n\n\
         Endpoints:\n\
         POST /api/dispatch - Query cross-chain message from blockchain\n\n\
         Example:\n\
         curl -X POST http://127.0.0.1:8080/api/dispatch \\\n\
           -H \"Content-Type: application/json\" \\\n\
           -d '{\"source\":\"base-sepolia\",\"destination\":\"arbitrum-sepolia\",\"message_hash\":\"0x...\"}'\n\n\
         Supported Chains:\n\
         - paseo (Paseo Substrate - coming soon)\n\
         - base-sepolia (Base Sepolia)\n\
         - arbitrum-sepolia (Arbitrum Sepolia)\n\
         - optimism-sepolia (Optimism Sepolia)\n\
         - bsc-testnet (BSC Testnet)"
    }
    
    let app = Router::new()
        .route("/", get(root))
        .route("/api/dispatch", post(dispatch_message_handler))
        .layer(cors);
    
    let addr = "127.0.0.1:8080";
    println!("🚀 Backend API running on http://{}", addr);
    println!("📖 Visit http://{} for API documentation", addr);
    println!("🔗 Connected to blockchain RPCs:");
    println!("   - Base Sepolia: {}", BASE_SEPOLIA_RPC);
    println!("   - Arbitrum Sepolia: {}", ARBITRUM_SEPOLIA_RPC);
    println!("   - Optimism Sepolia: {}", OPTIMISM_SEPOLIA_RPC);
    println!("   - BSC Testnet: {}", BSC_TESTNET_RPC);
    
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[cfg(not(feature = "backend"))]
fn main() {
    println!("Build with: cargo run --bin backend --features backend");
}
