#[cfg(feature = "backend")]
use axum::{routing::*, Router, Json};
#[cfg(feature = "backend")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "backend")]
use tower_http::cors::{CorsLayer, Any};
#[cfg(feature = "backend")]
use chrono::{DateTime, Utc};

// Shared data structures (match frontend exactly)
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

#[cfg(feature = "backend")]
fn derive_commitment_hash(message_hash: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    format!("commitment_{}", message_hash).hash(&mut hasher);
    let hash_value = hasher.finish();
    
    format!("0x{:016x}{:016x}{:016x}{:016x}", 
        hash_value, 
        hash_value.wrapping_mul(31), 
        hash_value.wrapping_mul(97),
        hash_value.wrapping_mul(127)
    )
}

#[cfg(feature = "backend")]
async fn dispatch_message(Json(payload): Json<DispatchRequest>) -> Json<CrossChainMessage> {
    println!("📨 Received dispatch request: {:?}", payload);
    
    // TODO: Integrate ISMP here - this will use real pallet-hyperbridge
    let message = CrossChainMessage {
        id: payload.message_hash.clone(),
        source_chain: payload.source,
        dest_chain: payload.destination,
        commitment: derive_commitment_hash(&payload.message_hash),
        nonce: (chrono::Utc::now().timestamp() % 100000) as u64,  // Simulate nonce
        status: MessageStatus::Pending,
        timestamp: Utc::now(),
        fee: "0.5 DAI".to_string(),  // Default fee
        relayer: None,  // No relayer yet (pending)
    };
    
    println!("✅ Dispatched message: {}", message.id);
    println!("   Commitment: {}", message.commitment);
    println!("   Nonce: {}", message.nonce);
    
    Json(message)
}

#[cfg(feature = "backend")]
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);
    
    async fn root() -> &'static str {
        "✅ ISMP Viewer Backend API\n\n\
         Endpoints:\n\
         POST /api/dispatch - Dispatch a cross-chain message\n\n\
         Example:\n\
         curl -X POST http://127.0.0.1:8080/api/dispatch \\\n\
           -H \"Content-Type: application/json\" \\\n\
           -d '{\"source\":\"paseo\",\"destination\":\"base-sepolia\",\"content\":\"test\"}'"
    }
    
    let app = Router::new()
        .route("/", get(root))
        .route("/api/dispatch", post(dispatch_message))
        .layer(cors);
    
    let addr = "127.0.0.1:8080";
    println!("🚀 Backend API running on http://{}", addr);
    println!("📖 Visit http://{} for API documentation", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[cfg(not(feature = "backend"))]
fn main() {
    println!("Build with: cargo run --bin backend --features backend");
}

