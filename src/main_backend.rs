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
    pub id: String,
    pub source_chain: String,
    pub dest_chain: String,
    pub message_content: String,
    pub status: MessageStatus,
    pub timestamp: DateTime<Utc>,
    pub tx_hash: Option<String>,
}

#[cfg(feature = "backend")]
#[derive(Debug, Serialize, Deserialize)]
struct DispatchRequest {
    source: String,
    destination: String,
    content: String,
}

#[cfg(feature = "backend")]
async fn dispatch_message(Json(payload): Json<DispatchRequest>) -> Json<CrossChainMessage> {
    println!("📨 Received dispatch request: {:?}", payload);
    
    // TODO: Integrate ISMP here
    let message = CrossChainMessage {
        id: uuid::Uuid::new_v4().to_string(),
        source_chain: payload.source,
        dest_chain: payload.destination,
        message_content: payload.content,
        status: MessageStatus::Pending,  // Use the enum, not a string!
        timestamp: Utc::now(),
        tx_hash: Some(format!("0x{}", uuid::Uuid::new_v4().to_string().replace("-", ""))),
    };
    
    println!("✅ Dispatched message: {:?}", message.id);
    
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

