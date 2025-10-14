use leptos::prelude::*;
use leptos::task::spawn_local;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use wasm_bindgen_futures::JsFuture;
use web_sys::js_sys;
use gloo_net::http::Request;

// ============================================================================
// Data Structures
// ============================================================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MessageStatus {
    Pending,               // Dispatched, awaiting delivery
    Delivered,             // Successfully delivered to destination
    Timeout,               // Message timed out
    Failed,                // Delivery failed
    Unknown,               // Status could not be determined
}

impl MessageStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            MessageStatus::Pending => "Pending",
            MessageStatus::Delivered => "Delivered",
            MessageStatus::Timeout => "Timeout",
            MessageStatus::Failed => "Failed",
            MessageStatus::Unknown => "Unknown",
        }
    }

    pub fn color(&self) -> &'static str {
        match self {
            MessageStatus::Pending => "#FFA500", // Orange
            MessageStatus::Delivered => "#4CAF50", // Green
            MessageStatus::Timeout => "#F44336", // Red
            MessageStatus::Failed => "#D32F2F", // Dark Red
            MessageStatus::Unknown => "#757575", // Grey
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            MessageStatus::Pending => "",
            MessageStatus::Delivered => "",
            MessageStatus::Timeout => "",
            MessageStatus::Failed => "",
            MessageStatus::Unknown => "",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossChainMessage {
    // Primary identifier
    pub commitment: String,              // Commitment hash (primary ID)
    
    // Source information
    pub source_chain: String,            // Source chain name
    pub source_tx_hash: String,          // Source transaction hash
    pub source_address: String,          // Sender address
    pub source_timestamp: DateTime<Utc>, // When dispatched
    
    // Destination information
    pub dest_chain: String,              // Destination chain
    pub dest_tx_hash: Option<String>,    // Delivery transaction hash
    pub dest_address: String,            // Recipient address
    pub dest_timestamp: Option<DateTime<Utc>>, // When delivered
    
    // Message details
    pub request_type: String,            // "PostRequest", "PostResponse", "GetResponse"
    pub status: MessageStatus,           // Current delivery status
    pub amount: Option<String>,          // Amount transferred
    
    // Metrics
    pub transit_time: Option<String>,    // Time from dispatch to delivery
    pub relayer: Option<String>,         // Relayer address
    pub relayer_fee: Option<String>,     // Fee paid to relayer
    
    // Technical
    pub nonce: u64,                      // Sequence number
    pub timeout_timestamp: Option<u64>,  // When message expires
}

// ============================================================================
// Backend API Integration
// ============================================================================

const BACKEND_URL: &str = "http://127.0.0.1:8080";

#[derive(Serialize, Deserialize)]
struct QueryRequest {
    commitment: String,           // Commitment hash (64-char hex)
    source: Option<String>,       // Optional: source chain for faster search
}

/// Query a message by commitment hash (with optional source chain)
async fn query_message_api(commitment: String, source: Option<String>) -> Result<CrossChainMessage, String> {
    let request_body = QueryRequest { commitment, source };

    let response = Request::post(&format!("{}/api/dispatch", BACKEND_URL))
        .json(&request_body)
        .map_err(|e| format!("Failed to create request: {}", e))?
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {}", e))?;

    if !response.ok() {
        return Err(format!("Backend error: HTTP {}", response.status()));
    }

    let message: CrossChainMessage = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    Ok(message)
}


/// Query message status (stub for now, will be implemented in Phase 2C)
async fn query_message_status_stub(_message_id: String) -> Result<MessageStatus, String> {
    // Simulate status progression for demo
    let promise = js_sys::Promise::new(&mut |resolve, _reject| {
        web_sys::window()
            .unwrap()
            .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 300)
            .unwrap();
    });
    let _ = JsFuture::from(promise).await;

    let rand = (js_sys::Math::random() * 8.0) as u32;
    
    Ok(match rand {
        0 => MessageStatus::Pending,
        1 => MessageStatus::Delivered,
        2 => MessageStatus::Pending,
        3 => MessageStatus::Delivered,
        4 => MessageStatus::Pending,
        5 => MessageStatus::Delivered,
        6 => MessageStatus::Timeout,
        _ => MessageStatus::Timeout,
    })
}

/// Validate that the message hash is in the correct format (64-char hex)
fn validate_message_hash(hash: &str) -> Result<(), String> {
    let trimmed = hash.trim();
    
    // Check if it starts with 0x
    if !trimmed.starts_with("0x") {
        return Err("Message hash must start with '0x'".to_string());
    }
    
    // Remove 0x prefix
    let hex_part = &trimmed[2..];
    
    // Check if it's exactly 64 characters (32 bytes in hex)
    if hex_part.len() != 64 {
        return Err(format!("Message hash must be 64 hex characters (found {}). Example: 0x8dd8443f837f2bbcd9c5b27e47587aa5ffd573c15c87e0f2d19ce89f6a9e9c7a", hex_part.len()));
    }
    
    // Check if all characters are valid hex
    if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Message hash contains invalid hex characters (must be 0-9, a-f, A-F)".to_string());
    }
    
    Ok(())
}

// ============================================================================
// Components
// ============================================================================

#[component]
pub fn App() -> impl IntoView {
    let (messages, set_messages) = signal(Vec::<CrossChainMessage>::new());
    let (is_dispatching, set_is_dispatching) = signal(false);
    let (notification, set_notification) = signal(None::<String>);

    let dispatch_message = move |commitment: String, source: Option<String>| {
        web_sys::console::log_1(&"🚀 Querying commitment...".into());
        spawn_local(async move {
            if let Some(ref src) = source {
                web_sys::console::log_1(&format!("📡 Searching on {}: {}", src, &commitment).into());
            } else {
                web_sys::console::log_1(&format!("📡 Auto-searching all chains: {}", &commitment).into());
            }
            set_is_dispatching.set(true);
            
            // Call the backend API with commitment hash and optional source
            match query_message_api(commitment.clone(), source).await {
                Ok(message) => {
                    web_sys::console::log_1(&format!("✅ Found message: {}", &message.commitment).into());
                    
                    set_messages.update(|msgs| {
                        web_sys::console::log_1(&format!("📝 Before push: {} messages", msgs.len()).into());
                        msgs.push(message.clone());
                        web_sys::console::log_1(&format!("📝 After push: {} messages", msgs.len()).into());
                    });
                    
                    web_sys::console::log_1(&"🔔 Setting notification...".into());
                    set_notification.set(Some(format!("✅ Message found! {} → {}", message.source_chain, message.dest_chain)));
                    
                    spawn_local(async move {
                        let promise = js_sys::Promise::new(&mut |resolve, _reject| {
                            web_sys::window()
                                .unwrap()
                                .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 5000)
                                .unwrap();
                        });
                        let _ = JsFuture::from(promise).await;
                        set_notification.set(None);
                    });
                }
                Err(e) => {
                    web_sys::console::log_1(&format!("❌ Backend error: {}", e).into());
                    set_notification.set(Some(format!("❌ Error: {}", e)));
                }
            }
            
            web_sys::console::log_1(&"✅ Query complete".into());
            set_is_dispatching.set(false);
        });
    };


    Effect::new(move |_| {
        let msgs = messages.get();
        for msg in msgs.iter() {
            // Check for messages awaiting delivery
            if matches!(msg.status, MessageStatus::Pending) {
                let msg_id = msg.commitment.clone();
                spawn_local(async move {
                    if let Ok(new_status) = query_message_status_stub(msg_id.clone()).await {
                        set_messages.update(|messages| {
                            if let Some(m) = messages.iter_mut().find(|m| m.commitment == msg_id) {
                                m.status = new_status;
                            }
                        });
                    }
                });
            }
        }
    });

    view! {
        <div class="app-container">
            <Header />
            
            {move || {
                if let Some(notif) = notification.get() {
                    view! {
                        <div class="notification" inner_html=notif></div>
                    }.into_any()
                } else {
                    view! { <div style="display: none;"></div> }.into_any()
                }
            }}

            <div class="main-content">
                <div class="dispatch-section">
                    <h2>"📤 Dispatch Message"</h2>
                    <MessageDispatcherForm
                        on_dispatch=dispatch_message
                        is_dispatching=is_dispatching
                    />
                </div>

                <div class="activity-section">
                    <h2>"ACTIVITY LOG"</h2>
                    {move || {
                        let msgs = messages.get();
                        if msgs.is_empty() {
                            view! {
                                <div class="empty-state">
                                    <p>"No messages yet. Send your first cross-chain message!"</p>
                                </div>
                            }.into_any()
                        } else {
                            view! {
                                <div class="message-list">
                                    <For
                                        each=move || messages.get()
                                        key=|msg| msg.commitment.clone()
                                        children=move |msg: CrossChainMessage| {
                                            view! {
                                                <MessageCard message=msg />
                                            }
                                        }
                                    />
                                </div>
                            }.into_any()
                        }
                    }}
                </div>
            </div>
        </div>
    }
}

#[component]
fn Header() -> impl IntoView {
    view! {
        <header class="header">
            <div class="header-content">
                <h1 class="title">
                    "ISMP VIEWER"
                </h1>
                <p class="subtitle">"CROSS-CHAIN MESSAGE TRACKING FOR HYPERBRIDGE MAINNET"</p>
            </div>
        </header>
    }
}

#[component]
fn MessageDispatcherForm<F>(
    on_dispatch: F,
    is_dispatching: ReadSignal<bool>,
) -> impl IntoView
where
    F: Fn(String, Option<String>) + 'static + Copy,
{
    let (commitment_hash, set_commitment_hash) = signal(String::new());
    let (source_chain, set_source_chain) = signal(String::from("ethereum"));
    let (error, set_error) = signal(None::<String>);

    let chains = vec![
        ("ethereum", "Ethereum Mainnet"),
        ("arbitrum", "Arbitrum One"),
        ("optimism", "OP Mainnet"),
        ("base", "Base"),
        ("bsc", "BSC (BNB Chain)"),
        ("gnosis", "Gnosis Chain"),
        ("scroll", "Scroll"),
        ("soneium", "Soneium"),
        ("polygon", "Polygon PoS"),
        ("unichain", "Unichain"),
        ("bifrost", "Bifrost (Polkadot)"),
        ("polkadot_asset_hub", "Polkadot Asset Hub"),
    ];

    let handle_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        set_error.set(None);

        let hash = commitment_hash.get();
        let source = source_chain.get();

        if hash.trim().is_empty() {
            set_error.set(Some("Commitment hash cannot be empty".to_string()));
            return;
        }
        
        // Validate commitment hash format
        if let Err(validation_error) = validate_message_hash(&hash) {
            set_error.set(Some(validation_error));
            return;
        }
        
        // Always pass the source chain (required for faster search)
        on_dispatch(hash.clone(), Some(source));
        set_commitment_hash.set(String::new());
    };

    view! {
        <form class="dispatch-form" on:submit=handle_submit>
            {move || error.get().map(|err| {
                view! {
                    <div class="error-message">
                        {err}
                    </div>
                }
            })}

            <div class="form-group">
                <label>"Source Chain " <span style="color: #ff4444; font-weight: normal;">"*"</span></label>
                <select
                    class="form-control"
                    on:change=move |ev| set_source_chain.set(event_target_value(&ev))
                    prop:value=move || source_chain.get()
                >
                    {chains.iter().map(|(value, label)| {
                        let value_str = value.to_string();
                        let label_str = label.to_string();
                        view! {
                            <option value=value_str>{label_str}</option>
                        }
                    }).collect::<Vec<_>>()}
                </select>
                <small class="char-count" style="color: #666;">
                    "Select the chain where the message originated"
                </small>
            </div>

            <div class="form-group">
                <label>"Commitment Hash " <span style="color: #666; font-weight: normal;">"(from Hyperbridge Explorer)"</span></label>
                <input
                    type="text"
                    class="form-control"
                    placeholder="0xa1d176071b47f8b9cb59a33ebc6e4ea503c5f7b168746dace8b15c47b03ce07d"
                    on:input=move |ev| set_commitment_hash.set(event_target_value(&ev))
                    prop:value=move || commitment_hash.get()
                />
                <small class="char-count" style="color: #666;">
                    "Destination will be automatically detected from blockchain"
                </small>
            </div>

            <button
                type="submit"
                class="btn-primary"
                disabled=move || is_dispatching.get()
            >
                "TRACK MESSAGE"
            </button>
        </form>
    }
}


#[component]
fn MessageCard(message: CrossChainMessage) -> impl IntoView {
    let formatted_source_time = message.source_timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string();
    let short_commitment = format!("{}...{}", &message.commitment[..10], &message.commitment[message.commitment.len()-8..]);

    view! {
        <div class="message-card">
            <div class="message-header">
                <div class="message-id">
                    <strong>"Commitment: "</strong>
                    <code>{short_commitment}</code>
                </div>
                <StatusIndicator status=message.status.clone() />
            </div>

            <div class="message-body">
                <div class="chain-flow">
                    <span class="chain-badge source">{message.source_chain.clone()}</span>
                    <span class="arrow">"→"</span>
                    <span class="chain-badge dest">{message.dest_chain.clone()}</span>
                </div>

                <div style="margin: 12px 0; padding: 8px 12px; background: rgba(99, 102, 241, 0.1); border-left: 3px solid var(--primary-color); border-radius: 4px;">
                    <strong style="color: var(--primary-light);">"Request Type: "</strong>
                    <span style="color: var(--text-primary);">{message.request_type.clone()}</span>
                </div>

                <div class="message-details" style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 12px; font-size: 0.9em;">
                    <div>
                        <strong>"Source TX: "</strong>
                        <code style="font-size: 0.85em;">{format!("{}...{}", &message.source_tx_hash[..8], &message.source_tx_hash[message.source_tx_hash.len()-6..])}</code>
                    </div>
                    <div>
                        <strong>"Nonce: "</strong>
                        <span>{message.nonce}</span>
                    </div>
                    <div>
                        <strong>"Amount: "</strong>
                        <span>{message.amount.as_ref().unwrap_or(&"N/A".to_string()).clone()}</span>
                    </div>
                    <div>
                        <strong>"Transit Time: "</strong>
                        <span>{message.transit_time.as_ref().unwrap_or(&"Pending...".to_string()).clone()}</span>
                    </div>
                    <div>
                        <strong>"Relayer Fee: "</strong>
                        <span>{message.relayer_fee.as_ref().unwrap_or(&"N/A".to_string()).clone()}</span>
                    </div>
                    <div>
                        <strong>"Relayer: "</strong>
                        <span>
                            {message.relayer.as_ref().map(|r| format!("{}...{}", &r[..6], &r[r.len()-4..]))
                                .unwrap_or_else(|| "N/A".to_string())}
                        </span>
                    </div>
                </div>

                <div class="message-meta" style="margin-top: 12px;">
                    <small class="timestamp">
                        <span>"🕐 Dispatched: "</span>
                        {formatted_source_time}
                    </small>
                    {message.dest_timestamp.map(|dt| {
                        let formatted = dt.format("%Y-%m-%d %H:%M:%S UTC").to_string();
                        view! {
                            <small class="timestamp" style="margin-left: 12px;">
                                <span>"Delivered: "</span>
                                {formatted}
                            </small>
                        }
                    })}
                </div>
            </div>
        </div>
    }
}

#[component]
fn StatusIndicator(status: MessageStatus) -> impl IntoView {
    let color = status.color().to_string();
    let icon = status.icon().to_string();
    let text = status.as_str().to_string();

    view! {
        <div class="status-indicator" style:background-color=color>
            <span class="status-icon">{icon}</span>
            <span class="status-text">{text}</span>
        </div>
    }
}

// ============================================================================
// Main Entry Point
// ============================================================================

fn main() {
    console_error_panic_hook::set_once();
    web_sys::console::log_1(&"🚀 WASM loaded, mounting app...".into());
    leptos::mount::mount_to_body(App);
    web_sys::console::log_1(&"✅ App mounted!".into());
}
