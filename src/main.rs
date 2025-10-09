use leptos::prelude::*;
use leptos::task::spawn_local;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use wasm_bindgen_futures::JsFuture;
use web_sys::js_sys;
use gloo_net::http::Request;
use wasm_bindgen::prelude::*;

// ============================================================================
// Data Structures
// ============================================================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MessageStatus {
    Pending,
    InTransit,
    Delivered,
    Failed,
}

impl MessageStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            MessageStatus::Pending => "Pending",
            MessageStatus::InTransit => "In Transit",
            MessageStatus::Delivered => "Delivered",
            MessageStatus::Failed => "Failed",
        }
    }

    pub fn color(&self) -> &'static str {
        match self {
            MessageStatus::Pending => "#FFA500",
            MessageStatus::InTransit => "#4A90E2",
            MessageStatus::Delivered => "#4CAF50",
            MessageStatus::Failed => "#F44336",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            MessageStatus::Pending => "⏳",
            MessageStatus::InTransit => "🚀",
            MessageStatus::Delivered => "✅",
            MessageStatus::Failed => "❌",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossChainMessage {
    pub id: String,                      // Message hash (64-char hex)
    pub source_chain: String,            // Source chain (e.g., "Paseo")
    pub dest_chain: String,              // Destination chain (e.g., "Base Sepolia")
    pub commitment: String,              // Cryptographic proof (derived from message)
    pub nonce: u64,                      // Unique sequence number
    pub status: MessageStatus,           // Current status
    pub timestamp: DateTime<Utc>,        // When dispatched
    pub fee: String,                     // Fee paid (in DAI or native token)
    pub relayer: Option<String>,         // Relayer address (if delivered)
}

// ============================================================================
// Backend API Integration
// ============================================================================

const BACKEND_URL: &str = "http://127.0.0.1:8080";

#[derive(Serialize, Deserialize)]
struct DispatchRequest {
    source: String,
    destination: String,
    message_hash: String,  // 64-char hex hash
}

/// Dispatch a message to the backend API
async fn dispatch_message_api(
    source: String,
    destination: String,
    message_hash: String,
) -> Result<CrossChainMessage, String> {
    let request_body = DispatchRequest {
        source,
        destination,
        message_hash,
    };

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

/// Generate realistic testnet message examples
fn generate_testnet_examples() -> Vec<CrossChainMessage> {
    use chrono::Utc;
    
    let msg1_id = "0x8dd8443f837f2bbcd9c5b27e47587aa5ffd573c15c87e0f2d19ce89f6a9e9c7a".to_string();
    let msg2_id = "0x7cc7332e726e1aa3b9c4b16d36476476aa4ec462b2ae9e1f1d18ce78f5a8e8c6".to_string();
    let msg3_id = "0x6bb6221d615d0992a8c3a05e25365365aa3db351a1ad8d0e0c07bd67e4979b5a".to_string();
    
    vec![
        CrossChainMessage {
            id: msg1_id.clone(),
            source_chain: "Paseo".to_string(),
            dest_chain: "Base Sepolia".to_string(),
            commitment: derive_commitment_hash(&msg1_id),
            nonce: 12345,
            status: MessageStatus::Delivered,
            timestamp: Utc::now(),
            fee: "0.5 DAI".to_string(),
            relayer: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb".to_string()),
        },
        CrossChainMessage {
            id: msg2_id.clone(),
            source_chain: "Base Sepolia".to_string(),
            dest_chain: "Paseo".to_string(),
            commitment: derive_commitment_hash(&msg2_id),
            nonce: 12346,
            status: MessageStatus::InTransit,
            timestamp: Utc::now(),
            fee: "0.3 DAI".to_string(),
            relayer: None,
        },
        CrossChainMessage {
            id: msg3_id.clone(),
            source_chain: "Paseo".to_string(),
            dest_chain: "Arbitrum Sepolia".to_string(),
            commitment: derive_commitment_hash(&msg3_id),
            nonce: 12347,
            status: MessageStatus::Pending,
            timestamp: Utc::now(),
            fee: "0.4 DAI".to_string(),
            relayer: None,
        },
    ]
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

    let rand = (js_sys::Math::random() * 4.0) as u32;
    
    Ok(match rand {
        0 => MessageStatus::Pending,
        1 => MessageStatus::InTransit,
        2 => MessageStatus::Delivered,
        _ => MessageStatus::Failed,
    })
}

fn validate_message_content(content: &str) -> Result<(), String> {
    let trimmed = content.trim();
    
    if trimmed.len() < 3 {
        return Err("Message is too short. Please provide a meaningful message.".to_string());
    }
    
    let letter_count = trimmed.chars().filter(|c| c.is_alphabetic()).count();
    if letter_count < 3 {
        return Err("Message must contain at least some letters.".to_string());
    }
    
    let mut consecutive_count = 1;
    let mut prev_char = '\0';
    for c in trimmed.chars() {
        if c == prev_char {
            consecutive_count += 1;
            if consecutive_count > 5 {
                return Err("Message contains too many repeated characters.".to_string());
            }
        } else {
            consecutive_count = 1;
            prev_char = c;
        }
    }
    
    let has_vowels = trimmed.to_lowercase().chars()
        .any(|c| matches!(c, 'a' | 'e' | 'i' | 'o' | 'u'));
    
    if !has_vowels && letter_count > 5 {
        return Err("Message appears to be unreadable. Please use normal words.".to_string());
    }
    
    Ok(())
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

/// Derive commitment hash from message hash
/// In real ISMP, this is computed from the message content using cryptographic hashing
fn derive_commitment_hash(message_hash: &str) -> String {
    // Simulate ISMP commitment derivation
    // Real implementation would use: keccak256(encode(request))
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    format!("commitment_{}", message_hash).hash(&mut hasher);
    let hash_value = hasher.finish();
    
    // Generate a 64-char hex commitment
    format!("0x{:016x}{:016x}{:016x}{:016x}", 
        hash_value, 
        hash_value.wrapping_mul(31), 
        hash_value.wrapping_mul(97),
        hash_value.wrapping_mul(127)
    )
}

// ============================================================================
// Components
// ============================================================================

#[component]
pub fn App() -> impl IntoView {
    let (messages, set_messages) = signal(Vec::<CrossChainMessage>::new());
    let (is_dispatching, set_is_dispatching) = signal(false);
    let (notification, set_notification) = signal(None::<String>);

    let dispatch_message = move |source: String, destination: String, message_hash: String| {
        web_sys::console::log_1(&"🚀 dispatch_message called from form".into());
        spawn_local(async move {
            web_sys::console::log_1(&"📡 Starting async dispatch...".into());
            set_is_dispatching.set(true);
            
            // Call the REAL backend API!
            match dispatch_message_api(source, destination, message_hash).await {
                Ok(message) => {
                    web_sys::console::log_1(&format!("✅ Got message from backend: {:?}", message.id).into());
                    
                    set_messages.update(|msgs| {
                        web_sys::console::log_1(&format!("📝 Before push: {} messages", msgs.len()).into());
                        msgs.push(message.clone());
                        web_sys::console::log_1(&format!("📝 After push: {} messages", msgs.len()).into());
                    });
                    
                    web_sys::console::log_1(&"🔔 Setting notification...".into());
                    set_notification.set(Some(format!("✅ Message dispatched via backend! ID: {}", &message.id[..8])));
                    
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
                    set_notification.set(Some(format!("❌ Backend Error: {}", e)));
                }
            }
            
            web_sys::console::log_1(&"✅ Dispatch complete, setting is_dispatching to false".into());
            set_is_dispatching.set(false);
        });
    };

    let load_examples = move |_| {
        web_sys::console::log_1(&"🔍 Load examples button clicked!".into());
        
        let examples = generate_testnet_examples();
        web_sys::console::log_1(&format!("🔍 Generated {} examples", examples.len()).into());
        
        set_messages.update(|msgs| {
            *msgs = examples;
        });
        web_sys::console::log_1(&"🔍 Messages state updated".into());
        
        set_notification.set(Some("✅ Loaded realistic Hyperbridge testnet examples!".to_string()));
        web_sys::console::log_1(&"🔍 Notification set".into());
        
        spawn_local(async move {
            let promise = js_sys::Promise::new(&mut |resolve, _reject| {
                web_sys::window()
                    .unwrap()
                    .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 3000)
                    .unwrap();
            });
            let _ = JsFuture::from(promise).await;
            set_notification.set(None);
        });
    };

    create_effect(move |_| {
        let msgs = messages.get();
        for msg in msgs.iter() {
            if matches!(msg.status, MessageStatus::Pending | MessageStatus::InTransit) {
                let msg_id = msg.id.clone();
                spawn_local(async move {
                    if let Ok(new_status) = query_message_status_stub(msg_id.clone()).await {
                        set_messages.update(|messages| {
                            if let Some(m) = messages.iter_mut().find(|m| m.id == msg_id) {
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
                    
                    <div class="examples-section">
                        <button 
                            class="btn-secondary"
                            on:click=load_examples
                        >
                            "Load Hyperbridge Testnet Examples 🚀"
                        </button>
                    </div>
                </div>

                <div class="activity-section">
                    <h2>"📊 Activity Log"</h2>
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
                                        key=|msg| msg.id.clone()
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
                    <span class="logo">"🌐"</span>
                    " ISMP Viewer"
                </h1>
                <p class="subtitle">"Cross-Chain Message Tracker powered by Hyperbridge"</p>
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
    F: Fn(String, String, String) + 'static + Copy,
{
    let (source_chain, set_source_chain) = signal(String::from("paseo"));
    let (dest_chain, set_dest_chain) = signal(String::from("base-sepolia"));
    let (message_hash, set_message_hash) = signal(String::new());
    let (error, set_error) = signal(None::<String>);

    let chains = vec![
        ("paseo", "Paseo (Polkadot Testnet)"),
        ("base-sepolia", "Base Sepolia"),
        ("arbitrum-sepolia", "Arbitrum Sepolia"),
        ("optimism-sepolia", "Optimism Sepolia"),
        ("bsc-testnet", "BSC Testnet"),
    ];

    let handle_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        set_error.set(None);

        let source = source_chain.get();
        let dest = dest_chain.get();
        let hash = message_hash.get();

        if source.is_empty() || dest.is_empty() {
            set_error.set(Some("Please select both source and destination chains".to_string()));
            return;
        }

        if source == dest {
            set_error.set(Some("Source and destination chains must be different".to_string()));
            return;
        }

        if hash.trim().is_empty() {
            set_error.set(Some("Message hash cannot be empty".to_string()));
            return;
        }
        
        // Validate message hash format
        if let Err(validation_error) = validate_message_hash(&hash) {
            set_error.set(Some(validation_error));
            return;
        }
        
        on_dispatch(source, dest, hash.clone());
        set_message_hash.set(String::new());
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
                <label>"Source Chain"</label>
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
            </div>

            <div class="form-group">
                <label>"Destination Chain"</label>
                <select
                    class="form-control"
                    on:change=move |ev| set_dest_chain.set(event_target_value(&ev))
                    prop:value=move || dest_chain.get()
                >
                    {chains.iter().map(|(value, label)| {
                        let value_str = value.to_string();
                        let label_str = label.to_string();
                        view! {
                            <option value=value_str>{label_str}</option>
                        }
                    }).collect::<Vec<_>>()}
                </select>
            </div>

            <div class="form-group">
                <label>"Message Hash (Transaction ID)"</label>
                <input
                    type="text"
                    class="form-control"
                    placeholder="0x8dd8443f837f2bbcd9c5b27e47587aa5ffd573c15c87e0f2d19ce89f6a9e9c7a"
                    on:input=move |ev| set_message_hash.set(event_target_value(&ev))
                    prop:value=move || message_hash.get()
                />
                <small class="char-count" style="color: #666;">
                    "64-character hex hash (e.g., from Hyperbridge Explorer)"
                </small>
            </div>

            <button
                type="submit"
                class="btn-primary"
                disabled=move || is_dispatching.get()
            >
                "Send Message 🚀"
            </button>
        </form>
    }
}

#[component]
fn ActivityLog(messages: ReadSignal<Vec<CrossChainMessage>>) -> impl IntoView {
    view! {
        <div class="activity-log">
            {move || {
                let msgs = messages.get();
                web_sys::console::log_1(&format!("🔍 ActivityLog re-rendering with {} messages", msgs.len()).into());
                
                if msgs.is_empty() {
                    web_sys::console::log_1(&"🔍 Showing empty state".into());
                    view! {
                        <div class="empty-state">
                            <p>"No messages yet. Send your first cross-chain message!"</p>
                        </div>
                    }.into_any()
                } else {
                    web_sys::console::log_1(&format!("🔍 Rendering {} message cards", msgs.len()).into());
                    view! {
                        <div class="message-list">
                            {msgs.iter().rev().map(|msg| {
                                view! {
                                    <MessageCard message=msg.clone() />
                                }
                            }).collect::<Vec<_>>()}
                        </div>
                    }.into_any()
                }
            }}
        </div>
    }
}

#[component]
fn MessageCard(message: CrossChainMessage) -> impl IntoView {
    let formatted_time = message.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string();
    let short_id = message.id[..8].to_string();

    view! {
        <div class="message-card">
            <div class="message-header">
                <div class="message-id">
                    <strong>"ID: "</strong>
                    <code>{format!("{}...", short_id)}</code>
                </div>
                <StatusIndicator status=message.status.clone() />
            </div>

            <div class="message-body">
                <div class="chain-flow">
                    <span class="chain-badge source">{message.source_chain.clone()}</span>
                    <span class="arrow">"→"</span>
                    <span class="chain-badge dest">{message.dest_chain.clone()}</span>
                </div>

                <div class="message-details" style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 12px; font-size: 0.9em;">
                    <div>
                        <strong>"Commitment: "</strong>
                        <code style="font-size: 0.85em;">{format!("{}...{}", &message.commitment[..10], &message.commitment[message.commitment.len()-8..])}</code>
                    </div>
                    <div>
                        <strong>"Nonce: "</strong>
                        <span>{message.nonce}</span>
                    </div>
                    <div>
                        <strong>"Fee: "</strong>
                        <span>{message.fee.clone()}</span>
                    </div>
                    <div>
                        <strong>"Relayer: "</strong>
                        <span>
                            {message.relayer.as_ref().map(|r| format!("{}...{}", &r[..6], &r[r.len()-4..]))
                                .unwrap_or_else(|| "Pending".to_string())}
                        </span>
                    </div>
                </div>

                <div class="message-meta" style="margin-top: 12px;">
                    <small class="timestamp">
                        <span>"🕐 "</span>
                        {formatted_time}
                    </small>
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
