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


    Effect::new(move |_| {
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
