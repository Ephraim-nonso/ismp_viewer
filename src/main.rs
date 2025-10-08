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
    pub id: String,
    pub source_chain: String,
    pub dest_chain: String,
    pub message_content: String,
    pub status: MessageStatus,
    pub timestamp: DateTime<Utc>,
    pub tx_hash: Option<String>,
}

// ============================================================================
// Backend API Integration
// ============================================================================

const BACKEND_URL: &str = "http://127.0.0.1:8080";

#[derive(Serialize, Deserialize)]
struct DispatchRequest {
    source: String,
    destination: String,
    content: String,
}

/// Dispatch a message to the backend API
async fn dispatch_message_api(
    source: String,
    destination: String,
    content: String,
) -> Result<CrossChainMessage, String> {
    let request_body = DispatchRequest {
        source,
        destination,
        content,
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
    use uuid::Uuid;
    
    vec![
        CrossChainMessage {
            id: Uuid::new_v4().to_string(),
            source_chain: "paseo".to_string(),
            dest_chain: "base-sepolia".to_string(),
            message_content: "Transfer 100 DOT tokens to Base Sepolia".to_string(),
            status: MessageStatus::Delivered,
            timestamp: Utc::now(),
            tx_hash: Some("0x1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890".to_string()),
        },
        CrossChainMessage {
            id: Uuid::new_v4().to_string(),
            source_chain: "base-sepolia".to_string(),
            dest_chain: "paseo".to_string(),
            message_content: "Execute smart contract function: updateOraclePrice(ETH, 2500)".to_string(),
            status: MessageStatus::InTransit,
            timestamp: Utc::now(),
            tx_hash: Some("0x2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef12345678901".to_string()),
        },
        CrossChainMessage {
            id: Uuid::new_v4().to_string(),
            source_chain: "paseo".to_string(),
            dest_chain: "base-sepolia".to_string(),
            message_content: "Cross-chain NFT bridge: Transfer CryptoPunk #1234".to_string(),
            status: MessageStatus::Pending,
            timestamp: Utc::now(),
            tx_hash: None,
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

// ============================================================================
// Components
// ============================================================================

#[component]
pub fn App() -> impl IntoView {
    let (messages, set_messages) = signal(Vec::<CrossChainMessage>::new());
    let (is_dispatching, set_is_dispatching) = signal(false);
    let (notification, set_notification) = signal(None::<String>);

    let dispatch_message = move |source: String, destination: String, content: String| {
        web_sys::console::log_1(&"🚀 dispatch_message called from form".into());
        spawn_local(async move {
            web_sys::console::log_1(&"📡 Starting async dispatch...".into());
            set_is_dispatching.set(true);
            
            // Call the REAL backend API!
            match dispatch_message_api(source, destination, content).await {
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
    let (message_content, set_message_content) = signal(String::new());
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
        let content = message_content.get();

        if source.is_empty() || dest.is_empty() {
            set_error.set(Some("Please select both source and destination chains".to_string()));
            return;
        }

        if source == dest {
            set_error.set(Some("Source and destination chains must be different".to_string()));
            return;
        }

        if content.trim().is_empty() {
            set_error.set(Some("Message content cannot be empty".to_string()));
            return;
        }

        if content.len() > 500 {
            set_error.set(Some("Message content must be less than 500 characters".to_string()));
            return;
        }
        
        if let Err(validation_error) = validate_message_content(&content) {
            set_error.set(Some(validation_error));
            return;
        }
        
        on_dispatch(source, dest, content.clone());
        set_message_content.set(String::new());
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
                <label>"Message Content"</label>
                <textarea
                    class="form-control"
                    rows="4"
                    placeholder="Enter your cross-chain message..."
                    on:input=move |ev| set_message_content.set(event_target_value(&ev))
                    prop:value=move || message_content.get()
                />
                <small class="char-count">
                    {move || format!("{} / 500 characters", message_content.get().len())}
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

                <div class="message-content">
                    <strong>"Message: "</strong>
                    <p>{message.message_content.clone()}</p>
                </div>

                <div class="message-meta">
                    <div class="timestamp">
                        <span>"🕐 "</span>
                        {formatted_time}
                    </div>
                    {message.tx_hash.as_ref().map(|hash| {
                        let short_hash = format!("{}...", &hash[..16]);
                        view! {
                            <div class="tx-hash">
                                <strong>"TX: "</strong>
                                <code>{short_hash}</code>
                            </div>
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
    leptos::mount::mount_to_body(App);
}
