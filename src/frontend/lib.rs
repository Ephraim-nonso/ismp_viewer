use leptos::*;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{JsFuture, spawn_local};
use web_sys::js_sys;

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
            MessageStatus::Pending => "#FFA500",     // Orange
            MessageStatus::InTransit => "#4A90E2",   // Blue
            MessageStatus::Delivered => "#4CAF50",   // Green
            MessageStatus::Failed => "#F44336",      // Red
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
// Stubbed Server Functions (will be implemented with Hyperbridge later)
// ============================================================================

/// Dispatch a cross-chain message (currently stubbed, will call backend in Phase 2B)
async fn dispatch_message_stub(
    source: String,
    destination: String,
    content: String,
) -> Result<CrossChainMessage, String> {
    // Simulate network delay
    let promise = js_sys::Promise::new(&mut |resolve, _reject| {
        web_sys::window()
            .unwrap()
            .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 500)
            .unwrap();
    });
    let _ = JsFuture::from(promise).await;

    Ok(CrossChainMessage {
        id: Uuid::new_v4().to_string(),
        source_chain: source,
        dest_chain: destination,
        message_content: content,
        status: MessageStatus::Pending,
        timestamp: Utc::now(),
        tx_hash: Some(format!("0x{}", Uuid::new_v4().to_string().replace("-", ""))),
    })
}

/// Query message status (currently stubbed, will call backend in Phase 2B)
async fn query_message_status_stub(_message_id: String) -> Result<MessageStatus, String> {
    // Simulate status progression
    let promise = js_sys::Promise::new(&mut |resolve, _reject| {
        web_sys::window()
            .unwrap()
            .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 300)
            .unwrap();
    });
    let _ = JsFuture::from(promise).await;

    // Random status for demo
    let rand = (js_sys::Math::random() * 4.0) as u32;
    
    Ok(match rand {
        0 => MessageStatus::Pending,
        1 => MessageStatus::InTransit,
        2 => MessageStatus::Delivered,
        _ => MessageStatus::Failed,
    })
}

// ============================================================================
// Main App Component
// ============================================================================

#[component]
pub fn App() -> impl IntoView {
    let (messages, set_messages) = create_signal::<Vec<CrossChainMessage>>(Vec::new());
    let (is_dispatching, set_is_dispatching) = create_signal(false);
    let (notification, set_notification) = create_signal::<Option<String>>(None);

    // Handle message dispatch
    let dispatch_message = move |source: String, destination: String, content: String| {
        spawn_local(async move {
            set_is_dispatching.set(true);
            
            match dispatch_message_stub(source, destination, content).await {
                Ok(message) => {
                    set_messages.update(|msgs| {
                        msgs.push(message.clone());
                    });
                    set_notification.set(Some(format!("✅ Message dispatched! ID: {}", &message.id[..8])));
                    
                    // Clear notification after 5 seconds
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
                    set_notification.set(Some(format!("❌ Error: {}", e)));
                }
            }
            
            set_is_dispatching.set(false);
        });
    };

    // Periodic status polling for pending/in-transit messages
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
            
            {move || notification.get().map(|notif| {
                view! {
                    <div class="notification">
                        {notif}
                    </div>
                }
            })}

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
                    <ActivityLog messages=messages />
                </div>
            </div>
        </div>
    }
}

// ============================================================================
// Header Component
// ============================================================================

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

// ============================================================================
// Message Validation Helper
// ============================================================================

/// Validates message content to ensure it's meaningful and not gibberish
fn validate_message_content(content: &str) -> Result<(), String> {
    let trimmed = content.trim();
    
    // Check minimum length
    if trimmed.len() < 3 {
        return Err("Message is too short. Please provide a meaningful message.".to_string());
    }
    
    // Check if message contains at least some letters
    let letter_count = trimmed.chars().filter(|c| c.is_alphabetic()).count();
    if letter_count < 3 {
        return Err("Message must contain at least some letters.".to_string());
    }
    
    // Check for excessive repeated characters (like "aaaaaaa" or "111111")
    let mut consecutive_count = 1;
    let mut prev_char = '\0';
    for c in trimmed.chars() {
        if c == prev_char {
            consecutive_count += 1;
            if consecutive_count > 5 {
                return Err("Message contains too many repeated characters. Please provide a meaningful message.".to_string());
            }
        } else {
            consecutive_count = 1;
            prev_char = c;
        }
    }
    
    // Check for unreadable text - look for at least one vowel
    let has_vowels = trimmed.to_lowercase().chars()
        .any(|c| matches!(c, 'a' | 'e' | 'i' | 'o' | 'u'));
    
    if !has_vowels && letter_count > 5 {
        return Err("Message appears to be unreadable. Please use normal words.".to_string());
    }
    
    // Check for minimum word-like patterns (spaces or reasonable letter sequences)
    let words: Vec<&str> = trimmed.split_whitespace().collect();
    
    // If message is longer than 20 chars but has no spaces, might be gibberish
    if trimmed.len() > 20 && words.len() == 1 {
        // Check if it's just random characters mashed together
        let consonant_clusters = trimmed.to_lowercase()
            .chars()
            .filter(|c| c.is_alphabetic())
            .collect::<String>()
            .split(|c: char| matches!(c, 'a' | 'e' | 'i' | 'o' | 'u'))
            .filter(|s: &&str| s.len() > 6)
            .count();
        
        if consonant_clusters > 2 {
            return Err("Message appears to contain random characters. Please provide a meaningful message.".to_string());
        }
    }
    
    // Check for messages that are mostly non-alphanumeric gibberish
    let alnum_count = trimmed.chars().filter(|c| c.is_alphanumeric() || c.is_whitespace()).count();
    let alnum_ratio = alnum_count as f32 / trimmed.len() as f32;
    
    if alnum_ratio < 0.7 {
        return Err("Message contains too many special characters. Please use normal text.".to_string());
    }
    
    Ok(())
}

// ============================================================================
// Message Dispatcher Form Component
// ============================================================================

#[component]
fn MessageDispatcherForm<F>(
    on_dispatch: F,
    is_dispatching: ReadSignal<bool>,
) -> impl IntoView
where
    F: Fn(String, String, String) + 'static + Copy,
{
    let (source_chain, set_source_chain) = create_signal(String::from("paseo"));
    let (dest_chain, set_dest_chain) = create_signal(String::from("base-sepolia"));
    let (message_content, set_message_content) = create_signal(String::new());
    let (error, set_error) = create_signal::<Option<String>>(None);

    // Available chains (from Hyperbridge testnet docs)
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

        // Validation
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
        
        // Validate message content quality
        if let Err(validation_error) = validate_message_content(&content) {
            set_error.set(Some(validation_error));
            return;
        }

        // Dispatch the message
        on_dispatch(source, dest, content.clone());
        
        // Clear the form
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
                    on:change=move |ev| {
                        set_source_chain.set(event_target_value(&ev));
                    }
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
                    on:change=move |ev| {
                        set_dest_chain.set(event_target_value(&ev));
                    }
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
                    on:input=move |ev| {
                        set_message_content.set(event_target_value(&ev));
                    }
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
                {move || if is_dispatching.get() {
                    "Dispatching..."
                } else {
                    "Send Message 🚀"
                }}
            </button>
        </form>
    }
}

// ============================================================================
// Activity Log Component
// ============================================================================

#[component]
fn ActivityLog(messages: ReadSignal<Vec<CrossChainMessage>>) -> impl IntoView {
    view! {
        <div class="activity-log">
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

// ============================================================================
// Message Card Component
// ============================================================================

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

// ============================================================================
// Status Indicator Component
// ============================================================================

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
// WASM Entry Point - Auto-mount the app
// ============================================================================

#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
    web_sys::console::log_1(&"🚀 WASM loaded, mounting FULL Phase 1 UI with correct Leptos 0.6 API...".into());
    
    let document = web_sys::window()
        .unwrap()
        .document()
        .unwrap();
    
    let app_root = document.get_element_by_id("app-root")
        .expect("Could not find app-root element")
        .dyn_into::<web_sys::HtmlElement>()
        .expect("app-root is not an HtmlElement");
    
    // Use mount_to with the correct Leptos 0.6 API - no cx parameter needed!
    leptos::mount_to(app_root, App);
    
    web_sys::console::log_1(&"✅ Full Phase 1 UI mounted!".into());
}
