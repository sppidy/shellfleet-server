use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::{get, post}, Json, Router};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{auth::verify_token, AppState};

/// Per-token metadata persisted alongside the token itself. The previous
/// schema stored `bool`; load_tokens still accepts that for migration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenInfo {
    /// Unix seconds of approval. 0 for legacy tokens migrated from the
    /// boolean schema.
    #[serde(default)]
    pub created_at: u64,
    /// Hostname reported by the agent the last time it registered. Filled
    /// in by handle_agent_socket so the operator can identify which entry
    /// corresponds to which host when revoking.
    #[serde(default)]
    pub hostname: Option<String>,
    /// Unix seconds of the last successful WebSocket handshake.
    #[serde(default)]
    pub last_seen: u64,
}

#[derive(Serialize)]
struct TokenRow {
    token_preview: String,
    hostname: Option<String>,
    created_at: u64,
    last_seen: u64,
}

#[derive(Deserialize)]
struct RevokeRequest {
    /// Full token string. Takes priority over `hostname` if both are sent.
    #[serde(default)]
    token: Option<String>,
    /// Hostname previously announced by an agent. Useful from the dashboard
    /// where the operator only sees the token preview.
    #[serde(default)]
    hostname: Option<String>,
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(list_tokens))
        .route("/revoke", post(revoke_token))
}

fn require_auth(jar: &CookieJar) -> bool {
    if std::env::var("JWT_SECRET").unwrap_or_default() == "dev" {
        return true;
    }
    jar.get("auth_token")
        .map(|c| verify_token(c.value()))
        .unwrap_or(false)
}

fn preview(token: &str) -> String {
    let chars: Vec<char> = token.chars().collect();
    if chars.len() <= 12 {
        return "*".repeat(chars.len());
    }
    let head: String = chars.iter().take(4).collect();
    let tail: String = chars.iter().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
    format!("{head}…{tail}")
}

async fn list_tokens(jar: CookieJar, State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if !require_auth(&jar) {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }
    let tokens = state.approved_tokens.read().await;
    let mut rows: Vec<TokenRow> = tokens
        .iter()
        .map(|(token, info)| TokenRow {
            token_preview: preview(token),
            hostname: info.hostname.clone(),
            created_at: info.created_at,
            last_seen: info.last_seen,
        })
        .collect();
    rows.sort_by(|a, b| {
        b.last_seen
            .cmp(&a.last_seen)
            .then_with(|| b.created_at.cmp(&a.created_at))
    });
    Json(rows).into_response()
}

async fn revoke_token(
    jar: CookieJar,
    State(state): State<Arc<AppState>>,
    Json(req): Json<RevokeRequest>,
) -> impl IntoResponse {
    if !require_auth(&jar) {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }
    if req.token.is_none() && req.hostname.is_none() {
        return (StatusCode::BAD_REQUEST, "Provide either token or hostname").into_response();
    }

    let removed = {
        let mut tokens = state.approved_tokens.write().await;
        if let Some(token) = req.token.as_ref() {
            tokens.remove(token).is_some()
        } else if let Some(hostname) = req.hostname.as_ref() {
            // Match exactly. Multiple tokens for the same hostname can
            // legitimately exist (e.g. after a re-pair) — drop them all so
            // a stale token can't quietly outlive a "revoke" click.
            let to_remove: Vec<String> = tokens
                .iter()
                .filter(|(_, info)| info.hostname.as_deref() == Some(hostname.as_str()))
                .map(|(k, _)| k.clone())
                .collect();
            let count = to_remove.len();
            for k in to_remove {
                tokens.remove(&k);
            }
            count > 0
        } else {
            false
        }
    };

    if removed {
        let snapshot = state.approved_tokens.read().await.clone();
        if let Err(e) = crate::save_tokens(&snapshot) {
            tracing::error!(error = %e, "failed to persist tokens after revoke");
        }
        tracing::info!(
            token = ?req.token.as_deref().map(preview),
            hostname = ?req.hostname,
            "token revoked"
        );
        return (StatusCode::OK, "Revoked").into_response();
    }
    (StatusCode::NOT_FOUND, "No matching token").into_response()
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
