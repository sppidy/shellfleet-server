//! Outbound webhook on update-window result. Wired in after the
//! existing `record_update_window_result` call so a Slack/Discord/
//! generic receiver can flag a failed run within seconds.
//!
//! Configuration via env (single global URL is enough for v1):
//!   UPDATE_WEBHOOK_URL    — full POST target. Empty/unset disables.
//!   UPDATE_WEBHOOK_FORMAT — "json" (default) or "slack".
//!
//! Both formats are fire-and-forget on a tokio task; failures are
//! audited as `webhook.update_result` with ok=0.

use serde::Serialize;
use sqlx::SqlitePool;

use crate::db;

const LOG_CAP: usize = 3_000;

#[derive(Serialize)]
struct JsonPayload<'a> {
    event: &'a str,
    agent_id: &'a str,
    status: &'a str,
    log: &'a str,
    error: Option<&'a str>,
    at: i64,
}

#[derive(Serialize)]
struct SlackPayload {
    text: String,
}

fn truncate(s: &str, cap: usize) -> String {
    if s.len() <= cap {
        s.to_string()
    } else {
        let cut = s.len() - cap;
        format!("…[{cut} bytes truncated]…\n{}", &s[s.len() - cap..])
    }
}

fn slack_text(agent_id: &str, status: &str, error: Option<&str>, log: &str) -> String {
    let icon = if status == "success" { ":white_check_mark:" } else { ":x:" };
    let mut text = format!(
        "{icon} *sys-manager apt upgrade* on `{agent_id}` → *{status}*"
    );
    if let Some(e) = error.filter(|s| !s.is_empty()) {
        text.push_str(&format!("\n> error: {e}"));
    }
    let tail: String = log.lines().rev().take(6).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n");
    if !tail.is_empty() {
        text.push_str(&format!("\n```\n{tail}\n```"));
    }
    text
}

/// Fire the webhook (if configured). Spawns a task and returns
/// immediately. Failures end up in the audit table.
pub fn fire_update_result(
    db: SqlitePool,
    agent_id: String,
    status: String,
    log: String,
    error: Option<String>,
    at: i64,
) {
    let url = match std::env::var("UPDATE_WEBHOOK_URL") {
        Ok(u) if !u.is_empty() => u,
        _ => return,
    };
    let format = std::env::var("UPDATE_WEBHOOK_FORMAT").unwrap_or_else(|_| "json".to_string());
    tokio::spawn(async move {
        let truncated = truncate(&log, LOG_CAP);
        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "webhook: client build failed");
                let _ = db::record_audit(
                    &db,
                    crate::now_unix(),
                    Some("webhook"),
                    Some(&agent_id),
                    "webhook.update_result",
                    false,
                    Some(&format!("client: {e}")),
                )
                .await;
                return;
            }
        };
        let req = match format.as_str() {
            "slack" => {
                let body = SlackPayload {
                    text: slack_text(&agent_id, &status, error.as_deref(), &truncated),
                };
                client.post(&url).json(&body)
            }
            _ => {
                let body = JsonPayload {
                    event: "update_window.result",
                    agent_id: &agent_id,
                    status: &status,
                    log: &truncated,
                    error: error.as_deref(),
                    at,
                };
                client.post(&url).json(&body)
            }
        };
        match req.send().await {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!(
                    %agent_id, %status, code = resp.status().as_u16(),
                    "webhook delivered"
                );
                db::record_audit(
                    &db,
                    crate::now_unix(),
                    Some("webhook"),
                    Some(&agent_id),
                    "webhook.update_result",
                    true,
                    Some(&format!("code={}", resp.status().as_u16())),
                )
                .await;
            }
            Ok(resp) => {
                let code = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let snippet = body.chars().take(200).collect::<String>();
                tracing::warn!(%agent_id, code, body = %snippet, "webhook non-2xx");
                db::record_audit(
                    &db,
                    crate::now_unix(),
                    Some("webhook"),
                    Some(&agent_id),
                    "webhook.update_result",
                    false,
                    Some(&format!("code={code} body={snippet}")),
                )
                .await;
            }
            Err(e) => {
                tracing::warn!(%agent_id, error = %e, "webhook send failed");
                db::record_audit(
                    &db,
                    crate::now_unix(),
                    Some("webhook"),
                    Some(&agent_id),
                    "webhook.update_result",
                    false,
                    Some(&format!("send: {e}")),
                )
                .await;
            }
        }
    });
}
