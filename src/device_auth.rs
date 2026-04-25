use axum::{
    extract::State,
    response::IntoResponse,
    routing::post,
    Router,
    Json,
};
use axum_extra::extract::cookie::CookieJar;
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{auth::verify_token, db, AppState};

#[derive(Serialize)]
pub struct DeviceAuthResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
    pub interval: u64,
}

#[derive(Deserialize)]
pub struct DeviceTokenRequest {
    pub device_code: String,
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum DeviceTokenResponse {
    Token { access_token: String, token_type: String },
    Error { error: String },
}

#[derive(Deserialize)]
pub struct ApproveDeviceRequest {
    pub user_code: String,
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/request", post(request_device_auth))
        .route("/token", post(poll_device_token))
        .route("/approve", post(approve_device))
}

async fn request_device_auth(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let (device_code, user_code) = {
        let mut rng = rand::thread_rng();
        let d_code: String = (&mut rng).sample_iter(&Alphanumeric).take(32).map(char::from).collect();
        let raw_user_code: String = (&mut rng).sample_iter(&Alphanumeric).take(8).map(char::from).collect();
        let u_code = format!("{}-{}", &raw_user_code[0..4], &raw_user_code[4..8]).to_uppercase();
        (d_code, u_code)
    };

    let expires_in = 300; // 5 minutes
    let expires_at = crate::now_unix() + expires_in as i64;

    if let Err(e) = db::insert_pending_device(&state.db, &device_code, &user_code, expires_at).await
    {
        tracing::error!(error = %e, "insert pending device failed");
        return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
    }

    let verification_uri = std::env::var("UI_URL").unwrap_or_else(|_| "https://dashboard.example.com/".to_string()) + "device";

    Json(DeviceAuthResponse {
        device_code,
        user_code,
        verification_uri,
        expires_in,
        interval: 5,
    })
    .into_response()
}

async fn poll_device_token(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<DeviceTokenRequest>,
) -> impl IntoResponse {
    let now = crate::now_unix();
    let row = match db::pending_device(&state.db, &payload.device_code).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "pending_device lookup failed");
            return Json(DeviceTokenResponse::Error { error: "server_error".to_string() })
                .into_response();
        }
    };

    let Some(row) = row else {
        return Json(DeviceTokenResponse::Error { error: "invalid_grant".to_string() })
            .into_response();
    };

    if now > row.expires_at {
        let _ = db::delete_pending_device(&state.db, &row.device_code).await;
        return Json(DeviceTokenResponse::Error { error: "expired_token".to_string() })
            .into_response();
    }

    if row.approved == 0 {
        return Json(DeviceTokenResponse::Error {
            error: "authorization_pending".to_string(),
        })
        .into_response();
    }

    // Approved — mint a fresh access token, persist it, and clean up the
    // pending row.
    let token: String = {
        let mut rng = rand::thread_rng();
        (&mut rng)
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect()
    };

    if let Err(e) = db::insert_token(&state.db, &token, now).await {
        tracing::error!(error = %e, "insert token failed");
        return Json(DeviceTokenResponse::Error { error: "server_error".to_string() })
            .into_response();
    }
    let _ = db::delete_pending_device(&state.db, &row.device_code).await;

    db::record_audit(
        &state.db,
        now,
        None,
        None,
        "device.token.issued",
        true,
        Some(&format!("user_code={}", row.user_code)),
    )
    .await;

    Json(DeviceTokenResponse::Token {
        access_token: token,
        token_type: "bearer".to_string(),
    })
    .into_response()
}

async fn approve_device(
    jar: CookieJar,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ApproveDeviceRequest>,
) -> impl IntoResponse {
    let mut actor: Option<String> = None;
    if std::env::var("JWT_SECRET").unwrap_or_default() == "dev" {
        actor = Some("dev".to_string());
    } else if let Some(cookie) = jar.get("auth_token") {
        if verify_token(cookie.value()) {
            actor = crate::auth::user_from_token(cookie.value());
        }
    }
    if actor.is_none() {
        return (axum::http::StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    let user_code = payload.user_code.to_uppercase();
    let now = crate::now_unix();
    let approved = match db::approve_user_code(&state.db, &user_code, now).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "approve_user_code failed");
            return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
        }
    };

    if approved {
        db::record_audit(
            &state.db,
            now,
            actor.as_deref(),
            None,
            "device.approve",
            true,
            Some(&format!("user_code={user_code}")),
        )
        .await;
        (axum::http::StatusCode::OK, "Approved").into_response()
    } else {
        (axum::http::StatusCode::BAD_REQUEST, "Invalid or expired code").into_response()
    }
}
