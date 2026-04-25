use axum::{
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    pub code: String,
    #[allow(dead_code)]
    pub state: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

#[derive(Debug, Deserialize)]
struct GithubTokenResponse {
    access_token: String,
}

#[derive(Debug, Deserialize)]
struct GithubUser {
    login: String,
}

pub fn auth_routes() -> Router {
    Router::new()
        .route("/login", get(login_handler))
        .route("/callback", get(callback_handler))
        .route("/logout", get(logout_handler))
}

fn allowed_users() -> Vec<String> {
    env::var("ALLOWED_GITHUB_USERS")
        .unwrap_or_else(|_| "sppidy".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn is_user_allowed(login: &str) -> bool {
    allowed_users().iter().any(|u| u == login)
}

fn cookie_secure() -> bool {
    // Honor an explicit override; default to secure since the public deploy is HTTPS-only.
    match env::var("COOKIE_SECURE").ok().as_deref() {
        Some("0") | Some("false") | Some("no") => false,
        _ => true,
    }
}

async fn login_handler() -> impl IntoResponse {
    let client_id = env::var("GITHUB_CLIENT_ID").unwrap_or_else(|_| "dummy_id".to_string());
    let redirect_uri = env::var("OAUTH_REDIRECT_URL")
        .unwrap_or_else(|_| "https://dashboard.example.com/auth/callback".to_string());

    let redirect_url = format!(
        "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&state=sysmanager&scope=read:user",
        client_id,
        urlencoding::encode(&redirect_uri)
    );

    Redirect::temporary(&redirect_url)
}

async fn logout_handler(jar: CookieJar) -> impl IntoResponse {
    let mut cookie = Cookie::build(("auth_token", ""))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(cookie_secure())
        .build();
    cookie.make_removal();

    let ui_url = env::var("UI_URL").unwrap_or_else(|_| "https://dashboard.example.com/".to_string());
    let login_url = format!("{}login", ui_url);
    (jar.add(cookie), Redirect::temporary(&login_url)).into_response()
}

async fn callback_handler(jar: CookieJar, Query(query): Query<AuthRequest>) -> Response {
    println!("Received GitHub OAuth callback");

    let client_id = env::var("GITHUB_CLIENT_ID").unwrap_or_else(|_| "dummy_id".to_string());
    let client_secret =
        env::var("GITHUB_CLIENT_SECRET").unwrap_or_else(|_| "dummy_secret".to_string());

    let client = reqwest::Client::new();

    let token_res = match client
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .form(&[
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("code", query.code),
        ])
        .send()
        .await
    {
        Ok(res) => res,
        Err(e) => {
            eprintln!("Failed to exchange token: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to get access token")
                .into_response();
        }
    };

    let token_data = match token_res.json::<GithubTokenResponse>().await {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to parse token response: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to parse access token")
                .into_response();
        }
    };

    let user_res = match client
        .get("https://api.github.com/user")
        .header("Authorization", format!("Bearer {}", token_data.access_token))
        .header("User-Agent", "sys-manager")
        .send()
        .await
    {
        Ok(res) => res,
        Err(e) => {
            eprintln!("Failed to fetch user profile: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to get user profile")
                .into_response();
        }
    };

    let user_data = match user_res.json::<GithubUser>().await {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to parse user profile: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to parse user profile")
                .into_response();
        }
    };

    if !is_user_allowed(&user_data.login) {
        println!("Unauthorized user attempted login: {}", user_data.login);
        return (
            StatusCode::UNAUTHORIZED,
            "Unauthorized user. Your GitHub account is not on the allowlist.",
        )
            .into_response();
    }

    let expiration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize
        + 24 * 3600;

    let claims = Claims {
        sub: user_data.login,
        exp: expiration,
    };

    let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "supersecretkey".to_string());
    let token = match encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    ) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to issue JWT: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to issue session token")
                .into_response();
        }
    };

    let cookie = Cookie::build(("auth_token", token))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(cookie_secure())
        .build();

    let ui_url = env::var("UI_URL").unwrap_or_else(|_| "https://dashboard.example.com/".to_string());

    (jar.add(cookie), Redirect::temporary(&ui_url)).into_response()
}

fn decode_claims(token: &str) -> Option<Claims> {
    let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "supersecretkey".to_string());
    let mut validation = Validation::default();
    validation.validate_exp = true;
    validation.validate_nbf = false;

    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .ok()
    .map(|d| d.claims)
}

pub fn verify_token(token: &str) -> bool {
    decode_claims(token)
        .map(|c| is_user_allowed(&c.sub))
        .unwrap_or(false)
}

pub fn user_from_token(token: &str) -> Option<String> {
    decode_claims(token).and_then(|c| {
        if is_user_allowed(&c.sub) {
            Some(c.sub)
        } else {
            None
        }
    })
}
