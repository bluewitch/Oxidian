//! Local inventory API. `/health` is open. Inventory routes require a bearer token.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::State;
use axum::http::{header::AUTHORIZATION, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use oxidian_core::{Asset, Finding, Inventory, InventoryError};
use serde::Serialize;
use thiserror::Error;

/// The API could not be configured.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("API token must be at least 16 characters and contain no whitespace")]
    WeakToken,
}

#[derive(Clone)]
pub struct AppState {
    token: String,
    inventory: Arc<dyn Inventory>,
}

impl AppState {
    pub fn new(token: impl Into<String>, inventory: Arc<dyn Inventory>) -> Result<Self, Error> {
        let token = token.into();
        if token.len() < 16 || token.chars().any(char::is_whitespace) {
            return Err(Error::WeakToken);
        }
        Ok(Self { token, inventory })
    }
}

pub fn router(state: AppState) -> Router {
    let authed = Router::new()
        .route("/assets", get(list_assets))
        .route("/findings", get(list_findings))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_bearer,
        ));
    Router::new()
        .route("/health", get(health))
        .merge(authed)
        .with_state(state)
}

pub async fn serve(state: AppState, bind: SocketAddr) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, router(state))
        .await
        .map_err(std::io::Error::other)
}

async fn health() -> Json<StatusBody> {
    Json(StatusBody { status: "ok" })
}

async fn list_assets(State(state): State<AppState>) -> Response {
    match state.inventory.list_assets().await {
        Ok(assets) => Json(assets).into_response(),
        Err(err) => inventory_failure(&err),
    }
}

async fn list_findings(State(state): State<AppState>) -> Response {
    match state.inventory.list_findings().await {
        Ok(findings) => Json(findings).into_response(),
        Err(err) => inventory_failure(&err),
    }
}

fn inventory_failure(err: &InventoryError) -> Response {
    eprintln!("oxidian api: {}", err.detail());
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorBody {
            error: "inventory unavailable",
        }),
    )
        .into_response()
}

async fn require_bearer(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let presented = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    if bearer_ok(presented, &state.token) {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: "unauthorized",
            }),
        )
            .into_response()
    }
}

fn bearer_ok(presented: Option<&str>, token: &str) -> bool {
    let Some(rest) = presented.and_then(|value| value.strip_prefix("Bearer ")) else {
        return false;
    };
    if rest.len() != token.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in rest.as_bytes().iter().zip(token.as_bytes()) {
        diff |= left ^ right;
    }
    diff == 0
}

#[derive(Serialize)]
struct StatusBody {
    status: &'static str,
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
}

/// In-memory inventory for tests and for running the API without Postgres.
pub struct MemoryInventory {
    pub assets: Vec<Asset>,
    pub findings: Vec<Finding>,
    fail: bool,
}

impl MemoryInventory {
    pub fn new(assets: Vec<Asset>, findings: Vec<Finding>) -> Self {
        Self {
            assets,
            findings,
            fail: false,
        }
    }

    pub fn failing() -> Self {
        Self {
            assets: Vec::new(),
            findings: Vec::new(),
            fail: true,
        }
    }
}

#[async_trait]
impl Inventory for MemoryInventory {
    async fn list_assets(&self) -> Result<Vec<Asset>, InventoryError> {
        if self.fail {
            Err(InventoryError::new("database offline"))
        } else {
            Ok(self.assets.clone())
        }
    }

    async fn list_findings(&self) -> Result<Vec<Finding>, InventoryError> {
        if self.fail {
            Err(InventoryError::new("database offline"))
        } else {
            Ok(self.findings.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn state(fail: bool) -> AppState {
        let inventory: Arc<dyn Inventory> = if fail {
            Arc::new(MemoryInventory::failing())
        } else {
            Arc::new(MemoryInventory::new(Vec::new(), Vec::new()))
        };
        AppState::new("test-token-value", inventory).unwrap()
    }

    async fn body_text(response: Response) -> String {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn health_is_open_and_inventory_requires_the_token() {
        let app = router(state(false));
        let health = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);
        assert!(body_text(health).await.contains("ok"));

        let denied = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/assets")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

        let allowed = app
            .oneshot(
                Request::builder()
                    .uri("/findings")
                    .header(AUTHORIZATION, "Bearer test-token-value")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);
        assert_eq!(body_text(allowed).await, "[]");
    }

    #[tokio::test]
    async fn inventory_errors_do_not_leak_the_detail() {
        let app = router(state(true));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/assets")
                    .header(AUTHORIZATION, "Bearer test-token-value")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let text = body_text(response).await;
        assert!(text.contains("inventory unavailable"));
        assert!(!text.contains("database offline"));
    }

    #[test]
    fn weak_tokens_are_rejected() {
        let inventory: Arc<dyn Inventory> = Arc::new(MemoryInventory::new(Vec::new(), Vec::new()));
        assert!(AppState::new("short", inventory.clone()).is_err());
        assert!(AppState::new("token with spaces!!", inventory).is_err());
    }
}
