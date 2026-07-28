//! Client-facing REST API. STUB — implemented by the API task.

use crate::state::AppState;
use axum::Router;

pub fn router(_state: AppState) -> Router {
    Router::new().route(
        "/healthz",
        axum::routing::get(|| async { "ok" }),
    )
}
