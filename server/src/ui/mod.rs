//! Approval UI (server-rendered). STUB — implemented by the UI task.

use crate::state::AppState;
use axum::Router;

pub fn router(_state: AppState) -> Router {
    Router::new()
}
