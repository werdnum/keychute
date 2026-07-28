//! Authentication.
//!
//! - `client`: machine clients — static API tokens (SHA-256 hash lookup) and
//!   Kubernetes TokenReview per docs/IMPLEMENTATION.md addendum #3.
//! - `human`: approval-UI principals — static bearer (dev/e2e) or OIDC JWT
//!   validation with an authorization allowlist.

pub mod client;
pub mod human;
