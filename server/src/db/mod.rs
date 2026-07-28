//! Store layer: all SQL lives here. Contract in docs/IMPLEMENTATION.md §DB.
//!
//! Conventions:
//! - Runtime queries only (`sqlx::query` / `query_as` / `query_scalar` with
//!   `.bind()`); no compile-time `query!` macros.
//! - Multi-statement invariants (approve, grant use, version append) run in
//!   explicit transactions; audit rows join the same transaction.
//! - Row structs mirror columns 1:1; higher layers convert to domain types.

pub mod api_ext;
pub mod clients;
pub mod grants;
pub mod policies;
pub mod requests;
pub mod secrets;
pub mod ui_ext;

#[cfg(test)]
mod tests;

pub use clients::{get_client_by_name, list_clients, reconcile_clients, ClientRow};
pub use grants::{
    begin_grant_use, get_grant, list_grants, purge_passthrough, revoke_grant,
    sweep_purge_passthroughs, GrantRow, GrantUse,
};
pub use policies::{delete_policy, insert_policy, list_policies, NewPolicy, PolicyRow};
pub use requests::{
    count_pending_for_client, expire_stale, get_request, increment_push_attempts,
    insert_access_request, list_pending, list_pending_needing_push, mark_push_delivered,
    purge_request_context, resolve_approve, resolve_deny, AccessRequestRow, GrantParams,
    InsertedRequest, NewAccessRequest, PassthroughPayload,
};
pub use secrets::{
    create_secret, get_secret_by_name, get_secret_version, get_secret_version_by_id,
    get_tags_for_secret, insert_secret_version, list_secrets, set_secret_tags, SecretRow,
    SecretVersionRow,
};
