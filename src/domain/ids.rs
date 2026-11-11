//! Typed identifiers for persisted entities.

use uuid::Uuid;

/// Create a new time-ordered identifier.
pub fn new_id() -> Uuid {
    Uuid::now_v7()
}
