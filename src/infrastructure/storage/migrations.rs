//! Ordered SQL migrations.

use rusqlite::{Connection, params};
use thiserror::Error;

use crate::domain::time::now_ms;

#[derive(Debug, Error)]
pub enum MigrationError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("schema version {found} is newer than this binary supports ({supported})")]
    NewerSchema { found: i64, supported: i64 },
}

struct Migration {
    version: i64,
    name: &'static str,
    sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "0001_discovery",
    sql: include_str!("migrations/0001_discovery.sql"),
}];

pub fn supported_version() -> i64 {
    MIGRATIONS.last().map_or(0, |migration| migration.version)
}

pub fn migrate(connection: &mut Connection) -> Result<(), MigrationError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version       INTEGER PRIMARY KEY,
            name          TEXT NOT NULL,
            applied_at_ms INTEGER NOT NULL
        );",
    )?;

    let current: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    let supported = supported_version();
    if current > supported {
        return Err(MigrationError::NewerSchema {
            found: current,
            supported,
        });
    }

    for migration in MIGRATIONS {
        if migration.version <= current {
            continue;
        }
        let transaction = connection.transaction()?;
        transaction.execute_batch(migration.sql)?;
        transaction.execute(
            "INSERT INTO schema_migrations (version, name, applied_at_ms) VALUES (?1, ?2, ?3)",
            params![migration.version, migration.name, now_ms()],
        )?;
        transaction.pragma_update(None, "user_version", migration.version)?;
        transaction.commit()?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use super::{migrate, supported_version};

    #[test]
    fn applies_migrations_once() {
        let mut connection = Connection::open_in_memory().unwrap();
        migrate(&mut connection).unwrap();
        migrate(&mut connection).unwrap();

        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, supported_version());

        let tables: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='devices'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tables, 1);
    }
}
