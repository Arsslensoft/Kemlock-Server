//! Maps what the database says to what the ports promise.

use kemlock_app::ports::StoreError;
use sea_orm::{DbErr, SqlErr};

/// A unique violation is `Duplicate`; a foreign key violation means the row it points at is gone,
/// so `NotFound`; anything else is a `Backend` failure whose message goes to the logs.
pub(crate) fn map_db(err: DbErr) -> StoreError {
    match err.sql_err() {
        Some(SqlErr::UniqueConstraintViolation(_)) => StoreError::Duplicate,
        Some(SqlErr::ForeignKeyConstraintViolation(_)) => StoreError::NotFound,
        _ => StoreError::Backend(err.to_string()),
    }
}

/// Whether the error is a unique-key violation, for code that handles a lost race itself.
pub(crate) fn is_unique_violation(err: &DbErr) -> bool {
    matches!(err.sql_err(), Some(SqlErr::UniqueConstraintViolation(_)))
}

/// `result.store()?` turns a SeaORM error into a `StoreError`.
pub(crate) trait StoreResult<T> {
    fn store(self) -> Result<T, StoreError>;
}

impl<T> StoreResult<T> for Result<T, DbErr> {
    fn store(self) -> Result<T, StoreError> {
        self.map_err(map_db)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn other_errors_are_backend_failures() {
        let err = map_db(DbErr::Custom("boom".to_owned()));
        assert_eq!(err, StoreError::Backend("Custom Error: boom".to_owned()));
        assert!(!is_unique_violation(&DbErr::Custom("x".to_owned())));
    }
}
