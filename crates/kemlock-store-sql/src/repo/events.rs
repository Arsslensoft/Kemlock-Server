//! `EventLog` on `events`. An event written while a request is being served (see
//! [`crate::with_request_ip`]) carries the client's address, truncated by the privacy port.

use crate::request_ip::request_ip;
use crate::store::SqlStore;
use kemlock_app::ports::{Event, EventLog, StoreError};
use kemlock_app::privacy::PrivacyLog;

impl EventLog for SqlStore {
    async fn record(&self, event: Event) -> Result<(), StoreError> {
        PrivacyLog::record_event(self, event, request_ip()).await
    }
}
