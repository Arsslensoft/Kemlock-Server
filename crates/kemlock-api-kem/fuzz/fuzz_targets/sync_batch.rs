//! Sync batches and cursors: a batch of item writes, and the `since` of a sync query.

#![no_main]

use kemlock_api_kem::dto::{BatchRequest, SyncQuery};
use kemlock_app::b64url;
use kemlock_domain::{Revision, SyncCursor};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(batch) = serde_json::from_slice::<BatchRequest>(data) {
        for write in batch.writes {
            let expected = write.expected_revision.map(Revision);
            let _ = write.item.into_write(expected);
        }
    }
    if let Ok(query) = serde_json::from_slice::<SyncQuery>(data)
        && let Some(bytes) = query.since.as_deref().and_then(b64url::decode)
    {
        let _ = SyncCursor::from_cursor_bytes(&bytes);
    }
});
