//! The federation view in a request: the server layers an `Extension<SharedView>` on the merged
//! router when federation is wired, and the failover routes read it here. A server without
//! federation provides none, and the routes then answer as if there were nothing to report.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use kemlock_app::federation_view::SharedView;
use std::convert::Infallible;

/// The federation view, if the server provided one. Never rejects.
#[derive(Clone)]
pub(crate) struct MaybeView(pub(crate) Option<SharedView>);

impl std::fmt::Debug for MaybeView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("MaybeView").field(&self.0.is_some()).finish()
    }
}

impl<St: Send + Sync> FromRequestParts<St> for MaybeView {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &St) -> Result<Self, Infallible> {
        Ok(MaybeView(parts.extensions.get::<SharedView>().cloned()))
    }
}
