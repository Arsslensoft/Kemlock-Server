//! The federation view in a request, as the Kemlock API reads it: the server layers an
//! `Extension<SharedView>` on the merged router when federation is wired. A server without
//! federation provides none, and the routes behave as they did.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use kemlock_app::federation_view::SharedView;
use std::convert::Infallible;

/// The federation view, if the server provided one. Never rejects.
#[derive(Clone)]
pub(crate) struct MaybeView(pub(crate) Option<SharedView>);

impl<St: Send + Sync> FromRequestParts<St> for MaybeView {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &St) -> Result<Self, Infallible> {
        Ok(MaybeView(parts.extensions.get::<SharedView>().cloned()))
    }
}
