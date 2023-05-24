use crate::{
    helpers::Transport,
    net::{
        http_serde,
        server::{ClientIdentity, Error},
        HttpTransport,
    },
    sync::Arc,
};
use axum::{extract::BodyStream, routing::post, Extension, Router};

#[allow(clippy::unused_async)] // axum doesn't like synchronous handler
async fn handler(
    transport: Extension<Arc<HttpTransport>>,
    from: Extension<ClientIdentity>,
    req: http_serde::query::step::Request<BodyStream>,
) -> Result<(), Error> {
    let transport = Transport::clone_ref(&*transport);
    transport.receive_stream(req.query_id, req.step, **from, req.body);
    Ok(())
}

pub fn router(transport: Arc<HttpTransport>) -> Router {
    Router::new()
        .route(http_serde::query::step::AXUM_PATH, post(handler))
        .layer(Extension(transport))
}

#[cfg(all(test, not(feature = "shuttle"), feature = "in-memory-infra"))]
mod tests {
    use std::{future::ready, task::Poll};

    use super::*;
    use crate::{
        helpers::{HelperIdentity, MESSAGE_PAYLOAD_SIZE_BYTES},
        net::{
            server::handlers::query::{
                test_helpers::{assert_req_fails_with, IntoFailingReq},
                MaybeExtensionExt,
            },
            test::{body_stream, TestServer},
        },
        protocol::{
            step::{self, StepNarrow},
            QueryId,
        },
    };
    use axum::http::Request;
    use futures::{
        stream::{once, poll_immediate},
        StreamExt,
    };
    use hyper::{Body, StatusCode};

    const DATA_LEN: usize = 3;

    #[tokio::test]
    async fn step() {
        let TestServer { transport, .. } = TestServer::builder().build().await;

        let step = step::Descriptive::default().narrow("test");
        let payload = vec![213; DATA_LEN * MESSAGE_PAYLOAD_SIZE_BYTES];
        let req = http_serde::query::step::Request::new(
            QueryId,
            step.clone(),
            body_stream(Box::new(once(ready(Ok(payload.clone().into()))))).await,
        );

        handler(
            Extension(Arc::clone(&transport)),
            Extension(ClientIdentity(HelperIdentity::TWO)),
            req,
        )
        .await
        .unwrap();

        let mut stream = Arc::clone(&transport).receive(HelperIdentity::TWO, (QueryId, step));

        assert_eq!(
            poll_immediate(&mut stream).next().await,
            Some(Poll::Ready(payload))
        );
    }

    struct OverrideReq {
        client_id: Option<ClientIdentity>,
        query_id: String,
        step: step::Descriptive,
        payload: Vec<u8>,
    }

    impl IntoFailingReq for OverrideReq {
        fn into_req(self, port: u16) -> Request<Body> {
            let uri = format!(
                "http://localhost:{}{}/{}/step/{}",
                port,
                http_serde::query::BASE_AXUM_PATH,
                self.query_id,
                self.step.as_ref()
            );
            hyper::Request::post(uri)
                .maybe_extension(self.client_id)
                .body(hyper::Body::from(self.payload))
                .unwrap()
        }
    }

    impl Default for OverrideReq {
        fn default() -> Self {
            Self {
                client_id: Some(ClientIdentity(HelperIdentity::ONE)),
                query_id: QueryId.as_ref().to_string(),
                step: step::Descriptive::default().narrow("test"),
                payload: vec![1; DATA_LEN * MESSAGE_PAYLOAD_SIZE_BYTES],
            }
        }
    }

    #[tokio::test]
    async fn malformed_query_id_fails() {
        let req = OverrideReq {
            query_id: "not-a-query-id".into(),
            ..Default::default()
        };
        assert_req_fails_with(req, StatusCode::UNPROCESSABLE_ENTITY).await;
    }

    #[tokio::test]
    async fn auth_required() {
        let req = OverrideReq {
            client_id: None,
            ..Default::default()
        };
        assert_req_fails_with(req, StatusCode::UNAUTHORIZED).await;
    }
}
