// there isn't an easy way to compose const strings at compile time, so we will hard-code
// everything

pub mod echo {
    pub const AXUM_PATH: &str = "/echo";

    pub fn uri(payload: &str) -> String {
        format!("/echo?foo={payload}")
    }
}

pub mod query {
    use crate::{
        ff::FieldType,
        helpers::{
            query::{IPAQueryConfig, QueryConfig, QueryType},
            HelperIdentity,
        },
        net::server,
    };
    use async_trait::async_trait;
    use axum::extract::{FromRequest, Query, RequestParts};
    use hyper::header::HeaderName;
    use std::fmt::{Display, Formatter};
    use std::str::FromStr;

    /// wrapper around [`QueryConfig`] to enable extraction from an `Axum` request. To be used with
    /// the `create` and `prepare` commands
    struct QueryConfigQueryParams(pub QueryConfig);

    impl std::ops::Deref for QueryConfigQueryParams {
        type Target = QueryConfig;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    #[async_trait]
    impl<B: Send> FromRequest<B> for QueryConfigQueryParams {
        type Rejection = server::Error;

        async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
            #[derive(serde::Deserialize)]
            struct QueryTypeParam {
                field_type: FieldType,
                query_type: String,
            }
            let Query(QueryTypeParam {
                field_type,
                query_type,
            }) = req.extract().await?;

            let query_type = match query_type.as_str() {
                #[cfg(any(test, feature = "cli", feature = "test-fixture"))]
                QueryType::TEST_MULTIPLY_STR => Ok(QueryType::TestMultiply),
                QueryType::IPA_STR => {
                    #[derive(serde::Deserialize)]
                    struct IPAQueryConfigParam {
                        num_bits: u32,
                        per_user_credit_cap: u32,
                        max_breakdown_key: u128,
                    }
                    let Query(IPAQueryConfigParam {
                        num_bits,
                        per_user_credit_cap,
                        max_breakdown_key,
                    }) = req.extract().await?;

                    Ok(QueryType::IPA(IPAQueryConfig {
                        num_bits,
                        per_user_credit_cap,
                        max_breakdown_key,
                    }))
                }
                other => Err(server::Error::bad_query_value("query_type", other)),
            }?;
            Ok(QueryConfigQueryParams(QueryConfig {
                field_type,
                query_type,
            }))
        }
    }

    impl Display for QueryConfigQueryParams {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "field-type={}&", self.field_type.as_ref())?;
            match self.query_type {
                QueryType::TestMultiply => write!(f, "query-type={}", QueryType::TEST_MULTIPLY_STR),
                QueryType::IPA(config) => write!(
                    f,
                    "query-type={}&num-bits={}&per-user-credit-cap={}&max-breakdown-key={}",
                    QueryType::IPA_STR,
                    config.num_bits,
                    config.per_user_credit_cap,
                    config.max_breakdown_key
                ),
            }
        }
    }

    /// name of the `origin` header to use for [`OriginHeader`]
    static ORIGIN_HEADER_NAME: HeaderName = HeaderName::from_static("origin");

    fn get_header<B, H: FromStr>(
        req: &RequestParts<B>,
        header_name: HeaderName,
    ) -> Result<H, server::Error>
    where
        server::Error: From<<H as FromStr>::Err>,
    {
        let header_name_string = header_name.to_string();
        req.headers()
            .get(header_name)
            .ok_or(server::Error::MissingHeader(header_name_string))
            .and_then(|header_value| header_value.to_str().map_err(Into::into))
            .and_then(|header_value_str| header_value_str.parse().map_err(Into::into))
    }

    /// Header indicating the originating `HelperIdentity`.
    /// May be replaced in the future with a method with better security
    #[cfg_attr(feature = "enable-serde", derive(serde::Deserialize))]
    struct OriginHeader {
        origin: HelperIdentity,
    }

    impl OriginHeader {
        fn add_to(self, req: axum::http::request::Builder) -> axum::http::request::Builder {
            req.header(ORIGIN_HEADER_NAME.clone(), self.origin)
        }
    }

    #[async_trait]
    impl<B: Send> FromRequest<B> for OriginHeader {
        type Rejection = server::Error;

        async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
            let origin: usize = get_header(req, ORIGIN_HEADER_NAME.clone())?;
            let origin = HelperIdentity::try_from(origin)
                .map_err(|err| server::Error::InvalidHeader(err.into()))?;
            Ok(OriginHeader { origin })
        }
    }

    pub const BASE_AXUM_PATH: &str = "/query";

    pub mod create {
        use crate::{
            helpers::query::QueryConfig,
            net::{
                client,
                http_serde::query::{server, QueryConfigQueryParams, BASE_AXUM_PATH},
            },
            protocol::QueryId,
        };
        use async_trait::async_trait;
        use axum::extract::{FromRequest, RequestParts};
        use hyper::http::uri;

        pub struct Request {
            pub query_config: QueryConfig,
        }

        impl Request {
            pub fn new(query_config: QueryConfig) -> Request {
                Request { query_config }
            }

            pub fn try_into_http_request(
                self,
                scheme: uri::Scheme,
                authority: uri::Authority,
            ) -> Result<hyper::Request<hyper::Body>, client::Error> {
                let uri = uri::Builder::new()
                    .scheme(scheme)
                    .authority(authority)
                    .path_and_query(format!(
                        "{}?{}",
                        BASE_AXUM_PATH,
                        QueryConfigQueryParams(self.query_config)
                    ))
                    .build()?;
                Ok(hyper::Request::post(uri).body(hyper::Body::empty())?)
            }
        }

        #[async_trait]
        impl<B: Send> FromRequest<B> for Request {
            type Rejection = server::Error;

            async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
                let QueryConfigQueryParams(query_config) = req.extract().await?;
                Ok(Self { query_config })
            }
        }

        #[cfg_attr(feature = "enable-serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct ResponseBody {
            pub query_id: QueryId,
        }

        pub const AXUM_PATH: &str = "/";
    }

    pub mod prepare {
        use crate::{
            helpers::{query::PrepareQuery, HelperIdentity, RoleAssignment},
            net::{
                client,
                http_serde::query::{OriginHeader, QueryConfigQueryParams, BASE_AXUM_PATH},
                server,
            },
        };
        use async_trait::async_trait;
        use axum::{
            extract::{FromRequest, Path, RequestParts},
            http::uri,
            Json,
        };
        use hyper::{header::CONTENT_TYPE, Body};

        pub struct Request {
            pub origin: HelperIdentity,
            pub data: PrepareQuery,
        }

        impl Request {
            pub fn new(origin: HelperIdentity, data: PrepareQuery) -> Self {
                Self { origin, data }
            }
            pub fn try_into_http_request(
                self,
                scheme: uri::Scheme,
                authority: uri::Authority,
            ) -> Result<hyper::Request<hyper::Body>, client::Error> {
                let uri = uri::Uri::builder()
                    .scheme(scheme)
                    .authority(authority)
                    .path_and_query(format!(
                        "{}/{}?{}",
                        BASE_AXUM_PATH,
                        self.data.query_id.as_ref(),
                        QueryConfigQueryParams(self.data.config),
                    ))
                    .build()?;
                let origin_header = OriginHeader {
                    origin: self.origin,
                };
                let body = RequestBody {
                    roles: self.data.roles,
                };
                let body = hyper::Body::from(serde_json::to_string(&body)?);
                Ok(origin_header
                    .add_to(hyper::Request::post(uri))
                    .header(CONTENT_TYPE, "application/json")
                    .body(body)?)
            }
        }

        #[async_trait]
        impl FromRequest<Body> for Request {
            type Rejection = server::Error;

            async fn from_request(req: &mut RequestParts<Body>) -> Result<Self, Self::Rejection> {
                let Path(query_id) = req.extract().await?;
                let QueryConfigQueryParams(config) = req.extract().await?;
                let origin_header = req.extract::<OriginHeader>().await?;
                let Json(RequestBody { roles }) = req.extract().await?;
                Ok(Request {
                    origin: origin_header.origin,
                    data: PrepareQuery {
                        query_id,
                        config,
                        roles,
                    },
                })
            }
        }

        #[cfg_attr(feature = "enable-serde", derive(serde::Serialize, serde::Deserialize))]
        struct RequestBody {
            roles: RoleAssignment,
        }

        pub const AXUM_PATH: &str = "/:query_id";
    }

    pub mod input {
        use crate::{
            ff::FieldType,
            helpers::{query::QueryInput, transport::ByteArrStream, TransportError},
            net::{client, http_serde::query::BASE_AXUM_PATH, server},
        };
        use async_trait::async_trait;
        use axum::{
            body::StreamBody,
            extract::{BodyStream, FromRequest, Path, Query, RequestParts},
            http::uri,
        };
        use futures::Stream;
        use futures_util::TryStreamExt;
        use hyper::{
            body::{Bytes, HttpBody},
            header::CONTENT_TYPE,
            Body,
        };
        use std::pin::Pin;

        pub struct Request {
            pub query_input: QueryInput,
        }

        impl Request {
            pub fn new(query_input: QueryInput) -> Self {
                Self { query_input }
            }

            #[allow(clippy::type_complexity)] // to be addressed in follow-up
            pub fn try_into_http_request(
                self,
                scheme: uri::Scheme,
                authority: uri::Authority,
            ) -> Result<
                hyper::Request<
                    StreamBody<Pin<Box<dyn Stream<Item = Result<Vec<u8>, TransportError>> + Send>>>,
                >,
                client::Error,
            > {
                let uri = uri::Uri::builder()
                    .scheme(scheme)
                    .authority(authority)
                    .path_and_query(format!(
                        "{}/{}/input?field_name={}",
                        BASE_AXUM_PATH,
                        self.query_input.query_id.as_ref(),
                        self.query_input.field_type.as_ref()
                    ))
                    .build()?;
                let body = StreamBody::new(self.query_input.input_stream);
                Ok(hyper::Request::post(uri)
                    .header(CONTENT_TYPE, "application/octet-stream")
                    .body(body)?)
            }
        }

        #[cfg_attr(feature = "enable-serde", derive(serde::Deserialize))]
        struct InputParams {
            field_type: FieldType,
        }

        struct ByteArrStreamFromReq(ByteArrStream);

        #[cfg(feature = "enable-serde")]
        #[async_trait]
        impl<B: HttpBody<Data = Bytes, Error = hyper::Error> + Send + 'static> FromRequest<B>
            for ByteArrStreamFromReq
        {
            type Rejection = server::Error;

            async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
                #[derive(serde::Deserialize)]
                struct FieldTypeParam {
                    field_type: FieldType,
                }

                // TODO: don't use `field_type` here. we need to use `size_in_bytes`, and possibly defer
                //       defer this decision to query processing layer
                let Query(FieldTypeParam { field_type }) = req.extract().await?;
                let body: BodyStream = req.extract().await?;
                let bas = ByteArrStream::new(body, field_type.size_in_bytes());
                Ok(ByteArrStreamFromReq(bas))
            }
        }

        #[async_trait]
        impl FromRequest<Body> for Request {
            type Rejection = server::Error;

            async fn from_request(req: &mut RequestParts<Body>) -> Result<Self, Self::Rejection> {
                let Path(query_id) = req.extract().await?;
                let Query::<InputParams>(input) = req.extract().await?;
                let input_stream = req
                    .extract::<ByteArrStreamFromReq>()
                    .await?
                    .0
                    .and_then(|bytes| futures::future::ok(bytes.to_vec()))
                    .map_err(TransportError::from);

                Ok(Request {
                    query_input: QueryInput {
                        query_id,
                        field_type: input.field_type,
                        input_stream: Box::pin(input_stream)
                            as Pin<Box<dyn Stream<Item = Result<Vec<u8>, TransportError>> + Send>>,
                    },
                })
            }
        }

        pub const AXUM_PATH: &str = "/:query_id/input";
    }

    pub mod step {
        use crate::{
            helpers::{HelperIdentity, MESSAGE_PAYLOAD_SIZE_BYTES},
            net::{
                client,
                http_serde::query::{get_header, OriginHeader, BASE_AXUM_PATH},
                server,
            },
            protocol::{QueryId, Step},
        };
        use async_trait::async_trait;
        use axum::{
            extract::{FromRequest, Path, RequestParts},
            http::uri,
        };
        use hyper::header::HeaderName;

        /// name of the `content-type` header used to get the length of the body, to verify valid `data-size`
        static CONTENT_LENGTH_HEADER_NAME: HeaderName = HeaderName::from_static("content-length");
        /// name of the `offset` header to use for [`Headers`]
        static OFFSET_HEADER_NAME: HeaderName = HeaderName::from_static("offset");

        /// Headers that are expected on `Step` commands
        /// # `offset`
        /// For any given batch, their `record_id`s must be known. The first record in the batch will have
        /// id `offset`, and subsequent records will be in-order from there.
        #[derive(Copy, Clone)]
        struct Headers {
            pub offset: u32,
        }

        impl Headers {
            pub(crate) fn add_to(
                self,
                req: axum::http::request::Builder,
            ) -> axum::http::request::Builder {
                req.header(OFFSET_HEADER_NAME.clone(), self.offset)
            }
        }

        #[async_trait]
        impl<B: Send> FromRequest<B> for Headers {
            type Rejection = server::Error;

            async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
                let content_length: u32 = get_header(req, CONTENT_LENGTH_HEADER_NAME.clone())?;
                let offset: u32 = get_header(req, OFFSET_HEADER_NAME.clone())?;
                // content_length must be aligned with the size of an element
                if content_length as usize % MESSAGE_PAYLOAD_SIZE_BYTES == 0 {
                    Ok(Headers { offset })
                } else {
                    Err(server::Error::WrongBodyLen {
                        body_len: content_length,
                        element_size: MESSAGE_PAYLOAD_SIZE_BYTES,
                    })
                }
            }
        }

        pub struct Request {
            pub origin: HelperIdentity,
            pub query_id: QueryId,
            pub step: Step,
            pub payload: Vec<u8>,
            pub offset: u32,
        }

        impl Request {
            pub fn new(
                origin: HelperIdentity,
                query_id: QueryId,
                step: Step,
                payload: Vec<u8>,
                offset: u32,
            ) -> Self {
                Self {
                    origin,
                    query_id,
                    step,
                    payload,
                    offset,
                }
            }

            pub fn try_into_http_request(
                self,
                scheme: uri::Scheme,
                authority: uri::Authority,
            ) -> Result<hyper::Request<hyper::Body>, client::Error> {
                let uri = uri::Uri::builder()
                    .scheme(scheme)
                    .authority(authority)
                    .path_and_query(format!(
                        "{}/{}/step/{}",
                        BASE_AXUM_PATH,
                        self.query_id.as_ref(),
                        self.step.as_ref()
                    ))
                    .build()?;
                let headers = Headers {
                    offset: self.offset,
                };
                let origin_header = OriginHeader {
                    origin: self.origin,
                };
                let body = hyper::Body::from(self.payload);
                let req = hyper::Request::post(uri);
                let req = headers.add_to(origin_header.add_to(req));
                Ok(req.body(body)?)
            }
        }

        #[async_trait]
        impl FromRequest<hyper::Body> for Request {
            type Rejection = server::Error;

            async fn from_request(
                req: &mut RequestParts<hyper::Body>,
            ) -> Result<Self, Self::Rejection> {
                let Path((query_id, step)) = req.extract().await?;
                let origin_header = req.extract::<OriginHeader>().await?;
                let step_headers = req.extract::<Headers>().await?;
                let body = req.take_body().unwrap();
                let payload = hyper::body::to_bytes(body).await?.to_vec();
                Ok(Self {
                    origin: origin_header.origin,
                    query_id,
                    step,
                    payload,
                    offset: step_headers.offset,
                })
            }
        }

        pub const AXUM_PATH: &str = "/:query_id/step/*step";
    }

    pub mod results {
        use crate::{
            net::{client, http_serde::query::BASE_AXUM_PATH, server},
            protocol::QueryId,
        };
        use async_trait::async_trait;
        use axum::{
            extract::{FromRequest, Path, RequestParts},
            http::uri,
        };

        pub struct Request {
            pub query_id: QueryId,
        }

        impl Request {
            pub fn new(query_id: QueryId) -> Self {
                Self { query_id }
            }

            pub fn try_into_http_request(
                self,
                scheme: uri::Scheme,
                authority: uri::Authority,
            ) -> Result<hyper::Request<hyper::Body>, client::Error> {
                let uri = uri::Uri::builder()
                    .scheme(scheme)
                    .authority(authority)
                    .path_and_query(format!(
                        "{}/{}/complete",
                        BASE_AXUM_PATH,
                        self.query_id.as_ref()
                    ))
                    .build()?;
                Ok(hyper::Request::get(uri).body(hyper::Body::empty())?)
            }
        }

        #[async_trait]
        impl<B: Send> FromRequest<B> for Request {
            type Rejection = server::Error;

            async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
                let Path(query_id) = req.extract().await?;
                Ok(Request { query_id })
            }
        }

        pub const AXUM_PATH: &str = "/:query_id/complete";
    }
}
