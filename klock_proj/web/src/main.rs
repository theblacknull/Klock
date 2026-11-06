mod ratelimit;
mod store;

use axum::extract::{ConnectInfo, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use axum::routing::{get, post};
use axum::Router;
use rand::Rng;
use ratelimit::RateLimiter;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use store::{Record, Store};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;
use axum::http::header::CACHE_CONTROL;
use axum::http::HeaderValue;

const SLUG_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

struct App {
    store: Store,
    encrypt_limiter: RateLimiter,
}

#[derive(Deserialize)]
struct EncryptReq {
    code: String,
    wrapped: String,
}

#[derive(Serialize)]
struct EncryptResp {
    slug: String,
}

fn gen_slug() -> String {
    let mut rng = rand::thread_rng();
    (0..6).map(|_| SLUG_CHARS[rng.gen_range(0..SLUG_CHARS.len())] as char).collect()
}

async fn encrypt(
    State(app): State<Arc<App>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<EncryptReq>,
) -> impl IntoResponse {
    if !app.encrypt_limiter.allow(addr.ip()) {
        return (StatusCode::TOO_MANY_REQUESTS, "quá nhiều yêu cầu, thử lại sau").into_response();
    }
    if req.code.len() < 15 || req.wrapped.is_empty() {
        return (StatusCode::BAD_REQUEST, "dữ liệu không hợp lệ").into_response();
    }
    let mut slug = gen_slug();
    while app.store.contains(&slug) {
        slug = gen_slug();
    }
    app.store.insert(slug.clone(), Record { code: req.code, wrapped: req.wrapped });
    Json(EncryptResp { slug }).into_response()
}

async fn item(State(app): State<Arc<App>>, Path(slug): Path<String>) -> impl IntoResponse {
    match app.store.get(&slug) {
        Some(r) => Json(r).into_response(),
        None => (StatusCode::NOT_FOUND, "không tìm thấy").into_response(),
    }
}

#[tokio::main]
async fn main() {
    let data_path = std::env::var("KLOCK_DB").unwrap_or_else(|_| "klock_web_data.json".into());
    let static_dir = std::env::var("KLOCK_STATIC").unwrap_or_else(|_| "static".into());
    let app = Arc::new(App {
        store: Store::open(data_path.into()),
        encrypt_limiter: RateLimiter::new(20, Duration::from_secs(300)), // 20 lần/5 phút mỗi IP
    });

    let serve_dir = tower::ServiceBuilder::new()
        .layer(SetResponseHeaderLayer::overriding(CACHE_CONTROL, HeaderValue::from_static("no-cache")))
        .service(ServeDir::new(&static_dir).not_found_service(ServeFile::new(format!("{static_dir}/index.html"))));

    let router = Router::new()
        .route("/api/encrypt", post(encrypt))
        .route("/api/item/:slug", get(item))
        .with_state(app)
        .fallback_service(serve_dir);

    let addr = std::env::var("KLOCK_ADDR").unwrap_or_else(|_| "127.0.0.1:8787".into());
    println!("klock-web listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}
