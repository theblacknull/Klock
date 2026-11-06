mod ratelimit;
mod store;

use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json};
use axum::routing::{get, post};
use axum::Router;
use rand::Rng;
use ratelimit::RateLimiter;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use store::{Record, Store};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;
use axum::http::header::CACHE_CONTROL;
use axum::http::HeaderValue;

/// Lấy IP thật của client. Khi chạy sau Nginx/reverse proxy, kết nối TCP trực tiếp
/// luôn là proxy (127.0.0.1) nên phải đọc X-Forwarded-For / X-Real-IP do proxy gắn vào.
/// Chỉ an toàn khi server KHÔNG lộ trực tiếp ra Internet (luôn đứng sau proxy tin cậy) —
/// đúng với cách triển khai khuyến nghị (bind 127.0.0.1, Nginx/Caddy đứng trước).
fn client_ip(headers: &HeaderMap, fallback: SocketAddr) -> IpAddr {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .and_then(|s| s.parse().ok())
        .or_else(|| headers.get("x-real-ip").and_then(|v| v.to_str().ok()).and_then(|s| s.parse().ok()))
        .unwrap_or(fallback.ip())
}

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
    headers: HeaderMap,
    Json(req): Json<EncryptReq>,
) -> impl IntoResponse {
    if !app.encrypt_limiter.allow(client_ip(&headers, addr)) {
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
    let _ = dotenvy::dotenv(); // đọc .env nếu có, không bắt buộc phải tồn tại
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
        .layer(DefaultBodyLimit::max(15 * 1024 * 1024)) // 8MB file + overhead armor/base64
        .with_state(app)
        .fallback_service(serve_dir);

    let addr = std::env::var("KLOCK_ADDR").unwrap_or_else(|_| "127.0.0.1:8787".into());
    println!("klock-web listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}
