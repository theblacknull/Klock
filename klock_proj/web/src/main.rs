mod payment;
mod ratelimit;
mod store;

use axum::body::Body;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Json};
use axum::routing::{get, post};
use axum::Router;
use rand::Rng;
use ratelimit::RateLimiter;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use store::Store;
use tower::util::ServiceExt;
use tower_http::decompression::RequestDecompressionLayer;
use tower_http::services::ServeDir;
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
const MAX_WRAPPED_BYTES: u64 = 150 * 1024 * 1024; // ~100MB file gốc + overhead armor/base64

struct App {
    store: Store,
    encrypt_limiter: RateLimiter,
    static_dir: String,
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
    if req.wrapped.len() as u64 > MAX_WRAPPED_BYTES {
        return (StatusCode::PAYLOAD_TOO_LARGE, "file quá lớn").into_response();
    }
    let mut slug = gen_slug();
    while app.store.contains(&slug) {
        slug = gen_slug();
    }
    app.store.insert(&slug, req.code, req.wrapped, false);
    Json(EncryptResp { slug }).into_response()
}

async fn item(State(app): State<Arc<App>>, Path(slug): Path<String>) -> impl IntoResponse {
    match app.store.get_and_touch(&slug) {
        Some(r) => Json(r).into_response(),
        None => (StatusCode::NOT_FOUND, "không tìm thấy").into_response(),
    }
}

/// Người dùng vừa tải xong nội dung đã giải mã — rút ngắn thời gian lưu còn 5 phút.
async fn downloaded(State(app): State<Arc<App>>, Path(slug): Path<String>) -> impl IntoResponse {
    if app.store.mark_downloaded(&slug) {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

#[derive(Deserialize)]
struct ConfirmPaymentReq {
    network: String,
    tx_hash: String,
}

#[derive(Serialize)]
struct ConfirmPaymentResp {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Client tự dò thấy 1 giao dịch ~1 USDT trên blockchain công khai trước; server ở đây LUÔN
/// tự kiểm tra lại trực tiếp trên chain (không tin số liệu client gửi lên) trước khi mở khóa lưu vĩnh viễn.
async fn confirm_payment(
    State(app): State<Arc<App>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Json(req): Json<ConfirmPaymentReq>,
) -> impl IntoResponse {
    if !app.encrypt_limiter.allow(client_ip(&headers, addr)) {
        return (StatusCode::TOO_MANY_REQUESTS, Json(ConfirmPaymentResp { ok: false, error: Some("quá nhiều yêu cầu".into()) })).into_response();
    }
    if !app.store.contains(&slug) {
        return (StatusCode::NOT_FOUND, Json(ConfirmPaymentResp { ok: false, error: Some("không tìm thấy".into()) })).into_response();
    }
    let Some(network) = payment::network_for(&req.network) else {
        return (StatusCode::BAD_REQUEST, Json(ConfirmPaymentResp { ok: false, error: Some("mạng không hỗ trợ".into()) })).into_response();
    };
    match payment::verify_tx(&network, &req.tx_hash).await {
        Ok(true) => {
            if !app.store.claim_tx(&req.tx_hash) {
                return (StatusCode::CONFLICT, Json(ConfirmPaymentResp { ok: false, error: Some("giao dịch đã được dùng".into()) })).into_response();
            }
            app.store.set_permanent(&slug);
            Json(ConfirmPaymentResp { ok: true, error: None }).into_response()
        }
        Ok(false) => (StatusCode::OK, Json(ConfirmPaymentResp { ok: false, error: Some("chưa tìm thấy giao dịch hợp lệ".into()) })).into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, Json(ConfirmPaymentResp { ok: false, error: Some(e) })).into_response(),
    }
}

/// Phục vụ file tĩnh; nếu không khớp file nào (vd link dạng /ABC123) thì trả về index.html
/// với mã 200 (SPA fallback đúng nghĩa) thay vì 404, để trang luôn tải và chạy JS bình thường.
async fn spa_fallback(State(app): State<Arc<App>>, req: Request<Body>) -> axum::response::Response {
    let serve_dir = ServeDir::new(&app.static_dir);
    let serve_result: Result<_, std::convert::Infallible> = serve_dir.oneshot(req).await;
    let mut res: axum::response::Response = match serve_result {
        Ok(res) if res.status() != StatusCode::NOT_FOUND => res.into_response(),
        _ => match tokio::fs::read_to_string(format!("{}/index.html", app.static_dir)).await {
            Ok(html) => Html(html).into_response(),
            Err(_) => return StatusCode::NOT_FOUND.into_response(),
        },
    };
    res.headers_mut().insert(CACHE_CONTROL, HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"));
    res
}

#[tokio::main]
async fn main() {
    let _ = dotenvy::dotenv(); // đọc .env nếu có, không bắt buộc phải tồn tại
    let data_dir = std::env::var("KLOCK_DB").unwrap_or_else(|_| "klock_data".into());
    let static_dir = std::env::var("KLOCK_STATIC").unwrap_or_else(|_| "static".into());
    let store = Store::open(data_dir.into());

    // dọn định kỳ các bản ghi hết hạn (xem quy tắc trong store.rs)
    let sweep_store = store.clone();
    tokio::spawn(async move {
        // chạy mỗi phút để khớp đúng mốc 5 phút/15 phút đã hứa (30 phút như trước là quá thưa)
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            let n = sweep_store.sweep_expired();
            if n > 0 {
                println!("klock-web: đã dọn {n} bản ghi hết hạn");
            }
        }
    });

    let app = Arc::new(App {
        store,
        encrypt_limiter: RateLimiter::new(20, Duration::from_secs(300)), // 20 lần/5 phút mỗi IP
        static_dir,
    });

    let router = Router::new()
        .route("/api/encrypt", post(encrypt))
        .route("/api/item/:slug", get(item))
        .route("/api/item/:slug/downloaded", post(downloaded))
        .route("/api/item/:slug/confirm-payment", post(confirm_payment))
        .layer(DefaultBodyLimit::max(MAX_WRAPPED_BYTES as usize + 4096))
        .layer(RequestDecompressionLayer::new().gzip(true))
        .fallback(spa_fallback)
        .with_state(app);

    let addr = std::env::var("KLOCK_ADDR").unwrap_or_else(|_| "127.0.0.1:8787".into());
    println!("klock-web listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}
