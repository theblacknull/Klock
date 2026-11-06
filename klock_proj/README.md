# klock

Khóa thư theo thời gian + bí mật chung. SHA-256/HMAC/AES-256-GCM tự cài bằng std; dẫn khóa qua Argon2id (crate `argon2`) để chống brute-force bí mật yếu.
Lớp thời gian gọi CLI `tle` của drand (cần cài: `go install github.com/drand/tlock/cmd/tle@latest`).

    cargo build --release
    ./target/release/klock enc "<bí mật S>" DDMMYYYYHHMMSS "How are you?"   # giờ UTC
    ./target/release/klock dec "<bí mật S>" <chuỗi số> < bản_mã
    cargo test                       # kiểm thử SHA-256/HMAC/AES-GCM/ngày giờ (không cần mạng)
    tests/klock_test.sh              # kiểm thử đầu-cuối với tle thật (STUB=1: tle giả, bỏ qua khóa thời gian)

Dùng như thư viện: `klock::{key, nonce, gcm, unix, tle}`.
Lưu ý: S dùng nguyên byte (không chuẩn hóa); x0 phải ngẫu nhiên mỗi thư (nonce suy từ x0).
