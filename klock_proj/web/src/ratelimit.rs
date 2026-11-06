use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Giới hạn tần suất đơn giản kiểu cửa sổ trượt cố định theo IP, chỉ giữ trong RAM.
pub struct RateLimiter {
    max_per_window: u32,
    window: Duration,
    hits: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

impl RateLimiter {
    pub fn new(max_per_window: u32, window: Duration) -> Self {
        Self { max_per_window, window, hits: Mutex::new(HashMap::new()) }
    }

    /// true nếu được phép đi tiếp, false nếu đã vượt giới hạn.
    pub fn allow(&self, ip: IpAddr) -> bool {
        let mut m = self.hits.lock().unwrap();
        let now = Instant::now();
        // dọn rác định kỳ để tránh phình bộ nhớ vô hạn
        if m.len() > 10_000 {
            m.retain(|_, (_, t)| now.duration_since(*t) < self.window);
        }
        let entry = m.entry(ip).or_insert((0, now));
        if now.duration_since(entry.1) >= self.window {
            *entry = (0, now);
        }
        if entry.0 >= self.max_per_window {
            return false;
        }
        entry.0 += 1;
        true
    }
}
