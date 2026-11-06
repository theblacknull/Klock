use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const ONE_MB: u64 = 1_000_000;
const DAY: i64 = 24 * 3600;

#[derive(Clone, Serialize, Deserialize)]
pub struct Record {
    pub code: String,    // x0 (12 chữ số) + DDMMYYYYHHMMSS — chứa cả thời điểm mở khóa thật
    pub wrapped: String, // bản mã đã bọc time-lock (armor text của tlock-js)
    pub created_at: i64,
    pub size: u64,
    #[serde(default)]
    pub first_accessed_at: Option<i64>,
}

pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

/// DDMMYYYYHHMMSS (UTC) -> unix time. Giống hệt logic trong CLI gốc (src/lib.rs::unix).
pub fn unlock_unix_from_code(code: &str) -> Option<i64> {
    if code.len() < 14 {
        return None;
    }
    let d = &code[code.len() - 14..];
    if !d.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let n = |a: usize, b: usize| d[a..b].parse::<i64>().ok();
    let (dd, mo, y, h, mi, sc) = (n(0, 2)?, n(2, 4)?, n(4, 8)?, n(8, 10)?, n(10, 12)?, n(12, 14)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&dd) || h >= 24 || mi >= 60 || sc >= 60 {
        return None;
    }
    let y = y - (mo <= 2) as i64;
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (mo + if mo > 2 { -3 } else { 9 }) + 2) / 5 + dd - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some((((era * 146097 + doe - 719468) * 24 + h) * 60 + mi) * 60 + sc)
}

#[derive(Clone)]
pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn open(dir: PathBuf) -> Self {
        std::fs::create_dir_all(&dir).ok();
        Self { dir }
    }

    fn path(&self, slug: &str) -> PathBuf {
        self.dir.join(format!("{slug}.json"))
    }

    pub fn contains(&self, slug: &str) -> bool {
        self.path(slug).exists()
    }

    pub fn insert(&self, slug: &str, code: String, wrapped: String) {
        let size = wrapped.len() as u64;
        let rec = Record { code, wrapped, created_at: now(), size, first_accessed_at: None };
        self.write(slug, &rec);
    }

    fn write(&self, slug: &str, rec: &Record) {
        let tmp = self.path(slug).with_extension("tmp");
        if let Ok(s) = serde_json::to_string(rec) {
            if std::fs::write(&tmp, s).is_ok() {
                let _ = std::fs::rename(&tmp, self.path(slug));
            }
        }
    }

    /// Đọc bản ghi; nếu đây là lần truy cập đầu tiên thì đánh dấu lại (bắt đầu đếm 24h).
    pub fn get_and_touch(&self, slug: &str) -> Option<Record> {
        let data = std::fs::read_to_string(self.path(slug)).ok()?;
        let mut rec: Record = serde_json::from_str(&data).ok()?;
        if rec.first_accessed_at.is_none() {
            rec.first_accessed_at = Some(now());
            self.write(slug, &rec);
        }
        Some(rec)
    }

    /// Dọn các bản ghi đã hết hạn. Mốc thời gian luôn tính từ THỜI ĐIỂM MỞ KHÓA (không phải lúc tạo):
    /// - đã có người truy cập: xóa sau 24h kể từ lần truy cập đầu tiên
    /// - chưa ai truy cập, kích thước ≥ 1MB: xóa sau 30 ngày kể từ lúc mở khóa
    /// - chưa ai truy cập, kích thước < 1MB: giữ vô thời hạn
    pub fn sweep_expired(&self) -> usize {
        let mut removed = 0;
        let Ok(entries) = std::fs::read_dir(&self.dir) else { return 0 };
        let t = now();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Ok(data) = std::fs::read_to_string(&path) else { continue };
            let Ok(rec) = serde_json::from_str::<Record>(&data) else { continue };
            let expired = if let Some(accessed) = rec.first_accessed_at {
                t - accessed >= DAY
            } else if rec.size >= ONE_MB {
                match unlock_unix_from_code(&rec.code) {
                    Some(unlock_at) => t - unlock_at >= 30 * DAY,
                    None => false,
                }
            } else {
                false
            };
            if expired {
                let _ = std::fs::remove_file(&path);
                removed += 1;
            }
        }
        removed
    }
}
