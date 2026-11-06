use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const DAY: i64 = 24 * 3600;
const MIN: i64 = 60;

#[derive(Clone, Serialize, Deserialize)]
pub struct Record {
    pub code: String,    // x0 (12 chữ số) + DDMMYYYYHHMMSS — chứa cả thời điểm mở khóa thật
    pub wrapped: String, // bản mã đã bọc time-lock (armor text của tlock-js)
    pub created_at: i64,
    pub size: u64,
    #[serde(default)]
    pub first_accessed_at: Option<i64>,
    /// Mốc thời gian xóa đã lên lịch (đặt khi có người giải mã lần đầu, rút ngắn khi họ bấm tải file).
    #[serde(default)]
    pub delete_at: Option<i64>,
    /// Người gửi đã trả phí lưu vĩnh viễn — bỏ qua mọi mốc tự xóa ở trên.
    #[serde(default)]
    pub permanent: bool,
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

    fn used_tx_path(&self) -> PathBuf {
        self.dir.join("_used_tx.json")
    }

    /// Đánh dấu 1 hash giao dịch đã được dùng để mở khóa lưu vĩnh viễn.
    /// Trả về true nếu đây là lần đầu dùng (hợp lệ), false nếu đã dùng rồi (chặn tái sử dụng).
    pub fn claim_tx(&self, tx_hash: &str) -> bool {
        let p = self.used_tx_path();
        let mut set: std::collections::HashSet<String> = std::fs::read_to_string(&p)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        if !set.insert(tx_hash.to_lowercase()) {
            return false;
        }
        if let Ok(s) = serde_json::to_string(&set) {
            let _ = std::fs::write(&p, s);
        }
        true
    }

    pub fn contains(&self, slug: &str) -> bool {
        self.path(slug).exists()
    }

    pub fn insert(&self, slug: &str, code: String, wrapped: String, permanent: bool) {
        let size = wrapped.len() as u64;
        let rec = Record { code, wrapped, created_at: now(), size, first_accessed_at: None, delete_at: None, permanent };
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

    fn read(&self, slug: &str) -> Option<Record> {
        let data = std::fs::read_to_string(self.path(slug)).ok()?;
        serde_json::from_str(&data).ok()
    }

    /// Đọc bản ghi; nếu đây là lần truy cập đầu tiên (giải mã thành công) thì bắt đầu hẹn giờ xóa sau 15 phút.
    pub fn get_and_touch(&self, slug: &str) -> Option<Record> {
        let mut rec = self.read(slug)?;
        if rec.first_accessed_at.is_none() && !rec.permanent {
            rec.first_accessed_at = Some(now());
            rec.delete_at = Some(now() + 15 * MIN);
            self.write(slug, &rec);
        }
        Some(rec)
    }

    /// Người dùng đã tải xong file/nội dung đã giải mã — rút ngắn còn 5 phút kể từ bây giờ.
    pub fn mark_downloaded(&self, slug: &str) -> bool {
        let Some(mut rec) = self.read(slug) else { return false };
        if !rec.permanent {
            rec.delete_at = Some(now() + 5 * MIN);
            self.write(slug, &rec);
        }
        true
    }

    pub fn set_permanent(&self, slug: &str) -> bool {
        let Some(mut rec) = self.read(slug) else { return false };
        rec.permanent = true;
        rec.delete_at = None;
        self.write(slug, &rec);
        true
    }

    /// Dọn các bản ghi đã hết hạn:
    /// - trả phí lưu vĩnh viễn: không bao giờ xóa
    /// - đã có người giải mã (delete_at đã đặt): xóa khi tới mốc đó (15 phút, hoặc 5 phút nếu đã tải file)
    /// - chưa ai giải mã: xóa sau 7 ngày kể từ THỜI ĐIỂM MỞ KHÓA (không phải lúc tạo)
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
            if rec.permanent {
                continue;
            }
            let expired = if let Some(deadline) = rec.delete_at {
                t >= deadline
            } else {
                match unlock_unix_from_code(&rec.code) {
                    Some(unlock_at) => t - unlock_at >= 7 * DAY,
                    None => false,
                }
            };
            if expired {
                let _ = std::fs::remove_file(&path);
                removed += 1;
            }
        }
        removed
    }
}
