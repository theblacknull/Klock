use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Clone, Serialize, Deserialize)]
pub struct Record {
    pub code: String,    // x0 (12 chữ số) + DDMMYYYYHHMMSS
    pub wrapped: String, // bản mã đã bọc time-lock (armor text của tlock-js)
}

pub struct Store {
    path: PathBuf,
    map: Mutex<HashMap<String, Record>>,
}

impl Store {
    pub fn open(path: PathBuf) -> Self {
        let map = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        Self { path, map: Mutex::new(map) }
    }

    pub fn insert(&self, slug: String, rec: Record) {
        let mut m = self.map.lock().unwrap();
        m.insert(slug, rec);
        self.flush(&m);
    }

    pub fn get(&self, slug: &str) -> Option<Record> {
        self.map.lock().unwrap().get(slug).cloned()
    }

    pub fn contains(&self, slug: &str) -> bool {
        self.map.lock().unwrap().contains_key(slug)
    }

    fn flush(&self, m: &HashMap<String, Record>) {
        let tmp = self.path.with_extension("tmp");
        if let Ok(mut f) = std::fs::File::create(&tmp) {
            if f.write_all(serde_json::to_string(m).unwrap().as_bytes()).is_ok() {
                let _ = std::fs::rename(&tmp, &self.path);
            }
        }
    }
}
