// Dùng:  klock enc "<bí mật>" DDMMYYYYHHMMSS "<thư>"   -> in chuỗi số rồi bản mã (armor)
//        klock dec "<bí mật>" <chuỗi số> < bản_mã    -> in thư
use klock::*;
use std::io::Read;

#[cfg(unix)]
fn rand8() -> [u8; 8] {
    let mut b = [0u8; 8];
    std::fs::File::open("/dev/urandom").unwrap().read_exact(&mut b).unwrap();
    b
}

#[cfg(windows)]
fn rand8() -> [u8; 8] {
    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(h_algorithm: *mut core::ffi::c_void, pb_buffer: *mut u8, cb_buffer: u32, dw_flags: u32) -> i32;
    }
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x00000002;
    let mut b = [0u8; 8];
    let status = unsafe { BCryptGenRandom(std::ptr::null_mut(), b.as_mut_ptr(), b.len() as u32, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    assert!(status == 0, "BCryptGenRandom thất bại");
    b
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 4 { return eprintln!("klock enc <bí mật> <DDMMYYYYHHMMSS> <thư>\nklock dec <bí mật> <chuỗi số> < bản_mã") }
    if a[1] == "enc" {
        let b = rand8();
        let x0 = format!("{:012}", u64::from_le_bytes(b) % 1_000_000_000_000);
        let code = format!("{x0}{}", a[3]);
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        let secs = unix(&a[3]) - now;
        assert!(secs > 0, "thời điểm mở phải ở tương lai");
        let c = gcm(&key(&a[2], &x0), &nonce(&x0), code.as_bytes(), a[4].as_bytes(), false).unwrap();
        println!("{code}");
        print!("{}", String::from_utf8(tle(&["-a", "-e", "-D", &format!("{secs}s")], &c)).unwrap());
    } else {
        let code = &a[3];
        let x0 = &code[..code.len() - 14];
        unix(&code[code.len() - 14..]);
        let mut blob = vec![];
        std::io::stdin().read_to_end(&mut blob).unwrap();
        let c = tle(&["-d"], &blob);
        let p = gcm(&key(&a[2], x0), &nonce(x0), code.as_bytes(), &c, true).expect("sai bí mật hoặc chuỗi số bị sửa");
        println!("{}", String::from_utf8_lossy(&p));
    }
}
