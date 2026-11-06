//! klock: AES-256-GCM(K_S) bọc ngoài bởi tlock (drand). SHA-256/HMAC/AES-GCM tự cài (std).
//! Riêng Argon2id (làm chậm brute-force bí mật yếu) dùng crate `argon2` đã kiểm định,
//! vì tự cài thuật toán memory-hard này rủi ro lỗi tinh vi cao hơn nhiều so với lợi ích.
use std::io::Write;

use std::process::{Command, Stdio};

pub fn sha256(m: &[u8]) -> [u8; 32] {
    // hằng số sinh từ căn bậc 2 / bậc 3 của các số nguyên tố đầu tiên
    let pr: Vec<f64> = (2u32..).filter(|n| (2..*n).take_while(|d| d * d <= *n).all(|d| n % d != 0)).take(64).map(|n| n as f64).collect();
    let fr = |x: f64| (x.fract() * 4294967296.0) as u32;
    let mut h: Vec<u32> = pr[..8].iter().map(|p| fr(p.sqrt())).collect();
    let k: Vec<u32> = pr.iter().map(|p| fr(p.cbrt())).collect();
    let mut d = m.to_vec();
    d.push(0x80);
    while d.len() % 64 != 56 { d.push(0) }
    d.extend(((m.len() as u64) * 8).to_be_bytes());
    for c in d.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 { w[i] = u32::from_be_bytes(c[4 * i..4 * i + 4].try_into().unwrap()) }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let mut v: [u32; 8] = h[..].try_into().unwrap();
        for i in 0..64 {
            let t1 = v[7]
                .wrapping_add(v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25))
                .wrapping_add((v[4] & v[5]) ^ (!v[4] & v[6]))
                .wrapping_add(k[i])
                .wrapping_add(w[i]);
            let t2 = (v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22))
                .wrapping_add((v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]));
            v = [t1.wrapping_add(t2), v[0], v[1], v[2], v[3].wrapping_add(t1), v[4], v[5], v[6]];
        }
        for i in 0..8 { h[i] = h[i].wrapping_add(v[i]) }
    }
    let mut o = [0u8; 32];
    for i in 0..8 { o[4 * i..4 * i + 4].copy_from_slice(&h[i].to_be_bytes()) }
    o
}

pub fn hmac(k: &[u8], m: &[u8]) -> [u8; 32] {
    let kk = if k.len() > 64 { sha256(k).to_vec() } else { k.to_vec() };
    let (mut i, mut o) = ([0x36u8; 64], [0x5cu8; 64]);
    for (j, b) in kk.iter().enumerate() { i[j] ^= b; o[j] ^= b }
    sha256(&[&o[..], &sha256(&[&i[..], m].concat())].concat())
}

pub fn xt(x: u8) -> u8 { (x << 1) ^ if x & 0x80 != 0 { 0x1b } else { 0 } }

pub fn aes(key: &[u8; 32]) -> impl Fn(&[u8; 16]) -> [u8; 16] {
    let mut s = [0u8; 256]; // S-box sinh bằng nghịch đảo GF(2^8) + biến đổi affine
    let (mut p, mut q) = (1u8, 1u8);
    loop {
        p = p ^ (p << 1) ^ if p & 0x80 != 0 { 0x1b } else { 0 };
        q ^= q << 1; q ^= q << 2; q ^= q << 4;
        if q & 0x80 != 0 { q ^= 0x09 }
        s[p as usize] = q ^ q.rotate_left(1) ^ q.rotate_left(2) ^ q.rotate_left(3) ^ q.rotate_left(4) ^ 0x63;
        if p == 1 { break }
    }
    s[0] = 0x63;
    let mut w: Vec<[u8; 4]> = key.chunks(4).map(|c| [c[0], c[1], c[2], c[3]]).collect();
    let mut rc = 1u8;
    for i in 8..60 {
        let mut t = w[i - 1];
        if i % 8 == 0 {
            t = [s[t[1] as usize] ^ rc, s[t[2] as usize], s[t[3] as usize], s[t[0] as usize]];
            rc = xt(rc);
        } else if i % 8 == 4 {
            t = t.map(|x| s[x as usize]);
        }
        let n = [0, 1, 2, 3].map(|j| w[i - 8][j] ^ t[j]);
        w.push(n);
    }
    move |b: &[u8; 16]| {
        let mut st = *b;
        let ak = |st: &mut [u8; 16], r: usize| for i in 0..16 { st[i] ^= w[4 * r + i / 4][i % 4] };
        ak(&mut st, 0);
        for r in 1..15 {
            for x in st.iter_mut() { *x = s[*x as usize] }
            let o = st;
            for c in 0..4 { for j in 0..4 { st[c * 4 + j] = o[((c + j) % 4) * 4 + j] } }
            if r < 14 {
                for c in 0..4 {
                    let a = [st[4 * c], st[4 * c + 1], st[4 * c + 2], st[4 * c + 3]];
                    let t = a[0] ^ a[1] ^ a[2] ^ a[3];
                    for i in 0..4 { st[4 * c + i] = a[i] ^ t ^ xt(a[i] ^ a[(i + 1) % 4]) }
                }
            }
            ak(&mut st, r);
        }
        st
    }
}

pub fn gm(x: u128, y: u128) -> u128 { // nhân GHASH trong GF(2^128)
    let (mut z, mut v) = (0u128, y);
    for i in 0..128 {
        if (x >> (127 - i)) & 1 == 1 { z ^= v }
        v = if v & 1 == 1 { (v >> 1) ^ (0xe1u128 << 120) } else { v >> 1 };
    }
    z
}

// dec=false: data=bản rõ  -> trả ct‖tag.  dec=true: data=ct‖tag -> trả bản rõ (None nếu tag sai)
pub fn gcm(key: &[u8; 32], n: &[u8; 12], aad: &[u8], data: &[u8], dec: bool) -> Option<Vec<u8>> {
    let e = aes(key);
    let h = u128::from_be_bytes(e(&[0; 16]));
    let ctr = |i: u32| { let mut b = [0u8; 16]; b[..12].copy_from_slice(n); b[12..].copy_from_slice(&i.to_be_bytes()); b };
    let (body, tag_in) = if dec {
        if data.len() < 16 { return None }
        data.split_at(data.len() - 16)
    } else { (data, &[][..]) };
    let out: Vec<u8> = body.chunks(16).enumerate().flat_map(|(i, c)| {
        let k = e(&ctr(i as u32 + 2));
        c.iter().zip(k).map(|(a, b)| a ^ b).collect::<Vec<_>>()
    }).collect();
    let ct = if dec { body } else { &out[..] };
    let mut g = 0u128;
    for blk in [aad, ct] {
        for c in blk.chunks(16) {
            let mut b = [0u8; 16];
            b[..c.len()].copy_from_slice(c);
            g = gm(g ^ u128::from_be_bytes(b), h);
        }
    }
    g = gm(g ^ ((((aad.len() as u128) * 8) << 64) | (ct.len() as u128) * 8), h);
    let t = (g ^ u128::from_be_bytes(e(&ctr(1)))).to_be_bytes();
    if dec { return if t[..] == *tag_in { Some(out) } else { None } }
    let mut o = out;
    o.extend(t);
    Some(o)
}

// K_S = HMAC-SHA256(Argon2id(password=S, salt=x0, m=64MiB, t=3, p=1), info = "klock-v1")
// Argon2id làm chậm brute-force với S yếu (memory-hard) — khớp tham số với bản web (hash-wasm).
pub fn key(s: &str, x0: &str) -> [u8; 32] {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(65536, 3, 1, Some(32)).unwrap();
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut stretched = [0u8; 32];
    a2.hash_password_into(s.as_bytes(), x0.as_bytes(), &mut stretched).unwrap();
    hmac(&stretched, b"klock-v1\x01")
}

pub fn nonce(x0: &str) -> [u8; 12] { sha256(x0.as_bytes())[..12].try_into().unwrap() } // nonce suy từ x0

// DDMMYYYYHHMMSS (UTC) -> unix time
pub fn unix(d: &str) -> i64 {
    assert!(d.len() == 14 && d.bytes().all(|c| c.is_ascii_digit()), "thời điểm phải đủ 14 chữ số DDMMYYYYHHMMSS");
    let n = |a: usize, b: usize| d[a..b].parse::<i64>().unwrap();
    let (dd, mo, y, h, mi, sc) = (n(0, 2), n(2, 4), n(4, 8), n(8, 10), n(10, 12), n(12, 14));
    assert!((1..=12).contains(&mo) && (1..=31).contains(&dd) && h < 24 && mi < 60 && sc < 60, "ngày giờ không hợp lệ");
    let y = y - (mo <= 2) as i64;
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (mo + if mo > 2 { -3 } else { 9 }) + 2) / 5 + dd - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (((era * 146097 + doe - 719468) * 24 + h) * 60 + mi) * 60 + sc
}

pub fn tle(args: &[&str], input: &[u8]) -> Vec<u8> { // lớp thời gian: CLI `tle` của drand
    let mut c = Command::new("tle").args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().expect("cần cài `tle`");
    c.stdin.take().unwrap().write_all(input).unwrap();
    let o = c.wait_with_output().unwrap();
    assert!(o.status.success(), "tle thất bại (chưa đến giờ?)");
    o.stdout
}

#[cfg(test)]
mod t {
    use super::*;
    fn hx(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
    #[test]
    fn sha() { assert_eq!(hx(&sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") }
    #[test]
    fn hm() { assert_eq!(hx(&hmac(b"Jefe", b"what do ya want for nothing?")), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843") }
    #[test]
    fn gcm_vec() {
        let (k, n) = ([0u8; 32], [0u8; 12]);
        assert_eq!(hx(&gcm(&k, &n, &[], &[], false).unwrap()), "530f8afbc74536b9a963b4f1c4cb738b");
        assert_eq!(hx(&gcm(&k, &n, &[], &[0; 16], false).unwrap()), "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919");
    }
    #[test]
    fn roundtrip() {
        let k = key("alpha beta", "123456789012");
        let c = gcm(&k, &nonce("123456789012"), b"aad", b"How are you?", false).unwrap();
        assert_eq!(gcm(&k, &nonce("123456789012"), b"aad", &c, true).unwrap(), b"How are you?");
        assert!(gcm(&key("alpha betA!", "123456789012"), &nonce("123456789012"), b"aad", &c, true).is_none());
        assert!(gcm(&k, &nonce("123456789012"), b"aae", &c, true).is_none());
        assert_ne!(key("Alpha beta", "100000000000"), key("alpha beta", "100000000000"));
    }
    #[test]
    fn time() { assert_eq!(unix("01012000000000"), 946684800); assert_eq!(unix("20112026090537"), 1795165200 + 5 * 60 + 37) }
}
