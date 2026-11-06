# Báo cáo đánh giá độ khó phá mã hệ thống Klock

**Phạm vi:** đánh giá độc lập độ mạnh mật mã của hai lớp mã hóa trong Klock — lớp bí mật chung (AES‑256‑GCM) và lớp khóa thời gian (tlock/drand). Dựa trên việc đọc trực tiếp mã nguồn `src/lib.rs`, `src/main.rs` (CLI gốc) và `web/static/app.js` (bản web, đã đối chiếu khớp bit‑for‑bit với CLI gốc).

---

## 1. Tổng quan kiến trúc mã hóa (2 lớp lồng nhau)

```
Thông điệp gốc (M)
   │  AES-256-GCM, khóa dẫn từ bí mật chung S + số ngẫu nhiên x0
   ▼
Lớp 1: ct = AES-GCM_K(M)                       [bảo vệ bởi bí mật chung S]
   │  tlock (IBE trên đường cong BLS12-381, mạng drand quicknet)
   ▼
Lớp 2: wrapped = tlock_encrypt(round, ct)       [bảo vệ bởi THỜI GIAN]
```

Hai lớp bảo vệ **hai thứ khác nhau** và cần được đánh giá **riêng biệt**:

- **Lớp 2 (time-lock)** chỉ trả lời câu hỏi: *"đã đến giờ mở hay chưa"*. Nó **không phân biệt người giải mã là ai** — sau đúng thời điểm đã định, **bất kỳ ai cũng gỡ được lớp này** (đây là thiết kế cố ý, không phải lỗi).
- **Lớp 1 (AES‑GCM + bí mật chung)** mới là lớp quyết định **ai đọc được nội dung thật**, kể cả sau khi đã tới giờ mở.

→ Độ an toàn **sau giờ mở** của toàn hệ thống = độ an toàn của **riêng lớp 1**.
→ Độ an toàn **trước giờ mở** = độ an toàn của **riêng lớp 2**.

---

## 2. Lớp 1 — AES‑256‑GCM + dẫn khóa từ bí mật chung

### 2.1 Cơ chế chính xác

```
x0        = số ngẫu nhiên 12 chữ số (CSPRNG, ~40 bit, CÔNG KHAI — nằm trong link)
inner     = HMAC-SHA256(key = x0,    msg = S)
K         = HMAC-SHA256(key = inner, msg = "klock-v1" + 0x01)     # khóa AES-256
nonce     = SHA-256(x0)[0..12]
AAD       = x0 + "DDMMYYYYHHMMSS"   (chuỗi "code", công khai trong link)
ciphertext‖tag = AES-256-GCM(K, nonce, AAD, M)
```

### 2.2 Độ mạnh lý thuyết vs. độ mạnh thực tế

**Điểm mấu chốt:** khóa AES chỉ thực sự có 256 bit ngẫu nhiên **nếu S được chọn ngẫu nhiên đều trên không gian 256 bit**. Trong thực tế, `S` là một chuỗi do con người tự nhập ("bí mật chung"), và hệ thống **không hề làm chậm** quá trình suy khóa — chỉ 2 lần gọi HMAC‑SHA256 (rất nhanh, không phải KDF chuyên dụng kiểu Argon2id/PBKDF2/bcrypt).

→ **Độ khó phá mã thực tế = độ khó đoán ra S**, không phải 256 bit danh nghĩa của AES.

Vì mỗi thông điệp dùng `x0` khác nhau (vai trò như "salt"), kẻ tấn công **không thể** dùng một bảng tra cứu (rainbow table) dùng chung cho nhiều thông điệp — phải brute-force lại từ đầu cho **mỗi** thông điệp riêng lẻ. Đây là điểm cộng thật sự của thiết kế.

AES‑256‑GCM và HMAC‑SHA256 tự thân **chưa từng bị phá** (không có điểm yếu toán học đã biết làm giảm độ an toàn thiết kế) — toàn bộ rủi ro nằm ở **tốc độ đoán S**, không phải ở thuật toán mã hóa.

### 2.3 Bảng thời gian phá mã theo độ mạnh của bí mật chung S

Giả định kẻ tấn công có `ciphertext`, biết `x0`/`AAD` (đều công khai trong link) và thử các giá trị S khác nhau, mỗi lượt thử tốn 2 lần HMAC‑SHA256 + 1 lần kiểm tra tag GCM (~ vài ns trên phần cứng hiện đại). Hai kịch bản phần cứng:

| Loại bí mật chung S | Entropy | Số tổ hợp | 1 GPU phổ thông (~10⁹ lượt/giây) | Cụm ASIC/cloud lớn (~10¹³ lượt/giây) |
|---|---:|---:|---:|---:|
| 2 ký tự (ví dụ `"Hi"`) | 11.4 bit | 2.7 × 10³ | **1.4 micro-giây** | tức thì |
| 6 ký tự chữ thường | 28.2 bit | 3.1 × 10⁸ | **≈ 0.15 giây** | tức thì |
| 8 ký tự chữ+số | 47.6 bit | 2.2 × 10¹⁴ | ≈ 1.3 ngày | **≈ 11 giây** |
| 10 ký tự chữ+số | 59.5 bit | 1.3 × 10¹⁸ | ≈ 13 năm | ≈ 12 giờ |
| Diceware 4 từ (EFF wordlist) | 51.7 bit | 3.7 × 10¹⁵ | ≈ 21 ngày | ≈ 3 phút |
| Diceware 6 từ | 77.5 bit | 1.4 × 10²³ | ≈ 3.5 triệu năm | ≈ 350 năm |
| Diceware 8 từ | 103.4 bit | 9.2 × 10³⁰ | bất khả thi | ≈ 2.1 × 10¹⁰ năm |
| 12 ký tự chữ+số+ký hiệu | 78.7 bit | 3.0 × 10²³ | ≈ 7.5 triệu năm | ≈ 754 năm |
| Chuỗi ngẫu nhiên 20 ký tự | 119.1 bit | 5.3 × 10³⁵ | bất khả thi | bất khả thi (≈ 10¹⁵ năm) |
| **Khóa AES‑256 ngẫu nhiên thật** | **256 bit** | 1.2 × 10⁷⁷ | **bất khả thi tuyệt đối** | **bất khả thi tuyệt đối** |

> Ghi chú: "bất khả thi tuyệt đối" với AES‑256 không chỉ vì chưa có máy đủ nhanh — theo giới hạn Landauer (nhiệt động lực học của tính toán), chỉ riêng việc **đếm** qua 2²⁵⁶ trạng thái cần năng lượng vượt xa tổng năng lượng bức xạ của Mặt Trời trong hàng tỷ năm. Đây là lý do AES‑256 được xem là an toàn vĩnh viễn trước brute-force thuần túy, kể cả với máy tính lượng tử tương lai gần (Grover's algorithm chỉ giảm còn ~128 bit hiệu dụng — vẫn bất khả thi).

### 2.4 Kết luận lớp 1

- **Nếu người dùng chọn S là một mật khẩu ngắn/thông dụng** (như ví dụ thật đã test trong dự án: `"Hi"`, `"secret123"`): **CÓ**, một máy tính phổ thông (thậm chí không cần GPU) có thể giải mã trong **vài giây đến vài phút**, vì KDF không làm chậm brute-force.
- **Nếu người dùng chọn S là một passphrase Diceware ≥ 6 từ, hoặc chuỗi ngẫu nhiên ≥ 16 ký tự**: **KHÔNG**, không có máy tính nào hiện có — kể cả siêu máy tính quốc gia — phá được trong thời gian hữu ích (hàng trăm đến hàng tỷ năm).
- **Mắt xích yếu nhất của toàn hệ thống nằm ở đây**, không phải ở AES‑256 hay time-lock.

---

## 3. Lớp 2 — Time-lock (tlock / mạng drand quicknet, đường cong BLS12‑381)

### 3.1 Cơ chế

Klock dùng **mã hóa dựa trên định danh (Identity-Based Encryption – IBE)** trên đường cong ghép cặp (pairing) BLS12‑381: dữ liệu được mã hóa theo một "định danh" là **số vòng (round number)** tương lai của mạng ngẫu nhiên phi tập trung drand. "Khóa riêng" tương ứng chính là **chữ ký ngưỡng BLS** mà mạng drand (League of Entropy — gồm nhiều tổ chức độc lập như Cloudflare, EPFL, Protocol Labs...) công bố công khai **đúng vào thời điểm round đó đến**, không sớm hơn.

### 3.2 Độ khó trước thời điểm mở khóa

Đây **không phải bài toán brute-force theo nghĩa thông thường** — không có "số tổ hợp cần thử". Để mở sớm, kẻ tấn công chỉ có 2 hướng:

1. **Giải bài toán toán học nền tảng** (logarit rời rạc / nghịch đảo phép ghép cặp trên BLS12‑381). Mức an toàn được giới học thuật và công nghiệp (Ethereum 2.0, Chia, Zcash, Filecoin đều dùng chung họ đường cong này) đánh giá **tương đương AES‑128, tức khoảng 2¹²⁸ phép toán** — dù trường số của đường cong là 381-bit, mức an toàn thực tế thấp hơn do đặc thù của mật mã ghép cặp. **2¹²⁸ vẫn là con số bất khả thi** với mọi phần cứng hiện có (tương đương việc dò toàn bộ không gian khóa AES‑128, chưa từng bị phá bằng brute-force).
2. **Thông đồng với đa số node ký của mạng drand** để tạo chữ ký giả sớm hơn lịch — đây **không phải vấn đề sức mạnh tính toán** mà là vấn đề **quản trị/niềm tin phân tán** (cần chiếm được ngưỡng đa số các tổ chức độc lập vận hành node — về mặt thực tế gần như bất khả thi với mạng quicknet hiện tại vì các node thuộc nhiều tổ chức không liên quan).

→ **Không máy tính nào — kể cả siêu máy tính — "tính" ra được đáp án sớm hơn giờ đã định**, vì bản thân "chìa khóa" (chữ ký) chưa tồn tại về mặt vật lý cho tới đúng thời điểm đó.

### 3.3 Sau thời điểm mở khóa

Ngay khi round đến, chữ ký trở thành **công khai hoàn toàn** (ai cũng tải được từ API của drand) → lớp 2 **không còn bảo vệ gì nữa cho bất kỳ ai**, kể cả người không liên quan. Đây là lý do lớp 1 (AES‑GCM + bí mật chung) **bắt buộc phải đủ mạnh độc lập**, vì nó là tuyến phòng thủ **duy nhất còn lại** sau giờ mở.

### 3.4 Kết luận lớp 2

An toàn ở mức thực tế **không thể phá được bằng tính toán** trước giờ hẹn, với điều kiện mạng drand quicknet không bị một nhóm thông đồng kiểm soát đa số node (rủi ro vận hành bên ngoài tầm kiểm soát của Klock, không phải lỗi thuật toán của Klock).

---

## 4. Đánh giá tổng hợp toàn hệ thống

| Thành phần | Mức an toàn danh nghĩa | Mức an toàn thực tế | Điểm nghẽn |
|---|---|---|---|
| AES‑256‑GCM (thuật toán) | 256 bit | 256 bit (không đổi, thuật toán không có lỗi) | — |
| Dẫn khóa từ bí mật chung S | (phụ thuộc S) | **= entropy thật của S** (không có key-stretching) | **S yếu → toàn hệ thống yếu** |
| Time-lock (BLS12‑381) | ~128 bit trước giờ mở | ~128 bit trước giờ mở, **0 bit sau giờ mở** | Niềm tin vào mạng drand (ngoài phạm vi code) |
| Số ngẫu nhiên x0 (nonce/salt) | ~40 bit | Không phải bí mật (công khai) — chỉ chống rainbow-table dùng chung | — |

**Kết luận một câu:** toàn bộ độ an toàn thực tế của Klock, sau khi đã qua thời điểm mở khóa, **quy về đúng một con số: entropy của bí mật chung mà người dùng tự chọn.** Thuật toán mã hóa (AES‑256‑GCM) và lớp time-lock (BLS12‑381/drand) đều đạt chuẩn công nghiệp, không có lỗi logic hay lỗ hổng toán học — chúng không phải là điểm yếu.

---

## 5. Khuyến nghị cải thiện (nếu muốn nâng cấp)

1. **Thêm hàm KDF chuyên dụng** (Argon2id hoặc tối thiểu PBKDF2 với ≥ 300.000 vòng lặp) thay cho 2 lần HMAC‑SHA256 hiện tại. Việc này **không làm yếu đi với bí mật mạnh**, nhưng tăng chi phí brute-force lên 10³–10⁶ lần với bí mật yếu — biến "vài giây" ở bảng mục 2.3 thành "vài giờ/ngày", mua thêm thời gian phản ứng.
2. **Cảnh báo độ mạnh bí mật** ngay trên giao diện khi người dùng nhập S quá ngắn (ví dụ < 12 ký tự hoặc trùng từ điển phổ biến) — biện pháp rẻ, hiệu quả cao vì đây chính là mắt xích yếu nhất.
3. Giữ nguyên lớp time-lock — đã đạt chuẩn ngành, không cần thay đổi.

---

## 6. Trả lời trực tiếp: "máy tính có giải được không?"

| Bạn dùng bí mật chung kiểu nào? | Máy tính (GPU/cluster) giải được không? |
|---|---|
| Từ ngắn, dễ đoán (`"Hi"`, `"123456"`, tên riêng...) | **Có — trong vài giây đến vài phút**, bằng một GPU phổ thông |
| Mật khẩu 8–10 ký tự ngẫu nhiên | **Có thể**, nếu kẻ tấn công có cụm máy mạnh (giờ → ngày); khó với máy đơn lẻ (năm) |
| Passphrase Diceware ≥ 6 từ hoặc chuỗi ngẫu nhiên ≥ 16 ký tự | **Không** — vượt xa khả năng mọi máy tính hiện nay |
| Trước thời điểm mở khóa (bất kể bí mật mạnh/yếu) | **Không** — bị chặn bởi time-lock, không phải bài toán tính toán mà là "chưa tồn tại chìa khóa" |

---

*Báo cáo dựa trên việc đọc trực tiếp mã nguồn tại thời điểm viết (sau khi đã vendor `tlock-js` nội bộ và thêm rate-limit). Các con số thời gian ở mục 2.3 là ước tính bậc độ lớn (order-of-magnitude), dùng giả định phần cứng tấn công hiện thực năm 2026; không nhằm mục đích chính xác tuyệt đối mà để minh họa mức chênh lệch khổng lồ giữa các lựa chọn bí mật chung.*
