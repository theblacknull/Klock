// Klock Telegram Bot — mã hóa/giải mã time-lock ngay trong Telegram, dùng lại đúng
// cùng công thức mã hóa với web (AES-256-GCM + Argon2id + tlock-js), và cùng server
// lưu trữ slug/link (http API nội bộ của klock-web).
"use strict";

require("dotenv").config({ path: require("path").join(__dirname, "..", ".env") });
require("dotenv").config(); // .env riêng của bot (nếu có) ghi đè thêm

const TelegramBot = require("node-telegram-bot-api");
const { timelockEncrypt, timelockDecrypt, mainnetClient, defaultChainInfo, roundAt } = require("tlock-js");

const BOT_TOKEN = process.env.API_KEY_BOT || process.env.BOT_TOKEN;
if (!BOT_TOKEN) {
  console.error("Thiếu BOT_TOKEN / API_KEY_BOT trong .env — không thể chạy bot.");
  process.exit(1);
}

// QUAN TRỌNG: package.json của hash-wasm không khai báo "exports", nên require("hash-wasm")
// (và cả import ESM thường) rơi về bản UMD ("main") — bản này cho ra kết quả Argon2id KHÁC
// với bản ESM ("dist/index.esm.js") mà web dùng (đã kiểm chứng), dù cùng tham số/version.
// Phải nạp đúng file ESM này để khóa suy ra khớp 100% với phía trình duyệt.
let argon2id;
const argon2idReady = import("hash-wasm/dist/index.esm.js").then((m) => { argon2id = m.argon2id; });

// API_BASE: gọi trực tiếp vào klock-web (nên để localhost, bot chạy cùng máy với server).
// PUBLIC_BASE: domain công khai để tạo link chia sẻ.
const API_BASE = process.env.API_BASE || "http://127.0.0.1:8787";
const PUBLIC_BASE = process.env.PUBLIC_BASE || "https://klock.blacknull.net";
const MAX_FILE_BYTES = 19 * 1024 * 1024; // giới hạn tải file của Telegram Bot API (~20MB)
const VN_OFFSET_MIN = 7 * 60; // giờ nhập tay trong bot luôn là giờ Việt Nam (UTC+7)
const MAX_WRONG_ATTEMPTS = 5; // chặn dò mật khẩu bằng cách spam sai nhiều lần

const bot = new TelegramBot(BOT_TOKEN, { polling: false });
const drandClient = mainnetClient();
const ARGON2 = { iterations: 3, parallelism: 1, memorySize: 65536, hashLength: 32, outputType: "binary" };
const enc = new TextEncoder();
const dec = new TextDecoder();

// ---------------------------------------------------------------------------
// i18n — cùng 5 ngôn ngữ như web (en/ru/vi/zh/es). Ngôn ngữ lưu theo chatId trong RAM.
// ---------------------------------------------------------------------------
const SUPPORTED_LANGS = ["en", "ru", "vi", "zh", "es"];
const chatLang = new Map();

function inferLang(code) {
  if (!code) return "en";
  const c = code.toLowerCase();
  for (const l of SUPPORTED_LANGS) if (c.startsWith(l)) return l;
  return "en";
}
function getLang(chatId) { return chatLang.get(chatId) || "en"; }
function setLang(chatId, lang) { chatLang.set(chatId, lang); }

function t(chatId, key, vars) {
  const lang = getLang(chatId);
  let s = (I18N[lang] && I18N[lang][key]) || I18N.en[key] || key;
  if (vars) for (const k of Object.keys(vars)) s = s.split(`{${k}}`).join(String(vars[k]));
  return s;
}

const I18N = {
  en: {
    start: "👋 *Klock* — time-lock encryption: content can only be decrypted after a time you choose.\n\nChoose an action:",
    btnEnc: "🔒 Encrypt", btnDec: "🔓 Decrypt", btnLang: "🌐 Language",
    askSecretEnc: "🔑 Enter the *secret password* used to encrypt (the recipient needs the same password to decrypt).\n_This message will be deleted automatically after I read it._",
    onlyText: "Please send the password as text.",
    askMessage: "✍️ Send the *content* to encrypt, or attach a *file/photo* (up to ~19MB):",
    sendTextFileOrPhoto: "Send text, a file, or a photo.",
    askTimeChoose: "⏰ Choose when it should unlock:",
    p10m: "+10 min", p1h: "+1 hour", p6h: "+6 hours", p1d: "+1 day", p3d: "+3 days", p1w: "+1 week", p1mo: "+1 month",
    pcustom: "📅 Custom date/time",
    askCustomTime: "Enter the unlock date/time in *Vietnam time (UTC+7)*, format:\n`YYYY-MM-DD HH:MM`\nExample: `2026-12-25 08:00`",
    badTimeFormat: "Wrong format. Example: `2026-12-25 08:00`",
    mustBeFuture: "The unlock time must be in the future.",
    encrypting: "⏳ Encrypting…",
    encryptedDone: "✅ Done!\n🔗 Link: {link}\n\nThe `.json` file above can be decrypted *without needing the link/server*. Unlocks at: {time}.",
    askDecInput: "🔗 Paste a Klock *link*, or send the encrypted *.json file* you received:",
    invalidLink: "Invalid link.", notFound: "Not found (expired or wrong link).",
    jsonBadFormat: "This file is not a valid Klock .json file.",
    locked: "🔒 Not unlocked yet. About {remain} left (unlocks at {time} UTC).",
    networkErr: "⚠️ Network error reaching drand, try again later.",
    askDecSecret: "🔑 Enter the *secret password* to decrypt.\n_This message will be deleted automatically after I read it._",
    wrongSecretRetry: "❌ Wrong password. Try again ({left} attempts left):",
    tooManyAttempts: "❌ Too many wrong attempts. Start over with /decrypt.",
    decryptedResult: "✅ Decrypted content:\n\n{text}",
    fileTooLarge: "File too large (limit ~19MB over Telegram).",
    cancelled: "Cancelled. Send /start to begin again.",
    chooseLang: "🌐 Choose your language:", langSet: "✅ Language set to English.",
    genericError: "⚠️ Something went wrong: {err}", fileDownloadErr: "Could not download the file from Telegram.",
  },
  vi: {
    start: "👋 *Klock* — mã hóa khóa thời gian: nội dung chỉ giải mã được sau 1 thời điểm bạn chọn.\n\nChọn 1 thao tác:",
    btnEnc: "🔒 Mã hóa", btnDec: "🔓 Giải mã", btnLang: "🌐 Ngôn ngữ",
    askSecretEnc: "🔑 Nhập *mật khẩu bí mật* dùng để mã hóa (người nhận cần đúng mật khẩu này để giải mã).\n_Tin nhắn này sẽ được bot tự xóa ngay sau khi đọc._",
    onlyText: "Vui lòng nhập mật khẩu dạng văn bản.",
    askMessage: "✍️ Nhập *nội dung* cần mã hóa, hoặc gửi 1 *file/ảnh* đính kèm (tối đa ~19MB):",
    sendTextFileOrPhoto: "Gửi văn bản, 1 file, hoặc 1 ảnh.",
    askTimeChoose: "⏰ Chọn thời điểm mở khóa:",
    p10m: "+10 phút", p1h: "+1 giờ", p6h: "+6 giờ", p1d: "+1 ngày", p3d: "+3 ngày", p1w: "+1 tuần", p1mo: "+1 tháng",
    pcustom: "📅 Chọn ngày giờ khác",
    askCustomTime: "Nhập *ngày giờ mở khóa* theo giờ Việt Nam (UTC+7), định dạng:\n`YYYY-MM-DD HH:MM`\nVí dụ: `2026-12-25 08:00`",
    badTimeFormat: "Sai định dạng. Ví dụ: `2026-12-25 08:00`",
    mustBeFuture: "Thời điểm mở khóa phải ở tương lai.",
    encrypting: "⏳ Đang mã hóa…",
    encryptedDone: "✅ Mã hóa xong!\n🔗 Link: {link}\n\nFile `.json` phía trên dùng để giải mã *không cần link/server*. Mở khóa lúc: {time}.",
    askDecInput: "🔗 Dán *link* Klock, hoặc gửi *file .json* đã mã hóa bạn nhận được:",
    invalidLink: "Link không hợp lệ.", notFound: "Không tìm thấy (hết hạn hoặc sai link).",
    jsonBadFormat: "File không đúng định dạng .json của Klock.",
    locked: "🔒 Chưa đến thời điểm mở khóa. Còn khoảng {remain} nữa (mở lúc {time} UTC).",
    networkErr: "⚠️ Lỗi mạng khi liên hệ drand, thử lại sau.",
    askDecSecret: "🔑 Nhập *mật khẩu bí mật* để giải mã.\n_Tin nhắn này sẽ được bot tự xóa ngay sau khi đọc._",
    wrongSecretRetry: "❌ Sai mật khẩu. Thử lại (còn {left} lần):",
    tooManyAttempts: "❌ Sai quá nhiều lần. Gõ /decrypt để thử lại từ đầu.",
    decryptedResult: "✅ Nội dung giải mã:\n\n{text}",
    fileTooLarge: "File quá lớn (giới hạn ~19MB qua Telegram).",
    cancelled: "Đã hủy. Gõ /start để bắt đầu lại.",
    chooseLang: "🌐 Chọn ngôn ngữ:", langSet: "✅ Đã đổi ngôn ngữ sang Tiếng Việt.",
    genericError: "⚠️ Có lỗi xảy ra: {err}", fileDownloadErr: "Không tải được file từ Telegram.",
  },
  ru: {
    start: "👋 *Klock* — шифрование с временным замком: содержимое можно расшифровать только после выбранного момента.\n\nВыберите действие:",
    btnEnc: "🔒 Зашифровать", btnDec: "🔓 Расшифровать", btnLang: "🌐 Язык",
    askSecretEnc: "🔑 Введите *секретный пароль* для шифрования (получателю нужен тот же пароль).\n_Это сообщение будет автоматически удалено после прочтения._",
    onlyText: "Пожалуйста, введите пароль текстом.",
    askMessage: "✍️ Отправьте *текст* для шифрования, или приложите *файл/фото* (до ~19МБ):",
    sendTextFileOrPhoto: "Отправьте текст, файл или фото.",
    askTimeChoose: "⏰ Выберите момент разблокировки:",
    p10m: "+10 мин", p1h: "+1 час", p6h: "+6 часов", p1d: "+1 день", p3d: "+3 дня", p1w: "+1 неделя", p1mo: "+1 месяц",
    pcustom: "📅 Своя дата/время",
    askCustomTime: "Введите *дату и время разблокировки* по времени Вьетнама (UTC+7), формат:\n`YYYY-MM-DD HH:MM`\nПример: `2026-12-25 08:00`",
    badTimeFormat: "Неверный формат. Пример: `2026-12-25 08:00`",
    mustBeFuture: "Время разблокировки должно быть в будущем.",
    encrypting: "⏳ Шифрование…",
    encryptedDone: "✅ Готово!\n🔗 Ссылка: {link}\n\nФайл `.json` выше можно расшифровать *без ссылки/сервера*. Разблокировка: {time}.",
    askDecInput: "🔗 Вставьте *ссылку* Klock или отправьте полученный *.json файл*:",
    invalidLink: "Неверная ссылка.", notFound: "Не найдено (истекло или неверная ссылка).",
    jsonBadFormat: "Это не корректный .json файл Klock.",
    locked: "🔒 Пока не разблокировано. Осталось около {remain} (разблокировка в {time} UTC).",
    networkErr: "⚠️ Ошибка сети при обращении к drand, попробуйте позже.",
    askDecSecret: "🔑 Введите *секретный пароль* для расшифровки.\n_Это сообщение будет автоматически удалено после прочтения._",
    wrongSecretRetry: "❌ Неверный пароль. Попробуйте снова (осталось попыток: {left}):",
    tooManyAttempts: "❌ Слишком много неверных попыток. Введите /decrypt, чтобы начать заново.",
    decryptedResult: "✅ Расшифрованное содержимое:\n\n{text}",
    fileTooLarge: "Файл слишком большой (лимит Telegram ~19МБ).",
    cancelled: "Отменено. Отправьте /start, чтобы начать снова.",
    chooseLang: "🌐 Выберите язык:", langSet: "✅ Язык изменён на русский.",
    genericError: "⚠️ Произошла ошибка: {err}", fileDownloadErr: "Не удалось скачать файл из Telegram.",
  },
  zh: {
    start: "👋 *Klock* — 时间锁加密:内容只能在你选择的时间之后解密。\n\n请选择操作:",
    btnEnc: "🔒 加密", btnDec: "🔓 解密", btnLang: "🌐 语言",
    askSecretEnc: "🔑 请输入用于加密的*密码*(接收者需要相同的密码才能解密)。\n_此消息读取后将自动删除。_",
    onlyText: "请以文本形式输入密码。",
    askMessage: "✍️ 发送要加密的*内容*,或附带一个*文件/图片*(最大约19MB):",
    sendTextFileOrPhoto: "发送文本、文件或图片。",
    askTimeChoose: "⏰ 选择解锁时间:",
    p10m: "+10分钟", p1h: "+1小时", p6h: "+6小时", p1d: "+1天", p3d: "+3天", p1w: "+1周", p1mo: "+1个月",
    pcustom: "📅 自定义日期/时间",
    askCustomTime: "请输入*解锁日期时间*(越南时间 UTC+7),格式:\n`YYYY-MM-DD HH:MM`\n例如:`2026-12-25 08:00`",
    badTimeFormat: "格式错误。例如:`2026-12-25 08:00`",
    mustBeFuture: "解锁时间必须在未来。",
    encrypting: "⏳ 正在加密…",
    encryptedDone: "✅ 完成!\n🔗 链接: {link}\n\n上面的 `.json` 文件可以*无需链接/服务器*直接解密。解锁时间: {time}。",
    askDecInput: "🔗 粘贴 Klock *链接*,或发送你收到的加密 *.json 文件*:",
    invalidLink: "链接无效。", notFound: "未找到(已过期或链接错误)。",
    jsonBadFormat: "该文件不是有效的 Klock .json 文件。",
    locked: "🔒 还未到解锁时间。大约还剩 {remain}(解锁时间 {time} UTC)。",
    networkErr: "⚠️ 连接 drand 网络出错,请稍后重试。",
    askDecSecret: "🔑 请输入解密用的*密码*。\n_此消息读取后将自动删除。_",
    wrongSecretRetry: "❌ 密码错误。请重试(还剩 {left} 次):",
    tooManyAttempts: "❌ 错误次数过多。请发送 /decrypt 重新开始。",
    decryptedResult: "✅ 解密内容:\n\n{text}",
    fileTooLarge: "文件过大(Telegram 限制约19MB)。",
    cancelled: "已取消。发送 /start 重新开始。",
    chooseLang: "🌐 选择语言:", langSet: "✅ 语言已切换为中文。",
    genericError: "⚠️ 出现错误: {err}", fileDownloadErr: "无法从 Telegram 下载文件。",
  },
  es: {
    start: "👋 *Klock* — cifrado con bloqueo temporal: el contenido solo se puede descifrar después de un momento que tú elijas.\n\nElige una acción:",
    btnEnc: "🔒 Cifrar", btnDec: "🔓 Descifrar", btnLang: "🌐 Idioma",
    askSecretEnc: "🔑 Introduce la *contraseña secreta* para cifrar (el destinatario necesita la misma contraseña).\n_Este mensaje se eliminará automáticamente después de leerlo._",
    onlyText: "Por favor, introduce la contraseña como texto.",
    askMessage: "✍️ Envía el *contenido* a cifrar, o adjunta un *archivo/foto* (hasta ~19MB):",
    sendTextFileOrPhoto: "Envía texto, un archivo o una foto.",
    askTimeChoose: "⏰ Elige cuándo se desbloqueará:",
    p10m: "+10 min", p1h: "+1 hora", p6h: "+6 horas", p1d: "+1 día", p3d: "+3 días", p1w: "+1 semana", p1mo: "+1 mes",
    pcustom: "📅 Fecha/hora personalizada",
    askCustomTime: "Introduce la *fecha y hora de desbloqueo* en hora de Vietnam (UTC+7), formato:\n`YYYY-MM-DD HH:MM`\nEjemplo: `2026-12-25 08:00`",
    badTimeFormat: "Formato incorrecto. Ejemplo: `2026-12-25 08:00`",
    mustBeFuture: "El momento de desbloqueo debe ser en el futuro.",
    encrypting: "⏳ Cifrando…",
    encryptedDone: "✅ ¡Listo!\n🔗 Enlace: {link}\n\nEl archivo `.json` de arriba se puede descifrar *sin necesidad del enlace/servidor*. Se desbloquea: {time}.",
    askDecInput: "🔗 Pega un *enlace* de Klock, o envía el *archivo .json* cifrado que recibiste:",
    invalidLink: "Enlace no válido.", notFound: "No encontrado (caducado o enlace incorrecto).",
    jsonBadFormat: "Este archivo no es un .json de Klock válido.",
    locked: "🔒 Aún no se ha desbloqueado. Falta aproximadamente {remain} (se desbloquea a las {time} UTC).",
    networkErr: "⚠️ Error de red al contactar drand, inténtalo más tarde.",
    askDecSecret: "🔑 Introduce la *contraseña secreta* para descifrar.\n_Este mensaje se eliminará automáticamente después de leerlo._",
    wrongSecretRetry: "❌ Contraseña incorrecta. Inténtalo de nuevo ({left} intentos restantes):",
    tooManyAttempts: "❌ Demasiados intentos incorrectos. Envía /decrypt para empezar de nuevo.",
    decryptedResult: "✅ Contenido descifrado:\n\n{text}",
    fileTooLarge: "Archivo demasiado grande (límite de Telegram ~19MB).",
    cancelled: "Cancelado. Envía /start para empezar de nuevo.",
    chooseLang: "🌐 Elige tu idioma:", langSet: "✅ Idioma cambiado a español.",
    genericError: "⚠️ Ocurrió un error: {err}", fileDownloadErr: "No se pudo descargar el archivo de Telegram.",
  },
};

// ---------------------------------------------------------------------------
// Crypto — y hệt công thức trong web/static/app.js (AES-256-GCM + Argon2id + HMAC),
// chỉ đổi WebCrypto trình duyệt -> crypto.subtle toàn cục của Node (cùng chuẩn WebCrypto).
// ---------------------------------------------------------------------------
function pad(n, w) { return String(n).padStart(w, "0"); }

async function sha256(bytes) { return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)); }

async function hmacSha256(keyBytes, msgBytes) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, msgBytes));
}

async function deriveKey(secretBytes, x0Bytes) {
  const stretched = await argon2id({ ...ARGON2, password: Buffer.from(secretBytes), salt: Buffer.from(x0Bytes) });
  return hmacSha256(stretched, new Uint8Array([...enc.encode("klock-v1"), 0x01]));
}

async function nonceOf(x0Bytes) { return (await sha256(x0Bytes)).slice(0, 12); }

async function gcmEncrypt(keyBytes, nonceBytes, aadBytes, plainBytes) {
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const out = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonceBytes, additionalData: aadBytes, tagLength: 128 }, key, plainBytes);
  return new Uint8Array(out);
}

async function gcmDecrypt(keyBytes, nonceBytes, aadBytes, ctBytes) {
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  const out = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonceBytes, additionalData: aadBytes, tagLength: 128 }, key, ctBytes);
  return new Uint8Array(out);
}

function randX0() {
  const b = require("crypto").randomBytes(8);
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
  v = v % 1000000000000n;
  return v.toString().padStart(12, "0");
}

// ---- gói tin: text hoặc file, giống hệt envelope của web ----
function buildEnvelope({ text, fileBuf, filename, mime }) {
  if (!fileBuf) return Buffer.concat([Buffer.from([0]), Buffer.from(text || "", "utf8")]);
  const fnBytes = Buffer.from(filename, "utf8");
  const mimeBytes = Buffer.from(mime || "application/octet-stream", "utf8");
  const head = Buffer.alloc(1 + 2 + fnBytes.length + 2 + mimeBytes.length);
  head[0] = 1;
  head.writeUInt16BE(fnBytes.length, 1);
  fnBytes.copy(head, 3);
  head.writeUInt16BE(mimeBytes.length, 3 + fnBytes.length);
  mimeBytes.copy(head, 3 + fnBytes.length + 2);
  return Buffer.concat([head, fileBuf]);
}

function parseEnvelope(bytes) {
  const buf = Buffer.from(bytes);
  if (buf[0] === 0) return { isFile: false, text: buf.slice(1).toString("utf8") };
  let off = 1;
  const fnLen = buf.readUInt16BE(off); off += 2;
  const filename = buf.slice(off, off + fnLen).toString("utf8"); off += fnLen;
  const mimeLen = buf.readUInt16BE(off); off += 2;
  const mime = buf.slice(off, off + mimeLen).toString("utf8"); off += mimeLen;
  return { isFile: true, filename, mime, fileBytes: buf.slice(off) };
}

// ---------------------------------------------------------------------------
// Gọi API nội bộ của klock-web (cùng server đứng sau web, chia sẻ đúng 1 kho lưu trữ)
// ---------------------------------------------------------------------------
async function apiEncrypt(code, wrapped) {
  const r = await fetch(`${API_BASE}/api/encrypt`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ code, wrapped }),
  });
  if (!r.ok) throw new Error(`encrypt API lỗi: HTTP ${r.status}`);
  return r.json();
}

async function apiGetItem(slug) {
  const r = await fetch(`${API_BASE}/api/item/${slug}`);
  if (!r.ok) return null;
  return r.json();
}

async function apiMarkDownloaded(slug) {
  try { await fetch(`${API_BASE}/api/item/${slug}/downloaded`, { method: "POST" }); } catch { /* best-effort */ }
}

function extractSlug(input) {
  const s = input.trim();
  const last = s.split("/").filter(Boolean).pop() || "";
  return last;
}

function unlockCodeFromDate(unlockMs) {
  const u = new Date(unlockMs);
  const dateStr = pad(u.getUTCDate(), 2) + pad(u.getUTCMonth() + 1, 2) + u.getUTCFullYear()
    + pad(u.getUTCHours(), 2) + pad(u.getUTCMinutes(), 2) + pad(u.getUTCSeconds(), 2);
  const x0 = randX0();
  return { x0, code: x0 + dateStr };
}

// Nhận "YYYY-MM-DD HH:MM" hoặc "YYYY-MM-DD HH:MM:SS" theo giờ Việt Nam (UTC+7) -> unix ms (UTC thật)
function parseVnDateTime(input) {
  const m = input.trim().match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?$/);
  if (!m) return null;
  const [, y, mo, d, h, mi, se] = m;
  const ms = Date.UTC(+y, +mo - 1, +d, +h, +mi, +(se || 0)) - VN_OFFSET_MIN * 60000;
  return Number.isNaN(ms) ? null : ms;
}

function fmtRemaining(ms, chatId) {
  const s = Math.max(0, Math.round(ms / 1000));
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), mi = Math.floor((s % 3600) / 60);
  const unit = { d: { en: "d", vi: " ngày", ru: " дн.", zh: " 天", es: " d" }, h: { en: "h", vi: " giờ", ru: " ч.", zh: " 时", es: " h" }, m: { en: "m", vi: " phút", ru: " мин", zh: " 分", es: " min" } };
  const lang = getLang(chatId);
  const parts = [];
  if (d) parts.push(`${d}${unit.d[lang] || unit.d.en}`);
  if (h) parts.push(`${h}${unit.h[lang] || unit.h.en}`);
  if (mi || parts.length === 0) parts.push(`${mi}${unit.m[lang] || unit.m.en}`);
  return parts.join(" ");
}

// Nhãn thời gian mở khóa hiển thị trong kết quả — giờ VN cho dễ đọc với mọi preset/custom.
function fmtVnTime(ms) {
  const t = new Date(ms + VN_OFFSET_MIN * 60000);
  return `${t.getUTCFullYear()}-${pad(t.getUTCMonth() + 1, 2)}-${pad(t.getUTCDate(), 2)} ${pad(t.getUTCHours(), 2)}:${pad(t.getUTCMinutes(), 2)} (UTC+7)`;
}

// ---------------------------------------------------------------------------
// State machine đơn giản theo chatId (bộ nhớ RAM, mất khi bot restart — không sao vì
// secret/nội dung chưa từng được lưu đĩa trong lúc chờ nhập, giống nguyên tắc của web)
// ---------------------------------------------------------------------------
const states = new Map();
const resetState = (chatId) => states.delete(chatId);

function mainMenu(chatId) {
  return { reply_markup: { inline_keyboard: [
    [{ text: t(chatId, "btnEnc"), callback_data: "enc" }, { text: t(chatId, "btnDec"), callback_data: "dec" }],
    [{ text: t(chatId, "btnLang"), callback_data: "langmenu" }],
  ] } };
}

function langMenu() {
  return { reply_markup: { inline_keyboard: [
    [{ text: "🇬🇧 English", callback_data: "lang:en" }, { text: "🇻🇳 Tiếng Việt", callback_data: "lang:vi" }],
    [{ text: "🇷🇺 Русский", callback_data: "lang:ru" }, { text: "🇨🇳 中文", callback_data: "lang:zh" }],
    [{ text: "🇪🇸 Español", callback_data: "lang:es" }],
  ] } };
}

const TIME_PRESETS = [
  ["p10m", 10], ["p1h", 60], ["p6h", 6 * 60], ["p1d", 24 * 60],
  ["p3d", 3 * 24 * 60], ["p1w", 7 * 24 * 60], ["p1mo", 30 * 24 * 60],
];

function timeMenu(chatId) {
  const rows = [];
  for (let i = 0; i < TIME_PRESETS.length; i += 2) {
    const row = TIME_PRESETS.slice(i, i + 2).map(([key, mins]) => ({ text: t(chatId, key), callback_data: `tp:${mins}` }));
    rows.push(row);
  }
  rows.push([{ text: t(chatId, "pcustom"), callback_data: "tp:custom" }]);
  return { reply_markup: { inline_keyboard: rows } };
}

bot.setMyCommands([
  { command: "start", description: "Open the Klock menu" },
  { command: "encrypt", description: "Encrypt a message/file with a time-lock" },
  { command: "decrypt", description: "Decrypt a link or received file" },
  { command: "lang", description: "Change language" },
  { command: "cancel", description: "Cancel the current operation" },
]).catch(() => {});

bot.onText(/\/start/, (msg) => {
  const chatId = msg.chat.id;
  if (!chatLang.has(chatId)) setLang(chatId, inferLang(msg.from && msg.from.language_code));
  resetState(chatId);
  bot.sendMessage(chatId, t(chatId, "start"), { parse_mode: "Markdown", ...mainMenu(chatId) });
});

bot.onText(/\/cancel/, (msg) => {
  resetState(msg.chat.id);
  bot.sendMessage(msg.chat.id, t(msg.chat.id, "cancelled"));
});

bot.onText(/\/lang/, (msg) => {
  bot.sendMessage(msg.chat.id, t(msg.chat.id, "chooseLang"), langMenu());
});

bot.onText(/\/encrypt/, (msg) => startEncrypt(msg.chat.id));
bot.onText(/\/decrypt/, (msg) => startDecrypt(msg.chat.id));

bot.on("callback_query", async (q) => {
  bot.answerCallbackQuery(q.id).catch(() => {});
  const chatId = q.message.chat.id;
  const data = q.data || "";

  if (data === "enc") return startEncrypt(chatId);
  if (data === "dec") return startDecrypt(chatId);
  if (data === "langmenu") return bot.sendMessage(chatId, t(chatId, "chooseLang"), langMenu());
  if (data.startsWith("lang:")) {
    const lang = data.slice(5);
    if (SUPPORTED_LANGS.includes(lang)) {
      setLang(chatId, lang);
      bot.sendMessage(chatId, t(chatId, "langSet"));
    }
    return;
  }

  if (data.startsWith("tp:")) {
    const st = states.get(chatId);
    if (!st || st.mode !== "enc" || st.step !== "time") return; // nút cũ từ phiên trước, bỏ qua
    const val = data.slice(3);
    if (val === "custom") {
      st.step = "time_custom";
      return bot.sendMessage(chatId, t(chatId, "askCustomTime"), { parse_mode: "Markdown" });
    }
    const unlockMs = Date.now() + Number(val) * 60000;
    try {
      await performEncrypt(chatId, st, unlockMs, fmtVnTime(unlockMs));
    } catch (e) {
      console.error("klock-bot lỗi:", e);
      bot.sendMessage(chatId, t(chatId, "genericError", { err: e.message }));
      resetState(chatId);
    }
  }
});

function startEncrypt(chatId) {
  states.set(chatId, { mode: "enc", step: "secret", data: {} });
  bot.sendMessage(chatId, t(chatId, "askSecretEnc"), { parse_mode: "Markdown" });
}

function startDecrypt(chatId) {
  states.set(chatId, { mode: "dec", step: "input", data: {} });
  bot.sendMessage(chatId, t(chatId, "askDecInput"), { parse_mode: "Markdown" });
}

// ---- xử lý tin nhắn văn bản theo state ----
bot.on("message", async (msg) => {
  const chatId = msg.chat.id;
  if (msg.text && msg.text.startsWith("/")) return; // đã xử lý bởi onText
  const st = states.get(chatId);
  if (!st) return; // chưa trong flow nào — bỏ qua (tránh spam khi người dùng chat tự do)

  try {
    if (st.mode === "enc") await handleEncryptMsg(chatId, st, msg);
    else if (st.mode === "dec") await handleDecryptMsg(chatId, st, msg);
  } catch (e) {
    if (e.message === "FILE_TOO_LARGE") bot.sendMessage(chatId, t(chatId, "fileTooLarge"));
    else if (e.message === "FILE_DOWNLOAD_ERR") bot.sendMessage(chatId, t(chatId, "fileDownloadErr"));
    else {
      console.error("klock-bot lỗi:", e);
      bot.sendMessage(chatId, t(chatId, "genericError", { err: e.message }));
    }
    resetState(chatId);
  }
});

async function downloadTelegramFile(fileId) {
  const link = await bot.getFileLink(fileId);
  const r = await fetch(link);
  if (!r.ok) throw new Error("FILE_DOWNLOAD_ERR");
  const buf = Buffer.from(await r.arrayBuffer());
  if (buf.length > MAX_FILE_BYTES) throw new Error("FILE_TOO_LARGE");
  return buf;
}

// Xóa ngay tin nhắn chứa mật khẩu bí mật khỏi lịch sử chat — Telegram cho bot xóa tin nhắn
// đến (incoming) trong chat riêng, nên hạn chế được việc mật khẩu bị lộ nếu ai đó xem lại
// lịch sử chat hoặc chụp màn hình sau này.
function deleteSoon(chatId, messageId) {
  bot.deleteMessage(chatId, messageId).catch(() => {});
}

async function performEncrypt(chatId, st, unlockMs, timeLabel) {
  if (unlockMs <= Date.now()) return bot.sendMessage(chatId, t(chatId, "mustBeFuture"));
  bot.sendMessage(chatId, t(chatId, "encrypting"));

  const { x0, code } = unlockCodeFromDate(unlockMs);
  const envelope = buildEnvelope(st.data.file
    ? { fileBuf: st.data.file.buf, filename: st.data.file.filename, mime: st.data.file.mime }
    : { text: st.data.text || "" });

  const secretBytes = enc.encode(st.data.secret);
  const x0Bytes = enc.encode(x0);
  const key = await deriveKey(secretBytes, x0Bytes);
  const nonceBytes = await nonceOf(x0Bytes);
  const aad = enc.encode(code);
  const ct = await gcmEncrypt(key, nonceBytes, aad, envelope);

  const roundNumber = roundAt(unlockMs, defaultChainInfo);
  const wrapped = await timelockEncrypt(roundNumber, Buffer.from(ct), drandClient);

  // Gửi file .klock trước (không cần server) — giống nguyên tắc bên web.
  const fileJson = Buffer.from(JSON.stringify({ code, wrapped }));
  await bot.sendDocument(chatId, fileJson, {}, { filename: `klock-${x0}.json`, contentType: "application/json" });

  const { slug } = await apiEncrypt(code, wrapped);
  const link = `${PUBLIC_BASE}/${slug}`;
  bot.sendMessage(chatId, t(chatId, "encryptedDone", { link, time: timeLabel }), { parse_mode: "Markdown" });
  resetState(chatId);
}

async function handleEncryptMsg(chatId, st, msg) {
  if (st.step === "secret") {
    if (!msg.text) return bot.sendMessage(chatId, t(chatId, "onlyText"));
    st.data.secret = msg.text;
    deleteSoon(chatId, msg.message_id);
    st.step = "message";
    bot.sendMessage(chatId, t(chatId, "askMessage"), { parse_mode: "Markdown" });
    return;
  }

  if (st.step === "message") {
    if (msg.document) {
      const buf = await downloadTelegramFile(msg.document.file_id);
      st.data.file = { buf, filename: msg.document.file_name || "file.bin", mime: msg.document.mime_type || "application/octet-stream" };
    } else if (msg.photo && msg.photo.length) {
      const best = msg.photo[msg.photo.length - 1];
      const buf = await downloadTelegramFile(best.file_id);
      st.data.file = { buf, filename: `photo_${best.file_id}.jpg`, mime: "image/jpeg" };
    } else if (msg.text) {
      st.data.text = msg.text;
    } else {
      return bot.sendMessage(chatId, t(chatId, "sendTextFileOrPhoto"));
    }
    st.step = "time";
    bot.sendMessage(chatId, t(chatId, "askTimeChoose"), timeMenu(chatId));
    return;
  }

  if (st.step === "time_custom") {
    if (!msg.text) return bot.sendMessage(chatId, t(chatId, "badTimeFormat"), { parse_mode: "Markdown" });
    const unlockMs = parseVnDateTime(msg.text);
    if (unlockMs === null) return bot.sendMessage(chatId, t(chatId, "badTimeFormat"), { parse_mode: "Markdown" });
    await performEncrypt(chatId, st, unlockMs, `${msg.text} (UTC+7)`);
  }
}

async function tryUnlockAndAskSecret(chatId, st, code, wrapped) {
  const unlockUnix = (() => {
    const d = code.slice(code.length - 14);
    const dd = +d.slice(0, 2), mo = +d.slice(2, 4), y = +d.slice(4, 8), h = +d.slice(8, 10), mi = +d.slice(10, 12), se = +d.slice(12, 14);
    return Date.UTC(y, mo - 1, dd, h, mi, se);
  })();

  let plain;
  try {
    plain = await timelockDecrypt(wrapped, drandClient);
  } catch (e) {
    const locked = /too early/i.test(e.message || "");
    if (locked) {
      const remain = unlockUnix - Date.now();
      bot.sendMessage(chatId, t(chatId, "locked", { remain: fmtRemaining(remain, chatId), time: new Date(unlockUnix).toISOString() }));
    } else {
      bot.sendMessage(chatId, t(chatId, "networkErr"));
    }
    resetState(chatId);
    return;
  }

  st.data.code = code;
  st.data.ct = Buffer.from(plain);
  st.data.attempts = 0;
  st.step = "secret";
  bot.sendMessage(chatId, t(chatId, "askDecSecret"), { parse_mode: "Markdown" });
}

async function handleDecryptMsg(chatId, st, msg) {
  if (st.step === "input") {
    if (msg.document) {
      const buf = await downloadTelegramFile(msg.document.file_id);
      let obj;
      try { obj = JSON.parse(buf.toString("utf8")); } catch { return bot.sendMessage(chatId, t(chatId, "jsonBadFormat")); }
      if (typeof obj.code !== "string" || typeof obj.wrapped !== "string") return bot.sendMessage(chatId, t(chatId, "jsonBadFormat"));
      st.data.slug = null; // file trực tiếp -> không cần server
      return tryUnlockAndAskSecret(chatId, st, obj.code, obj.wrapped);
    }
    if (!msg.text) return bot.sendMessage(chatId, t(chatId, "askDecInput"), { parse_mode: "Markdown" });
    const slug = extractSlug(msg.text);
    if (!/^[A-Za-z0-9]{6}$/.test(slug)) return bot.sendMessage(chatId, t(chatId, "invalidLink"));
    const item = await apiGetItem(slug);
    if (!item) return bot.sendMessage(chatId, t(chatId, "notFound"));
    st.data.slug = slug;
    return tryUnlockAndAskSecret(chatId, st, item.code, item.wrapped);
  }

  if (st.step === "secret") {
    if (!msg.text) return bot.sendMessage(chatId, t(chatId, "onlyText"));
    deleteSoon(chatId, msg.message_id);
    const { code, ct } = st.data;
    const x0 = code.slice(0, code.length - 14);
    const secretBytes = enc.encode(msg.text);
    const x0Bytes = enc.encode(x0);
    const key = await deriveKey(secretBytes, x0Bytes);
    const nonceBytes = await nonceOf(x0Bytes);
    const aad = enc.encode(code);
    let pt;
    try {
      pt = await gcmDecrypt(key, nonceBytes, aad, ct);
    } catch {
      st.data.attempts = (st.data.attempts || 0) + 1;
      if (st.data.attempts >= MAX_WRONG_ATTEMPTS) {
        bot.sendMessage(chatId, t(chatId, "tooManyAttempts"));
        resetState(chatId);
      } else {
        bot.sendMessage(chatId, t(chatId, "wrongSecretRetry", { left: MAX_WRONG_ATTEMPTS - st.data.attempts }), { parse_mode: "Markdown" });
      }
      return;
    }
    const envelope = parseEnvelope(pt);
    if (envelope.isFile) {
      await bot.sendDocument(chatId, Buffer.from(envelope.fileBytes), {}, { filename: envelope.filename, contentType: envelope.mime });
      if (st.data.slug) await apiMarkDownloaded(st.data.slug); // giống hành vi nút "tải file" trên web: rút ngắn còn 5 phút
    } else {
      await bot.sendMessage(chatId, t(chatId, "decryptedResult", { text: envelope.text }));
    }
    resetState(chatId);
  }
}

argon2idReady.then(() => {
  bot.startPolling();
  console.log(`klock-bot đang chạy — API_BASE=${API_BASE} PUBLIC_BASE=${PUBLIC_BASE}`);
}).catch((e) => {
  console.error("Không nạp được module argon2id:", e);
  process.exit(1);
});
