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
const MAX_WRONG_ATTEMPTS = 5; // chặn dò mật khẩu bằng cách spam sai nhiều lần

// Múi giờ dùng khi nhập ngày giờ tay — đi theo ngôn ngữ bot đang chọn, mỗi ngôn ngữ ứng với
// 1 múi giờ tiêu biểu cho vùng dùng ngôn ngữ đó (không có cách khác để suy múi giờ thật của
// người dùng qua Bot API).
const LANG_TZ_MIN = { en: 0, vi: 7 * 60, ru: 3 * 60, zh: 8 * 60, es: 1 * 60 };
function tzOffsetMin(chatId) { return LANG_TZ_MIN[getLang(chatId)] ?? 0; }
function tzLabel(chatId) {
  const m = tzOffsetMin(chatId);
  const sign = m >= 0 ? "+" : "-";
  const a = Math.abs(m);
  return `UTC${sign}${pad(Math.floor(a / 60), 2)}:${pad(a % 60, 2)}`;
}

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
function setLang(chatId, lang) { chatLang.set(chatId, lang); applyCommandsForChat(chatId); }

function t(chatId, key, vars) {
  const lang = getLang(chatId);
  let s = (I18N[lang] && I18N[lang][key]) || I18N.en[key] || key;
  if (vars) for (const k of Object.keys(vars)) s = s.split(`{${k}}`).join(String(vars[k]));
  return s;
}

const I18N = {
  en: {
    start: "<blockquote>🔐 <b>Klock</b>\nI'm your data-protection assistant, resistant to quantum computers and supercomputers. Decrypting my files needs both time and a secret key!</blockquote>\n🔒 Encrypt: password + time → get a link/file.\n🔓 Decrypt: send link/file + password.\n\nChoose an action:",
    btnEnc: "🔒 Encrypt", btnDec: "🔓 Decrypt", btnLang: "🌐 Language", btnHelp: "📘 Help",
    askSecretEnc: "🔑 Secret password:",
    onlyText: "Please send as text.",
    askMessage: "✍️ Content or file/photo to encrypt (≤19MB):",
    sendTextFileOrPhoto: "Send text, a file, or a photo.",
    askTimeChoose: "⏰ Unlock at:",
    p1m: "+1 min", p10m: "+10 min", p1h: "+1 hour", p6h: "+6 hours", p1d: "+1 day", p3d: "+3 days", p1w: "+1 week", p1mo: "+1 month",
    pcustom: "📅 Custom",
    askCustomTime: "Date/time ({tz}):\n`YYYY-MM-DD HH:MM`",
    badTimeFormat: "Wrong format. E.g.: `2026-12-25 08:00`",
    mustBeFuture: "The unlock time must be in the future.",
    encrypting: "⏳ Encrypting…",
    encryptedDone: "<blockquote>✅ Done!\n🔗 {link}\nUnlocks: {time}</blockquote>",
    btnCopyLink: "📋 Copy link",
    askDecInput: "🔗 Paste a link or send the .json file:",
    invalidLink: "Invalid link.", notFound: "Not found (expired or wrong link).",
    jsonBadFormat: "Not a valid Klock .json file.",
    locked: "🔒 Not unlocked yet. {remain} left.",
    networkErr: "⚠️ Network error reaching drand, try again later.",
    askDecSecret: "🔑 Secret password:",
    wrongSecretRetry: "❌ Wrong password ({left} left):",
    tooManyAttempts: "❌ Too many wrong attempts. /decrypt to start over.",
    decryptedResult: "✅ Result:\n\n{text}",
    fileTooLarge: "File too large (limit ~19MB over Telegram).",
    cancelled: "Cancelled. /start to begin again.",
    chooseLang: "🌐 Choose your language:", langSet: "✅ Language set to English.",
    genericError: "⚠️ Error: {err}", fileDownloadErr: "Could not download the file.",
    helpText: "📘 <b>How to use</b>\n🔒 /encrypt — password, content/file, unlock time → get a link + .json file.\n🔓 /decrypt — send the link or .json file, then the password (after unlock time).\n🌐 /lang — change language.\n❌ /cancel — cancel the current step.\nFiles up to ~19MB.",
  },
  vi: {
    start: "<blockquote>🔐 <b>Klock</b>\nTôi là trợ lý bảo vệ dữ liệu cho bạn, chống lại máy tính lượng tử và các siêu máy tính. Để giải mã được file của tôi cần thời gian và khóa bí mật!</blockquote>\n🔒 Mã hóa: mật khẩu + thời gian → nhận link/file.\n🔓 Giải mã: gửi link/file + mật khẩu.\n\nChọn thao tác:",
    btnEnc: "🔒 Mã hóa", btnDec: "🔓 Giải mã", btnLang: "🌐 Ngôn ngữ", btnHelp: "📘 Hướng dẫn",
    askSecretEnc: "🔑 Mật khẩu bí mật:",
    onlyText: "Vui lòng nhập dạng văn bản.",
    askMessage: "✍️ Nội dung hoặc file/ảnh cần mã hóa (≤19MB):",
    sendTextFileOrPhoto: "Gửi văn bản, file hoặc ảnh.",
    askTimeChoose: "⏰ Mở khóa lúc:",
    p1m: "+1 phút", p10m: "+10 phút", p1h: "+1 giờ", p6h: "+6 giờ", p1d: "+1 ngày", p3d: "+3 ngày", p1w: "+1 tuần", p1mo: "+1 tháng",
    pcustom: "📅 Ngày giờ khác",
    askCustomTime: "Ngày giờ ({tz}):\n`YYYY-MM-DD HH:MM`",
    badTimeFormat: "Sai định dạng. VD: `2026-12-25 08:00`",
    mustBeFuture: "Thời điểm mở khóa phải ở tương lai.",
    encrypting: "⏳ Đang mã hóa…",
    encryptedDone: "<blockquote>✅ Xong!\n🔗 {link}\nMở khóa: {time}</blockquote>",
    btnCopyLink: "📋 Copy link",
    askDecInput: "🔗 Dán link hoặc gửi file .json:",
    invalidLink: "Link không hợp lệ.", notFound: "Không tìm thấy (hết hạn hoặc sai link).",
    jsonBadFormat: "File không đúng định dạng .json của Klock.",
    locked: "🔒 Chưa mở khóa. Còn {remain}.",
    networkErr: "⚠️ Lỗi mạng khi liên hệ drand, thử lại sau.",
    askDecSecret: "🔑 Mật khẩu bí mật:",
    wrongSecretRetry: "❌ Sai mật khẩu ({left} lần):",
    tooManyAttempts: "❌ Sai quá nhiều lần. /decrypt để thử lại từ đầu.",
    decryptedResult: "✅ Kết quả:\n\n{text}",
    fileTooLarge: "File quá lớn (giới hạn ~19MB qua Telegram).",
    cancelled: "Đã hủy. /start để bắt đầu lại.",
    chooseLang: "🌐 Chọn ngôn ngữ:", langSet: "✅ Đã đổi ngôn ngữ sang Tiếng Việt.",
    genericError: "⚠️ Lỗi: {err}", fileDownloadErr: "Không tải được file.",
    helpText: "📘 <b>Hướng dẫn sử dụng</b>\n🔒 /encrypt — mật khẩu, nội dung/file, thời gian mở khóa → nhận link + file .json.\n🔓 /decrypt — gửi link hoặc file .json, rồi mật khẩu (sau khi tới giờ mở khóa).\n🌐 /lang — đổi ngôn ngữ.\n❌ /cancel — hủy bước đang làm.\nFile tối đa ~19MB.",
  },
  ru: {
    start: "<blockquote>🔐 <b>Klock</b>\nЯ ваш помощник по защите данных, устойчивый к квантовым компьютерам и суперкомпьютерам. Для расшифровки файла нужны время и секретный ключ!</blockquote>\n🔒 Шифрование: пароль + время → ссылка/файл.\n🔓 Расшифровка: ссылка/файл + пароль.\n\nВыберите действие:",
    btnEnc: "🔒 Зашифровать", btnDec: "🔓 Расшифровать", btnLang: "🌐 Язык", btnHelp: "📘 Справка",
    askSecretEnc: "🔑 Секретный пароль:",
    onlyText: "Введите текстом.",
    askMessage: "✍️ Текст или файл/фото для шифрования (до 19МБ):",
    sendTextFileOrPhoto: "Отправьте текст, файл или фото.",
    askTimeChoose: "⏰ Разблокировать через:",
    p1m: "+1 мин", p10m: "+10 мин", p1h: "+1 час", p6h: "+6 часов", p1d: "+1 день", p3d: "+3 дня", p1w: "+1 неделя", p1mo: "+1 месяц",
    pcustom: "📅 Другое",
    askCustomTime: "Дата/время ({tz}):\n`YYYY-MM-DD HH:MM`",
    badTimeFormat: "Неверный формат. Напр.: `2026-12-25 08:00`",
    mustBeFuture: "Время разблокировки должно быть в будущем.",
    encrypting: "⏳ Шифрование…",
    encryptedDone: "<blockquote>✅ Готово!\n🔗 {link}\nРазблокировка: {time}</blockquote>",
    btnCopyLink: "📋 Копировать ссылку",
    askDecInput: "🔗 Вставьте ссылку или отправьте .json файл:",
    invalidLink: "Неверная ссылка.", notFound: "Не найдено (истекло или неверная ссылка).",
    jsonBadFormat: "Не корректный .json файл Klock.",
    locked: "🔒 Пока заблокировано. Осталось {remain}.",
    networkErr: "⚠️ Ошибка сети при обращении к drand, попробуйте позже.",
    askDecSecret: "🔑 Секретный пароль:",
    wrongSecretRetry: "❌ Неверный пароль ({left} попыток):",
    tooManyAttempts: "❌ Слишком много попыток. /decrypt чтобы начать заново.",
    decryptedResult: "✅ Результат:\n\n{text}",
    fileTooLarge: "Файл слишком большой (лимит Telegram ~19МБ).",
    cancelled: "Отменено. /start чтобы начать снова.",
    chooseLang: "🌐 Выберите язык:", langSet: "✅ Язык изменён на русский.",
    genericError: "⚠️ Ошибка: {err}", fileDownloadErr: "Не удалось скачать файл.",
    helpText: "📘 <b>Как использовать</b>\n🔒 /encrypt — пароль, текст/файл, время разблокировки → ссылка + .json файл.\n🔓 /decrypt — отправьте ссылку или .json файл, затем пароль (после разблокировки).\n🌐 /lang — сменить язык.\n❌ /cancel — отменить текущий шаг.\nФайлы до ~19МБ.",
  },
  zh: {
    start: "<blockquote>🔐 <b>Klock</b>\n我是你的数据保护助手,能抵御量子计算机和超级计算机。解密文件需要时间和密钥!</blockquote>\n🔒 加密:密码+时间→获得链接/文件。\n🔓 解密:发送链接/文件+密码。\n\n请选择操作:",
    btnEnc: "🔒 加密", btnDec: "🔓 解密", btnLang: "🌐 语言", btnHelp: "📘 帮助",
    askSecretEnc: "🔑 密码:",
    onlyText: "请以文字输入。",
    askMessage: "✍️ 要加密的内容或文件/图片(≤19MB):",
    sendTextFileOrPhoto: "发送文本、文件或图片。",
    askTimeChoose: "⏰ 解锁时间:",
    p1m: "+1分钟", p10m: "+10分钟", p1h: "+1小时", p6h: "+6小时", p1d: "+1天", p3d: "+3天", p1w: "+1周", p1mo: "+1个月",
    pcustom: "📅 自定义",
    askCustomTime: "日期时间({tz}):\n`YYYY-MM-DD HH:MM`",
    badTimeFormat: "格式错误,如:`2026-12-25 08:00`",
    mustBeFuture: "解锁时间必须在未来。",
    encrypting: "⏳ 正在加密…",
    encryptedDone: "<blockquote>✅ 完成!\n🔗 {link}\n解锁: {time}</blockquote>",
    btnCopyLink: "📋 复制链接",
    askDecInput: "🔗 粘贴链接或发送 .json 文件:",
    invalidLink: "链接无效。", notFound: "未找到(已过期或链接错误)。",
    jsonBadFormat: "不是有效的 Klock .json 文件。",
    locked: "🔒 尚未解锁,还剩 {remain}。",
    networkErr: "⚠️ 连接 drand 网络出错,请稍后重试。",
    askDecSecret: "🔑 密码:",
    wrongSecretRetry: "❌ 密码错误(剩{left}次):",
    tooManyAttempts: "❌ 错误次数过多。发送 /decrypt 重新开始。",
    decryptedResult: "✅ 结果:\n\n{text}",
    fileTooLarge: "文件过大(Telegram 限制约19MB)。",
    cancelled: "已取消。发送 /start 重新开始。",
    chooseLang: "🌐 选择语言:", langSet: "✅ 语言已切换为中文。",
    genericError: "⚠️ 出错: {err}", fileDownloadErr: "无法下载文件。",
    helpText: "📘 <b>使用说明</b>\n🔒 /encrypt — 密码、内容/文件、解锁时间 → 获得链接 + .json 文件。\n🔓 /decrypt — 发送链接或 .json 文件,然后输入密码(解锁后)。\n🌐 /lang — 更改语言。\n❌ /cancel — 取消当前步骤。\n文件最大约19MB。",
  },
  es: {
    start: "<blockquote>🔐 <b>Klock</b>\nSoy tu asistente de protección de datos, resistente a ordenadores cuánticos y superordenadores. Descifrar un archivo necesita tiempo y una clave secreta!</blockquote>\n🔒 Cifrar: contraseña + tiempo → enlace/archivo.\n🔓 Descifrar: enlace/archivo + contraseña.\n\nElige una acción:",
    btnEnc: "🔒 Cifrar", btnDec: "🔓 Descifrar", btnLang: "🌐 Idioma", btnHelp: "📘 Ayuda",
    askSecretEnc: "🔑 Contraseña secreta:",
    onlyText: "Envíalo como texto.",
    askMessage: "✍️ Contenido o archivo/foto a cifrar (≤19MB):",
    sendTextFileOrPhoto: "Envía texto, un archivo o una foto.",
    askTimeChoose: "⏰ Desbloquear en:",
    p1m: "+1 min", p10m: "+10 min", p1h: "+1 hora", p6h: "+6 horas", p1d: "+1 día", p3d: "+3 días", p1w: "+1 semana", p1mo: "+1 mes",
    pcustom: "📅 Personalizado",
    askCustomTime: "Fecha/hora ({tz}):\n`YYYY-MM-DD HH:MM`",
    badTimeFormat: "Formato incorrecto. Ej.: `2026-12-25 08:00`",
    mustBeFuture: "El momento de desbloqueo debe ser en el futuro.",
    encrypting: "⏳ Cifrando…",
    encryptedDone: "<blockquote>✅ ¡Listo!\n🔗 {link}\nDesbloquea: {time}</blockquote>",
    btnCopyLink: "📋 Copiar enlace",
    askDecInput: "🔗 Pega el enlace o envía el archivo .json:",
    invalidLink: "Enlace no válido.", notFound: "No encontrado (caducado o enlace incorrecto).",
    jsonBadFormat: "No es un .json de Klock válido.",
    locked: "🔒 Aún bloqueado. Quedan {remain}.",
    networkErr: "⚠️ Error de red al contactar drand, inténtalo más tarde.",
    askDecSecret: "🔑 Contraseña secreta:",
    wrongSecretRetry: "❌ Contraseña incorrecta ({left} intentos):",
    tooManyAttempts: "❌ Demasiados intentos. /decrypt para empezar de nuevo.",
    decryptedResult: "✅ Resultado:\n\n{text}",
    fileTooLarge: "Archivo demasiado grande (límite ~19MB).",
    cancelled: "Cancelado. /start para empezar de nuevo.",
    chooseLang: "🌐 Elige tu idioma:", langSet: "✅ Idioma cambiado a español.",
    genericError: "⚠️ Error: {err}", fileDownloadErr: "No se pudo descargar el archivo.",
    helpText: "📘 <b>Cómo usarlo</b>\n🔒 /encrypt — contraseña, contenido/archivo, hora de desbloqueo → enlace + archivo .json.\n🔓 /decrypt — envía el enlace o el archivo .json, luego la contraseña (tras desbloquear).\n🌐 /lang — cambiar idioma.\n❌ /cancel — cancelar el paso actual.\nArchivos hasta ~19MB.",
  },
};

// Mô tả lệnh hiển thị trong menu (nút "/") của Telegram, theo từng ngôn ngữ đã chọn
// — đặt riêng theo scope "chat" cho mỗi chatId, vì setMyCommands không nhận {key} nội suy.
const COMMAND_I18N = {
  en: { start: "Open the Klock menu", encrypt: "Encrypt a message/file with a time-lock", decrypt: "Decrypt a link or received file", lang: "Change language", help: "How to use this bot", cancel: "Cancel the current operation" },
  vi: { start: "Mở menu Klock", encrypt: "Mã hóa tin nhắn/file theo thời gian", decrypt: "Giải mã link hoặc file đã nhận", lang: "Đổi ngôn ngữ", help: "Hướng dẫn sử dụng bot", cancel: "Hủy thao tác hiện tại" },
  ru: { start: "Открыть меню Klock", encrypt: "Зашифровать сообщение/файл с таймлоком", decrypt: "Расшифровать ссылку или файл", lang: "Сменить язык", help: "Как использовать бота", cancel: "Отменить текущую операцию" },
  zh: { start: "打开 Klock 菜单", encrypt: "按时间锁加密消息/文件", decrypt: "解密链接或收到的文件", lang: "更改语言", help: "使用说明", cancel: "取消当前操作" },
  es: { start: "Abrir el menú de Klock", encrypt: "Cifrar un mensaje/archivo con bloqueo temporal", decrypt: "Descifrar un enlace o archivo recibido", lang: "Cambiar idioma", help: "Cómo usar este bot", cancel: "Cancelar la operación actual" },
};

function applyCommandsForChat(chatId) {
  const c = COMMAND_I18N[getLang(chatId)] || COMMAND_I18N.en;
  bot.setMyCommands(
    [
      { command: "start", description: c.start },
      { command: "encrypt", description: c.encrypt },
      { command: "decrypt", description: c.decrypt },
      { command: "lang", description: c.lang },
      { command: "help", description: c.help },
      { command: "cancel", description: c.cancel },
    ],
    { scope: { type: "chat", chat_id: chatId } }
  ).catch(() => {});
}

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

// Nhận "YYYY-MM-DD HH:MM" hoặc "YYYY-MM-DD HH:MM:SS" theo múi giờ của ngôn ngữ đang chọn -> unix ms (UTC thật)
function parseCustomDateTime(input, chatId) {
  const m = input.trim().match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?$/);
  if (!m) return null;
  const [, y, mo, d, h, mi, se] = m;
  const ms = Date.UTC(+y, +mo - 1, +d, +h, +mi, +(se || 0)) - tzOffsetMin(chatId) * 60000;
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

// Nhãn thời gian mở khóa hiển thị trong kết quả — theo múi giờ của ngôn ngữ đang chọn.
function fmtTzTime(ms, chatId) {
  const off = tzOffsetMin(chatId);
  const t = new Date(ms + off * 60000);
  return `${t.getUTCFullYear()}-${pad(t.getUTCMonth() + 1, 2)}-${pad(t.getUTCDate(), 2)} ${pad(t.getUTCHours(), 2)}:${pad(t.getUTCMinutes(), 2)} (${tzLabel(chatId)})`;
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
    [{ text: t(chatId, "btnHelp"), callback_data: "help" }, { text: t(chatId, "btnLang"), callback_data: "langmenu" }],
  ] } };
}

// Gửi lại đúng tin nhắn/menu như /start — dùng để người dùng thao tác tiếp ngay sau khi
// mã hóa/giải mã xong, không cần tự gõ /start lại.
function sendMenu(chatId) {
  bot.sendMessage(chatId, t(chatId, "start"), { parse_mode: "HTML", ...mainMenu(chatId) });
}

function langMenu() {
  return { reply_markup: { inline_keyboard: [
    [{ text: "🇬🇧 English", callback_data: "lang:en" }, { text: "🇻🇳 Tiếng Việt", callback_data: "lang:vi" }],
    [{ text: "🇷🇺 Русский", callback_data: "lang:ru" }, { text: "🇨🇳 中文", callback_data: "lang:zh" }],
    [{ text: "🇪🇸 Español", callback_data: "lang:es" }],
  ] } };
}

const TIME_PRESETS = [
  ["p1m", 1], ["p10m", 10], ["p1h", 60], ["p6h", 6 * 60], ["p1d", 24 * 60],
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
  { command: "help", description: "How to use this bot" },
  { command: "cancel", description: "Cancel the current operation" },
]).catch(() => {});

bot.onText(/\/start/, (msg) => {
  const chatId = msg.chat.id;
  if (!chatLang.has(chatId)) setLang(chatId, inferLang(msg.from && msg.from.language_code));
  resetState(chatId);
  sendMenu(chatId);
});

bot.onText(/\/cancel/, (msg) => {
  resetState(msg.chat.id);
  bot.sendMessage(msg.chat.id, t(msg.chat.id, "cancelled"));
});

bot.onText(/\/lang/, (msg) => {
  bot.sendMessage(msg.chat.id, t(msg.chat.id, "chooseLang"), langMenu());
});

bot.onText(/\/help/, (msg) => {
  bot.sendMessage(msg.chat.id, t(msg.chat.id, "helpText"), { parse_mode: "HTML" });
});

bot.onText(/\/encrypt/, (msg) => startEncrypt(msg.chat.id));
bot.onText(/\/decrypt/, (msg) => startDecrypt(msg.chat.id));

bot.on("callback_query", async (q) => {
  bot.answerCallbackQuery(q.id).catch(() => {});
  const chatId = q.message.chat.id;
  const data = q.data || "";

  if (data === "enc") return startEncrypt(chatId);
  if (data === "dec") return startDecrypt(chatId);
  if (data === "help") return bot.sendMessage(chatId, t(chatId, "helpText"), { parse_mode: "HTML" });
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
      return bot.sendMessage(chatId, t(chatId, "askCustomTime", { tz: tzLabel(chatId) }), { parse_mode: "Markdown" });
    }
    const unlockMs = Date.now() + Number(val) * 60000;
    try {
      await performEncrypt(chatId, st, unlockMs, fmtTzTime(unlockMs, chatId));
    } catch (e) {
      console.error("klock-bot lỗi:", e);
      bot.sendMessage(chatId, t(chatId, "genericError", { err: e.message }));
      resetState(chatId);
    }
  }
});

function startEncrypt(chatId) {
  states.set(chatId, { mode: "enc", step: "secret", data: {} });
  bot.sendMessage(chatId, t(chatId, "askSecretEnc"), { parse_mode: "Markdown" }).then((m) => {
    const st = states.get(chatId);
    if (st) st.data.secretPromptMsgId = m.message_id;
  }).catch(() => {});
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
  if (!st) {
    // không ở giữa bước nào (không phải lúc nhập thời gian/mật khẩu/nội dung...) — nhắn gì
    // cũng hiện lại menu như /start, để người dùng luôn có lối thao tác tiếp theo trong tầm tay.
    if (!chatLang.has(chatId)) setLang(chatId, inferLang(msg.from && msg.from.language_code));
    return sendMenu(chatId);
  }

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
  bot.sendMessage(chatId, t(chatId, "encryptedDone", { link, time: timeLabel }), {
    parse_mode: "HTML",
    reply_markup: { inline_keyboard: [[{ text: t(chatId, "btnCopyLink"), copy_text: { text: link } }]] },
  });
  resetState(chatId);
  sendMenu(chatId);
}

async function handleEncryptMsg(chatId, st, msg) {
  if (st.step === "secret") {
    if (!msg.text) return bot.sendMessage(chatId, t(chatId, "onlyText"));
    st.data.secret = msg.text;
    deleteSoon(chatId, msg.message_id);
    if (st.data.secretPromptMsgId) deleteSoon(chatId, st.data.secretPromptMsgId);
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
    const unlockMs = parseCustomDateTime(msg.text, chatId);
    if (unlockMs === null) return bot.sendMessage(chatId, t(chatId, "badTimeFormat"), { parse_mode: "Markdown" });
    await performEncrypt(chatId, st, unlockMs, `${msg.text} (${tzLabel(chatId)})`);
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
  st.data.secretMsgIds = [];
  st.step = "secret";
  const m = await bot.sendMessage(chatId, t(chatId, "askDecSecret"), { parse_mode: "Markdown" });
  st.data.secretMsgIds.push(m.message_id);
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
        (st.data.secretMsgIds || []).forEach((id) => deleteSoon(chatId, id));
        bot.sendMessage(chatId, t(chatId, "tooManyAttempts"));
        resetState(chatId);
      } else {
        const wm = await bot.sendMessage(chatId, t(chatId, "wrongSecretRetry", { left: MAX_WRONG_ATTEMPTS - st.data.attempts }), { parse_mode: "Markdown" });
        (st.data.secretMsgIds = st.data.secretMsgIds || []).push(wm.message_id);
      }
      return;
    }
    // Đúng mật khẩu — xóa luôn cả chuỗi tin nhắn hỏi mật khẩu / báo sai trước đó, chỉ giữ kết quả.
    (st.data.secretMsgIds || []).forEach((id) => deleteSoon(chatId, id));
    const envelope = parseEnvelope(pt);
    if (envelope.isFile) {
      await bot.sendDocument(chatId, Buffer.from(envelope.fileBytes), {}, { filename: envelope.filename, contentType: envelope.mime });
      if (st.data.slug) await apiMarkDownloaded(st.data.slug); // giống hành vi nút "tải file" trên web: rút ngắn còn 5 phút
    } else {
      await bot.sendMessage(chatId, t(chatId, "decryptedResult", { text: envelope.text }));
    }
    resetState(chatId);
    sendMenu(chatId);
  }
}

argon2idReady.then(() => {
  bot.startPolling();
  console.log(`klock-bot đang chạy — API_BASE=${API_BASE} PUBLIC_BASE=${PUBLIC_BASE}`);
}).catch((e) => {
  console.error("Không nạp được module argon2id:", e);
  process.exit(1);
});
