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
const VN_OFFSET_MIN = 7 * 60; // giờ nhập trong bot luôn là giờ Việt Nam (UTC+7)

const bot = new TelegramBot(BOT_TOKEN, { polling: false });
const drandClient = mainnetClient();
const ARGON2 = { iterations: 3, parallelism: 1, memorySize: 65536, hashLength: 32, outputType: "binary" };
const enc = new TextEncoder();
const dec = new TextDecoder();

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

function fmtRemaining(ms) {
  const s = Math.max(0, Math.round(ms / 1000));
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), mi = Math.floor((s % 3600) / 60);
  const parts = [];
  if (d) parts.push(`${d} ngày`);
  if (h) parts.push(`${h} giờ`);
  if (mi || parts.length === 0) parts.push(`${mi} phút`);
  return parts.join(" ");
}

// ---------------------------------------------------------------------------
// State machine đơn giản theo chatId (bộ nhớ RAM, mất khi bot restart — không sao vì
// secret/nội dung chưa từng được lưu đĩa trong lúc chờ nhập, giống nguyên tắc của web)
// ---------------------------------------------------------------------------
const states = new Map();
const resetState = (chatId) => states.delete(chatId);

function mainMenu() {
  return { reply_markup: { inline_keyboard: [[{ text: "🔒 Mã hóa", callback_data: "enc" }, { text: "🔓 Giải mã", callback_data: "dec" }]] } };
}

bot.setMyCommands([
  { command: "start", description: "Mở menu Klock" },
  { command: "encrypt", description: "Mã hóa tin nhắn/file theo thời gian" },
  { command: "decrypt", description: "Giải mã link hoặc file đã nhận" },
  { command: "cancel", description: "Hủy thao tác hiện tại" },
]).catch(() => {});

bot.onText(/\/start/, (msg) => {
  resetState(msg.chat.id);
  bot.sendMessage(msg.chat.id,
    "👋 *Klock* — mã hóa khóa thời gian: nội dung chỉ giải mã được sau 1 thời điểm bạn chọn.\n\nChọn 1 thao tác:",
    { parse_mode: "Markdown", ...mainMenu() });
});

bot.onText(/\/cancel/, (msg) => {
  resetState(msg.chat.id);
  bot.sendMessage(msg.chat.id, "Đã hủy. Gõ /start để bắt đầu lại.");
});

bot.onText(/\/encrypt/, (msg) => startEncrypt(msg.chat.id));
bot.onText(/\/decrypt/, (msg) => startDecrypt(msg.chat.id));

bot.on("callback_query", async (q) => {
  bot.answerCallbackQuery(q.id).catch(() => {});
  if (q.data === "enc") startEncrypt(q.message.chat.id);
  else if (q.data === "dec") startDecrypt(q.message.chat.id);
});

function startEncrypt(chatId) {
  states.set(chatId, { mode: "enc", step: "secret", data: {} });
  bot.sendMessage(chatId, "🔑 Nhập *mật khẩu bí mật* dùng để mã hóa (người nhận cần đúng mật khẩu này để giải mã):", { parse_mode: "Markdown" });
}

function startDecrypt(chatId) {
  states.set(chatId, { mode: "dec", step: "input", data: {} });
  bot.sendMessage(chatId, "🔗 Dán *link* Klock, hoặc gửi *file .json* đã mã hóa bạn nhận được:", { parse_mode: "Markdown" });
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
    console.error("klock-bot lỗi:", e);
    bot.sendMessage(chatId, "⚠️ Có lỗi xảy ra: " + e.message);
    resetState(chatId);
  }
});

async function downloadTelegramFile(fileId) {
  const link = await bot.getFileLink(fileId);
  const r = await fetch(link);
  if (!r.ok) throw new Error("không tải được file từ Telegram");
  const buf = Buffer.from(await r.arrayBuffer());
  if (buf.length > MAX_FILE_BYTES) throw new Error("file quá lớn (giới hạn ~19MB qua Telegram)");
  return buf;
}

async function handleEncryptMsg(chatId, st, msg) {
  if (st.step === "secret") {
    if (!msg.text) return bot.sendMessage(chatId, "Vui lòng nhập mật khẩu dạng văn bản.");
    st.data.secret = msg.text;
    st.step = "message";
    bot.sendMessage(chatId, "✍️ Nhập *nội dung* cần mã hóa, hoặc gửi 1 *file/ảnh* đính kèm (tối đa ~19MB):", { parse_mode: "Markdown" });
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
      return bot.sendMessage(chatId, "Gửi văn bản, 1 file, hoặc 1 ảnh.");
    }
    st.step = "time";
    bot.sendMessage(chatId,
      "⏰ Nhập *thời điểm mở khóa* theo giờ Việt Nam (UTC+7), định dạng:\n`YYYY-MM-DD HH:MM`\nVí dụ: `2026-12-25 08:00`",
      { parse_mode: "Markdown" });
    return;
  }

  if (st.step === "time") {
    if (!msg.text) return bot.sendMessage(chatId, "Nhập thời gian dạng YYYY-MM-DD HH:MM.");
    const unlockMs = parseVnDateTime(msg.text);
    if (unlockMs === null) return bot.sendMessage(chatId, "Sai định dạng. Ví dụ: `2026-12-25 08:00`", { parse_mode: "Markdown" });
    if (unlockMs <= Date.now()) return bot.sendMessage(chatId, "Thời điểm mở khóa phải ở tương lai.");

    bot.sendMessage(chatId, "⏳ Đang mã hóa…");
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
    bot.sendMessage(chatId,
      `✅ Mã hóa xong!\n🔗 Link: ${link}\n\nFile \`.json\` phía trên dùng để giải mã *không cần link/server*. Mở khóa lúc: ${msg.text} (giờ VN).`,
      { parse_mode: "Markdown" });
    resetState(chatId);
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
      bot.sendMessage(chatId, `🔒 Chưa đến thời điểm mở khóa. Còn khoảng ${fmtRemaining(remain)} nữa (mở lúc ${new Date(unlockUnix).toISOString()} UTC).`);
    } else {
      bot.sendMessage(chatId, "⚠️ Lỗi mạng khi liên hệ drand, thử lại sau.");
    }
    resetState(chatId);
    return;
  }

  st.data.code = code;
  st.data.ct = Buffer.from(plain);
  st.step = "secret";
  bot.sendMessage(chatId, "🔑 Nhập *mật khẩu bí mật* để giải mã:", { parse_mode: "Markdown" });
}

async function handleDecryptMsg(chatId, st, msg) {
  if (st.step === "input") {
    if (msg.document) {
      const buf = await downloadTelegramFile(msg.document.file_id);
      let obj;
      try { obj = JSON.parse(buf.toString("utf8")); } catch { return bot.sendMessage(chatId, "File không đúng định dạng .json của Klock."); }
      if (typeof obj.code !== "string" || typeof obj.wrapped !== "string") return bot.sendMessage(chatId, "File không đúng định dạng .json của Klock.");
      st.data.slug = null; // file trực tiếp -> không cần server
      return tryUnlockAndAskSecret(chatId, st, obj.code, obj.wrapped);
    }
    if (!msg.text) return bot.sendMessage(chatId, "Dán link hoặc gửi file .json.");
    const slug = extractSlug(msg.text);
    if (!/^[A-Za-z0-9]{6}$/.test(slug)) return bot.sendMessage(chatId, "Link không hợp lệ.");
    const item = await apiGetItem(slug);
    if (!item) return bot.sendMessage(chatId, "Không tìm thấy (hết hạn hoặc sai link).");
    st.data.slug = slug;
    return tryUnlockAndAskSecret(chatId, st, item.code, item.wrapped);
  }

  if (st.step === "secret") {
    if (!msg.text) return bot.sendMessage(chatId, "Nhập mật khẩu dạng văn bản.");
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
      bot.sendMessage(chatId, "❌ Sai mật khẩu hoặc dữ liệu hỏng.");
      resetState(chatId);
      return;
    }
    const envelope = parseEnvelope(pt);
    if (envelope.isFile) {
      await bot.sendDocument(chatId, Buffer.from(envelope.fileBytes), {}, { filename: envelope.filename, contentType: envelope.mime });
      if (st.data.slug) await apiMarkDownloaded(st.data.slug); // giống hành vi nút "tải file" trên web: rút ngắn còn 5 phút
    } else {
      await bot.sendMessage(chatId, "✅ Nội dung giải mã:\n\n" + envelope.text);
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
