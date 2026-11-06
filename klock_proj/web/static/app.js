import { timelockEncrypt, timelockDecrypt, mainnetClient, defaultChainInfo, roundAt, Buffer } from "/vendor/tlock-js.bundle.mjs";
import { argon2id } from "/vendor/hash-wasm.bundle.mjs";

// tham số Argon2id — OWASP khuyến nghị tối thiểu cho ứng dụng trình duyệt
const ARGON2 = { iterations: 3, parallelism: 1, memorySize: 65536, hashLength: 32, outputType: "binary" };

const enc = new TextEncoder();
const dec = new TextDecoder();
const drandClient = mainnetClient();

function pad(n, w) { return String(n).padStart(w, "0"); }

// ---- gói tin: text hoặc file, đóng gói trước khi mã hóa AES-GCM (AES không quan tâm nội dung) ----
const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB
let selectedFile = null; // File | null

function truncateMiddle(name, max = 26) {
  if (name.length <= max) return name;
  const half = Math.floor((max - 1) / 2);
  return name.slice(0, half) + "…" + name.slice(name.length - (max - 1 - half));
}

function onFilePicked() {
  const input = document.getElementById("encFile");
  const f = input.files && input.files[0];
  setMsg("encMsg", "");
  if (!f) return;
  if (f.size > MAX_FILE_SIZE) {
    setMsg("encMsg", t("fileTooLarge"), true);
    input.value = "";
    return;
  }
  selectedFile = f;
  document.getElementById("encFileChipName").textContent = truncateMiddle(f.name);
  document.getElementById("encFileChip").classList.remove("hidden");
  document.getElementById("attachBtn").classList.add("hidden");
  const msgEl = document.getElementById("encMessage");
  msgEl.value = "";
  msgEl.disabled = true;
}

function clearFile() {
  selectedFile = null;
  document.getElementById("encFile").value = "";
  document.getElementById("encFileChip").classList.add("hidden");
  document.getElementById("attachBtn").classList.remove("hidden");
  document.getElementById("encMessage").disabled = false;
}

// ---- upload file mã hóa (.klock.json) lúc giải mã — bỏ qua hẳn việc hỏi server ----
let decFilePayload = null; // { code, wrapped } | null

async function onDecFilePicked() {
  const input = document.getElementById("decFile");
  const f = input.files && input.files[0];
  setMsg("decMsg", "");
  if (!f) return;
  try {
    const obj = JSON.parse(await f.text());
    if (typeof obj.code !== "string" || typeof obj.wrapped !== "string") throw new Error("bad format");
    decFilePayload = obj;
  } catch (e) {
    setMsg("decMsg", t("notDecrypted"), true);
    input.value = "";
    return;
  }
  document.getElementById("decFileChipName").textContent = truncateMiddle(f.name);
  document.getElementById("decFileChip").classList.remove("hidden");
  document.getElementById("decAttachBtn").classList.add("hidden");
  const inputEl = document.getElementById("decInput");
  inputEl.value = "";
  inputEl.disabled = true;
}

function clearDecFile() {
  decFilePayload = null;
  document.getElementById("decFile").value = "";
  document.getElementById("decFileChip").classList.add("hidden");
  document.getElementById("decAttachBtn").classList.remove("hidden");
  document.getElementById("decInput").disabled = false;
}

async function buildEnvelope(message) {
  if (!selectedFile) return new Uint8Array([0, ...enc.encode(message)]);
  const fileBytes = new Uint8Array(await selectedFile.arrayBuffer());
  const fnBytes = enc.encode(selectedFile.name);
  const mimeBytes = enc.encode(selectedFile.type || "application/octet-stream");
  const head = new Uint8Array(1 + 2 + fnBytes.length + 2 + mimeBytes.length);
  const dv = new DataView(head.buffer);
  head[0] = 1;
  dv.setUint16(1, fnBytes.length);
  head.set(fnBytes, 3);
  dv.setUint16(3 + fnBytes.length, mimeBytes.length);
  head.set(mimeBytes, 3 + fnBytes.length + 2);
  const out = new Uint8Array(head.length + fileBytes.length);
  out.set(head, 0);
  out.set(fileBytes, head.length);
  return out;
}

function parseEnvelope(bytes) {
  if (bytes[0] === 0) return { isFile: false, text: dec.decode(bytes.slice(1)) };
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let off = 1;
  const fnLen = dv.getUint16(off); off += 2;
  const filename = dec.decode(bytes.slice(off, off + fnLen)); off += fnLen;
  const mimeLen = dv.getUint16(off); off += 2;
  const mime = dec.decode(bytes.slice(off, off + mimeLen)); off += mimeLen;
  return { isFile: true, filename, mime, fileBytes: bytes.slice(off) };
}

function tzLabel(mins) {
  const sign = mins >= 0 ? "+" : "-";
  const a = Math.abs(mins);
  return `UTC${sign}${pad(Math.floor(a / 60), 2)}:${pad(a % 60, 2)}`;
}

function fillTzSelect() {
  const sel = document.getElementById("encTz");
  if (!sel || sel.options.length) return;
  const browserMins = -new Date().getTimezoneOffset();
  for (let mins = -12 * 60; mins <= 14 * 60; mins += 30) {
    const opt = document.createElement("option");
    opt.value = String(mins);
    opt.textContent = tzLabel(mins);
    if (mins === browserMins) opt.selected = true;
    sel.appendChild(opt);
  }
  if (sel.selectedIndex < 0) sel.value = "0";
}

function randX0() {
  const b = new Uint8Array(8);
  crypto.getRandomValues(b);
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
  v = v % 1000000000000n;
  return v.toString().padStart(12, "0");
}

async function sha256(bytes) { return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)); }

async function hmacSha256(keyBytes, msgBytes) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, msgBytes));
}

async function deriveKey(secretBytes, x0Bytes) {
  // Argon2id làm chậm brute-force với bí mật yếu (memory-hard, tốn ~64MB RAM + nhiều vòng lặp mỗi lần thử)
  const stretched = await argon2id({ ...ARGON2, password: secretBytes, salt: x0Bytes });
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

function showTab(which) {
  document.getElementById("panelEnc").classList.toggle("active", which === "enc");
  document.getElementById("panelDec").classList.toggle("active", which === "dec");
  document.getElementById("tabEncBtn").classList.toggle("active", which === "enc");
  document.getElementById("tabDecBtn").classList.toggle("active", which === "dec");
}

function setMsg(id, text, bad) {
  const el = document.getElementById(id);
  el.textContent = text;
  el.className = "msg" + (bad ? " bad" : text ? " good" : "");
}

// ---- thanh tiến trình % trên nút: khóa nút lại, hiện % chạy tới 100% rồi mới cho bấm lại ----
function startProgress(btn) {
  btn.dataset.label = btn.textContent;
  btn.disabled = true;
  btn.classList.add("progress");
  btn.innerHTML = '<span class="fill"></span><span class="pct">0%</span>';
}

function setProgress(btn, pct) {
  const clamped = Math.max(0, Math.min(100, pct));
  const fill = btn.querySelector(".fill");
  const label = btn.querySelector(".pct");
  if (fill) fill.style.width = clamped + "%";
  if (label) label.textContent = Math.round(clamped) + "%";
}

function endProgress(btn) {
  btn.disabled = false;
  btn.classList.remove("progress");
  btn.textContent = btn.dataset.label || btn.textContent;
}

// giả lập tiến trình chạy dần tới gần `to` trong lúc chờ 1 bước không có tiến trình thật (vd Argon2id, time-lock)
function creepProgress(btn, from, to, guessMs) {
  setProgress(btn, from);
  const start = performance.now();
  const id = setInterval(() => {
    const t = Math.min(0.94, (performance.now() - start) / guessMs);
    setProgress(btn, from + (to - from) * t);
  }, 80);
  return () => clearInterval(id);
}

function postEncryptXHR(code, wrapped, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/encrypt");
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.upload.onprogress = (e) => { if (e.lengthComputable) onProgress(e.loaded / e.total); };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        try { resolve(JSON.parse(xhr.responseText)); }
        catch { reject(new Error("bad response")); }
      } else {
        reject(new Error(`HTTP ${xhr.status}: ${xhr.responseText}`));
      }
    };
    xhr.onerror = () => reject(new Error("network error"));
    xhr.send(JSON.stringify({ code, wrapped }));
  });
}

async function doEncrypt() {
  const btn = document.getElementById("encBtn");
  const secretEl = document.getElementById("encSecret");
  const msgEl = document.getElementById("encMessage");
  const timeEl = document.getElementById("encTime");
  const secret = secretEl.value;
  const message = msgEl.value;
  setMsg("encMsg", "");
  document.getElementById("encOut").classList.remove("show");
  document.getElementById("encFileOut").classList.remove("show");

  if (!timeEl.value) return setMsg("encMsg", t("future"), true);
  const [datePart, timePart] = timeEl.value.split("T");
  const [y, mo, d] = datePart.split("-").map(Number);
  const [h, mi, se] = timePart.split(":").map(Number);
  const sec = se || 0;
  // giờ nhập là giờ theo múi giờ người dùng chọn; quy đổi sang UTC để tính đúng thời điểm thật
  const tzMins = Number(document.getElementById("encTz").value || 0);
  const unlockMs = Date.UTC(y, mo - 1, d, h, mi, sec) - tzMins * 60000;
  if (unlockMs <= Date.now()) return setMsg("encMsg", t("future"), true);

  const u = new Date(unlockMs);
  const dateStr = pad(u.getUTCDate(), 2) + pad(u.getUTCMonth() + 1, 2) + u.getUTCFullYear()
    + pad(u.getUTCHours(), 2) + pad(u.getUTCMinutes(), 2) + pad(u.getUTCSeconds(), 2);
  const x0 = randX0();
  const code = x0 + dateStr;

  startProgress(btn);
  try {
    setProgress(btn, 3);
    const payload = await buildEnvelope(message);
    setProgress(btn, 10);

    const secretBytes = enc.encode(secret);
    const x0Bytes = enc.encode(x0);
    let stop = creepProgress(btn, 10, 35, 500);
    const key = await deriveKey(secretBytes, x0Bytes);
    stop();
    setProgress(btn, 35);

    const nonceBytes = await nonceOf(x0Bytes);
    const aad = enc.encode(code);
    stop = creepProgress(btn, 35, 55, 400);
    const ct = await gcmEncrypt(key, nonceBytes, aad, payload);
    stop();
    setProgress(btn, 55);

    secretEl.value = "";
    msgEl.value = "";
    clearFile();

    const roundNumber = roundAt(unlockMs, defaultChainInfo);
    stop = creepProgress(btn, 55, 70, 400);
    const wrapped = await timelockEncrypt(roundNumber, Buffer.from(ct), drandClient);
    stop();
    setProgress(btn, 70);

    const { slug } = await postEncryptXHR(code, wrapped, (frac) => setProgress(btn, 70 + frac * 30));
    setProgress(btn, 100);

    // file tải về chứa đúng dữ liệu mà server lưu — người dùng có thể tự lưu/gửi thay vì phụ thuộc link
    if (window.__encFileUrl) URL.revokeObjectURL(window.__encFileUrl);
    const fileBlob = new Blob([JSON.stringify({ code, wrapped })], { type: "application/json" });
    const fileUrl = URL.createObjectURL(fileBlob);
    window.__encFileUrl = fileUrl;
    const dl = document.getElementById("encFileDownload");
    dl.href = fileUrl;
    dl.download = `klock-${slug}.json`;

    const link = location.origin + "/" + slug;
    document.getElementById("encLink").textContent = link;
    document.getElementById("encOut").classList.add("show");
    document.getElementById("encFileOut").classList.add("show");
    document.getElementById("shareBtn").classList.toggle("hidden", !navigator.share);
    window.__lastLink = link;
    window.__lastEncSlug = slug;
    document.getElementById("payStatus").textContent = "";
  } catch (e) {
    console.error("klock encrypt failed:", e);
    setMsg("encMsg", t("encryptErr") + " (" + e.message + ")", true);
  } finally {
    endProgress(btn);
  }
}

function copyLink() {
  if (window.__lastLink) {
    navigator.clipboard.writeText(window.__lastLink).then(() => setMsg("encMsg", t("copied"), false));
  }
}

function shareLink() {
  if (window.__lastLink && navigator.share) {
    navigator.share({ url: window.__lastLink }).catch(() => {});
  }
}

let pending = null; // { code, wrapped } — tạm trong RAM, không lưu đĩa
let currentSlug = null; // slug đang xem (null nếu giải mã từ file tải lên, không qua server)

function notifyDownloaded() {
  if (currentSlug) {
    fetch("/api/item/" + currentSlug + "/downloaded", { method: "POST" }).catch(() => {});
  }
}

function extractSlug(input) {
  const s = input.trim();
  const last = s.split("/").filter(Boolean).pop() || "";
  return last;
}

function goStep(n) {
  document.getElementById("decStep1").classList.toggle("active", n === 1);
  document.getElementById("decStep2").classList.toggle("active", n === 2);
}

function resetDecrypt() {
  pending = null;
  currentSlug = null;
  clearDecFile();
  document.getElementById("decInput").value = "";
  document.getElementById("decOut").classList.remove("show");
  document.getElementById("decOutFile").classList.add("hidden");
  document.getElementById("decOutText").classList.remove("hidden");
  revokeDecObjectUrl();
  setMsg("decMsg", "");
  goStep(1);
}

function revokeDecObjectUrl() {
  if (window.__decObjectUrl) {
    URL.revokeObjectURL(window.__decObjectUrl);
    window.__decObjectUrl = null;
  }
}

async function doDecryptCheck() {
  const btn = document.getElementById("decCheckBtn");
  document.getElementById("decOut").classList.remove("show");
  setMsg("decMsg", "");

  let code, wrapped;
  currentSlug = null;
  if (decFilePayload) {
    // dữ liệu lấy thẳng từ file người dùng tải lên — không cần hỏi server
    ({ code, wrapped } = decFilePayload);
  } else {
    const slug = extractSlug(document.getElementById("decInput").value);
    if (!/^[A-Za-z0-9]{6}$/.test(slug)) { goStep(1); return setMsg("decMsg", t("notDecrypted"), true); }
    currentSlug = slug;
    startProgress(btn);
    setProgress(btn, 10);
    const r = await fetch("/api/item/" + slug);
    if (!r.ok) { endProgress(btn); goStep(1); return setMsg("decMsg", t("notDecrypted"), true); }
    setProgress(btn, 35);
    ({ code, wrapped } = await r.json());
  }

  if (!btn.classList.contains("progress")) startProgress(btn);
  try {
    setProgress(btn, 35);
    let plainWrapped;
    const stop = creepProgress(btn, 35, 95, 1500); // thời gian mạng tới drand không biết trước
    try {
      plainWrapped = await timelockDecrypt(wrapped, drandClient); // ném lỗi nếu chưa tới giờ
    } catch (e) {
      stop();
      const locked = /too early/i.test(e.message || "");
      goStep(1);
      return setMsg("decMsg", locked ? t("notDecrypted") : t("networkErr"), true);
    }
    stop();
    setProgress(btn, 100);
    pending = { code, ct: new Uint8Array(plainWrapped) };
    setMsg("decMsg", "");
    goStep(2);
  } catch (e) {
    goStep(1);
    setMsg("decMsg", t("networkErr"), true);
  } finally {
    endProgress(btn);
  }
}

async function doDecryptFinal() {
  const btn = document.getElementById("decFinalBtn");
  const secretEl = document.getElementById("decSecret");
  if (!pending) return;
  const { code, ct } = pending;
  const x0 = code.slice(0, code.length - 14);
  const secretBytes = enc.encode(secretEl.value);
  secretEl.value = "";
  startProgress(btn);
  const x0Bytes = enc.encode(x0);
  let stop = creepProgress(btn, 0, 70, 500);
  const key = await deriveKey(secretBytes, x0Bytes);
  stop();
  setProgress(btn, 70);
  const nonceBytes = await nonceOf(x0Bytes);
  const aad = enc.encode(code);
  try {
    stop = creepProgress(btn, 70, 95, 400);
    const pt = await gcmDecrypt(key, nonceBytes, aad, ct);
    stop();
    setProgress(btn, 100);
    const envelope = parseEnvelope(pt);
    revokeDecObjectUrl();
    const textEl = document.getElementById("decOutText");
    const fileBox = document.getElementById("decOutFile");
    if (envelope.isFile) {
      textEl.classList.add("hidden");
      fileBox.classList.remove("hidden");
      const blob = new Blob([envelope.fileBytes], { type: envelope.mime });
      const url = URL.createObjectURL(blob);
      window.__decObjectUrl = url;
      const img = document.getElementById("decOutImg");
      if (envelope.mime.startsWith("image/")) {
        img.src = url;
        img.classList.remove("hidden");
      } else {
        img.classList.add("hidden");
      }
      document.getElementById("decOutFileName").textContent = envelope.filename;
      const dl = document.getElementById("decOutDownload");
      dl.href = url;
      dl.download = envelope.filename;
    } else {
      fileBox.classList.add("hidden");
      textEl.classList.remove("hidden");
      textEl.textContent = envelope.text;
    }
    document.getElementById("decOut").classList.add("show");
    setMsg("decMsg", "");
  } catch (e) {
    document.getElementById("decOut").classList.remove("show");
    setMsg("decMsg", t("notDecrypted"), true);
  } finally {
    endProgress(btn);
  }
}

window.showTab = showTab;
window.doEncrypt = doEncrypt;
window.copyLink = copyLink;
window.shareLink = shareLink;
window.doDecryptCheck = doDecryptCheck;
window.doDecryptFinal = doDecryptFinal;
window.resetDecrypt = resetDecrypt;
window.onFilePicked = onFilePicked;
window.clearFile = clearFile;
window.onDecFilePicked = onDecFilePicked;
window.notifyDownloaded = notifyDownloaded;
window.clearDecFile = clearDecFile;
window.toggleInfo = () => document.getElementById("infoPanel").classList.toggle("hidden");

// ---- lưu vĩnh viễn trả phí (1 USDT qua BSC hoặc ETH) ----
const TREASURY_EVM = "0xb11be01e0d81b20f373aa0de7058946765e68d97";
const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const PAY_NETWORKS = {
  bsc: { rpc: "https://bsc-rpc.publicnode.com", usdt: "0x55d398326f99059ff775485246999027b3197955", decimals: 18, lookback: 150 },
  eth: { rpc: "https://ethereum-rpc.publicnode.com", usdt: "0xdac17f958d2ee523a2206206994597c13d831ec7", decimals: 6, lookback: 40 },
};

function togglePermanent() {
  const sw = document.getElementById("permSwitch");
  const on = !sw.classList.contains("on");
  sw.classList.toggle("on", on);
  sw.setAttribute("aria-checked", String(on));
  document.getElementById("payBox").classList.toggle("hidden", !on);
}

function copyPayAddr(el) {
  navigator.clipboard.writeText(el.textContent.trim()).catch(() => {});
}

async function rpcCall(rpc, method, params) {
  const r = await fetch(rpc, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const j = await r.json();
  if (j.error) throw new Error(j.error.message || "rpc error");
  return j.result;
}

function topicAddr(addr) { return "0x" + addr.replace(/^0x/, "").toLowerCase().padStart(64, "0"); }

// Client tự dò trên RPC công khai trước (không tốn tài nguyên server); server vẫn tự
// xác minh lại độc lập trước khi mở khóa lưu vĩnh viễn — không tin kết quả này.
async function findPaymentTx(net) {
  const cfg = PAY_NETWORKS[net];
  const latest = parseInt(await rpcCall(cfg.rpc, "eth_blockNumber", []), 16);
  const fromBlock = "0x" + Math.max(0, latest - cfg.lookback).toString(16);
  const logs = await rpcCall(cfg.rpc, "eth_getLogs", [{
    fromBlock, toBlock: "latest", address: cfg.usdt,
    topics: [TRANSFER_TOPIC, null, topicAddr(TREASURY_EVM)],
  }]);
  const want = 10n ** BigInt(cfg.decimals);
  const tol = 100000n;
  for (const log of logs) {
    if (BigInt(log.data) + tol >= want) return log.transactionHash;
  }
  return null;
}

async function checkPayment(net) {
  const statusEl = document.getElementById("payStatus");
  if (!window.__lastEncSlug) {
    statusEl.className = "payStatus bad";
    statusEl.textContent = "Encrypt first.";
    return;
  }
  const btns = document.querySelectorAll(".paidBtn");
  btns.forEach((b) => (b.disabled = true));
  statusEl.className = "payStatus";
  statusEl.textContent = "Checking blockchain…";

  const deadline = Date.now() + 5 * 60000;
  let found = null;
  while (Date.now() < deadline && !found) {
    try { found = await findPaymentTx(net); } catch (e) { /* thử lại ở vòng sau */ }
    if (!found) await new Promise((r) => setTimeout(r, 10000));
  }
  if (!found) {
    statusEl.className = "payStatus bad";
    statusEl.textContent = "Payment not found, try again.";
    btns.forEach((b) => (b.disabled = false));
    return;
  }

  statusEl.textContent = "Confirming…";
  try {
    const r = await fetch(`/api/item/${window.__lastEncSlug}/confirm-payment`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ network: net, tx_hash: found }),
    });
    const j = await r.json();
    if (j.ok) {
      statusEl.className = "payStatus good";
      statusEl.textContent = "Confirmed — stored forever.";
    } else {
      statusEl.className = "payStatus bad";
      statusEl.textContent = j.error || "Failed.";
      btns.forEach((b) => (b.disabled = false));
    }
  } catch (e) {
    statusEl.className = "payStatus bad";
    statusEl.textContent = "Network error.";
    btns.forEach((b) => (b.disabled = false));
  }
}

window.togglePermanent = togglePermanent;
window.copyPayAddr = copyPayAddr;
window.checkPayment = checkPayment;

(function init() {
  applyLang();
  fillTzSelect();
  const def = document.getElementById("encTime");
  if (def) {
    const t = new Date(Date.now() + 60000); // mặc định: giờ hiện tại của máy + 1 phút
    def.value = `${t.getFullYear()}-${pad(t.getMonth() + 1, 2)}-${pad(t.getDate(), 2)}T${pad(t.getHours(), 2)}:${pad(t.getMinutes(), 2)}:${pad(t.getSeconds(), 2)}`;
  }

  const parts = location.pathname.split("/").filter(Boolean);
  if (parts.length === 1 && /^[A-Za-z0-9]{6}$/.test(parts[0])) {
    showTab("dec");
    document.getElementById("decInput").value = location.href;
    doDecryptCheck();
  }
})();
