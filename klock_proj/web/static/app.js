import { timelockEncrypt, timelockDecrypt, mainnetClient, defaultChainInfo, roundAt, Buffer } from "/vendor/tlock-js.bundle.mjs";
import { argon2id } from "/vendor/hash-wasm.bundle.mjs";

// tham số Argon2id — OWASP khuyến nghị tối thiểu cho ứng dụng trình duyệt
const ARGON2 = { iterations: 3, parallelism: 1, memorySize: 65536, hashLength: 32, outputType: "binary" };

const enc = new TextEncoder();
const dec = new TextDecoder();
const drandClient = mainnetClient();

function pad(n, w) { return String(n).padStart(w, "0"); }

// ---- gói tin: text hoặc file, đóng gói trước khi mã hóa AES-GCM (AES không quan tâm nội dung) ----
const MAX_FILE_SIZE = 8 * 1024 * 1024; // 8MB
let selectedFile = null; // File | null

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
  document.getElementById("encFileName").textContent = `${f.name} (${(f.size / 1024).toFixed(1)} KB)`;
  document.getElementById("encFileClear").classList.remove("hidden");
  document.getElementById("encMessage").disabled = true;
}

function clearFile() {
  selectedFile = null;
  document.getElementById("encFile").value = "";
  document.getElementById("encFileName").textContent = "";
  document.getElementById("encFileClear").classList.add("hidden");
  document.getElementById("encMessage").disabled = false;
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

async function doEncrypt() {
  const secretEl = document.getElementById("encSecret");
  const msgEl = document.getElementById("encMessage");
  const timeEl = document.getElementById("encTime");
  const secret = secretEl.value;
  const message = msgEl.value;
  setMsg("encMsg", "");
  document.getElementById("encOut").classList.remove("show");

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

  setMsg("encMsg", t("working"));
  const payload = await buildEnvelope(message);
  const secretBytes = enc.encode(secret);
  const x0Bytes = enc.encode(x0);
  const key = await deriveKey(secretBytes, x0Bytes);
  const nonceBytes = await nonceOf(x0Bytes);
  const aad = enc.encode(code);
  const ct = await gcmEncrypt(key, nonceBytes, aad, payload);

  secretEl.value = "";
  msgEl.value = "";
  clearFile();
  setMsg("encMsg", "");

  try {
    const roundNumber = roundAt(unlockMs, defaultChainInfo);
    const wrapped = await timelockEncrypt(roundNumber, Buffer.from(ct), drandClient);

    const r = await fetch("/api/encrypt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code, wrapped }),
    });
    if (!r.ok) throw new Error(`HTTP ${r.status}: ${await r.text()}`);
    const { slug } = await r.json();
    const link = location.origin + "/" + slug;
    document.getElementById("encLink").textContent = link;
    document.getElementById("encOut").classList.add("show");
    window.__lastLink = link;
  } catch (e) {
    console.error("klock encrypt failed:", e);
    setMsg("encMsg", t("encryptErr") + " (" + e.message + ")", true);
  }
}

function copyLink() {
  if (window.__lastLink) {
    navigator.clipboard.writeText(window.__lastLink).then(() => setMsg("encMsg", t("copied"), false));
  }
}

let pending = null; // { code, wrapped } — tạm trong RAM, không lưu đĩa

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
  const input = document.getElementById("decInput").value;
  const slug = extractSlug(input);
  document.getElementById("decOut").classList.remove("show");
  setMsg("decMsg", "");
  if (!/^[A-Za-z0-9]{6}$/.test(slug)) { goStep(1); return setMsg("decMsg", t("notDecrypted"), true); }

  try {
    const r = await fetch("/api/item/" + slug);
    if (!r.ok) { goStep(1); return setMsg("decMsg", t("notDecrypted"), true); }
    const { code, wrapped } = await r.json();
    let plainWrapped;
    try {
      plainWrapped = await timelockDecrypt(wrapped, drandClient); // ném lỗi nếu chưa tới giờ
    } catch (e) {
      const locked = /too early/i.test(e.message || "");
      goStep(1);
      return setMsg("decMsg", locked ? t("notDecrypted") : t("networkErr"), true);
    }
    pending = { code, ct: new Uint8Array(plainWrapped) };
    setMsg("decMsg", "");
    goStep(2);
  } catch (e) {
    goStep(1);
    setMsg("decMsg", t("networkErr"), true);
  }
}

async function doDecryptFinal() {
  const secretEl = document.getElementById("decSecret");
  if (!pending) return;
  const { code, ct } = pending;
  const x0 = code.slice(0, code.length - 14);
  const secretBytes = enc.encode(secretEl.value);
  secretEl.value = "";
  setMsg("decMsg", t("working"));
  const x0Bytes = enc.encode(x0);
  const key = await deriveKey(secretBytes, x0Bytes);
  const nonceBytes = await nonceOf(x0Bytes);
  const aad = enc.encode(code);
  try {
    const pt = await gcmDecrypt(key, nonceBytes, aad, ct);
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
  }
}

window.showTab = showTab;
window.doEncrypt = doEncrypt;
window.copyLink = copyLink;
window.doDecryptCheck = doDecryptCheck;
window.doDecryptFinal = doDecryptFinal;
window.resetDecrypt = resetDecrypt;
window.onFilePicked = onFilePicked;
window.clearFile = clearFile;

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
