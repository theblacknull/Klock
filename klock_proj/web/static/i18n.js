const I18N = {
  en: {
    secret: "Shared secret", message: "Message", unlock: "Unlock time",
    encryptBtn: "Encrypt", linkLabel: "Link", copyBtn: "Copy", copied: "Copied",
    decryptInput: "Paste link or code", decryptBtn: "Decrypt",
    notDecrypted: "Not decrypted yet.", enterSecret: "Enter the secret keyword!",
    confirmBtn: "Decrypt", result: "Message", tabEncrypt: "Encrypt", tabDecrypt: "Decrypt",
    future: "Pick a time in the future.", backLink: "← Use a different link",
    networkErr: "Network error, try again.", encryptErr: "Encryption failed.",
    working: "Processing…",
  },
  ru: {
    secret: "Общий секрет", message: "Сообщение", unlock: "Время открытия",
    encryptBtn: "Зашифровать", linkLabel: "Ссылка", copyBtn: "Копировать", copied: "Скопировано",
    decryptInput: "Вставьте ссылку или код", decryptBtn: "Расшифровать",
    notDecrypted: "Пока не расшифровано.", enterSecret: "Введите секретное слово!",
    confirmBtn: "Расшифровать", result: "Сообщение", tabEncrypt: "Шифровать", tabDecrypt: "Расшифровать",
    future: "Выберите время в будущем.", backLink: "← Другая ссылка",
    networkErr: "Ошибка сети, попробуйте снова.", encryptErr: "Ошибка шифрования.",
    working: "Обработка…",
  },
  vi: {
    secret: "Bí mật chung", message: "Thông điệp", unlock: "Thời gian mở",
    encryptBtn: "Mã hóa", linkLabel: "Link", copyBtn: "Sao chép", copied: "Đã chép",
    decryptInput: "Dán link hoặc mã", decryptBtn: "Giải mã",
    notDecrypted: "Chưa giải mã được.", enterSecret: "Hãy nhập từ khóa bí mật!",
    confirmBtn: "Giải mã", result: "Thông điệp", tabEncrypt: "Mã hóa", tabDecrypt: "Giải mã",
    future: "Chọn thời gian ở tương lai.", backLink: "← Dùng link khác",
    networkErr: "Lỗi mạng, thử lại.", encryptErr: "Mã hóa thất bại.",
    working: "Đang xử lý…",
  },
  zh: {
    secret: "共享密钥", message: "消息", unlock: "解锁时间",
    encryptBtn: "加密", linkLabel: "链接", copyBtn: "复制", copied: "已复制",
    decryptInput: "粘贴链接或代码", decryptBtn: "解密",
    notDecrypted: "尚未解密。", enterSecret: "请输入密钥！",
    confirmBtn: "解密", result: "消息", tabEncrypt: "加密", tabDecrypt: "解密",
    future: "请选择未来的时间。", backLink: "← 使用其他链接",
    networkErr: "网络错误，请重试。", encryptErr: "加密失败。",
    working: "处理中…",
  },
  es: {
    secret: "Secreto compartido", message: "Mensaje", unlock: "Hora de apertura",
    encryptBtn: "Cifrar", linkLabel: "Enlace", copyBtn: "Copiar", copied: "Copiado",
    decryptInput: "Pega el enlace o código", decryptBtn: "Descifrar",
    notDecrypted: "Aún no descifrado.", enterSecret: "¡Introduce la palabra secreta!",
    confirmBtn: "Descifrar", result: "Mensaje", tabEncrypt: "Cifrar", tabDecrypt: "Descifrar",
    future: "Elige una hora futura.", backLink: "← Usar otro enlace",
    networkErr: "Error de red, inténtalo de nuevo.", encryptErr: "Error al cifrar.",
    working: "Procesando…",
  },
};

let LANG = localStorage.getItem("klock_lang") || "en";

function t(key) { return (I18N[LANG] && I18N[LANG][key]) || I18N.en[key] || key; }

function applyLang() {
  document.querySelectorAll("[data-i18n]").forEach((el) => { el.textContent = t(el.dataset.i18n); });
  document.querySelectorAll("[data-i18n-ph]").forEach((el) => { el.placeholder = t(el.dataset.i18nPh); });
  document.getElementById("langSel").value = LANG;
}

function setLang(l) {
  LANG = l;
  localStorage.setItem("klock_lang", l);
  applyLang();
}
