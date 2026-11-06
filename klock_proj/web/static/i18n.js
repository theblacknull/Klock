const I18N = {
  en: {
    secret: "Shared secret", message: "Message", unlock: "Unlock time",
    encryptBtn: "Encrypt", linkLabel: "Link", fileLabel: "File", copyBtn: "Copy", copied: "Copied",
    decryptInput: "Paste link or code", decryptBtn: "Decrypt",
    notDecrypted: "Not decrypted yet.", enterSecret: "Enter the secret keyword!",
    confirmBtn: "Decrypt", result: "Message", tabEncrypt: "Encrypt", tabDecrypt: "Decrypt",
    future: "Pick a time in the future.", backLink: "← Use a different link",
    networkErr: "Network error, try again.", encryptErr: "Encryption failed.",
    working: "Processing…",
    attachFile: "Attach file", removeFile: "Remove", downloadFile: "Download",
    fileTooLarge: "File too large (max 100MB).", shareBtn: "Share",
    infoEncrypt: "Encrypt: enter a shared secret and a message or file, pick an unlock time, then share the link you get.",
    infoDecrypt: "Decrypt: paste the link, wait until unlock time, then enter the same shared secret.",
    infoPrivacy: "The secret and content never leave your browser — the server only stores an already-encrypted blob.",
    infoSize: "Files up to 100MB are supported.",
    infoRetention: "Unopened items under 1MB are kept indefinitely; 1MB+ items are deleted 30 days after unlock time if never opened. Once opened, they're deleted after 24 hours.",
  },
  ru: {
    secret: "Общий секрет", message: "Сообщение", unlock: "Время открытия",
    encryptBtn: "Зашифровать", linkLabel: "Ссылка", fileLabel: "Файл", copyBtn: "Копировать", copied: "Скопировано",
    decryptInput: "Вставьте ссылку или код", decryptBtn: "Расшифровать",
    notDecrypted: "Пока не расшифровано.", enterSecret: "Введите секретное слово!",
    confirmBtn: "Расшифровать", result: "Сообщение", tabEncrypt: "Шифровать", tabDecrypt: "Расшифровать",
    future: "Выберите время в будущем.", backLink: "← Другая ссылка",
    networkErr: "Ошибка сети, попробуйте снова.", encryptErr: "Ошибка шифрования.",
    working: "Обработка…",
    attachFile: "Прикрепить файл", removeFile: "Убрать", downloadFile: "Скачать",
    fileTooLarge: "Файл слишком большой (макс. 100МБ).", shareBtn: "Поделиться",
    infoEncrypt: "Шифрование: введите общий секрет, сообщение или файл, выберите время открытия и поделитесь полученной ссылкой.",
    infoDecrypt: "Расшифровка: вставьте ссылку, дождитесь времени открытия, затем введите тот же секрет.",
    infoPrivacy: "Секрет и содержимое никогда не покидают ваш браузер — сервер хранит только уже зашифрованные данные.",
    infoSize: "Поддерживаются файлы до 100МБ.",
    infoRetention: "Неоткрытые записи до 1МБ хранятся бессрочно; от 1МБ — удаляются через 30 дней после времени открытия, если их не открыли. После открытия — удаляются через 24 часа.",
  },
  vi: {
    secret: "Bí mật chung", message: "Thông điệp", unlock: "Thời gian mở",
    encryptBtn: "Mã hóa", linkLabel: "Link", fileLabel: "File", copyBtn: "Sao chép", copied: "Đã chép",
    decryptInput: "Dán link hoặc mã", decryptBtn: "Giải mã",
    notDecrypted: "Chưa giải mã được.", enterSecret: "Hãy nhập từ khóa bí mật!",
    confirmBtn: "Giải mã", result: "Thông điệp", tabEncrypt: "Mã hóa", tabDecrypt: "Giải mã",
    future: "Chọn thời gian ở tương lai.", backLink: "← Dùng link khác",
    networkErr: "Lỗi mạng, thử lại.", encryptErr: "Mã hóa thất bại.",
    working: "Đang xử lý…",
    attachFile: "Đính kèm file", removeFile: "Bỏ chọn", downloadFile: "Tải xuống",
    fileTooLarge: "File quá lớn (tối đa 100MB).", shareBtn: "Chia sẻ",
    infoEncrypt: "Mã hóa: nhập bí mật chung, thông điệp hoặc file, chọn giờ mở khóa, rồi chia sẻ link nhận được.",
    infoDecrypt: "Giải mã: dán link, đợi tới giờ mở khóa, rồi nhập đúng bí mật chung.",
    infoPrivacy: "Bí mật và nội dung không rời trình duyệt của bạn — server chỉ lưu bản mã đã khóa sẵn.",
    infoSize: "Hỗ trợ file tối đa 100MB.",
    infoRetention: "Link chưa ai mở và nhỏ hơn 1MB được giữ vô thời hạn; từ 1MB trở lên bị xóa sau 30 ngày kể từ giờ mở khóa nếu không ai mở. Đã mở thì bị xóa sau 24 giờ.",
  },
  zh: {
    secret: "共享密钥", message: "消息", unlock: "解锁时间",
    encryptBtn: "加密", linkLabel: "链接", fileLabel: "文件", copyBtn: "复制", copied: "已复制",
    decryptInput: "粘贴链接或代码", decryptBtn: "解密",
    notDecrypted: "尚未解密。", enterSecret: "请输入密钥！",
    confirmBtn: "解密", result: "消息", tabEncrypt: "加密", tabDecrypt: "解密",
    future: "请选择未来的时间。", backLink: "← 使用其他链接",
    networkErr: "网络错误，请重试。", encryptErr: "加密失败。",
    working: "处理中…",
    attachFile: "附加文件", removeFile: "移除", downloadFile: "下载",
    fileTooLarge: "文件过大（最大 100MB）。", shareBtn: "分享",
    infoEncrypt: "加密：输入共享密钥和消息或文件，选择解锁时间，然后分享生成的链接。",
    infoDecrypt: "解密：粘贴链接，等待解锁时间，然后输入相同的共享密钥。",
    infoPrivacy: "密钥和内容永远不会离开您的浏览器——服务器只存储已加密的数据。",
    infoSize: "支持最大 100MB 的文件。",
    infoRetention: "未打开且小于1MB的内容将永久保留；1MB及以上的内容若解锁后30天内无人打开将被删除。一旦被打开，将在24小时后删除。",
  },
  es: {
    secret: "Secreto compartido", message: "Mensaje", unlock: "Hora de apertura",
    encryptBtn: "Cifrar", linkLabel: "Enlace", fileLabel: "Archivo", copyBtn: "Copiar", copied: "Copiado",
    decryptInput: "Pega el enlace o código", decryptBtn: "Descifrar",
    notDecrypted: "Aún no descifrado.", enterSecret: "¡Introduce la palabra secreta!",
    confirmBtn: "Descifrar", result: "Mensaje", tabEncrypt: "Cifrar", tabDecrypt: "Descifrar",
    future: "Elige una hora futura.", backLink: "← Usar otro enlace",
    networkErr: "Error de red, inténtalo de nuevo.", encryptErr: "Error al cifrar.",
    working: "Procesando…",
    attachFile: "Adjuntar archivo", removeFile: "Quitar", downloadFile: "Descargar",
    fileTooLarge: "Archivo demasiado grande (máx. 100MB).", shareBtn: "Compartir",
    infoEncrypt: "Cifrar: introduce un secreto compartido y un mensaje o archivo, elige la hora de apertura y comparte el enlace generado.",
    infoDecrypt: "Descifrar: pega el enlace, espera a la hora de apertura y luego introduce el mismo secreto compartido.",
    infoPrivacy: "El secreto y el contenido nunca salen de tu navegador — el servidor solo guarda el contenido ya cifrado.",
    infoSize: "Se admiten archivos de hasta 100MB.",
    infoRetention: "Los elementos no abiertos de menos de 1MB se conservan indefinidamente; los de 1MB o más se eliminan 30 días después de la apertura si nadie los abre. Una vez abiertos, se eliminan a las 24 horas.",
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
