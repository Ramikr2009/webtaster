// app.js
// webtaster - client-side scanner (heuristic + file hash)
// مطوّر: Rami-Alshurifi

// --- عناصر DOM ---
const tabs = document.querySelectorAll('.tab-btn');
const panels = document.querySelectorAll('.panel');

tabs.forEach(btn => {
  btn.addEventListener('click', () => {
    tabs.forEach(b => b.classList.remove('active'));
    panels.forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(btn.dataset.target).classList.add('active');
  });
});

// URL scan
const urlInput = document.getElementById('url-input');
const scanUrlBtn = document.getElementById('scan-url-btn');
const urlResults = document.getElementById('url-results');

// File scan
const fileInput = document.getElementById('file-input');
const scanFileBtn = document.getElementById('scan-file-btn');
const fileResults = document.getElementById('file-results');

// Domain/IP scan
const domainInput = document.getElementById('domain-input');
const scanDomainBtn = document.getElementById('scan-domain-btn');
const domainResults = document.getElementById('domain-results');

/* ---------------------------
   Utilities and heuristics
   --------------------------- */

// safe URL normalization + simple validator
function normalizeUrl(u) {
  try {
    // if scheme missing, add http for parsing
    if (!/^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\//.test(u)) u = 'http://' + u;
    const url = new URL(u);
    return url;
  } catch (e) {
    return null;
  }
}

function simpleUrlHeuristics(urlObj) {
  const notes = [];
  const host = urlObj.hostname;
  const pathname = urlObj.pathname + urlObj.search;

  // length checks
  if (urlObj.href.length > 200) notes.push('طول الرابط كبير جداً — قد يكون رابط اختصار أو متشابك.');

  // uses IP address instead of domain?
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) notes.push('المضيف هو عنوان IP — تحقق إذا كان متوقعاً.');

  // missing HTTPS
  if (urlObj.protocol !== 'https:') notes.push('لا يستخدم HTTPS — هذا يقلّل من الأمان.');

  // suspicious characters (punycode)
  if (/xn--/i.test(host)) notes.push('النطاق يحتوي punycode (xn--) — قد يتم استغلاله لخداع الحروف.');

  // many subdomains
  const parts = host.split('.');
  if (parts.length > 4) notes.push('وجود عدد كبير من المستويات الفرعية في النطاق — لاحظ النطاق الأصلي.');

  // very long path
  if (pathname.length > 120) notes.push('المسار طويل جداً — قد يخفي معلمات مشبوهة.');

  // suspicious TLDs (heuristic list, لا يعني خطر مؤكد)
  const suspiciousTLDs = ['zip','tk','gq','cf','ml'];
  const tld = parts[parts.length-1].toLowerCase();
  if (suspiciousTLDs.includes(tld)) notes.push(امتداد النطاق .${tld} قد يكون مرتبطاً بروابط قصيرة/مشبوهة.);

  return notes;
}

// show progress simulation (visual)
function fakeProgressResults(container, steps, onDone) {
  container.innerText = '';
  let i = 0;
  const stepDelay = 600;
  const tryStep = () => {
    if (i < steps.length) {
      container.innerText += '› ' + steps[i] + '\n';
      i++;
      setTimeout(tryStep, stepDelay);
    } else {
      onDone();
    }
  };
  tryStep();
}

/* ---------------------------
   URL scan handler
   --------------------------- */
scanUrlBtn.addEventListener('click', () => {
  const raw = urlInput.value.trim();
  if (!raw) {
    urlResults.innerText = 'أدخل رابطاً للفحص.';
    return;
  }
  const urlObj = normalizeUrl(raw);
  if (!urlObj) {
    urlResults.innerText = 'الرابط غير صحيح. تأكد من الصيغة (مثال: https://example.com).';
    return;
  }

  const steps = [
    'التحقق من صيغة الرابط...',
    'فحص استخدام HTTPS وميزات الأمان...',
    'تحليل المضيف وTLD...',
    'التحقق من طول الرابط والرموز المشبوهة...',
    'توليد تقرير هيورستيك...'
  ];

  fakeProgressResults(urlResults, steps, () => {
    const notes = simpleUrlHeuristics(urlObj);
    let out = الرابط: ${urlObj.href}\n\nالنتائج:\n;
    if (notes.length === 0) {
      out += '- لم يتم اكتشاف مؤشرات هيورستيك خطيرة (نتيجة أولية). لكن هذا لا يعني أن الرابط آمن تماماً.\n';
    } else {
      notes.forEach((n, idx) => {
        out += ${idx+1}. ${n}\n;
      });
    }
    out += \nتوصيات:\n• لا تفتح الرابط في جهازك الشخصي مباشرةً إن كنت تشك.\n• استخدم بيئة معزولة (VM) أو أدوات فحص مثل VirusTotal/URLVoid (باستخدام خادم وسيط إذا أردت التكامل).\n• يمكنك مشاركة الرابط مع الدعم عبر البريد أو الهاتف أدناه.\n;
    urlResults.innerText = out;
  });
});

/* ---------------------------
   File scan handler (SHA-256)
   --------------------------- */
async function sha256OfFile(file) {
  const arrayBuffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return hex;
}

scanFileBtn.addEventListener('click', async () => {
  const file = fileInput.files && fileInput.files[0];
  if (!file) {
    fileResults.innerText = 'اختر ملفاً أولاً.';
    return;
  }
  fileResults.innerText = 'جارٍ حساب SHA-256... يرجى الانتظار.';
  try {
    const hex = await sha256OfFile(file);
    fileResults.innerText =
`اسم الملف: ${file.name}
حجم الملف: ${file.size} بايت
نوع الملف: ${file.type || 'غير محدد'}

SHA-256: ${hex}

نصائح:
• يمكنك أخذ تجزئة SHA-256 ورفعها يدوياً على مواقع فحص الملفات (مثل VirusTotal).
• لا تشغّل الملفات المشتبه بها على جهاز رئيسي — استخدم بيئة معزولة.`;
  } catch (err) {
    fileResults.innerText = 'حدث خطأ أثناء حساب التجزئة: ' + err;
  }
});

/* ---------------------------
   Domain/IP heuristics
   --------------------------- */
function simpleDomainChecks(s) {
  const notes = [];
  // clean
  const t = s.trim();
  // IP?
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(t)) {
    notes.push('النص يبدو كعنوان IP. تحقق من كونها IP معروفة/متوقعة.');
    return notes;
  }
  // basic domain pattern
  if (!/^[a-zA-Z0-9\-.]{1,253}\.[a-zA-Z]{2,63}$/.test(t)) {
    notes.push('لا يبدو كنطاق صالح (صيغة غير نمطية).');
    return notes;
  }
  const parts = t.split('.');
  if (parts.length < 2) notes.push('النطاق قصير جداً.');
  if (t.length > 60) notes.push('النطاق طويل نسبيًا — تحقق من وجود تقاطر أو محاولات تشابه.');
  // check numeric-domains
  if (/[0-9]{6,}/.test(t)) notes.push('وجود سلسلة أرقام طويلة داخل النطاق — قد تكون علامة على دومين مولَّد تلقائياً.');
  return notes;
}

scanDomainBtn.addEventListener('click', () => {
  const raw = domainInput.value.trim();
  if (!raw) { domainResults.innerText = 'أدخل دومين أو IP للفحص.'; return; }
  domainResults.innerText = 'جارٍ تحليل...';
  setTimeout(() => {
    const notes = simpleDomainChecks(raw);
    let out = المدخل: ${raw}\n\n;
    if (notes.length === 0) {
      out += '- لم يتم اكتشاف مؤشرات خطأ فورية (فحص هيورستيك بسيط).\n';
    } else {
      notes.forEach((n, i) => out += ${i+1}. ${n}\n);
    }
    out += \nتوصيات:\n• لا تعتمد على هذا الفحص وحده — استخدم خدمات WHOIS, DNS lookup, RBL lists عبر خادم آمن إن أردت تحليل أعمق.\n;
    domainResults.innerText = out;
  }, 700);
});

/* ---------------------------
   End of file
   --------------------------- */