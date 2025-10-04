// app.js
// webtaster - client-side scanner (heuristic + file hash)
// Developer: Rami-Alshurifi

// --- 1. DOM Elements ---
const tabs = document.querySelectorAll('.tab-btn');
const panels = document.querySelectorAll('.panel');

// Consolidate DOM elements
const domElements = {
    url: {
        input: document.getElementById('url-input'),
        button: document.getElementById('scan-url-btn'),
        results: document.getElementById('url-results')
    },
    file: {
        input: document.getElementById('file-input'),
        button: document.getElementById('scan-file-btn'),
        results: document.getElementById('file-results')
    },
    domain: {
        input: document.getElementById('domain-input'),
        button: document.getElementById('scan-domain-btn'),
        results: document.getElementById('domain-results')
    }
};

// --- 2. Tabs Logic ---
tabs.forEach(btn => {
  btn.addEventListener('click', () => {
    tabs.forEach(b => b.classList.remove('active'));
    panels.forEach(p => p.classList.remove('active'));
    
    const targetPanel = document.getElementById(btn.dataset.target);
    if (targetPanel) {
        btn.classList.add('active');
        targetPanel.classList.add('active');
    }
  });
});

/* ---------------------------
   3. Utilities and Heuristics
   --------------------------- */

/**
 * Normalizes an input string to a valid URL object or returns null.
 * @param {string} u - The input URL string.
 * @returns {URL|null}
 */
function normalizeUrl(u) {
  try {
    const trimmedUrl = u.trim();
    // Add http:// prefix if protocol is missing
    const prefix = /^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\//.test(trimmedUrl) ? '' : 'http://';
    const url = new URL(prefix + trimmedUrl);

    // Exclude non-web protocols
    if (url.protocol === 'file:' || url.protocol === 'about:' || url.protocol === 'javascript:') {
        return null; 
    }

    return url;
  } catch (e) {
    return null;
  }
}

/**
 * Applies simple heuristic rules to a URL object.
 * @param {URL} urlObj - The parsed URL object.
 * @returns {string[]} - List of suspicious notes in Arabic.
 */
function simpleUrlHeuristics(urlObj) {
  const notes = [];
  const host = urlObj.hostname;
  
  // 1. Length Check
  if (urlObj.href.length > 150) notes.push('طول الرابط كبير نسبياً — قد يكون رابط اختصار أو متشابك.');

  // 2. IP Address check
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) notes.push('المضيف هو عنوان IP — تحقق إذا كان متوقعاً ويجب استبداله بالنطاق.');

  // 3. HTTPS check
  if (urlObj.protocol === 'http:') notes.push('🚫 لا يستخدم HTTPS — يقلّل من الأمان ويجب تجنبه.');

  // 4. Punycode (IDN) check
  if (/xn--/i.test(host)) notes.push('❌ النطاق يحتوي Punycode (xn--) — قد يتم استغلاله لخداع الحروف (Homograph Attack).');

  // 5. Excessive Subdomains
  const parts = host.split('.');
  if (parts.length > 5) notes.push('⚠ وجود عدد كبير من المستويات الفرعية — لاحظ النطاق الأصلي بعناية (Domain Squatting).');
  
  // 6. @ in URL check
  if (urlObj.href.includes('@')) notes.push('⚠ وجود علامة @ في الرابط — قد يكون محاولة لخداع المتصفح (URL Cloaking).');

  // 7. Suspicious TLDs
  const suspiciousTLDs = ['zip','tk','gq','cf','ml','xyz','top'];
  const tld = parts[parts.length-1]?.toLowerCase();
  if (tld && suspiciousTLDs.includes(tld)) notes.push(امتداد النطاق .${tld} قد يكون مرتبطاً بروابط قصيرة/مشبوهة.);
  
  return notes;
}

/**
 * Simulation of scan progress using Promises.
 * @param {HTMLElement} container - The element to display progress in.
 * @param {string[]} steps - Progress messages in Arabic.
 * @returns {Promise<void>}
 */
function fakeProgressResults(container, steps) {
    return new Promise(resolve => {
        container.innerText = '';
        let i = 0;
        const stepDelay = 600;
        const tryStep = () => {
            if (i < steps.length) {
                container.innerText += '› ' + steps[i] + '\n';
                i++;
                setTimeout(tryStep, stepDelay);
            } else {
                resolve(); 
            }
        };
        tryStep();
    });
}

/**
 * Applies simple heuristic rules to a domain/IP input.
 * @param {string} s - The input domain or IP.
 * @returns {string[]} - List of suspicious notes in Arabic.
 */
function simpleDomainChecks(s) {
  const notes = [];
  const t = s.trim().toLowerCase(); 
  
  // 1. IP Check
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(t)) {
    notes.push('المدخل هو عنوان IP. يفضل فحص الـ Whois والـ Geolocation الخاصة به.');
    return notes;
  }
  
  // 2. Basic Domain Pattern Check
  if (!/^[a-z0-9]([a-z0-9\-][a-z0-9])?(\.[a-z0-9]([a-z0-9\-][a-z0-9])?){1,}$/.test(t)) {
    notes.push('⚠ لا يبدو كنطاق صالح (صيغة غير نمطية أو مشبوهة).');
    return notes;
  }
  
  // 3. Length Check
  if (t.length > 50) notes.push('النطاق طويل نسبيًا — تحقق من وجود تقاطر أو محاولات تشابه نطاق.');
  
  // 4. Long Numbers Check
  if (/[0-9]{6,}/.test(t)) notes.push('وجود سلسلة أرقام طويلة داخل النطاق — قد تكون علامة على دومين مولَّد تلقائياً.');
  
  // 5. Double Hyphen Check
  if (t.includes('--')) notes.push('وجود واصلات متتالية (--) في النطاق — علامة قديمة على Spam/Adware.');
  
  return notes;
}

/* ---------------------------
   4. URL Scan Handler
   --------------------------- */
domElements.url.button.addEventListener('click', async () => {
  const raw = domElements.url.input.value.trim();
  const resultsContainer = domElements.url.results;
  
  // Clear CSS state
  resultsContainer.classList.remove('error', 'warning', 'safe'); 

  if (!raw) {
    resultsContainer.innerText = 'أدخل رابطاً للفحص.';
    return;
  }
  
  const urlObj = normalizeUrl(raw);
  if (!urlObj) {
    resultsContainer.innerText = 'الرابط غير صحيح. تأكد من الصيغة (مثال: https://example.com).';
    resultsContainer.classList.add('error');
    return;
  }

  const steps = [
    'التحقق من صيغة الرابط...',
    'فحص استخدام HTTPS وميزات الأمان...',
    'تحليل المضيف وTLD...',
    'التحقق من طول الرابط والرموز المشبوهة...',
    'توليد تقرير هيورستيك...'
  ];

  await fakeProgressResults(resultsContainer, steps); 
  
  const notes = simpleUrlHeuristics(urlObj);
  let out = الرابط: ${urlObj.href}\n\nالنتائج:\n;
  
  if (notes.length === 0) {
    out += '✅ لم يتم اكتشاف مؤشرات هيورستيك خطيرة (نتيجة أولية).';
    resultsContainer.classList.add('safe');
  } else {
    out += '⚠ تم اكتشاف مؤشرات تحتاج إلى مراجعة!\n';
    notes.forEach((n, idx) => {
      out += [${idx+1}] ${n}\n;
    });
    resultsContainer.classList.add('warning');
  }
  
  out += \n\nتوصيات:\n• لا تفتح الرابط في جهازك الشخصي مباشرةً إن كنت تشك.\n• استخدم أدوات فحص خارجية مثل VirusTotal/URLVoid لتأكيد النتيجة.\n;
  resultsContainer.innerText = out;
});

/* ---------------------------
   5. File Scan Handler (SHA-256)
   --------------------------- */

/**
 * Calculates SHA-256 hash of a file.
 * @param {File} file - The File object.
 * @returns {Promise<string>} - The SHA-256 hash in Hex format.
 */
async function sha256OfFile(file) {
    const MAX_FILE_SIZE = 200 * 1024 * 1024; // 200MB limit
    if (file.size > MAX_FILE_SIZE) { 
        throw new Error(حجم الملف كبير جداً (${(file.size / (1024 * 1024)).toFixed(2)} MB). تجاوز الحد المسموح به.);
    }
    const arrayBuffer = await file.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hex;
}

domElements.file.button.addEventListener('click', async () => {
  const file = domElements.file.input.files && domElements.file.input.files[0];
  const resultsContainer = domElements.file.results;
  
  resultsContainer.classList.remove('error', 'warning', 'safe');

  if (!file) {
    resultsContainer.innerText = 'اختر ملفاً أولاً.';
    return;
  }
  
  resultsContainer.innerText = جارٍ حساب SHA-256 للملف ${file.name}... يرجى الانتظار للملفات الكبيرة.;
  
  try {
    const hex = await sha256OfFile(file);
    resultsContainer.innerText =
`✅ اكتمل حساب التجزئة.
اسم الملف: ${file.name}
حجم الملف: ${(file.size / (1024 * 1024)).toFixed(2)} ميجابايت
نوع الملف: ${file.type || 'غير محدد'}

SHA-256: ${hex}

نصائح:
• يمكنك أخذ تجزئة SHA-256 ورفعها يدوياً على مواقع فحص الملفات (مثل VirusTotal).
• لا تشغّل الملفات المشتبه بها على جهاز رئيسي — استخدم بيئة معزولة.`;
    resultsContainer.classList.add('safe');
  } catch (err) {
    resultsContainer.innerText = '❌ حدث خطأ أثناء حساب التجزئة: ' + err.message;
    resultsContainer.classList.add('error');
  }
});

/* ---------------------------
   6. Domain/IP Scan Handler
   --------------------------- */
domElements.domain.button.addEventListener('click', () => {
  const raw = domElements.domain.input.value.trim();
  const resultsContainer = domElements.domain.results;
  
  resultsContainer.classList.remove('error', 'warning', 'safe');

  if (!raw) { resultsContainer.innerText = 'أدخل دومين أو IP للفحص.'; return; }
  resultsContainer.innerText = 'جارٍ تحليل...';
  
  // Simulate deeper scan delay
  setTimeout(() => {
    const notes = simpleDomainChecks(raw);
    let out = المدخل: ${raw}\n\nالنتائج:\n;
    
    if (notes.length === 0) {
      out += '✅ لم يتم اكتشاف مؤشرات خطأ فورية (فحص هيورستيك بسيط).\n';
      resultsContainer.classList.add('safe');
    } else {
      out += '⚠ تم اكتشاف مؤشرات تحتاج إلى مراجعة!\n';
      notes.forEach((n, i) => out += [${i+1}] ${n}\n);
      resultsContainer.classList.add('warning');
    }
    
    out += \n\nتوصيات:\n• لا تعتمد على هذا الفحص وحده — استخدم خدمات WHOIS, DNS lookup, RBL lists (عبر خادم آمن إن أردت تحليل أعمق).\n;
    resultsContainer.innerText = out;
  }, 700);
});

/* ---------------------------
   End of file
   --------------------------- */
