# موقع تعريفي لهجمة الزيرو داي — مشروع تخرج

## فهرس المحتويات

- [1. نظرة عامة على المشروع](#1-نظرة-عامة-على-المشروع)
- [2. شرح المصطلحات التقنية](#2-شرح-المصطلحات-التقنية)
- [3. هيكل المشروع](#3-هيكل-المشروع)
- [4. التقنيات المستخدمة](#4-التقنيات-المستخدمة)
- [5. متطلبات التشغيل](#5-متطلبات-التشغيل)
- [6. خطوات التثبيت والتشغيل](#6-خطوات-التثبيت-والتشغيل)
- [7. شرح كل صفحة وما تفعله](#7-شرح-كل-صفحة-وما-تفعله)
- [8. شرح قاعدة البيانات والجداول](#8-شرح-قاعدة-البيانات-والجداول)
- [9. شرح الـ API Endpoints](#9-شرح-api-endpoints)
- [10. مقتطفات من الكود مع الشرح](#10-مقتطفات-من-الكود-مع-الشرح)
- [11. خصائص المحاكاة](#11-خصائص-المحاكاة)
- [12. الأسئلة الشائعة FAQ](#12-الأسئلة-الشائعة-faq)
- [13. المصادر والمراجع](#13-المصادر-والمراجع)

---

## 1. نظرة عامة على المشروع

المشروع عبارة عن موقع ويب تعليمي باللغة العربية يشرح مفهوم **هجمة الزيرو داي** (استغلال ثغرات قبل توفر تصحيح رسمي أو قبل علم المطور العلني)، ويعرض **قاعدة بيانات ثغرات موثقة**، **جدولاً زمنياً للأحداث**، **اختباراً تفاعلياً**، و**محاكاة بصرية أمامية** لا تنفّذ أي كود خبيث حقيقي. بُني المشروع ليكون أداة توعية أكاديمية تربط بين المفاهيم، البيانات المنظمة، وتجربة مستخدم واضحة باتجاه RTL.

---

## 2. شرح المصطلحات التقنية

| المصطلح | شرح مبسط | مثال واقعي |
|--------|-----------|------------|
| **Zero-Day Vulnerability** | ثغرة تُستغل والمجتمع أو المورد لم يوفّر حلاً جاهزاً بعد للجميع | خدمة عامة تتعرض لهجوم قبل صدور التصحيح النهائي |
| **CVE** | اسم مرجعي قياسي للثغرات المنشورة | `CVE-2021-44228` لثغرة Log4j |
| **CVSS Score** | درجة تقريبية للخطورة وفق نموذج معياري | درجة عالية تعني ضرورة معالجة أسرع |
| **Exploit** | أسلوب برمجي لتفعيل الثغرة وتحقيق هدف المهاجم | حزمة تتجاوز الحماية ثم تثبت حمولة |
| **Payload** | الجزء الذي ينفّذ بعد نجاح الاستغلال | برمجية خبيثة للسرقة أو التشفير |
| **Buffer Overflow** | كتابة بيانات أكبر من حجم المخزن فتُفسد ذاكرة مجاورة | فساد مؤشر عودة ليتحول مسار التنفيذ |
| **SQL Injection** | حقن أوامر SQL عبر مدخلات غير مُعقّمة | قراءة جدول كلمات المرور من التطبيق |
| **Remote Code Execution (RCE)** | تنفيذ تعليمات على نظام بعيد دون تثبيت شرعي مسبق | السيطرة على خادم ويب مباشرة |
| **Man-in-the-Middle (MITM)** | مهاجم بين طرفي اتصال يقرأ أو يبدّل البيانات | التلاعب بجلسة مفترضة آمينة |
| **Patch** | تحديث رسمي يعالج ثغرة معروفة | إصدار Microsoft Patch Tuesday |
| **Zero-Day Market** | أسواق أو صفقات خاصة تتداول ثغرات غير منشورة | بيع معلومات ثغرة لجهة حكومية أو شركة |

---

## 3. هيكل المشروع

```
ZeroDay/
├── app.py              # تطبيق Flask، المسارات وواجهات JSON
├── database.py         # تهيئة SQLite واتصال موحّد
├── seed_data.py        # ملء البيانات التجريبية مرة واحدة
├── requirements.txt    # اعتمادية Flask 3.0.3
├── README.md           # هذا الملف
├── zerodaydb.sqlite    # قاعدة البيانات (تُنشأ بعد التشغيل الأول)
├── assets/
│   └── fonts/          # خط IBM Plex Sans Arabic (Regular/Bold) — لا تُستبدل من CDN
├── static/
│   ├── css/style.css   # الألوان، RTL، المكوّنات
│   ├── js/main.js      # دوال مشتركة (تسجيل المحاكاة، شارات الخطورة)
│   └── images/         # فارغ — الأيقونات SVG داخل القوالب
└── templates/
          # قوالب Jinja2 للصفحات العربية
```

---

## 4. التقنيات المستخدمة

- **HTML**: هيكلة المحتوى، روابط التنقل، وـ SVG مضمّن للأيقونات في صفحة المحاكاة.
- **CSS**: نظام ألوان داكن، `@font-face` للخط المحلي، تنسيق الجداول والأزرار وفق متطلبات المشروع.
- **JavaScript**: استدعاءات `fetch` للـ API، محاكاة الخطوات، الاختبار التفاعلي.
- **Python 3.10+**: منطق الخلفية وتجميع الإحصائيات.
- **Flask**: تقديم القوالب وتعريف REST بسيط بصيغة JSON.
- **SQLite**: تخزين منظم للثغرات، الأحداث، الأسئلة، نتائج الاختبار، وسجلات المحاكاة.

---

## 5. متطلبات التشغيل

- Python 3.10 أو أحدث
- أداة `pip` لإدارة الحزم
- متصفح ويب حديث (Chrome/Firefox/Edge)

---

## 6. خطوات التثبيت والتشغيل

```bash
cd D:\VSCode\Projects\ZeroDay
pip install -r requirements.txt
python seed_data.py
python app.py
```

ثم افتح المتصفح على العنوان `http://127.0.0.1:5000`.

**تنبيه الخطوط:** يجب أن يوجد الملفان `IBMPlexSansArabic-Regular.ttf` و`IBMPlexSansArabic-Bold.ttf` داخل `assets/fonts/` ليعمل التنسيق كما هو مصمم. الخطوط موثقة برخصة OFL المرفقة.

---

## 7. شرح كل صفحة وما تفعله

| الصفحة | الوظيفة |
|--------|---------|
| `index.html` | مقدمة، إحصائيات من API، أحدث أربع ثغرات، خطوات سير هجمة مفاهيمية. |
| `vulnerabilities.html` | بحث وفلاتر وجدول مع ترقيم صفحات عند تجاوز 10 نتائج. |
| `vulnerability_detail.html` | تفاصيل ثغرة واحدة، شريط CVSS، مصادر، زر عودة. |
| `simulation.html` | ثلاث محاكاات (متصفح، MITM، طرفية وهمية) مع تسجيل خطوات في الخادم. |
| `timeline.html` | أحداث زمنية مع فلتر سنة. |
| `quiz.html` | 10 أسئلة عشوائية، تصحيح فوري، حفظ النتيجة. |
| `about.html` | أهداف المشروع، منهجية، تقنيات، مراجع، معلومات المطور. |

---

## 8. شرح قاعدة البيانات والجداول

### جدول `vulnerabilities`

| العمود | النوع | الغرض |
|--------|-------|--------|
| `id` | INTEGER PK | مفتاح فريد. |
| `cve_id` | TEXT | معرف CVE. |
| `name` | TEXT | اسم الثغرة. |
| `type` | TEXT | تصنيف نوعي (مثلاً RCE، حقن SQL). |
| `severity` | TEXT | حرج / عالٍ / متوسط / منخفض. |
| `cvss_score` | REAL | درجة CVSS رقمية للعرض البصري. |
| `description` | TEXT | وصف عام. |
| `technical_details` | TEXT | تفاصيل تقنية للصفحة التفصيلية. |
| `exploitation` | TEXT | شرح استغلال **تعليمي** دون كود ضار. |
| `mitigation` | TEXT | إصلاح وتخفيف. |
| `affected_systems` | TEXT | قائمة نصية مفصولة بفواصل. |
| `year` | INTEGER | سنة مرتبطة بالثغرة. |
| `discovered_by` | TEXT | جهة/شخص اكتشاف أو نسبة. |
| `references` | TEXT | روابط مفصولة بـ \| |

### جدول `timeline_events`

أحداث تاريخية: سنة، عنوان، هدف، تأثير، نوع الثغرة، وصف، خطورة.

### جدول `quiz_questions`

سؤال، أربع خيارات، الإجابة الصحيحة (A–D)، شرح، صعوبة.

### جدول `quiz_results`

درجة، الإجمالي، مستوى تقييم، وقت تلقائي.

### جدول `simulation_logs`

سيناريو، رقم خطوة، نص الحدث، وقت تلقائي.

---

## 9. شرح API Endpoints

### `GET /api/vulnerabilities`

**المعاملات (اختيارية):** `search`, `severity`, `year`, `type`, `page`, `per_page`, أو `limit` لأحدث N ثغرة.

**مثال:** `/api/vulnerabilities?search=Log4j&page=1`

**استجابة مختصرة:**

```json
{
  "items": [
    {
      "id": 1,
      "cve_id": "CVE-2021-44228",
      "name": "...",
      "severity": "حرج",
      "year": 2021
    }
  ],
  "page": 1,
  "per_page": 10,
  "total": 16,
  "pages": 2
}
```

### `GET /api/vulnerability/<id>`

يعيد كائناً واحداً بنفس حقول العنصر أعلاه مع `references` كمصفوفة روابط.

### `GET /api/stats`

```json
{
  "vulnerabilities_count": 16,
  "documented_attacks_count": 21,
  "affected_systems_estimate": 42,
  "government_attacks_percentage": 12.5
}
```

> ملاحظة: نسبة الأهداف «الحكومية/المشابهة» تُحسب من كلمات مفتاحية في حقل `target` ضمن الأحداث الزمنية (تقريب توعوي وليس إحصاء رسمياً).

### `GET /api/timeline`

**معامل:** `year` اختياري.

```json
{
  "events": [
    {
      "year": 2017,
      "title": "WannaCry + EternalBlue + Petya",
      "target": "...",
      "impact": "...",
      "vulnerability_type": "...",
      "description": "...",
      "severity": "حرج"
    }
  ]
}
```

### `GET /api/quiz`

يعيد 10 أسئلة مع خيارات مخلوطة وقيم `correct_answer` و`explanation` لاستخدامها في الواجهة بعد الإجابة.

### `POST /api/quiz/result`

**جسم JSON:**

```json
{ "score": 7, "total": 10, "level": "متوسط" }
```

**استجابة:** `{ "ok": true, "id": 12 }`

### `POST /api/simulation/log`

```json
{ "scenario": "browser_chain", "step": 2, "action": "..." }
```

### `GET /api/simulation/stats`

```json
{
  "total_logs": 120,
  "by_scenario": [
    { "scenario": "browser_chain", "count": 45 }
  ]
}
```

---

## 10. مقتطفات من الكود مع الشرح

### 1) `init_db` — إنشاء الجداول

```python
def init_db():
    db = get_db()
    cur = db.cursor()
    cur.executescript(
        """
CREATE TABLE IF NOT EXISTS vulnerabilities (
...
    "references" TEXT
);
...
"""
    )
    db.commit()
```

- يفتح اتصال SQLite عبر `get_db` ثم ينفّذ سكربت SQL واحد لإنشاء الجداول إن لم توجد، مع استخدام `"references"` بين علامتي اقتباس لأن الاسم حاجز في SQL.

### 2) `_row_vuln` — تحويل صف إلى JSON

```python
def _row_vuln(r):
    ref_raw = r["references"]
    refs = [u for u in str(ref_raw or "").split("|") if u.strip()]
    return {
        "id": r["id"],
        "cve_id": r["cve_id"],
        ...
        "references": refs,
    }
```

- يحوّل حقل الروابط المخزّن كنص مفصول بـ `|` إلى قائمة جاهزة للواجهة.

### 3) `_unique_systems_count` — تقدير أنظمة متأثرة

```python
def _unique_systems_count(conn):
    cur = conn.cursor()
    cur.execute("SELECT affected_systems FROM vulnerabilities WHERE affected_systems IS NOT NULL")
    seen = set()
    for row in cur.fetchall():
        parts = re.split(r"،|,|\|", row["affected_systems"] or "")
        for p in parts:
            t = p.strip()
            if t:
                seen.add(t)
    return len(seen)
```

- يجمّع قيماً فريدة من حقول نصية متعددة الفواصل لعرض رقم توعوي في الصفحة الرئيسية.

### 4) `api_vulnerabilities` — ترشيح وترقيم صفحات

```python
if limit and limit.isdigit() and int(limit) <= 50:
    lim = int(limit)
    cur.execute(
        f"SELECT * FROM vulnerabilities WHERE {sql_where} ORDER BY year DESC, id DESC LIMIT ?",
        (*params, lim),
    )
```

- يدعم وضع «أحدث N» للصفحة الرئيسية مع نفس عبارة `WHERE` المستخدمة في البحث.

### 5) `api_quiz` — عيّنة عشوائية

```python
cur.execute("SELECT * FROM quiz_questions ORDER BY RANDOM() LIMIT 10")
rows = cur.fetchall()
for r in rows:
    opts = [...]
    random.shuffle(opts)
```

- يضمن تنويعاً في كل جلسة مع خلط ترتيب الإجابات المعروضة.

### 6) `api_quiz_result` — حفظ النتيجة

```python
cur.execute(
    "INSERT INTO quiz_results (score, total, level) VALUES (?,?,?)",
    (score, total, level),
)
conn.commit()
return jsonify({"ok": True, "id": cur.lastrowid})
```

- يخزّن مستوى المستخدم العربي (`مبتدئ` / `متوسط` / `متقدم`) كما يُحدَّد في الواجهة.

### 7) `api_simulation_log` — تتبع تعليمي

```python
cur.execute(
    "INSERT INTO simulation_logs (scenario, step, action) VALUES (?,?,?)",
    (scenario, step, action),
)
```

- كل خطوة محاكاة تترك أثراً زمنياً للتحليل أو لعروض تخرّج تشرح التدفق.

### 8) `assets` route — تقديم الخطوط المحلية

```python
@app.route("/assets/<path:filename>")
def assets(filename):
    return send_from_directory(BASE_DIR / "assets", filename)
```

- يسمح لملف CSS باستدعاء `/assets/fonts/...` دون الاعتماد على CDN خارجي.

### 9) `get_db` — اتصال موحّد

```python
def get_db():
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(_DB_PATH.as_posix())
        _conn.row_factory = sqlite3.Row
    return _conn
```

- `Row` يمكّن الوصول بأسماء الأعمدة مثل `r["cve_id"]`.

### 10) شرط عدم إعادة البذر في `seed_data`

```python
cur.execute("SELECT COUNT(*) AS c FROM vulnerabilities")
if cur.fetchone()["c"] > 0:
    return
```

- يمنع مضاعفة السجلات عند إعادة تشغيل السكربت بالخطأ.

---

## 11. خصائص المحاكاة

1. **سيناريو المتصفح:** واجهة شبيهة بالمتصفح، خطوات تسلسلية (رابط، تحميل، محرك، امتيازات، خلفية وهمية) مع نص «طرفية» وهمي.
2. **سيناريو MITM:** مخطط مستخدم — شبكة — مهاجم — خادم مع مراحل شرح اعتراض مفهومي.
3. **سيناريو نظام التشغيل:** طرفية نصية تطبع أوامر **وهمية** مع شروح عربية؛ لا تُمرَّر إلى نظام التشغيل.

كل تنقّل خطوة يستدعي `POST /api/simulation/log` من الواجهة.

---

## 12. الأسئلة الشائعة (FAQ)

**هل المحاكاة خطرة على جهازي؟**  
لا. كل شيء عرض في المتصفح؛ لا يُنفَّذ كود حقيقي.

**لماذا تظهر إجابات الاختبار في طلب الشبكة؟**  
لتبسيط التطبيق الأكاديمي وإظهار الشروح فوراً؛ يمكن تطوير نسخة تخفي الإجابة عبر مسار تحقق لاحق.

**ماذا أفعل إذا لم تظهر الخطوط؟**  
تأكد من وجود ملفات TTF بالمسار المحدد في CSS داخل `assets/fonts/`.

**كيف أفرغ قاعدة البيانات لإعادة البذر؟**  
احذف ملف `zerodaydb.sqlite` ثم شغّل `python seed_data.py` من جديد (مع التأكد من إغلاق التطبيق أولاً).

---

## 13. المصادر والمراجع

- [MITRE ATT&CK](https://attack.mitre.org/)
- [CVE Program](https://www.cve.org/)
- [FIRST CVSS](https://www.first.org/cvss/)
- [NVD](https://nvd.nist.gov/)
- وثائق [Flask 3.x](https://flask.palletsprojects.com/)

---

## ملاحظات أمنية وتعليمية

المحتوى والمحاكاة **للتوعية فقط**. لا يتم توفير أدوات استغلال حقيقية أو تعليمات قابلة للإساءة. الهدف رفع الوعي ومناقشة الدفاع والتحديثات وسلاسل التوريد.

---

