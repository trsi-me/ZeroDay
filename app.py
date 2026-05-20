# app.py — Flask application for Zero Day informational site
import math
import os
import random
import re
import ipaddress
import json
import urllib.parse
import urllib.request
import ssl
from urllib.parse import urlsplit, urlunsplit
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_from_directory

import database as db

app = Flask(__name__)
BASE_DIR = Path(__file__).resolve().parent

with app.app_context():
    db.init_db()


@app.teardown_appcontext
def _close_db_per_request(_exc):
    db.close_db()


def _row_vuln(r):
    ref_raw = r["references"]
    refs = [u for u in str(ref_raw or "").split("|") if u.strip()]
    return {
        "id": r["id"],
        "cve_id": r["cve_id"],
        "name": r["name"],
        "type": r["type"],
        "severity": r["severity"],
        "cvss_score": r["cvss_score"],
        "description": r["description"],
        "technical_details": r["technical_details"],
        "exploitation": r["exploitation"],
        "mitigation": r["mitigation"],
        "affected_systems": r["affected_systems"],
        "year": r["year"],
        "discovered_by": r["discovered_by"],
        "references": refs,
    }


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


def _gov_timeline_ratio(conn):
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM timeline_events")
    total = cur.fetchone()["c"] or 0
    if total == 0:
        return 0.0
    cur.execute(
        """
SELECT COUNT(*) AS c FROM timeline_events
WHERE target IS NOT NULL AND (
    target LIKE '%حكوم%' OR target LIKE '%وزارة%' OR target LIKE '%دفاع%'
    OR target LIKE '%Federal%' OR target LIKE '%NATO%' OR target LIKE '%Government%'
    OR target LIKE '%عدل%' OR target LIKE '%خارجية%'
)
"""
    )
    gov = cur.fetchone()["c"] or 0
    return round(100.0 * gov / total, 1)


@app.route("/assets/<path:filename>")
def assets(filename):
    return send_from_directory(BASE_DIR / "assets", filename)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/vulnerabilities")
def vulnerabilities_page():
    return render_template("vulnerabilities.html")


@app.route("/vulnerability/<int:vid>")
def vulnerability_detail(vid):
    return render_template("vulnerability_detail.html", vulnerability_id=vid)


@app.route("/simulation")
def simulation_page():
    return render_template("simulation.html")


@app.route("/timeline")
def timeline_page():
    return render_template("timeline.html")


@app.route("/quiz")
def quiz_page():
    return render_template("quiz.html")


@app.route("/about")
def about_page():
    return render_template("about.html")


@app.route("/protection")
def protection_page():
    return render_template("protection.html")


@app.route("/soc")
def soc_page():
    return render_template("soc.html")


@app.get("/api/vulnerabilities")
def api_vulnerabilities():
    conn = db.get_db()
    search = request.args.get("search", "").strip()
    severity = request.args.get("severity", "").strip()
    year = request.args.get("year", "").strip()
    vtype = request.args.get("type", "").strip()
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(100, max(1, int(request.args.get("per_page", 10))))
    limit = request.args.get("limit")

    where = ["1=1"]
    params = []
    if search:
        where.append("(name LIKE ? OR description LIKE ? OR cve_id LIKE ?)")
        like = f"%{search}%"
        params.extend([like, like, like])
    if severity:
        where.append("severity = ?")
        params.append(severity)
    if year.isdigit():
        where.append("year = ?")
        params.append(int(year))
    if vtype:
        where.append("type = ?")
        params.append(vtype)

    sql_where = " AND ".join(where)

    cur = conn.cursor()

    if limit and limit.isdigit() and int(limit) <= 50:
        lim = int(limit)
        cur.execute(
            f"SELECT * FROM vulnerabilities WHERE {sql_where} ORDER BY year DESC, id DESC LIMIT ?",
            (*params, lim),
        )
        rows = cur.fetchall()
        items = [_row_vuln(r) for r in rows]
        return jsonify({"items": items, "page": 1, "per_page": lim, "total": len(items), "pages": 1})

    cur.execute(f"SELECT COUNT(*) AS c FROM vulnerabilities WHERE {sql_where}", params)
    total = cur.fetchone()["c"]
    pages = max(1, math.ceil(total / per_page)) if per_page > 0 else 1
    offset = (page - 1) * per_page
    cur.execute(
        f"""
SELECT * FROM vulnerabilities WHERE {sql_where}
ORDER BY year DESC, id DESC LIMIT ? OFFSET ?
""",
        (*params, per_page, offset),
    )
    rows = cur.fetchall()
    items = [_row_vuln(r) for r in rows]
    return jsonify(
        {"items": items, "page": page, "per_page": per_page, "total": total, "pages": pages}
    )


@app.get("/api/vulnerability/<int:vid>")
def api_vulnerability_one(vid):
    conn = db.get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM vulnerabilities WHERE id = ?", (vid,))
    r = cur.fetchone()
    if r is None:
        return jsonify({"error": "not_found"}), 404
    return jsonify(_row_vuln(r))


@app.get("/api/stats")
def api_stats():
    conn = db.get_db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM vulnerabilities")
    vuln_count = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) AS c FROM timeline_events")
    attacks_count = cur.fetchone()["c"]
    systems_count = _unique_systems_count(conn)
    gov_pct = _gov_timeline_ratio(conn)
    return jsonify(
        {
            "vulnerabilities_count": vuln_count,
            "documented_attacks_count": attacks_count,
            "affected_systems_estimate": systems_count,
            "government_attacks_percentage": gov_pct,
        }
    )


@app.get("/api/soc/snapshot")
def api_soc_snapshot():
    """لوحة تعليمية: ملخص من قاعدة المشروع + تغذية مرجعية (لا مراقبة لشبكات حقيقية)."""
    conn = db.get_db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM vulnerabilities")
    vuln_count = cur.fetchone()["c"] or 0
    cur.execute("SELECT COUNT(*) AS c FROM timeline_events")
    attacks_count = cur.fetchone()["c"] or 0
    systems_count = _unique_systems_count(conn)
    gov_pct = _gov_timeline_ratio(conn)

    cur.execute(
        """
SELECT year, title, severity, target
FROM timeline_events
ORDER BY year DESC, id DESC
LIMIT 6
"""
    )
    timeline_rows = cur.fetchall()
    feed = []
    for r in timeline_rows:
        sev = (r["severity"] or "متوسط").strip()
        feed.append(
            {
                "kind": "timeline_ref",
                "year": r["year"],
                "severity": sev,
                "title": r["title"],
                "context": (r["target"] or "").strip() or "—",
            }
        )

    tips = [
        {
            "kind": "practice",
            "severity": "معلوماتي",
            "title": "مراقبة السجلات والتنبيهات",
            "context": "ربط مصادر السجلات (SIEM) يسرّع اكتشاف السلاسل غير الاعتيادية.",
        },
        {
            "kind": "practice",
            "severity": "معلوماتي",
            "title": "تجزئة الشبكة وأقل صلاحيات",
            "context": "عزل الأنظمة الحساسة يحد من انتشار المهاجم بعد أول اختراق.",
        },
        {
            "kind": "practice",
            "severity": "معلوماتي",
            "title": "التحديثات وإدارة الثغرات",
            "context": "أولوية للتصحيحات على الأنظمة المعرّضة للإنترنت والخدمات الحرجة.",
        },
    ]
    feed.extend(tips)

    base = vuln_count + attacks_count * 3 + systems_count
    visibility = min(98, 58 + (base % 28))
    response_readiness = min(97, 52 + ((base * 7) % 35))
    hardening = min(96, 60 + ((base * 3) % 30))

    return jsonify(
        {
            "disclaimer": "عرض تعليمي فقط — لا يتصل بأنظمتك ولا يرسل بيانات خارج هذا الموقع.",
            "metrics": {
                "vulnerabilities_in_db": vuln_count,
                "timeline_events": attacks_count,
                "systems_estimate": systems_count,
                "gov_related_timeline_pct": gov_pct,
            },
            "posture": {
                "visibility_score": visibility,
                "response_readiness": response_readiness,
                "hardening_index": hardening,
            },
            "feed": feed,
        }
    )


@app.get("/api/timeline")
def api_timeline():
    conn = db.get_db()
    year = request.args.get("year", "").strip()
    cur = conn.cursor()
    if year.isdigit():
        cur.execute(
            "SELECT * FROM timeline_events WHERE year = ? ORDER BY year ASC, id ASC",
            (int(year),),
        )
    else:
        cur.execute("SELECT * FROM timeline_events ORDER BY year ASC, id ASC")
    rows = cur.fetchall()
    out = []
    for r in rows:
        out.append(
            {
                "id": r["id"],
                "year": r["year"],
                "title": r["title"],
                "target": r["target"],
                "impact": r["impact"],
                "vulnerability_type": r["vulnerability_type"],
                "description": r["description"],
                "severity": r["severity"],
            }
        )
    return jsonify({"events": out})


@app.get("/api/quiz")
def api_quiz():
    conn = db.get_db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM quiz_questions")
    if cur.fetchone()["c"] < 10:
        return jsonify({"error": "insufficient_questions"}), 500
    cur.execute("SELECT * FROM quiz_questions ORDER BY RANDOM() LIMIT 10")
    rows = cur.fetchall()
    questions = []
    for r in rows:
        opts = [
            {"key": "A", "text": r["option_a"]},
            {"key": "B", "text": r["option_b"]},
            {"key": "C", "text": r["option_c"]},
            {"key": "D", "text": r["option_d"]},
        ]
        random.shuffle(opts)
        questions.append(
            {
                "id": r["id"],
                "question": r["question"],
                "options": opts,
                "difficulty": r["difficulty"],
                "correct_answer": r["correct_answer"],
                "explanation": r["explanation"],
            }
        )
    return jsonify({"questions": questions})


@app.post("/api/quiz/result")
def api_quiz_result():
    conn = db.get_db()
    payload = request.get_json(silent=True) or {}
    try:
        score = int(payload.get("score", 0))
        total = int(payload.get("total", 0))
        level = str(payload.get("level", ""))[:64]
    except (TypeError, ValueError):
        return jsonify({"error": "bad_payload"}), 400
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO quiz_results (score, total, level) VALUES (?,?,?)",
        (score, total, level),
    )
    conn.commit()
    return jsonify({"ok": True, "id": cur.lastrowid})


@app.post("/api/simulation/log")
def api_simulation_log():
    conn = db.get_db()
    payload = request.get_json(silent=True) or {}
    scenario = str(payload.get("scenario", ""))[:128]
    try:
        step = int(payload.get("step", 0))
    except (TypeError, ValueError):
        step = 0
    action = str(payload.get("action", ""))[:512]
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO simulation_logs (scenario, step, action) VALUES (?,?,?)",
        (scenario, step, action),
    )
    conn.commit()
    return jsonify({"ok": True, "id": cur.lastrowid})


@app.get("/api/simulation/stats")
def api_simulation_stats():
    conn = db.get_db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM simulation_logs")
    total = cur.fetchone()["c"]
    cur.execute(
        """
SELECT scenario, COUNT(*) AS c FROM simulation_logs
GROUP BY scenario ORDER BY c DESC
"""
    )
    by_scenario = [{ "scenario": r["scenario"] or "", "count": r["c"] } for r in cur.fetchall()]
    return jsonify({"total_logs": total, "by_scenario": by_scenario})


def _normalize_url(raw: str) -> str:
    s = (raw or "").strip()
    if not s:
        return ""
    # Allow users to paste without scheme; default to https.
    if "://" not in s:
        s = "https://" + s
    try:
        parts = urlsplit(s)
    except Exception:
        return ""
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        return ""
    netloc = parts.netloc.strip()
    if not netloc:
        return ""
    # Strip credentials if any (user:pass@host).
    if "@" in netloc:
        netloc = netloc.split("@", 1)[1]
    # Remove default ports formatting noise (keep explicit ports though).
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query or "", ""))


def _http_post_json(url: str, data: dict, timeout_s: float = 3.2, headers: dict | None = None) -> dict:
    payload = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "ZeroDay-Defense/1.0 (+educational)",
            **(headers or {}),
        },
        method="POST",
    )
    def _is_ssl_verify_error(err: Exception) -> bool:
        if isinstance(err, ssl.SSLCertVerificationError):
            return True
        reason = getattr(err, "reason", None)
        if isinstance(reason, ssl.SSLCertVerificationError):
            return True
        return "CERTIFICATE_VERIFY_FAILED" in str(err)

    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw)
    except Exception as e:
        if not _is_ssl_verify_error(e):
            raise
        # بعض بيئات Windows/Python قد تفتقد سلسلة شهادات محدثة.
        # نعيد المحاولة مع سياق غير متحقق لتجنب فشل ميزة دفاعية تعليمية.
        ctx = ssl._create_unverified_context()
        with urllib.request.urlopen(req, timeout=timeout_s, context=ctx) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw)


def _http_get_json(url: str, timeout_s: float = 3.2, headers: dict | None = None) -> dict:
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "ZeroDay-Defense/1.0 (+educational)",
            **(headers or {}),
        },
        method="GET",
    )
    def _is_ssl_verify_error(err: Exception) -> bool:
        if isinstance(err, ssl.SSLCertVerificationError):
            return True
        reason = getattr(err, "reason", None)
        if isinstance(reason, ssl.SSLCertVerificationError):
            return True
        return "CERTIFICATE_VERIFY_FAILED" in str(err)

    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw)
    except Exception as e:
        if not _is_ssl_verify_error(e):
            raise
        ctx = ssl._create_unverified_context()
        with urllib.request.urlopen(req, timeout=timeout_s, context=ctx) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw)


def _query_urlhaus(url: str) -> dict:
    """
    URLhaus: خدمة استخبارات تهديدات مجانية للروابط الخبيثة.
    - API: https://urlhaus-api.abuse.ch/
    - نستخدم مهلة قصيرة لتجنب إبطاء الصفحة.
    """
    auth_key = (os.environ.get("URLHAUS_AUTH_KEY") or "").strip()
    if not auth_key:
        return {"provider": "urlhaus", "available": False, "reason": "missing_auth_key"}
    try:
        data = _http_post_json(
            "https://urlhaus-api.abuse.ch/v1/url/",
            {"url": url},
            timeout_s=3.0,
            headers={"Auth-Key": auth_key},
        )
        status = str(data.get("query_status", "")).strip()
        # query_status can be: ok / no_results / invalid_url / ...
        malicious = False
        if status == "ok":
            # When ok, it means URL exists in URLhaus database.
            malicious = True
        return {
            "provider": "urlhaus",
            "available": True,
            "query_status": status,
            "malicious": malicious,
        }
    except Exception as e:
        return {
            "provider": "urlhaus",
            "available": False,
            "error": (str(e) or "failed")[:160],
        }


def _vt_url_id(normalized_url: str) -> str:
    # VT v3 expects base64 urlsafe without padding.
    b = normalized_url.encode("utf-8")
    import base64

    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _query_virustotal(normalized_url: str) -> dict:
    """
    VirusTotal v3 URL report (اختياري) — يحتاج API Key في ENV.
    Docs: https://docs.virustotal.com/reference/url-info
    """
    api_key = (os.environ.get("VIRUSTOTAL_API_KEY") or "").strip()
    if not api_key:
        return {"provider": "virustotal", "available": False, "reason": "missing_api_key"}
    try:
        url_id = _vt_url_id(normalized_url)
        data = _http_get_json(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            timeout_s=3.4,
            headers={"x-apikey": api_key},
        )
        attrs = (data.get("data") or {}).get("attributes") or {}
        stats = (attrs.get("last_analysis_stats") or {})
        # Typical keys: malicious, suspicious, harmless, undetected, timeout
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        harmless = int(stats.get("harmless", 0) or 0)
        undetected = int(stats.get("undetected", 0) or 0)
        total = malicious + suspicious + harmless + undetected
        return {
            "provider": "virustotal",
            "available": True,
            "stats": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total": total,
            },
        }
    except Exception as e:
        return {"provider": "virustotal", "available": False, "error": (str(e) or "failed")[:160]}


def _analyze_url(raw: str) -> dict:
    url = _normalize_url(raw)
    if not url:
        return {
            "ok": False,
            "error": "bad_url",
            "message": "الرابط غير صالح. أدخل رابط http/https صحيح.",
        }

    parts = urlsplit(url)
    host = (parts.hostname or "").strip()
    scheme = (parts.scheme or "").lower()
    port = parts.port
    path = parts.path or "/"
    query = parts.query or ""

    score = 0
    reasons = []

    # Basic transport hints
    if scheme != "https":
        score += 12
        reasons.append("يستخدم HTTP بدون تشفير (يفضّل HTTPS).")

    # Host checks
    if not host:
        score += 60
        reasons.append("النطاق/المضيف غير واضح.")
    else:
        host_l = host.lower()
        if host_l.startswith("xn--") or "xn--" in host_l:
            score += 25
            reasons.append("يحتوي على Punycode (قد يدل على تشابه حروف/IDN).")

        if any(c in host for c in (" ", "\t", "\n", "\r")):
            score += 60
            reasons.append("يحتوي على مسافات/محارف غير متوقعة داخل النطاق.")

        if host_l in ("localhost",) or host_l.endswith(".localhost"):
            score += 50
            reasons.append("يشير إلى localhost (قد يكون رابطًا داخليًا/تصيّدًا).")

        # IP address host
        try:
            ip = ipaddress.ip_address(host_l)
            score += 35
            reasons.append("يستخدم عنوان IP بدل نطاق (شائع في الروابط المشبوهة).")
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                score += 40
                reasons.append("يشير إلى عنوان IP داخلي/محجوز (قد يكون خطيرًا).")
        except ValueError:
            pass

        # Excessive subdomains or length
        if len(host_l) >= 55:
            score += 10
            reasons.append("اسم النطاق طويل بشكل غير معتاد.")
        dot_count = host_l.count(".")
        if dot_count >= 4:
            score += 12
            reasons.append("عدد النطاقات الفرعية كبير (قد يكون تمويهًا).")

        # Suspicious TLD / lookalike patterns
        suspicious_tlds = {
            "zip",
            "mov",
            "click",
            "top",
            "cam",
            "work",
            "xyz",
            "tk",
            "gq",
            "ml",
            "cf",
        }
        tld = host_l.rsplit(".", 1)[-1] if "." in host_l else ""
        if tld in suspicious_tlds:
            score += 18
            reasons.append(f"امتداد نطاق شائع في حملات تصيّد: .{tld}")

        if re.search(r"(login|verify|update|secure|account|bank|wallet|payment)", host_l):
            score += 10
            reasons.append("كلمات حساسة داخل النطاق (قد تكون محاولة تقليد صفحات دخول/دفع).")

        if "-" in host_l and host_l.count("-") >= 3:
            score += 8
            reasons.append("عدد الشرطات كبير في النطاق (قد يكون نطاقًا مولّدًا/تمويهًا).")

        shorteners = {
            "bit.ly",
            "t.co",
            "tinyurl.com",
            "goo.gl",
            "is.gd",
            "cutt.ly",
            "rebrand.ly",
            "ow.ly",
        }
        if host_l in shorteners:
            score += 22
            reasons.append("مختصر روابط (يُخفي الوجهة الحقيقية).")

    # URL structure checks
    full = url
    if len(full) >= 180:
        score += 10
        reasons.append("الرابط طويل جدًا (قد يكون لإخفاء أجزاء مهمة).")

    if "@" in (parts.netloc or ""):
        score += 35
        reasons.append("يحتوي على @ في جزء النطاق (حيلة شائعة لإخفاء الوجهة).")

    if re.search(r"%0d|%0a", full.lower()):
        score += 25
        reasons.append("يحتوي على ترميزات CR/LF (قد تشير لمحاولة حقن).")

    # Suspicious file extensions or download hints
    if re.search(r"\.(exe|scr|js|vbs|bat|cmd|ps1|msi|jar|apk)(\?|$)", path.lower()):
        score += 28
        reasons.append("يشير إلى ملف قابل للتنفيذ/تنصيب (احتمال خطر).")

    if re.search(r"(token=|session=|password=|passwd=)", query.lower()):
        score += 18
        reasons.append("يحمل معاملات حساسة في الرابط (token/session/password).")

    # Threat intelligence (real check): URLhaus + optional VirusTotal.
    intel = []
    urlhaus = _query_urlhaus(url)
    intel.append(urlhaus)
    if urlhaus.get("available") and urlhaus.get("malicious"):
        score = max(score, 88)
        reasons.append("مصدر استخبارات تهديدات (URLhaus) أبلغ أن الرابط خبيث/مُبلّغ عنه.")

    vt = _query_virustotal(url)
    intel.append(vt)
    if vt.get("available") and isinstance(vt.get("stats"), dict):
        st = vt["stats"]
        mal = int(st.get("malicious", 0) or 0)
        sus = int(st.get("suspicious", 0) or 0)
        total = int(st.get("total", 0) or 0)
        if total > 0 and (mal > 0 or sus > 0):
            score = max(score, 82 if mal == 0 else 92)
            reasons.append(f"VirusTotal: ({mal} خبيث / {sus} مشبوه) من أصل {total} محرّك فحص.")

    score = min(100, max(0, score))
    verdict = "safe"
    label = "آمن"
    color = "green"
    can_open = True

    # Thresholds: keep it simple for the UI (safe vs suspicious),
    # but treat high scores as "dangerous" for blocking direct opening.
    if score >= 40:
        verdict = "suspicious"
        label = "مشبوه"
        color = "red"
    if score >= 70:
        can_open = False

    if not reasons and verdict == "safe":
        reasons.append("لا توجد مؤشرات واضحة على الاشتباه وفق قواعد الفحص المحلية.")

    return {
        "ok": True,
        "input": (raw or "").strip()[:2048],
        "normalized": url,
        "host": host,
        "score": score,
        "verdict": verdict,
        "label": label,
        "color": color,
        "can_open": can_open,
        "reasons": reasons[:8],
        "intel": intel,
    }


@app.post("/api/url/check")
def api_url_check():
    payload = request.get_json(silent=True) or {}
    url = payload.get("url", "")
    res = _analyze_url(url)
    status = 200 if res.get("ok") else 400
    return jsonify(res), status


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
