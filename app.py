# app.py — Flask application for Zero Day informational site
import math
import os
import random
import re
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


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
