async function logSimulationStep(scenario, step, action) {
    try {
        await fetch("/api/simulation/log", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ scenario, step, action }),
        });
    } catch (e) {
        console.warn("simulation log failed", e);
    }
}

function severityClass(sev) {
    const m = {
        حرج: "badge-critical",
        عالٍ: "badge-high",
        متوسط: "badge-medium",
        منخفض: "badge-low",
    };
    return m[sev] || "badge-medium";
}

function animateNumber(el, endVal, options) {
    const o = options || {};
    const dur = o.duration != null ? o.duration : 650;
    const decimals = o.decimals;
    const start = 0;
    let t0 = null;
    function frame(t) {
        if (t0 === null) t0 = t;
        const p = Math.min(1, (t - t0) / dur);
        const ease = 1 - (1 - p) * (1 - p);
        const cur = start + (endVal - start) * ease;
        if (decimals != null) {
            el.textContent = cur.toFixed(decimals);
        } else {
            el.textContent = String(Math.round(cur));
        }
        if (p < 1) requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
}

function initPhaseTabs(root) {
    if (!root) return;
    const tabs = root.querySelectorAll(".phase-tab");
    const panels = root.querySelectorAll(".phase-panel");
    function activate(i) {
        tabs.forEach(function (t) {
            const on = t.getAttribute("data-tab") === i;
            t.classList.toggle("is-active", on);
            t.setAttribute("aria-selected", on ? "true" : "false");
        });
        panels.forEach(function (p) {
            const on = p.id === "phase-panel-" + i;
            p.classList.toggle("is-active", on);
            p.setAttribute("aria-hidden", on ? "false" : "true");
        });
    }
    tabs.forEach(function (tab) {
        tab.addEventListener("click", function () {
            activate(tab.getAttribute("data-tab"));
        });
    });
    const first = root.querySelector(".phase-tab.is-active");
    if (first) activate(first.getAttribute("data-tab"));
}

function initMobileNav() {
    var header = document.getElementById("site-header");
    var btn = document.getElementById("nav-toggle");
    var backdrop = document.getElementById("nav-backdrop");
    var nav = document.getElementById("site-navigation");
    if (!header || !btn || !nav) {
        return;
    }

    function isMobile() {
        return window.matchMedia("(max-width: 768px)").matches;
    }

    function setOpen(open) {
        header.classList.toggle("is-nav-open", open);
        btn.setAttribute("aria-expanded", open ? "true" : "false");
        if (backdrop) {
            if (open && isMobile()) {
                backdrop.removeAttribute("hidden");
                backdrop.setAttribute("aria-hidden", "false");
            } else {
                backdrop.setAttribute("hidden", "");
                backdrop.setAttribute("aria-hidden", "true");
            }
        }
        document.body.style.overflow = open && isMobile() ? "hidden" : "";
    }

    btn.addEventListener("click", function () {
        setOpen(!header.classList.contains("is-nav-open"));
    });

    if (backdrop) {
        backdrop.addEventListener("click", function () {
            setOpen(false);
        });
    }

    nav.querySelectorAll("a").forEach(function (link) {
        link.addEventListener("click", function () {
            if (isMobile()) {
                setOpen(false);
            }
        });
    });

    document.addEventListener("keydown", function (e) {
        if (e.key === "Escape") {
            setOpen(false);
        }
    });

    window.addEventListener("resize", function () {
        if (!isMobile()) {
            setOpen(false);
        }
    });
}

function initUrlCheck() {
    var form = document.getElementById("url-check-form");
    if (!form) return;

    var input = document.getElementById("url-input");
    var btn = document.getElementById("url-check-btn");

    var result = document.getElementById("url-check-result");
    var pill = document.getElementById("url-check-pill");
    var statusEl = document.getElementById("url-check-status");
    var scoreEl = document.getElementById("url-check-score");
    var reasonsEl = document.getElementById("url-check-reasons");
    var openLink = document.getElementById("url-open-link");
    var copyBtn = document.getElementById("url-copy-btn");
    var blockedEl = document.getElementById("url-check-blocked");

    var lastNormalized = "";

    function setLoading(loading) {
        if (btn) btn.disabled = loading;
        if (btn) btn.textContent = loading ? "جاري الفحص…" : "فحص";
    }

    function escapeHtml(s) {
        return String(s || "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    function show(res) {
        result.classList.remove("hidden");
        pill.classList.remove("is-safe", "is-suspicious");
        blockedEl.classList.add("hidden");
        if (openLink) openLink.classList.remove("hidden");

        if (!res || !res.ok) {
            statusEl.textContent = "خطأ";
            scoreEl.textContent = "";
            pill.classList.add("is-suspicious");
            reasonsEl.innerHTML = "<li>" + escapeHtml((res && res.message) || "تعذّر فحص الرابط.") + "</li>";
            if (openLink) openLink.classList.add("hidden");
            lastNormalized = "";
            return;
        }

        var isSuspicious = res.verdict === "suspicious";
        pill.classList.add(isSuspicious ? "is-suspicious" : "is-safe");
        statusEl.textContent = res.label || (isSuspicious ? "مشبوه" : "آمن");
        scoreEl.textContent = (res.score != null ? String(res.score) : "0") + "/100";
        lastNormalized = res.normalized || "";

        var reasons = Array.isArray(res.reasons) ? res.reasons : [];
        if (reasons.length === 0) reasons = ["لا توجد تفاصيل إضافية."];
        reasonsEl.innerHTML = reasons.map(function (r) { return "<li>" + escapeHtml(r) + "</li>"; }).join("");

        if (openLink) {
            openLink.href = lastNormalized || "#";
            openLink.textContent = "فتح الرابط";
        }

        // Prevent direct opening for high-risk URLs.
        if (res.can_open === false) {
            if (openLink) openLink.classList.add("hidden");
            blockedEl.classList.remove("hidden");
        }
    }

    form.addEventListener("submit", function (e) {
        e.preventDefault();
        var raw = (input && input.value ? input.value : "").trim();
        if (!raw) return;
        setLoading(true);
        fetch("/api/url/check", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: raw }),
        })
            .then(function (r) { return r.json().catch(function () { return { ok: false, message: "استجابة غير صالحة." }; }); })
            .then(function (res) { show(res); })
            .catch(function () { show({ ok: false, message: "تعذّر الاتصال بالخادم." }); })
            .finally(function () { setLoading(false); });
    });

    if (copyBtn) {
        copyBtn.addEventListener("click", function () {
            var txt = lastNormalized || (input && input.value ? String(input.value).trim() : "");
            if (!txt) return;
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(txt).catch(function () {});
            } else {
                try {
                    var tmp = document.createElement("textarea");
                    tmp.value = txt;
                    tmp.style.position = "fixed";
                    tmp.style.left = "-9999px";
                    document.body.appendChild(tmp);
                    tmp.focus();
                    tmp.select();
                    document.execCommand("copy");
                    document.body.removeChild(tmp);
                } catch (e) {}
            }
        });
    }
}

document.addEventListener("DOMContentLoaded", function () {
    initMobileNav();
    initPhaseTabs(document.querySelector(".phase-deck"));
    initUrlCheck();
});
