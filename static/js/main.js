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

document.addEventListener("DOMContentLoaded", function () {
    initMobileNav();
    initPhaseTabs(document.querySelector(".phase-deck"));
});
