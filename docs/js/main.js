// Auto-detect API base
const API = (location.hostname === "127.0.0.1" || location.hostname === "localhost")
  ? "http://127.0.0.1:5000"
  : "https://phishguard-sneg.onrender.com";

// ── Shared nav highlight + hamburger ──
document.addEventListener("DOMContentLoaded", () => {
  // Active link highlight
  const path = location.pathname;
  document.querySelectorAll(".nav-links a").forEach(a => {
    const href = a.getAttribute("href");
    if (href === "/" && (path === "/" || path === "/index.html")) {
      a.classList.add("active");
    } else if (href !== "/" && path.endsWith(href.replace(/^\//, ""))) {
      a.classList.add("active");
    }
  });

  // Inject hamburger button into every nav
  const nav = document.querySelector("nav");
  if (nav) {
    const btn = document.createElement("button");
    btn.className = "nav-hamburger";
    btn.setAttribute("aria-label", "Toggle menu");
    btn.innerHTML = "&#9776;";
    btn.addEventListener("click", () => {
      document.querySelector(".nav-links").classList.toggle("open");
      btn.innerHTML = document.querySelector(".nav-links").classList.contains("open") ? "&#10005;" : "&#9776;";
    });
    nav.appendChild(btn);
  }
});

// ── Scan history (localStorage) ──
const History = {
  KEY: "phishguard_history",
  get() {
    try { return JSON.parse(localStorage.getItem(this.KEY)) || []; }
    catch { return []; }
  },
  add(entry) {
    const list = this.get();
    list.unshift({ ...entry, time: new Date().toISOString() });
    localStorage.setItem(this.KEY, JSON.stringify(list.slice(0, 50)));
  },
  clear() { localStorage.removeItem(this.KEY); }
};

// ── Verdict helpers ──
function verdictBadge(verdict) {
  const map = {
    SAFE:       { cls: "badge-safe",       icon: "✔", label: "Safe" },
    SUSPICIOUS: { cls: "badge-suspicious", icon: "⚠", label: "Suspicious" },
    PHISHING:   { cls: "badge-phishing",   icon: "✖", label: "Phishing" },
  };
  const v = map[verdict] || map.SUSPICIOUS;
  return `<span class="badge ${v.cls}">${v.icon} ${v.label}</span>`;
}

function verdictColor(verdict) {
  return verdict === "SAFE" ? "safe" : verdict === "SUSPICIOUS" ? "suspicious" : "phishing";
}

function riskColor(risk) {
  return risk === "LOW" ? "safe" : risk === "MEDIUM" ? "suspicious" : "phishing";
}

// ── API call ──
async function analyzeURL(url) {
  const res = await fetch(`${API}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url })
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

// ── Format time ago ──
function timeAgo(iso) {
  if (!iso) return "—";
  const diff = (Date.now() - new Date(iso)) / 1000;
  if (diff < 60)   return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  if (diff < 86400)return `${Math.floor(diff/3600)}h ago`;
  return `${Math.floor(diff/86400)}d ago`;
}

// ── Truncate URL ──
function truncateURL(url, max = 55) {
  return url.length > max ? url.slice(0, max) + "…" : url;
}
