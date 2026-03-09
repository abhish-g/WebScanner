const explanationBox = document.getElementById("explanationBox");
const scanBtn = document.getElementById("scanBtn");
const clearBtn = document.getElementById("clearBtn");
const sampleBtn = document.getElementById("sampleBtn");
const themeBtn = document.getElementById("themeBtn");
const copyBtn = document.getElementById("copyBtn");

const payloadEl = document.getElementById("payload");
const attackTypeEl = document.getElementById("attackType");
const confidenceValEl = document.getElementById("confidenceVal");
const confBarEl = document.getElementById("confBar");
const rawJsonEl = document.getElementById("rawJson");
const overlayEl = document.getElementById("overlay");
const statusDot = document.getElementById("statusDot");
const statusText = document.getElementById("statusText");
const severityBadge = document.getElementById("severityBadge");
const toast = document.getElementById("toast");

const historyBody = document.getElementById("historyBody");
const historyCount = document.getElementById("historyCount");

let history = [];

function setStatus(state, text){
  statusText.textContent = text;
  statusDot.style.background =
    state === "ok" ? "rgba(34,197,94,0.85)" :
    state === "warn" ? "rgba(245,158,11,0.85)" :
    state === "err" ? "rgba(239,68,68,0.85)" :
    "rgba(255,255,255,0.25)";
}

function showLoading(show){
  overlayEl.classList.toggle("show", show);
  scanBtn.disabled = show;
  scanBtn.style.opacity = show ? "0.7" : "1";
}

function clamp01(x){
  if (isNaN(x)) return 0;
  return Math.max(0, Math.min(1, x));
}

function severityFrom(conf, attack){
  // You can tweak these rules later
  const c = clamp01(conf);
  const a = (attack || "").toLowerCase();

  if (a === "benign" || a === "safe" || a === "none") return {label:"SAFE", css:"safe"};
  if (c >= 0.75) return {label:"HIGH", css:"high"};
  if (c >= 0.40) return {label:"MEDIUM", css:"med"};
  return {label:"LOW", css:"unk"};
}

function renderResult(data){
  const attack = data.attack ?? "—";
  const confidence = clamp01(Number(data.confidence ?? 0));

  attackTypeEl.textContent = attack;
  confidenceValEl.textContent = `${Math.round(confidence * 100)}%`;
  confBarEl.style.width = `${Math.round(confidence * 100)}%`;

  const sev = severityFrom(confidence, attack);
  severityBadge.textContent = sev.label;
  severityBadge.className = `badge ${sev.css}`;

  // 🔥 Remove explanation from Raw JSON
  const rawData = { ...data };
  delete rawData.explanation;

  rawJsonEl.textContent = JSON.stringify(rawData, null, 2);

  // ✅ Show explanation separately (multiline safe)
  if (data.explanation) {
    explanationBox.textContent = data.explanation;
  } else {
    explanationBox.textContent = "No explanation available.";
  }

  setStatus("ok", "Scan complete");
}


function addToHistory(payload, data){
  const t = new Date();
  history.unshift({
    time: t.toLocaleTimeString(),
    payload: payload,
    attack: data.attack ?? "—",
    confidence: clamp01(Number(data.confidence ?? 0)),
    severity: severityFrom(Number(data.confidence ?? 0), data.attack ?? "").label
  });

  // keep last 10
  history = history.slice(0, 10);
  renderHistory();
}

function renderHistory(){
  historyCount.textContent = `${history.length} scans`;

  if (history.length === 0){
    historyBody.innerHTML = `<tr class="empty"><td colspan="5">No scans yet. Run your first scan.</td></tr>`;
    return;
  }

  historyBody.innerHTML = history.map(h => `
    <tr>
      <td>${h.time}</td>
      <td title="${escapeHtml(h.payload)}">${escapeHtml(truncate(h.payload, 60))}</td>
      <td>${escapeHtml(h.attack)}</td>
      <td>${Math.round(h.confidence*100)}%</td>
      <td>${h.severity}</td>
    </tr>
  `).join("");
}

function truncate(str, n){
  if (!str) return "";
  return str.length > n ? str.slice(0, n-1) + "…" : str;
}

function escapeHtml(s){
  return (s || "").replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;");
}

async function scan(){
  const payload = payloadEl.value.trim();
  if (!payload){
    setStatus("warn", "Enter a payload first");
    return;
  }

  showLoading(true);
  setStatus("warn", "Scanning…");

  try{
    const res = await fetch("/scan", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ payload })
    });

    if (!res.ok){
      const text = await res.text();
      throw new Error(`HTTP ${res.status}: ${text}`);
    }

    const data = await res.json();
    renderResult(data);
    addToHistory(payload, data);

  }catch(e){
    setStatus("err", "Scan failed");
    rawJsonEl.textContent = String(e);
    severityBadge.textContent = "ERROR";
    severityBadge.className = "badge high";
    confBarEl.style.width = "0%";
  }finally{
    showLoading(false);
  }
}

function showToast(msg){
  toast.textContent = msg;
  toast.classList.add("show");
  setTimeout(()=> toast.classList.remove("show"), 900);
}

function loadSample(){
  payloadEl.value = "admin' OR '1'='1";
}

function clearAll(){
  payloadEl.value = "";
  attackTypeEl.textContent = "—";
  confidenceValEl.textContent = "—";
  confBarEl.style.width = "0%";
  rawJsonEl.textContent = "{ }";
  severityBadge.textContent = "—";
  severityBadge.className = "badge unk";
  rawJsonEl.textContent = "{ }";
  explanationBox.textContent = "—";
  severityBadge.textContent = "—";
  setStatus("idle", "Idle");
}

function toggleTheme(){
  document.body.classList.toggle("light");
  themeBtn.textContent = document.body.classList.contains("light") ? "☀️" : "🌙";
}

function copyRaw(){
  const text = rawJsonEl.textContent || "";
  navigator.clipboard.writeText(text).then(() => showToast("Copied ✅")).catch(() => showToast("Copy failed"));
}

scanBtn.addEventListener("click", scan);
clearBtn.addEventListener("click", clearAll);
sampleBtn.addEventListener("click", loadSample);
themeBtn.addEventListener("click", toggleTheme);
copyBtn.addEventListener("click", copyRaw);

// default
clearAll();
renderHistory();