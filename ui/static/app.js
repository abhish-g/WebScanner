// ============================================================
// RAG SECURITY SCANNER - FRONTEND
// ============================================================

// ---------- Elements ----------
const payloadEl = document.getElementById("payload");

const scanBtn = document.getElementById("scanBtn");
const clearBtn = document.getElementById("clearBtn");

const attackTypeEl = document.getElementById("attackType");
const confidenceValEl = document.getElementById("confidenceVal");
const confBarEl = document.getElementById("confBar");

const severityBadge = document.getElementById("severityBadge");
const detectedPayloadEl = document.getElementById("detectedPayload");

const explanationBox = document.getElementById("explanationBox");
const rawJsonEl = document.getElementById("rawJson");

const statusDot = document.getElementById("statusDot");
const statusText = document.getElementById("statusText");

const overlayEl = document.getElementById("overlay");
const toast = document.getElementById("toast");

const historyBody = document.getElementById("historyBody");
const historyCount = document.getElementById("historyCount");

const themeBtn = document.getElementById("themeBtn");
const copyBtn = document.getElementById("copyBtn");


// ---------- History ----------
let history = [];


// ============================================================
// STATUS
// ============================================================

function setStatus(state, text) {

    if (statusText) {
        statusText.textContent = text;
    }

    if (!statusDot) return;

    if (state === "ok") {
        statusDot.style.background = "rgba(34,197,94,0.85)";
    }
    else if (state === "warn") {
        statusDot.style.background = "rgba(245,158,11,0.85)";
    }
    else if (state === "err") {
        statusDot.style.background = "rgba(239,68,68,0.85)";
    }
    else {
        statusDot.style.background = "rgba(255,255,255,0.25)";
    }
}


// ============================================================
// LOADING
// ============================================================

function showLoading(show) {

    if (overlayEl) {
        overlayEl.classList.toggle("show", show);
    }

    if (scanBtn) {
        scanBtn.disabled = show;
        scanBtn.style.opacity = show ? "0.7" : "1";
    }
}


// ============================================================
// HELPERS
// ============================================================

function clamp01(value) {

    const number = Number(value);

    if (Number.isNaN(number)) {
        return 0;
    }

    return Math.max(0, Math.min(1, number));
}


function escapeHtml(value) {

    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}


function truncate(value, length) {

    const text = String(value ?? "");

    if (text.length <= length) {
        return text;
    }

    return text.slice(0, length - 1) + "…";
}


// ============================================================
// SEVERITY
// ============================================================

function getSeverity(data) {

    const attack = String(data.attack ?? "").toLowerCase();

    // IMPORTANT:
    // Use backend severity when available.
    if (data.severity) {

        const severity = String(data.severity).toUpperCase();

        if (severity === "SAFE") {
            return {
                label: "SAFE",
                css: "safe"
            };
        }

        if (severity === "CRITICAL") {
            return {
                label: "CRITICAL",
                css: "high"
            };
        }

        if (severity === "HIGH") {
            return {
                label: "HIGH",
                css: "high"
            };
        }

        if (severity === "MEDIUM") {
            return {
                label: "MEDIUM",
                css: "med"
            };
        }

        if (severity === "LOW") {
            return {
                label: "LOW",
                css: "unk"
            };
        }
    }

    // Fallback
    if (
        attack === "normal" ||
        attack === "safe" ||
        attack === "benign"
    ) {
        return {
            label: "SAFE",
            css: "safe"
        };
    }

    return {
        label: "UNKNOWN",
        css: "unk"
    };
}


// ============================================================
// RENDER RESULT
// ============================================================

function renderResult(data) {

    console.log("SCAN RESULT:", data);

    const attack = data.attack ?? "—";

    const confidence = clamp01(
        data.confidence ?? 0
    );

    const confidencePercent =
        Math.round(confidence * 100);


    // --------------------------------------------------------
    // Attack Type
    // --------------------------------------------------------

    if (attackTypeEl) {
        attackTypeEl.textContent = attack;
    }


    // --------------------------------------------------------
    // Confidence
    // --------------------------------------------------------

    if (confidenceValEl) {
        confidenceValEl.textContent =
            `${confidencePercent}%`;
    }

    if (confBarEl) {
        confBarEl.style.width =
            `${confidencePercent}%`;
    }


    // --------------------------------------------------------
    // Severity
    // --------------------------------------------------------

    const severity = getSeverity(data);

    if (severityBadge) {

        severityBadge.textContent =
            severity.label;

        severityBadge.className =
            `badge ${severity.css}`;
    }


    // --------------------------------------------------------
    // DETECTED PAYLOAD
    // --------------------------------------------------------
    // THIS WAS MISSING IN YOUR PREVIOUS JS.
    //
    // textContent is intentionally used instead of innerHTML
    // so payloads like <script>alert(1)</script> are displayed
    // as text and NOT executed.
    // --------------------------------------------------------

    if (detectedPayloadEl) {

        detectedPayloadEl.textContent =
            data.payload || "—";

    }


    // --------------------------------------------------------
    // AI Explanation
    // --------------------------------------------------------

    if (explanationBox) {

        explanationBox.textContent =
            data.explanation ||
            "No explanation available.";

    }


    // --------------------------------------------------------
    // Raw JSON
    // --------------------------------------------------------

    if (rawJsonEl) {

        // Don't duplicate the long explanation
        // inside Raw JSON.
        const rawData = {
            ...data
        };

        delete rawData.explanation;

        rawJsonEl.textContent =
            JSON.stringify(
                rawData,
                null,
                2
            );
    }


    // --------------------------------------------------------
    // Status
    // --------------------------------------------------------

    setStatus(
        "ok",
        "Analysis complete"
    );
}


// ============================================================
// HISTORY
// ============================================================

function addToHistory(payload, data) {

    const severity =
        getSeverity(data);

    history.unshift({

        time:
            new Date().toLocaleTimeString(),

        payload:
            payload,

        attack:
            data.attack ?? "—",

        confidence:
            clamp01(data.confidence),

        severity:
            severity.label
    });

    // Keep only last 10
    history =
        history.slice(0, 10);

    renderHistory();
}


function renderHistory() {

    if (historyCount) {

        historyCount.textContent =
            `${history.length} scan${history.length === 1 ? "" : "s"}`;
    }


    if (!historyBody) {
        return;
    }


    if (history.length === 0) {

        historyBody.innerHTML = `
            <tr class="empty">
                <td colspan="5">
                    No scans yet. Run your first scan.
                </td>
            </tr>
        `;

        return;
    }


    historyBody.innerHTML =
        history.map(item => {

            return `
                <tr>

                    <td>
                        ${escapeHtml(item.time)}
                    </td>

                    <td
                        title="${escapeHtml(item.payload)}"
                    >
                        ${escapeHtml(
                            truncate(
                                item.payload,
                                60
                            )
                        )}
                    </td>

                    <td>
                        ${escapeHtml(item.attack)}
                    </td>

                    <td>
                        ${Math.round(
                            item.confidence * 100
                        )}%
                    </td>

                    <td>
                        ${escapeHtml(item.severity)}
                    </td>

                </tr>
            `;

        }).join("");
}


// ============================================================
// SCAN
// ============================================================

async function scan() {

    if (!payloadEl) {
        console.error(
            "Payload textarea not found."
        );
        return;
    }


    const payload =
        payloadEl.value.trim();


    // Empty input
    if (!payload) {

        setStatus(
            "warn",
            "Enter a payload first"
        );

        payloadEl.focus();

        return;
    }


    // Start loading
    showLoading(true);

    setStatus(
        "warn",
        "Running analysis..."
    );


    try {

        const response =
            await fetch(
                "/scan",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        payload: payload
                    })
                }
            );


        // HTTP error
        if (!response.ok) {

            const errorText =
                await response.text();

            throw new Error(
                `HTTP ${response.status}: ${errorText}`
            );
        }


        // Convert response to JSON
        const data =
            await response.json();


        console.log(
            "Backend response:",
            data
        );


        // Render result
        renderResult(data);


        // Add to history
        addToHistory(
            payload,
            data
        );


    }
    catch (error) {

        console.error(
            "Scan error:",
            error
        );


        setStatus(
            "err",
            "Scan failed"
        );


        if (rawJsonEl) {

            rawJsonEl.textContent =
                error.message ||
                String(error);
        }


        if (attackTypeEl) {
            attackTypeEl.textContent =
                "ERROR";
        }


        if (confidenceValEl) {
            confidenceValEl.textContent =
                "—";
        }


        if (confBarEl) {
            confBarEl.style.width =
                "0%";
        }


        if (severityBadge) {

            severityBadge.textContent =
                "ERROR";

            severityBadge.className =
                "badge high";
        }


        if (detectedPayloadEl) {

            detectedPayloadEl.textContent =
                payload;
        }


        if (explanationBox) {

            explanationBox.textContent =
                "Unable to complete the security analysis.";
        }

    }
    finally {

        showLoading(false);

    }
}


// ============================================================
// CLEAR
// ============================================================

function clearAll() {

    if (payloadEl) {
        payloadEl.value = "";
    }

    if (attackTypeEl) {
        attackTypeEl.textContent = "—";
    }

    if (confidenceValEl) {
        confidenceValEl.textContent = "—";
    }

    if (confBarEl) {
        confBarEl.style.width = "0%";
    }

    if (severityBadge) {

        severityBadge.textContent =
            "—";

        severityBadge.className =
            "badge unk";
    }

    if (detectedPayloadEl) {
        detectedPayloadEl.textContent = "—";
    }

    if (explanationBox) {
        explanationBox.textContent = "—";
    }

    if (rawJsonEl) {
        rawJsonEl.textContent = "{ }";
    }

    setStatus(
        "idle",
        "Ready"
    );
}


// ============================================================
// SAMPLE PAYLOADS
// ============================================================

function loadPayload(value) {

    if (!payloadEl) {
        return;
    }

    payloadEl.value = value;

    payloadEl.focus();
}


// SQL Injection
function loadSQL() {

    loadPayload(
        "admin' OR '1'='1"
    );
}


// XSS
function loadXSS() {

    loadPayload(
        "<script>alert(1)</script>"
    );
}


// Prompt Injection
function loadPromptInjection() {

    loadPayload(
        "ignore previous instructions"
    );
}


// Safe
function loadSafe() {

    loadPayload(
        "show my profile"
    );
}


// ============================================================
// COPY RAW JSON
// ============================================================

function showToast(message) {

    if (!toast) {
        return;
    }

    toast.textContent =
        message;

    toast.classList.add("show");

    setTimeout(() => {

        toast.classList.remove("show");

    }, 1200);
}


async function copyRaw() {

    if (!rawJsonEl) {
        return;
    }

    const text =
        rawJsonEl.textContent || "";


    try {

        await navigator.clipboard.writeText(
            text
        );

        showToast(
            "Copied"
        );

    }
    catch (error) {

        console.error(
            error
        );

        showToast(
            "Copy failed"
        );
    }
}


// ============================================================
// THEME
// ============================================================

function toggleTheme() {

    document.body.classList.toggle(
        "light"
    );

    if (!themeBtn) {
        return;
    }

    themeBtn.textContent =
        document.body.classList.contains("light")
            ? "☀️"
            : "🌙";
}


// ============================================================
// EVENT LISTENERS
// ============================================================

if (scanBtn) {

    scanBtn.addEventListener(
        "click",
        scan
    );

}


if (clearBtn) {

    clearBtn.addEventListener(
        "click",
        clearAll
    );

}


if (copyBtn) {

    copyBtn.addEventListener(
        "click",
        copyRaw
    );

}


if (themeBtn) {

    themeBtn.addEventListener(
        "click",
        toggleTheme
    );

}


// ============================================================
// EXAMPLE BUTTONS
// ============================================================
//
// These support different possible IDs in your index.html.
// If an ID exists, it gets connected automatically.
//

const sqlBtn =
    document.getElementById("sqlBtn");

const xssBtn =
    document.getElementById("xssBtn");

const promptBtn =
    document.getElementById("promptBtn");

const safeBtn =
    document.getElementById("safeBtn");


if (sqlBtn) {

    sqlBtn.addEventListener(
        "click",
        loadSQL
    );

}


if (xssBtn) {

    xssBtn.addEventListener(
        "click",
        loadXSS
    );

}


if (promptBtn) {

    promptBtn.addEventListener(
        "click",
        loadPromptInjection
    );

}


if (safeBtn) {

    safeBtn.addEventListener(
        "click",
        loadSafe
    );

}


// ============================================================
// INITIAL STATE
// ============================================================

clearAll();
renderHistory();

console.log(
    "RAG Security Scanner UI loaded."
);