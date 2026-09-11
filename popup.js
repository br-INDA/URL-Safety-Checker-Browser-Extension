document.addEventListener("DOMContentLoaded", () => {
    const checkBtn = document.getElementById("checkBtn");
    const checkUrlBtn = document.getElementById("checkUrlBtn");
    const urlInput = document.getElementById("urlInput");
    const resultDiv = document.getElementById("result");
    const warningDiv = document.getElementById("extWarning");

    // Turns a /check_url/ response into a readable report (used by both
    // "Check This Page" and the pasted-URL check, so output looks the same).
    function formatResult(data) {
        let emoji = "🟢"; // SAFE
        if (data.verdict === "SUSPICIOUS") emoji = "🟡";
        if (data.verdict === "DANGEROUS") emoji = "🔴";

        const redirects = data.redirect_chain && data.redirect_chain.length > 0
            ? data.redirect_chain.map((r, i) => `${i + 1}. ${r.url} [${r.status}]`).join("\n")
            : "N/A";

        return `URL: ${data.url}
Verdict: ${emoji} ${data.verdict}
Risk Score: ${data.risk_score}/100
SSL Expiry: ${data.ssl?.notAfter || "N/A"}
Domain Age: ${data.whois?.age_days ?? "N/A"} days

Reasons:
${data.reasons.length > 0 ? data.reasons.join(", ") : "None"}

Redirect Chain:
${redirects}`;
    }

    // Listen for suspicious extension list
    chrome.runtime.onMessage.addListener((msg) => {
        if (msg.type === "suspicious_extensions") {
            if (msg.list.length > 0) {
                warningDiv.style.display = "block";
                warningDiv.textContent =
                    "⚠ Suspicious extensions detected: " + msg.list.join(", ");
            } else {
                warningDiv.style.display = "none";
            }
        }
    });

    // When user clicks "Check This Page"
    checkBtn.addEventListener("click", () => {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (!tabs || !tabs[0]) return;

            chrome.tabs.sendMessage(tabs[0].id, { action: "check_url_manual" });
        });
    });

    // Receive scan results from content.js (triggered by "Check This Page")
    chrome.runtime.onMessage.addListener((msg) => {
        if (msg.type === "scan_result") {
            resultDiv.textContent = formatResult(msg.data);
        }
    });

    // Check a pasted URL directly — goes straight to background.js, no tab
    // or content script involved, so nothing ever has to be opened.
    function checkPastedUrl() {
        const url = urlInput.value.trim();
        if (!url) return;

        resultDiv.textContent = "Checking...";
        checkUrlBtn.disabled = true;

        chrome.runtime.sendMessage({ action: "check_url", url: url }, (response) => {
            checkUrlBtn.disabled = false;

            if (!response || !response.success) {
                resultDiv.textContent = "Error: " +
                    (response?.error || "Could not reach the backend. Is it running on 127.0.0.1:8000?");
                return;
            }
            resultDiv.textContent = formatResult(response.data);
        });
    }

    checkUrlBtn.addEventListener("click", checkPastedUrl);
    urlInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") checkPastedUrl();
    });

    // Request extension list from background.js
    chrome.runtime.sendMessage({ getExtensions: true });
});