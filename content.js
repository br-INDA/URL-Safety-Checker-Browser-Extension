// Runs the check_url flow via background.js and hands the result to a callback.
function runScan(url, onData) {
  chrome.runtime.sendMessage({ action: "check_url", url: url }, (response) => {
    if (!response || !response.success) {
      console.error("Error fetching URL data:", response?.error);
      return;
    }
    onData(response.data);
  });
}

// Builds (or rebuilds) the floating verdict card from a result object.
function renderPopup(data) {
  // Remove any existing card so a rescan replaces it instead of being blocked by it
  const existing = document.getElementById("urlSafetyPopup");
  if (existing) existing.remove();

  const modal = document.createElement("div");
  modal.id = "urlSafetyPopup";
  modal.style = `
    position: fixed;
    top: 20px;
    right: 20px;
    width: 380px;
    background: #1e1e1e;
    color: #f1f1f1;
    font-family: Arial, sans-serif;
    border-radius: 8px;
    box-shadow: 0 0 15px rgba(0,0,0,0.5);
    z-index: 999999;
    padding: 15px;
  `;

  // Verdict emoji
  let verdictEmoji = "🟢"; // SAFE
  if (data.verdict === "SUSPICIOUS") verdictEmoji = "🟡";
  if (data.verdict === "DANGEROUS") verdictEmoji = "🔴";

  // Check if affiliate
  const isAffiliate = data.affiliate === true;

  modal.innerHTML = `
    <h3>URL Safety Checker</h3>
    <div style="margin-bottom:8px; font-weight:bold; font-size: 14px;">
      Verdict: ${verdictEmoji} ${data.verdict}
    </div>

    <pre style="white-space: pre-wrap; font-size: 13px; max-height: 150px; overflow-y: auto;">
Risk Score: ${data.risk_score}/100
SSL Expiry: ${data.ssl?.notAfter || "N/A"}
Domain Age: ${data.whois?.age_days || "N/A"} days

Reasons:
${data.reasons.length > 0 ? data.reasons.join(", ") : "None"}

Redirect Chain:
${data.redirect_chain && data.redirect_chain.length > 0
      ? data.redirect_chain.map((r,i) => `${i+1}. ${r.url} [${r.status}]`).join("\n")
      : "N/A"}
    </pre>

    <div style="text-align: right; margin-top: 10px;">
      <button id="rescanPopup">Rescan</button>
      ${isAffiliate
        ? `<button id="continuePopup">Continue</button>
           <button id="blockPopup">Block</button>
           <button id="closePopup">Close</button>`
        : `<button id="closePopup">Close</button>`}
    </div>
  `;

  document.body.appendChild(modal);

  // Button handlers
  document.getElementById("closePopup").addEventListener("click", () => modal.remove());

  document.getElementById("rescanPopup").addEventListener("click", () => {
    runScan(window.location.href, renderPopup);
  });

  if (isAffiliate) {
    document.getElementById("blockPopup").addEventListener("click", () => {
      modal.remove();
      // Quick block hack
      window.location.href = "about:blank";
    });

    document.getElementById("continuePopup").addEventListener("click", () => {
      modal.remove(); // user continues
    });
  }
}

// Automatic scan on page load
window.addEventListener("load", () => {
  runScan(window.location.href, renderPopup);
});

// Manual rescan, triggered by the "Check This Page" button in popup.js
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "check_url_manual") {
    runScan(window.location.href, (data) => {
      renderPopup(data);                                   // refresh the in-page card
      chrome.runtime.sendMessage({ type: "scan_result", data }); // update the toolbar popup too
    });
  }
});