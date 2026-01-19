function checkAndShowPopup(url) {
  chrome.runtime.sendMessage({ action: "check_url", url: url }, (response) => {
    if (!response || !response.success) {
      console.error("Error fetching URL data:", response?.error);
      return;
    }

    const data = response.data;

    // Prevent duplicate popup
    if (document.getElementById("urlSafetyPopup")) return;

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
        ${isAffiliate
          ? `<button id="continuePopup">Continue</button>
             <button id="blockPopup">Block</button>
             <button id="closePopup">Close</button>`
          : `<button id="closePopup">Close</button>`}
      </div>
    `;

    document.body.appendChild(modal);

    // Button handlers
    if (isAffiliate) {
      document.getElementById("closePopup").addEventListener("click", () => modal.remove());

      document.getElementById("blockPopup").addEventListener("click", () => {
        modal.remove();
        // Quick block hack
        window.location.href = "about:blank";
      });

      document.getElementById("continuePopup").addEventListener("click", () => {
        modal.remove(); // user continues
      });
    } else {
      document.getElementById("closePopup").addEventListener("click", () => modal.remove());
    }
  });
}

// Run on page load
window.addEventListener("load", () => checkAndShowPopup(window.location.href));
