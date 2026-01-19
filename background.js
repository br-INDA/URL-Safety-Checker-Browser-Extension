// List of common affiliate keywords
const affiliateKeywords = ["aff", "ref", "affiliate_id", "utm_source", "partner", "tracking_id", "tag"];

// Listen for messages from content.js
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "check_url") {
    (async () => {
      try {
        // Fetch the backend
        const response = await fetch("http://127.0.0.1:8000/check_url/", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: request.url })
        });

        const data = await response.json();

        // Extra check: force affiliate detection if query params match keywords
        const urlObj = new URL(request.url);
        const queryParams = Array.from(urlObj.searchParams.keys());
        const isAffiliate = queryParams.some(param => affiliateKeywords.includes(param.toLowerCase()));

        if (isAffiliate) {
          data.affiliate = true;
          data.verdict = "DANGEROUS"; // override verdict
          data.reasons.push("affiliate_link_detected (query param)");
        }

        sendResponse({ success: true, data: data });
      } catch (err) {
        sendResponse({ success: false, error: err.message });
      }
    })();

    return true; // keep message channel open
  }
});
