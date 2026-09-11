// List of common affiliate keywords
const affiliateKeywords = ["aff", "ref", "affiliate_id", "utm_source", "partner", "tracking_id", "tag"];

// Adds a scheme if one is missing. window.location.href (from content.js)
// always has one already, but a pasted/typed URL from the popup often
// doesn't (e.g. "example.com"), and `new URL()` throws on those.
function normalizeUrl(url) {
  try {
    new URL(url);
    return url;
  } catch {
    return "http://" + url;
  }
}

// Listen for messages from content.js and popup.js
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "check_url") {
    (async () => {
      try {
        const url = normalizeUrl(request.url);

        // Fetch the backend
        const response = await fetch("http://127.0.0.1:8000/check_url/", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: url })
        });

        const data = await response.json();

        // Extra check: force affiliate detection if query params match keywords
        const urlObj = new URL(url);
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