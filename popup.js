document.addEventListener("DOMContentLoaded", () => {
    const checkBtn = document.getElementById("checkBtn");
    const resultDiv = document.getElementById("result");
    const warningDiv = document.getElementById("extWarning");

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

    // Receive scan results from content.js
    chrome.runtime.onMessage.addListener((msg) => {
        if (msg.type === "scan_result") {
            resultDiv.textContent = JSON.stringify(msg.data, null, 2);
        }
    });

    // Request extension list from background.js
    chrome.runtime.sendMessage({ getExtensions: true });
});
