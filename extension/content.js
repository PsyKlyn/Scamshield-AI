chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "scanText") {
    // Highlight scanned text
    alert(`🔍 Scanning: "${request.text}"\n\n⚠️ Open popup for full scan!`);
  }
});
