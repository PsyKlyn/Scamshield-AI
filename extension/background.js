chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "scan-selection",
    title: "🔍 Scan this text for scams",
    contexts: ["selection"]
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "scan-selection") {
    chrome.tabs.sendMessage(tab.id, {action: "scanText", text: info.selectionText});
  }
});
