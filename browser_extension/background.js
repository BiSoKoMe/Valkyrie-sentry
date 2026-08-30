const NATIVE_HOST = "com.valkyrie.browser_context";
const MAX_PER_TAB_PER_SECOND = 8;
const counters = new Map();
let nativePort = null;

function orderedNativePort() {
  if (nativePort) return nativePort;
  try {
    const port = chrome.runtime.connectNative(NATIVE_HOST);
    port.onMessage.addListener(() => {
      // Acknowledgements contain no browser data and need no retention.
    });
    port.onDisconnect.addListener(() => {
      if (nativePort === port) nativePort = null;
    });
    nativePort = port;
    return port;
  } catch (_) {
    return null;
  }
}

function originOf(value) {
  try {
    const url = new URL(value);
    return (url.protocol === "http:" || url.protocol === "https:") ? url.origin : "";
  } catch (_) {
    return "";
  }
}

function allowed(tabId) {
  const second = Math.floor(Date.now() / 1000);
  const entry = counters.get(tabId);
  if (!entry || entry.second !== second) {
    counters.set(tabId, {second, count: 1});
    return true;
  }
  entry.count += 1;
  return entry.count <= MAX_PER_TAB_PER_SECOND;
}

function sendContext(input, sender = null) {
  const tabId = sender?.tab?.id ?? input.tab_id ?? -1;
  if (!allowed(tabId)) return;
  const origin = originOf(sender?.url || sender?.tab?.url || input.url || "");
  if (!origin) return;
  const event = {
    version: 1,
    event_id: crypto.randomUUID(),
    event_type: input.event_type,
    url: origin,
    tab_id: tabId,
    frame_id: sender?.frameId ?? input.frame_id ?? -1,
    user_initiated: input.user_initiated === true,
    gesture: input.gesture || "unknown",
    consent_state: input.consent_state || "unknown",
    browser: "chromium",
    ts: Date.now() / 1000,
    interaction_id: typeof input.interaction_id === "string" ? input.interaction_id : "",
    intended_action: input.intended_action === "form_submit" ? "form_submit" : "",
    destination_origin: originOf(input.destination_origin || ""),
    data_labels: Array.isArray(input.data_labels) ? input.data_labels.slice(0, 10) : []
  };
  try {
    // One persistent port preserves gesture -> consequence ordering. Native host
    // absence is an honest disabled state; do not retry or buffer page activity.
    orderedNativePort()?.postMessage(event);
  } catch (_) {
    nativePort = null;
  }
}

chrome.runtime.onMessage.addListener((message, sender) => {
  if (message?.kind === "valkyrie_browser_context") sendContext(message, sender);
});

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  sendContext({event_type: "page_view", url: details.url, tab_id: details.tabId});
}, {url: [{schemes: ["http", "https"]}]});
