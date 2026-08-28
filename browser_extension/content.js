(() => {
  const send = (event_type, extra = {}) => {
    chrome.runtime.sendMessage({
      kind: "valkyrie_browser_context",
      event_type,
      user_initiated: true,
      ...extra,
    });
  };

  document.addEventListener("pointerdown", (event) => {
    if (event.isTrusted) send("user_gesture", {gesture: "pointer"});
  }, {capture: true, passive: true});

  document.addEventListener("keydown", (event) => {
    // Key identity/text is intentionally not collected.
    if (event.isTrusted) send("user_gesture", {gesture: "keyboard"});
  }, {capture: true, passive: true});

  document.addEventListener("submit", (event) => {
    if (event.isTrusted) send("form_submit", {gesture: "submit"});
  }, {capture: true});

  document.addEventListener("click", (event) => {
    if (!event.isTrusted) return;
    const control = event.target?.closest?.("button, a, input, [role='button']");
    // Only inspect implementation metadata locally; it is never transmitted.
    const hint = [control?.id, control?.getAttribute?.("name"), control?.className]
      .filter((x) => typeof x === "string").join(" ").toLowerCase();
    if (!/(consent|cookie|privacy|gdpr)/.test(hint)) return;
    const state = /(reject|decline|deny)/.test(hint) ? "rejected"
      : /(accept|allow|agree)/.test(hint) ? "accepted" : "unknown";
    send("consent_signal", {gesture: "pointer", consent_state: state});
  }, {capture: true, passive: true});
})();
