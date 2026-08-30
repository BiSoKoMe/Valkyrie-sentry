(() => {
  const pendingByForm = new WeakMap();
  const GRANT_WINDOW_MS = 2000;

  const send = (event_type, extra = {}) => {
    chrome.runtime.sendMessage({
      kind: "valkyrie_browser_context",
      event_type,
      user_initiated: true,
      ...extra,
    });
  };

  const originOf = (value) => {
    try {
      const url = new URL(value, document.baseURI);
      return (url.protocol === "http:" || url.protocol === "https:") ? url.origin : "";
    } catch (_) {
      return "";
    }
  };

  const labelsOf = (form) => {
    const labels = new Set();
    for (const control of form?.elements || []) {
      if (control.disabled) continue;
      const type = String(control.type || "").toLowerCase();
      const autocomplete = String(control.autocomplete || "").toLowerCase();
      const hint = `${control.name || ""} ${control.id || ""} ${autocomplete}`.toLowerCase();

      // Values are read transiently here and never included in a message.
      const value = typeof control.value === "string" ? control.value : "";
      if (type === "password" || /password|current-password|new-password/.test(hint)) {
        labels.add("credential");
      } else if (type === "email" || /\bemail\b/.test(hint) || /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value)) {
        labels.add("email");
      } else if (type === "tel" || /\btel|phone/.test(hint)) {
        labels.add("phone");
      } else if (/address|postal|street|country|city/.test(hint)) {
        labels.add("address");
      } else if (/cc-|card|payment|iban|routing|bank/.test(hint)) {
        labels.add("payment");
      } else if (/ssn|social.security|passport|national.id|tax.id/.test(hint)) {
        labels.add("government_id");
      } else if (/health|medical|diagnos|prescription/.test(hint)) {
        labels.add("health");
      } else if (type === "file") {
        labels.add("file");
      } else if (value) {
        labels.add("ordinary");
      }
    }
    if (!labels.size) labels.add("ordinary");
    return [...labels].sort();
  };

  const scopeForm = (form, gesture, submitter = null) => {
    if (!form) return false;
    const destination = originOf(submitter?.formAction || form.action || location.href);
    if (!destination) return false;
    const interactionId = crypto.randomUUID();
    pendingByForm.set(form, {interactionId, expiresAt: performance.now() + GRANT_WINDOW_MS});
    send("user_gesture", {
      gesture,
      interaction_id: interactionId,
      intended_action: "form_submit",
      destination_origin: destination,
      data_labels: labelsOf(form),
    });
    return true;
  };

  document.addEventListener("pointerdown", (event) => {
    if (!event.isTrusted) return;
    const submitter = event.target?.closest?.(
      "button:not([type]), button[type='submit'], input[type='submit'], input[type='image']"
    );
    if (!scopeForm(submitter?.form, "pointer", submitter)) {
      send("user_gesture", {gesture: "pointer"});
    }
  }, {capture: true, passive: true});

  document.addEventListener("keydown", (event) => {
    // Key identity/text is intentionally not collected.
    if (!event.isTrusted) return;
    if (event.key === "Enter" && scopeForm(event.target?.form, "keyboard")) return;
    send("user_gesture", {gesture: "keyboard"});
  }, {capture: true, passive: true});

  document.addEventListener("submit", (event) => {
    const pending = pendingByForm.get(event.target);
    const interactionId = pending && pending.expiresAt >= performance.now()
      ? pending.interactionId : "";
    pendingByForm.delete(event.target);
    send("form_submit", {
      user_initiated: event.isTrusted,
      gesture: "submit",
      interaction_id: interactionId,
      destination_origin: originOf(
        event.submitter?.formAction || event.target?.action || location.href
      ),
      data_labels: labelsOf(event.target),
    });
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
