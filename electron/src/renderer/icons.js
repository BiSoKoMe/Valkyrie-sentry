'use strict';
/* Minimal, consistent 1.6px stroke icon set (Lucide-style geometry).
   Kept inline + local so the strict CSP needs no external image host. */
const ICON = (() => {
  const s = (p) =>
    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">${p}</svg>`;
  return {
    shield: s('<path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z"/>'),
    shieldCheck: s('<path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z"/><path d="M9 12l2 2 4-4"/>'),
    dashboard: s('<rect x="3" y="3" width="8" height="8" rx="2"/><rect x="13" y="3" width="8" height="5" rx="2"/><rect x="13" y="10" width="8" height="11" rx="2"/><rect x="3" y="13" width="8" height="8" rx="2"/>'),
    lock: s('<rect x="4.5" y="10.5" width="15" height="10" rx="2.5"/><path d="M8 10.5V7a4 4 0 0 1 8 0v3.5"/>'),
    flame: s('<path d="M12 3c1 3 4 4 4 8a4 4 0 0 1-8 0c0-1.5.7-2.4 1.4-3.2C10 9 11 7.5 12 3z"/><path d="M12 21a5 5 0 0 0 5-5c0-2-1-3.5-2.2-5"/>'),
    alert: s('<path d="M12 4l9 16H3l9-16z"/><path d="M12 10v4"/><path d="M12 17.5h.01"/>'),
    brain: s('<path d="M9 4a3 3 0 0 0-3 3 3 3 0 0 0-1 5.5A3 3 0 0 0 7 18a3 3 0 0 0 5 1 3 3 0 0 0 5-1 3 3 0 0 0 2-5.5A3 3 0 0 0 18 7a3 3 0 0 0-3-3 3 3 0 0 0-3 1.5A3 3 0 0 0 9 4z"/>'),
    apps: s('<rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="3" width="7" height="7" rx="2"/><rect x="3" y="14" width="7" height="7" rx="2"/><rect x="14" y="14" width="7" height="7" rx="2"/>'),
    network: s('<circle cx="12" cy="5" r="2.4"/><circle cx="5" cy="19" r="2.4"/><circle cx="19" cy="19" r="2.4"/><path d="M12 7.4v4M12 11.4L6.5 17M12 11.4L17.5 17"/>'),
    globe: s('<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.5 2.5 15 0 18M12 3c-2.5 2.5-2.5 15 0 18"/>'),
    devices: s('<rect x="3" y="5" width="13" height="10" rx="2"/><rect x="17" y="8" width="4" height="11" rx="1.5"/><path d="M8 19h5"/>'),
    download: s('<path d="M12 4v10m0 0l-4-4m4 4l4-4"/><path d="M5 19h14"/>'),
    settings: s('<circle cx="12" cy="12" r="3"/><path d="M12 3v2M12 19v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M3 12h2M19 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4"/>'),
    info: s('<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>'),
    bell: s('<path d="M6 9a6 6 0 0 1 12 0c0 5 2 6 2 6H4s2-1 2-6z"/><path d="M10 20a2 2 0 0 0 4 0"/>'),
    check: s('<path d="M5 12l4 4 10-10"/>'),
    power: s('<path d="M12 4v8"/><path d="M7.5 7a7 7 0 1 0 9 0"/>'),
    dns: s('<ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6v12c0 1.7 3.1 3 7 3s7-1.3 7-3V6"/><path d="M5 12c0 1.7 3.1 3 7 3s7-1.3 7-3"/>'),
    activity: s('<path d="M3 12h4l3 8 4-16 3 8h4"/>'),
    cpu: s('<rect x="7" y="7" width="10" height="10" rx="2"/><path d="M10 3v2M14 3v2M10 19v2M14 19v2M3 10h2M3 14h2M19 10h2M19 14h2"/>'),
    search: s('<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.35-4.35"/>'),
    target: s('<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1"/>'),
    min: s('<path d="M5 12h14"/>'),
    max: s('<rect x="5" y="5" width="14" height="14" rx="2"/>'),
    x: s('<path d="M6 6l12 12M18 6L6 18"/>'),
    // Brand mark — the twin-wing "V" emblem. Fixed identity color (not
    // currentColor like the rest of the set) since it's the logo, not a
    // semantic UI glyph. Same geometry as the big splash/About LOGO in
    // app.js, just reused at icon size — one shape, one source of truth.
    mark: '<svg viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">' +
      '<polygon points="29,4 2,14 9,19" fill="#f6f6f7" opacity="0.72"/>' +
      '<polygon points="35,4 62,14 55,19" fill="#f6f6f7" opacity="0.72"/>' +
      '<polygon points="18,12 2,22 7.5,25.5" fill="#f6f6f7" opacity="0.72"/>' +
      '<polygon points="46,12 62,22 56.5,25.5" fill="#f6f6f7" opacity="0.72"/>' +
      '<polygon points="29,4 25.5,8.5 2,14" fill="#f6f6f7"/>' +
      '<polygon points="35,4 38.5,8.5 62,14" fill="#f6f6f7"/>' +
      '<polygon points="18,12 15.5,16 2,22" fill="#f6f6f7"/>' +
      '<polygon points="46,12 48.5,16 62,22" fill="#f6f6f7"/>' +
      '<polygon points="30,19 32,31 34,19" fill="#f6f6f7"/>' +
      '</svg>',
  };
})();
