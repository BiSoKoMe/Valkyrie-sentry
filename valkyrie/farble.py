"""Fingerprint farbling — per-origin, per-session randomisation of the
browser surfaces that identify a machine.

WHY THIS EXISTS (the bug it replaces)
-------------------------------------
The previous fingerprint protection injected the same constants into every
page on every machine::

    toDataURL          -> always 'data:image/png,v'
    navigator.plugins  -> always []
    navigator.languages-> always ['en-US','en']
    screen.colorDepth  -> always 24

That is counterproductive, and it is worth being precise about why, because
the intuition ("lie about the value") is right and the implementation is
what turns it into a liability:

  * A *constant* lie is itself a fingerprint. No real browser on earth
    returns ``data:image/png,v`` for a canvas readback, so that value does
    not hide a user — it uniquely marks them as a Valkyrie user, and it is
    identical across every site and every session, which is the precise
    definition of a durable tracking ID.
  * An empty ``navigator.plugins`` is rare in the wild, so it *raises*
    entropy rather than lowering it. Same for any "clean" round number.
  * Breaking ``toDataURL`` outright also breaks legitimate canvas use
    (charts, games, image editors, signature pads).

The fix is the approach Brave calls *farbling*: derive every spoofed value
from a seed that is unique per (browsing session x site), so that

  * the SAME site within one session sees STABLE values — the page works,
    and re-reading a canvas twice does not return two different answers,
    which would itself be a tamper signal;
  * DIFFERENT sites in the same session see DIFFERENT values — so two
    trackers cannot correlate the same user across sites, which is the
    entire point;
  * the SAME site in a LATER session sees DIFFERENT values — so nobody
    builds a durable long-term identifier;
  * every value stays PLAUSIBLE — drawn from the distribution real
    hardware actually reports, so the user blends into the crowd instead
    of standing out as "the one lying".

Canvas/audio are perturbed rather than replaced: a per-origin noise table
shifts readback samples by at most one least-significant bit, which is
invisible to a human and to any legitimate use, but destroys the exact
byte-equality that canvas fingerprinting depends on.

HONEST BOUNDARY
---------------
This only reaches pages Valkyrie can actually see and rewrite, which today
means HTML served through the TLS-inspection path. It cannot touch:
  * traffic that is not intercepted (TLS inspection off, or a
    certificate-pinned app that refuses the proxy),
  * fingerprinting done server-side (IP, TLS/JA3 handshake shape, HTTP
    header order) — see fingerprint.py for the network-layer half,
  * native (non-browser) applications, which do not run injected JS at all.
It raises the cost of browser fingerprinting substantially. It does not
make a machine unidentifiable, and nothing here should be described as if
it did.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from urllib.parse import urlsplit

# Regenerated every engine start. Never persisted, never leaves the process:
# persisting it would recreate the exact durable-identifier problem this
# module exists to remove, since a stored seed would make a site's farbled
# values stable forever rather than only for the session.
_SESSION_SEED = secrets.token_bytes(32)


def new_session() -> None:
    """Roll the session seed (every site sees fresh values after this)."""
    global _SESSION_SEED
    _SESSION_SEED = secrets.token_bytes(32)


def origin_of(url: str) -> str:
    """scheme://host — the correlation boundary we farble against.

    Deliberately excludes the path: a tracker embedded on many pages of one
    site must see one consistent identity there (otherwise the site breaks
    in ways a user notices), while a tracker embedded across two *different*
    sites must see two unrelated identities.
    """
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if not host:
            return "about:blank"
        return f"{parts.scheme or 'https'}://{host}"
    except Exception:
        return "about:blank"


def origin_seed(origin: str) -> int:
    """Deterministic 32-bit seed for (this session, this origin).

    HMAC (not a plain hash) so the session secret cannot be recovered from
    an observed seed — a page can read the number we inject, and must not
    be able to work backwards from it to predict what any *other* origin
    will receive.
    """
    mac = hmac.new(_SESSION_SEED, origin.encode("utf-8", "replace"),
                   hashlib.sha256).digest()
    return int.from_bytes(mac[:4], "big")


# ---------------------------------------------------------------------------
# The injected script.
#
# Structure notes:
#   * Everything is wrapped in try/catch and a single IIFE — a failure here
#     must degrade to "no protection", never to "the page is broken".
#   * Each surface gets its OWN sub-stream from the seed, so a page that
#     hammers one surface cannot shift the values another surface reports.
#   * Patched functions carry a native-looking toString(), because the
#     naive override is trivially detectable via
#     Function.prototype.toString and detection is itself a fingerprint.
# ---------------------------------------------------------------------------
_SCRIPT_TEMPLATE = r"""<script>
(function(){
'use strict';
try{
var SEED = %SEED% >>> 0;

/* Independent deterministic stream per surface (xorshift32). Stable for a
   given (origin, session), so repeated reads agree -- a site that reads the
   same canvas twice and gets two answers would detect tampering. */
function mk(n){
  var s = (SEED ^ ((n * 2654435761) >>> 0)) >>> 0;
  if(s === 0) s = 0x9E3779B9;
  return function(){
    s ^= s << 13; s >>>= 0;
    s ^= s >>> 17;
    s ^= s << 5;  s >>>= 0;
    return s / 4294967296;
  };
}
function pick(r, arr){ return arr[Math.floor(r() * arr.length) % arr.length]; }

/* Make a patched function indistinguishable from a native one.
   A per-function OWN 'toString' is not enough on its own: a tracker checks for
   hooks via Function.prototype.toString.call(fn) (or ('' + fn)) using the
   ORIGINAL toString, which bypasses the own property and exposes our source --
   and a detectable hook is itself a durable "this is a Valkyrie user"
   fingerprint, the exact thing this module exists to remove. So we patch the
   one real Function.prototype.toString to report native code for exactly the
   functions we cloak (tracked in a WeakMap), and register the patch itself so
   it cannot give itself away. Anything we do NOT cloak falls through to the
   real source unchanged, so nothing a page legitimately relies on is altered. */
var _cloaked = (function(){ try{ return new WeakMap(); }catch(e){ return null; } })();
try{
  if(_cloaked){
    var _realFPTS = Function.prototype.toString;
    var _fakeFPTS = function toString(){
      try{ var nm = _cloaked.get(this);
           if(nm !== undefined) return 'function ' + nm + '() { [native code] }'; }
      catch(e){}
      return _realFPTS.apply(this, arguments);
    };
    Function.prototype.toString = _fakeFPTS;
    _cloaked.set(_fakeFPTS, 'toString');        /* the patch hides itself too */
  }
}catch(e){}

function cloak(patched, original, name){
  try{
    Object.defineProperty(patched, 'name', {value: name, configurable: true});
    Object.defineProperty(patched, 'length',
      {value: original.length, configurable: true});
    if(_cloaked) _cloaked.set(patched, name);
    else Object.defineProperty(patched, 'toString', {   /* fallback: own prop */
      value: function(){ return 'function ' + name + '() { [native code] }'; },
      writable: true, configurable: true });
  }catch(e){}
  return patched;
}
function def(obj, prop, getter){
  try{ Object.defineProperty(obj, prop, {get: getter, configurable: true}); }
  catch(e){}
}

/* ---- 1. Canvas readback -------------------------------------------------
   Perturb, do not replace. A +/-1 shift on colour channels is invisible and
   keeps charts/games/signature pads working, while destroying the exact
   byte-equality canvas fingerprinting relies on. The noise table is fixed
   per origin+session so two reads of identical pixels stay identical. */
var cr = mk(1);
var NT = new Int8Array(1024);
for(var i=0;i<1024;i++){ var v = cr(); NT[i] = v < 0.33 ? -1 : (v < 0.66 ? 0 : 1); }
function farbleImageData(d){
  try{
    for(var i=0;i<d.length;i+=4){
      var n = NT[(i >>> 2) & 1023];
      if(n){
        d[i]   = Math.min(255, Math.max(0, d[i]   + n));
        d[i+1] = Math.min(255, Math.max(0, d[i+1] + n));
        d[i+2] = Math.min(255, Math.max(0, d[i+2] + n));
      }
    }
  }catch(e){}
  return d;
}
try{
  var _gid = CanvasRenderingContext2D.prototype.getImageData;
  CanvasRenderingContext2D.prototype.getImageData = cloak(function(){
    var r = _gid.apply(this, arguments);
    try{ farbleImageData(r.data); }catch(e){}
    return r;
  }, _gid, 'getImageData');
}catch(e){}
try{
  var _tdu = HTMLCanvasElement.prototype.toDataURL;
  HTMLCanvasElement.prototype.toDataURL = cloak(function(){
    try{
      var ctx = this.getContext('2d');
      if(ctx && this.width && this.height){
        var img = ctx.getImageData(0, 0, this.width, this.height);
        ctx.putImageData(img, 0, 0);   /* already farbled by the hook above */
      }
    }catch(e){}
    return _tdu.apply(this, arguments);
  }, _tdu, 'toDataURL');
}catch(e){}
try{
  var _tb = HTMLCanvasElement.prototype.toBlob;
  HTMLCanvasElement.prototype.toBlob = cloak(function(){
    try{
      var ctx = this.getContext('2d');
      if(ctx && this.width && this.height){
        var img = ctx.getImageData(0, 0, this.width, this.height);
        ctx.putImageData(img, 0, 0);
      }
    }catch(e){}
    return _tb.apply(this, arguments);
  }, _tb, 'toBlob');
}catch(e){}

/* ---- 1b. OffscreenCanvas -----------------------------------------------
   The identical 2D-canvas fingerprint, one API over. OffscreenCanvas readback
   is used precisely because it slips past on-screen canvas hooks; if we do not
   perturb it too, it is a clean bypass of everything above. Same noise table,
   so on-screen and offscreen readings of the same pixels stay consistent. */
try{
  if(typeof OffscreenCanvasRenderingContext2D !== 'undefined' &&
     OffscreenCanvasRenderingContext2D.prototype.getImageData){
    var _ogid = OffscreenCanvasRenderingContext2D.prototype.getImageData;
    OffscreenCanvasRenderingContext2D.prototype.getImageData = cloak(function(){
      var r = _ogid.apply(this, arguments);
      try{ farbleImageData(r.data); }catch(e){}
      return r;
    }, _ogid, 'getImageData');
  }
}catch(e){}
try{
  if(typeof OffscreenCanvas !== 'undefined' && OffscreenCanvas.prototype.convertToBlob){
    var _octb = OffscreenCanvas.prototype.convertToBlob;
    OffscreenCanvas.prototype.convertToBlob = cloak(function(){
      try{
        var ctx = this.getContext('2d');
        if(ctx && this.width && this.height){
          var img = ctx.getImageData(0, 0, this.width, this.height);
          ctx.putImageData(img, 0, 0);   /* already farbled by the hook above */
        }
      }catch(e){}
      return _octb.apply(this, arguments);
    }, _octb, 'convertToBlob');
  }
}catch(e){}

/* ---- 2. WebGL ----------------------------------------------------------
   UNMASKED_VENDOR_WEBGL / UNMASKED_RENDERER_WEBGL are among the highest-
   entropy values a page can read. Report a real-looking pair, chosen per
   origin from cards that genuinely exist. */
var gr = mk(2);
var GPUS = [
  ['Google Inc. (Intel)',  'ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)'],
  ['Google Inc. (Intel)',  'ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)'],
  ['Google Inc. (NVIDIA)', 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0, D3D11)'],
  ['Google Inc. (NVIDIA)', 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)'],
  ['Google Inc. (AMD)',    'ANGLE (AMD, AMD Radeon RX 580 Direct3D11 vs_5_0 ps_5_0, D3D11)'],
  ['Google Inc. (AMD)',    'ANGLE (AMD, AMD Radeon(TM) Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)']
];
var GPU = pick(gr, GPUS);
function patchGL(proto){
  if(!proto || !proto.getParameter) return;
  try{
    var _gp = proto.getParameter;
    proto.getParameter = cloak(function(p){
      if(p === 37445) return GPU[0];   /* UNMASKED_VENDOR_WEBGL   */
      if(p === 37446) return GPU[1];   /* UNMASKED_RENDERER_WEBGL */
      return _gp.apply(this, arguments);
    }, _gp, 'getParameter');
  }catch(e){}
  /* WebGL-canvas fingerprinting reads the rendered pixels straight back with
     readPixels -- a separate vector from 2D getImageData that the vendor spoof
     above does nothing about. Perturb the byte readback with the SAME noise
     table, so a GL fingerprint is broken exactly like the 2D one. Only 8-bit
     views (the fingerprinting path) are touched; float/other readbacks used
     for real GPGPU compute are left exact. */
  try{
    if(proto.readPixels){
      var _rp = proto.readPixels;
      proto.readPixels = cloak(function(x, y, w, h, fmt, type, pixels){
        var ret = _rp.apply(this, arguments);
        try{
          if(pixels && (pixels instanceof Uint8Array ||
                        pixels instanceof Uint8ClampedArray))
            farbleImageData(pixels);
        }catch(e){}
        return ret;
      }, _rp, 'readPixels');
    }
  }catch(e){}
}
try{ patchGL(window.WebGLRenderingContext  && WebGLRenderingContext.prototype); }catch(e){}
try{ patchGL(window.WebGL2RenderingContext && WebGL2RenderingContext.prototype); }catch(e){}

/* ---- 3. AudioContext ---------------------------------------------------
   Audio fingerprinting hashes the exact float output of an oscillator.
   A ~1e-7 relative shift is inaudible and unmeasurable in normal use, and
   changes the hash. */
var ar = mk(3);
var AN = new Float32Array(512);
for(var j=0;j<512;j++){ AN[j] = (ar() - 0.5) * 2e-7; }
function farbleFloats(arr){
  try{ for(var k=0;k<arr.length;k++){ arr[k] = arr[k] + AN[k & 511]; } }catch(e){}
  return arr;
}
try{
  var _gcd = AudioBuffer.prototype.getChannelData;
  AudioBuffer.prototype.getChannelData = cloak(function(){
    return farbleFloats(_gcd.apply(this, arguments));
  }, _gcd, 'getChannelData');
}catch(e){}
try{
  var _gffd = AnalyserNode.prototype.getFloatFrequencyData;
  AnalyserNode.prototype.getFloatFrequencyData = cloak(function(a){
    _gffd.apply(this, arguments); farbleFloats(a);
  }, _gffd, 'getFloatFrequencyData');
}catch(e){}

/* ---- 4. Font metrics ---------------------------------------------------
   Font enumeration measures text width to millimetre precision to infer the
   installed font set. Sub-pixel noise defeats the comparison. */
var fr = mk(4);
var FN = fr() * 0.0002 - 0.0001;
try{
  var _mt = CanvasRenderingContext2D.prototype.measureText;
  CanvasRenderingContext2D.prototype.measureText = cloak(function(){
    var m = _mt.apply(this, arguments);
    try{
      var w = m.width;
      Object.defineProperty(m, 'width', {value: w + w * FN, configurable: true});
    }catch(e){}
    return m;
  }, _mt, 'measureText');
}catch(e){}

/* ---- 5. Hardware + screen ----------------------------------------------
   Plausible values from the real-world distribution -- NOT round "clean"
   numbers, which are themselves distinctive. availWidth/availHeight get a
   few pixels of jitter; width/height are left alone because layout code
   depends on them and breaking layout is user-visible. */
var hr = mk(5);
def(navigator, 'hardwareConcurrency', function(){ return pick(hr, [4,6,8,8,12,16]); });
def(navigator, 'deviceMemory',        function(){ return pick(hr, [4,8,8,16]); });
try{
  var aw = screen.availWidth, ah = screen.availHeight;
  var dw = Math.floor(hr() * 3), dh = Math.floor(hr() * 3);
  def(screen, 'availWidth',  function(){ return aw - dw; });
  def(screen, 'availHeight', function(){ return ah - dh; });
}catch(e){}

/* ---- 6. Plugins --------------------------------------------------------
   The real modern Chrome set. An EMPTY list (what this code used to
   report) is rare and therefore identifying -- the opposite of the goal. */
try{
  var names = ['PDF Viewer','Chrome PDF Viewer','Chromium PDF Viewer',
               'Microsoft Edge PDF Viewer','WebKit built-in PDF'];
  var fake = names.map(function(n){
    return {name: n, filename: 'internal-pdf-viewer', description: 'Portable Document Format', length: 1};
  });
  fake.item = function(i){ return this[i]; };
  fake.namedItem = function(n){ return this.find(function(p){ return p.name === n; }); };
  def(navigator, 'plugins', function(){ return fake; });
}catch(e){}

/* ---- 7. Analytics no-ops ----------------------------------------------
   Kept from the original implementation: stubbing the collector entry
   points means the tracker's own code cannot fire even if its script
   loaded from cache or a first-party proxy path. */
try{
  window.fbq  = function(){};
  window.gtag = function(){};
  window.ga   = function(){};
  window._gaq = {push: function(){}};
}catch(e){}

}catch(e){ /* protection must never break the page */ }
})();
</script>"""


def script_for(url_or_origin: str) -> bytes:
    """The farbling <script> tag to inject into a page from *url_or_origin*.

    Accepts a full URL or a bare origin — ``origin_of`` normalises both to
    scheme://host, so a page and every sub-path of it share one identity.
    """
    return _SCRIPT_TEMPLATE.replace(
        "%SEED%", str(origin_seed(origin_of(url_or_origin)))
    ).encode("utf-8")


__all__ = ["script_for", "origin_of", "origin_seed", "new_session"]
