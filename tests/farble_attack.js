// Execution-based regression guard for farble.py's injected script.
//
// Structural string-checks (test_farble.py) prove the hooks EXIST; this proves
// they WORK by actually running the farbling IIFE in a mock browser and then
// playing a fingerprinting / anti-tamper script (CreepJS-style) against it.
// Exits 0 only if every attack is defeated, so a future farble change that
// reintroduces a detectable hook or an uncovered readback surface fails CI.
//
// Usage: node farble_attack.js <path-to-injected-script-html>
// (test_farble.py generates the script via farble.script_for and invokes this.)
'use strict';
const fs = require('fs');
const vm = require('vm');

const scriptPath = process.argv[2];
if (!scriptPath) { console.error('usage: farble_attack.js <script.html>'); process.exit(2); }
const inner = fs.readFileSync(scriptPath, 'utf8')
  .replace(/^<script>/, '').replace(/<\/script>\s*$/, '');

// Contextify an EMPTY object so the sandbox gets its OWN complete, fresh
// intrinsics (Object, Function, WeakMap, Reflect...). Injecting the harness
// realm's intrinsics instead would corrupt cross-realm toString/coercion - a
// mistake that makes '' + fn appear to leak when it does not.
const sb = vm.createContext({});
vm.runInContext(`
  const RAW = i => (i * 7) & 255;
  function C2D(){}
  C2D.prototype = {
    getImageData(x,y,w,h){ const d=new Uint8ClampedArray((w*h*4)||64);
      for(let i=0;i<d.length;i++) d[i]=RAW(i); return {data:d,width:w,height:h}; },
    putImageData(){}, measureText(){ return {width:123.456}; },
  };
  this.CanvasRenderingContext2D = C2D;
  this.OffscreenCanvasRenderingContext2D = function(){};
  OffscreenCanvasRenderingContext2D.prototype = C2D.prototype;
  this.HTMLCanvasElement = function(){};
  HTMLCanvasElement.prototype = { width:4, height:4,
    getContext(){ return Object.create(C2D.prototype); },
    toDataURL(){ return 'x'; }, toBlob(cb){ cb && cb(); } };
  this.OffscreenCanvas = function(){};
  OffscreenCanvas.prototype = { width:4, height:4,
    getContext(){ return Object.create(C2D.prototype); },
    convertToBlob(){ return Promise.resolve({}); } };
  function GL(){}
  GL.prototype = { getParameter(p){ if(p===37445) return 'RealVendor Intel';
      if(p===37446) return 'RealRenderer Intel HD'; return 4096; },
    readPixels(x,y,w,h,f,t,px){ if(px) for(let i=0;i<px.length;i++) px[i]=RAW(i); } };
  this.WebGLRenderingContext = GL; this.WebGL2RenderingContext = GL;
  this.AudioBuffer = function(){};
  AudioBuffer.prototype = { getChannelData(){ const a=new Float32Array(8);
      for(let i=0;i<8;i++)a[i]=i*0.1; return a; } };
  this.AnalyserNode = function(){};
  AnalyserNode.prototype = {
    getFloatFrequencyData(a){ for(let i=0;i<a.length;i++)a[i]=-50-i; },
    getFloatTimeDomainData(a){ for(let i=0;i<a.length;i++)a[i]=0.5; },
    getByteFrequencyData(a){ for(let i=0;i<a.length;i++)a[i]=100; },
    getByteTimeDomainData(a){ for(let i=0;i<a.length;i++)a[i]=128; },
  };
  this.navigator = { hardwareConcurrency:20, deviceMemory:2, plugins:[] };
  this.screen = { availWidth:1920, availHeight:1040, width:1920, height:1080 };
  this.window = this;
`, sb);

vm.runInContext(inner, sb, { filename: 'farble_inject.js' });

// All attacks run INSIDE the sandbox realm (no cross-realm coercion artifacts).
const report = vm.runInContext(`(function(){
  const RAW = i => (i * 7) & 255;
  const FPT = Function.prototype.toString;
  const R = [];
  const A = (name, pass) => R.push({name, pass:!!pass});

  const gid = CanvasRenderingContext2D.prototype.getImageData;
  // 1-2: hooks must be undetectable across EVERY stringify path.
  A('getImageData hidden: fn.toString()', /native code/.test(gid.toString()) && !/farble|apply|_gid/.test(gid.toString()));
  A('getImageData hidden: FPT.call',      /native code/.test(FPT.call(gid)));
  A('getImageData hidden: "" + fn',       /native code/.test('' + gid));
  A('getImageData hidden: String(fn)',    /native code/.test(String(gid)));
  const gp = WebGLRenderingContext.prototype.getParameter;
  A('getParameter hidden: FPT.call',      /native code/.test(FPT.call(gp)) && !/GPU|_gp/.test(FPT.call(gp)));
  A('toString patch hides ITSELF',        /native code/.test(FPT.call(FPT)));

  // 3-4: canvas perturbed AND stable per read.
  const c = new CanvasRenderingContext2D();
  const r1 = c.getImageData(0,0,4,4).data, r2 = c.getImageData(0,0,4,4).data;
  let pert=false, stable=true;
  for(let i=0;i<r1.length;i++){ if(r1[i]!==RAW(i)) pert=true; if(r1[i]!==r2[i]) stable=false; }
  A('canvas 2D perturbed', pert); A('canvas 2D stable across reads', stable);

  // 5: WebGL vendor spoofed (real value gone).
  A('WebGL vendor spoofed', gp.call(new WebGLRenderingContext(),37445) !== 'RealVendor Intel');
  // 6: WebGL readPixels perturbed.
  const gl = new WebGLRenderingContext(); const px = new Uint8Array(64); gl.readPixels(0,0,4,4,0,0,px);
  let glP=false; for(let i=0;i<64;i++){ if(px[i]!==RAW(i)) glP=true; }
  A('WebGL readPixels perturbed', glP);
  // 7: OffscreenCanvas perturbed.
  const oc = new OffscreenCanvasRenderingContext2D(); const od = oc.getImageData(0,0,4,4).data;
  let offP=false; for(let i=0;i<od.length;i++){ if(od[i]!==RAW(i)) offP=true; }
  A('OffscreenCanvas perturbed', offP);
  // 8: audio byte + time-domain readbacks perturbed (not just float-freq).
  const an = new AnalyserNode();
  const bf = new Uint8Array(32); an.getByteFrequencyData(bf);
  const bt = new Uint8Array(32); an.getByteTimeDomainData(bt);
  const ft = new Float32Array(8); an.getFloatTimeDomainData(ft);
  let bfP=false,btP=false,ftP=false;
  for(let i=0;i<32;i++){ if(bf[i]!==100)bfP=true; if(bt[i]!==128)btP=true; }
  for(let i=0;i<8;i++){ if(ft[i]!==0.5)ftP=true; }
  A('audio byteFrequency perturbed', bfP); A('audio byteTimeDomain perturbed', btP);
  A('audio floatTimeDomain perturbed', ftP);

  // OVERREACH GUARDS: must NOT make normal code look fake.
  const foo = function foo(){ return 42; };
  A('no overreach: user fn shows real source', /return 42/.test(FPT.call(foo)) && !/native code/.test(FPT.call(foo)));
  A('no overreach: genuine native still native', /native code/.test(FPT.call(Object.keys)));
  A('patched fn.name preserved', gid.name === 'getImageData');

  return JSON.stringify(R);
})()`, sb);

const results = JSON.parse(report);
let pass = 0;
for (const r of results) { console.log(`  [${r.pass ? 'DEFEATED' : 'LEAK'}] ${r.name}`); if (r.pass) pass++; }
console.log(`\nFARBLE ATTACK: ${pass}/${results.length} defeated`);
process.exit(pass === results.length ? 0 : 1);
