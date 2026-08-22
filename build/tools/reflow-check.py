"""Headless 320px reflow check (WCAG 2.1 SC 1.4.10, ADR 0003).

    python build/tools/reflow-check.py http://localhost:5099/dev/primitives

Exits non-zero and names the offending elements when the body scrolls
horizontally. ADR 0003 makes this an acceptance gate on every screen ticket in
TFND-40: axe-core CANNOT detect 1.4.10 — reflow needs a real viewport and a
judgement about loss of information — so the dogfood scan is silent on it and
this check is what actually enforces the decision.

Requires Chrome and `pip install websocket-client`.

Drives Chrome over CDP: set a 320px viewport, load the page, and compare
document.scrollWidth against the viewport width. Any excess means the body
scrolls in two dimensions, which is the thing ADR 0003 forbids.
"""
import json, subprocess, time, urllib.request, sys, os, socket
from urllib.request import urlopen

CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5099/dev/primitives"
PORT = 9333
# Scratch profile in the OS temp dir, NOT next to this script — Chrome
# writes a full profile tree here and it must never land in the repo.
import tempfile
PROFILE = os.path.join(tempfile.gettempdir(), "tamp-findings-reflow-profile")

proc = subprocess.Popen([
    CHROME, "--headless=new", f"--remote-debugging-port={PORT}",
    f"--user-data-dir={PROFILE}", "--no-first-run", "--no-default-browser-check",
    "--window-size=320,900", "--remote-allow-origins=*", "about:blank",
], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def wait_cdp():
    for _ in range(60):
        try:
            return json.loads(urlopen(f"http://127.0.0.1:{PORT}/json/version", timeout=2).read())
        except Exception:
            time.sleep(0.5)
    raise SystemExit("chrome did not expose CDP")

try:
    wait_cdp()
    import websocket  # type: ignore
except ImportError:
    proc.terminate(); raise SystemExit("NEEDS: pip install websocket-client")

tabs = json.loads(urlopen(f"http://127.0.0.1:{PORT}/json/list", timeout=5).read())
page = next(t for t in tabs if t["type"] == "page")
ws = websocket.create_connection(page["webSocketDebuggerUrl"], timeout=30)
_id = [0]

def cmd(method, **params):
    _id[0] += 1
    ws.send(json.dumps({"id": _id[0], "method": method, "params": params}))
    while True:
        msg = json.loads(ws.recv())
        if msg.get("id") == _id[0]:
            return msg.get("result", {})

cmd("Page.enable")
cmd("Emulation.setDeviceMetricsOverride", width=320, height=900,
    deviceScaleFactor=1, mobile=False)
cmd("Page.navigate", url=URL)
time.sleep(4)

res = cmd("Runtime.evaluate", returnByValue=True, expression=r"""
(() => {
  const d = document.documentElement;
  const over = [...document.querySelectorAll('*')]
    .filter(e => e.getBoundingClientRect().right > d.clientWidth + 1)
    .slice(0, 8)
    .map(e => e.tagName.toLowerCase() + (e.className ? '.' + String(e.className).trim().split(/\s+/).join('.') : ''));
  const sx = document.querySelector('.scroll-x');
  const chain = [];
  if (sx) {
    let e = sx;
    while (e && e !== document.documentElement) {
      const cs = getComputedStyle(e);
      chain.push({
        el: e.tagName.toLowerCase() + (e.className ? '.' + String(e.className).trim().split(/\s+/).join('.') : ''),
        clientW: e.clientWidth, scrollW: e.scrollWidth,
        overflowX: cs.overflowX, display: cs.display, minWidth: cs.minWidth,
      });
      e = e.parentElement;
    }
  }
  return { scrollWidth: d.scrollWidth, clientWidth: d.clientWidth, overflowing: over, chain };
})()
""")
v = res.get("result", {}).get("value", {})
ws.close(); proc.terminate()

sw, cw = v.get("scrollWidth"), v.get("clientWidth")
print(f"viewport {cw}px  documentScrollWidth {sw}px")
if sw is None:
    raise SystemExit("no result")
if sw > cw:
    print(f"FAIL: body scrolls horizontally by {sw - cw}px")
    for o in v.get("overflowing", []):
        print("   overflowing:", o)
    print("   --- ancestor chain from .scroll-x ---")
    for c in v.get("chain", []):
        print(f"   {c['el'][:60]:<60} client={c['clientW']:<5} scroll={c['scrollW']:<5} ox={c['overflowX']:<8} disp={c['display']}")
    raise SystemExit(1)
print("PASS: no horizontal body scroll at 320px")
