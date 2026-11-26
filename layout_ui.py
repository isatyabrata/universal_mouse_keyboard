"""Drag-and-drop screen layout editor, served by the server on http://localhost:<port+1>.

Stdlib only. Listens on 127.0.0.1 and rejects foreign Host headers / cross-site POSTs, so
only a browser on the server machine itself can rearrange screens.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import kvm

PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Screen layout</title>
<style>
:root{--bg:#f6f7f9;--fg:#1d2330;--mut:#667085;--card:#fff;--line:#d0d5dd;--acc:#2563eb;--ok:#16a34a;--cell:#eceff4}
@media (prefers-color-scheme:dark){:root{--bg:#10131a;--fg:#e6e9f0;--mut:#98a2b3;--card:#1b2130;--line:#394152;--acc:#6ea0ff;--ok:#4ade80;--cell:#171c27}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.45 system-ui,sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px}
h1{font-size:20px;margin:0 0 4px}p{color:var(--mut);margin:0 0 16px}
#wrap{overflow:auto;border:1px solid var(--line);border-radius:12px;background:var(--cell);padding:8px}
#board{position:relative;margin:0 auto}
.cell{position:absolute;border:1px dashed var(--line);border-radius:10px}
.screen{position:absolute;border:2px solid var(--acc);border-radius:10px;background:var(--card);padding:10px 12px;
 cursor:grab;user-select:none;touch-action:none;display:flex;flex-direction:column;justify-content:space-between;
 box-shadow:0 1px 3px rgba(0,0,0,.12)}
.screen.drag{cursor:grabbing;opacity:.9;z-index:5;box-shadow:0 8px 24px rgba(0,0,0,.3)}
.screen.off{border-style:dashed;border-color:var(--line);color:var(--mut)}
.screen.me{border-color:var(--ok)}
.name{font-weight:600;font-size:16px}.sub{font-size:12px;color:var(--mut)}
.row{display:flex;justify-content:space-between;align-items:center;font-size:12px;color:var(--mut)}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--line);margin-right:6px}
.on .dot,.me .dot{background:var(--ok)}
kbd{border:1px solid var(--line);border-radius:4px;padding:0 5px;font-size:11px}
#msg{min-height:22px;margin-top:12px;font-size:13px;color:var(--mut)}#msg.err{color:#dc2626}
</style></head><body><main>
<h1>Screen layout</h1>
<p>Drag the screens to match how your desks are arranged. Moving the mouse off an edge crosses to the
screen next to it. Drop a screen on any dashed cell; changes apply instantly.</p>
<div id="wrap"><div id="board"></div></div>
<div id="msg"></div>
<p style="margin-top:12px">Hotkeys: <kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>Shift</kbd>+<kbd>1&ndash;9</kbd> jumps to that
computer, <kbd>0</kbd> returns to the server.</p>
</main>
<script>
const CW=200, CH=124, G=8;
const board=document.getElementById('board'), msg=document.getElementById('msg');
let state=null, view=null, drag=null;

async function api(path, body){
  const r=await fetch(path, body?{method:'POST',headers:{'Content-Type':'application/json','X-KVM':'1'},body:JSON.stringify(body)}:undefined);
  if(!r.ok) throw new Error((await r.text())||r.status);
  return r.json();
}
function say(t,err){msg.textContent=t||'';msg.className=err?'err':''}
async function load(){ try{ state=await api('/api/state'); render(); }catch(e){ say('Lost connection to the server: '+e.message,true);} }

function render(){
  if(drag) return;
  const xs=state.nodes.map(n=>n.x), ys=state.nodes.map(n=>n.y);
  view={x0:Math.min(...xs)-1,x1:Math.max(...xs)+1,y0:Math.min(...ys)-1,y1:Math.max(...ys)+1};
  board.style.width=(view.x1-view.x0+1)*CW+'px'; board.style.height=(view.y1-view.y0+1)*CH+'px';
  board.innerHTML='';
  for(let x=view.x0;x<=view.x1;x++)for(let y=view.y0;y<=view.y1;y++){
    const c=document.createElement('div'); c.className='cell';
    place(c,x,y); board.appendChild(c);
  }
  for(const n of state.nodes){
    const el=document.createElement('div');
    el.className='screen'+(n.server?' me':n.connected?' on':' off');
    place(el,n.x,n.y);
    const size=n.w?n.w+' × '+n.h:'size unknown';
    el.innerHTML='<div><div class="name"></div><div class="sub"></div></div>'+
      '<div class="row"><span><span class="dot"></span>'+(n.server?'this computer':n.connected?'connected':'not connected')+'</span>'+
      (n.hotkey?'<kbd>'+n.hotkey+'</kbd>':'')+'</div>';
    el.querySelector('.name').textContent=n.name==='server'?'Server':n.name;
    el.querySelector('.sub').textContent=size;
    el.addEventListener('pointerdown',e=>start(e,el,n));
    board.appendChild(el);
  }
}
function place(el,x,y){
  el.style.left=((x-view.x0)*CW+G/2)+'px'; el.style.top=((y-view.y0)*CH+G/2)+'px';
  el.style.width=(CW-G)+'px'; el.style.height=(CH-G)+'px';
}
function start(e,el,n){
  drag={el,n,sx:e.clientX,sy:e.clientY,l:parseFloat(el.style.left),t:parseFloat(el.style.top)};
  el.setPointerCapture(e.pointerId); el.classList.add('drag');
  el.onpointermove=ev=>{el.style.left=drag.l+ev.clientX-drag.sx+'px'; el.style.top=drag.t+ev.clientY-drag.sy+'px';};
  el.onpointerup=ev=>finish(ev);
  el.onpointercancel=()=>{drag=null;render();};
}
async function finish(ev){
  const d=drag, el=d.el;
  const x=Math.min(view.x1,Math.max(view.x0,Math.round((parseFloat(el.style.left)-G/2)/CW)+view.x0));
  const y=Math.min(view.y1,Math.max(view.y0,Math.round((parseFloat(el.style.top)-G/2)/CH)+view.y0));
  drag=null;
  const taken=state.nodes.some(o=>o!==d.n&&o.x===x&&o.y===y);
  if(taken){ say('That spot is taken - drop the screen on an empty cell.',true); render(); return; }
  if(x!==d.n.x||y!==d.n.y){
    const pos={}; for(const o of state.nodes) pos[o.name]=[o.x,o.y]; pos[d.n.name]=[x,y];
    try{ state=await api('/api/layout',{positions:pos}); say('Layout saved.'); }catch(e){ say(e.message,true); }
  }
  render();
}
load(); setInterval(()=>{ if(!drag) load(); },2000);
</script></body></html>
"""


def make_handler(srv):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _local_host(self):
            return self.headers.get('Host', '').rsplit(':', 1)[0] in ('127.0.0.1', 'localhost', '[::1]')

        def _send(self, code, body, ctype='application/json'):
            data = body if isinstance(body, bytes) else body.encode()
            self.send_response(code)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(data)

        def _state(self):
            lay, peers = srv.layout, srv.ctl.peers
            nodes = []
            for name, (x, y) in list(lay.pos.items()):
                me = name == kvm.SERVER
                w, h = srv.be.size() if me else ((peers[name].w, peers[name].h) if name in peers else (0, 0))
                nodes.append({'name': name, 'x': x, 'y': y, 'w': w, 'h': h, 'server': me,
                              'connected': me or name in peers,
                              'hotkey': 0 if me else lay.order.index(name) + 1})
            return json.dumps({'nodes': nodes})

        def do_GET(self):
            if not self._local_host():
                return self._send(403, 'forbidden', 'text/plain')
            if self.path == '/':
                return self._send(200, PAGE, 'text/html; charset=utf-8')
            if self.path == '/api/state':
                return self._send(200, self._state())
            self._send(404, 'not found', 'text/plain')

        def do_POST(self):
            if not self._local_host() or self.headers.get('X-KVM') != '1':
                return self._send(403, 'forbidden', 'text/plain')
            if self.path != '/api/layout':
                return self._send(404, 'not found', 'text/plain')
            try:
                n = int(self.headers.get('Content-Length', 0))
                if not 0 < n <= 65536:
                    raise ValueError('bad request size')
                srv.update_positions(json.loads(self.rfile.read(n))['positions'])
            except (ValueError, KeyError, TypeError) as e:
                return self._send(400, str(e), 'text/plain')
            self._send(200, self._state())

    return Handler


def start(srv, port):
    """Serve the editor in a background thread. Returns its URL, or None if the port is busy."""
    try:
        httpd = ThreadingHTTPServer(('127.0.0.1', port), make_handler(srv))
    except OSError as e:
        kvm.log('layout editor unavailable (port %d: %s)' % (port, e))
        return None
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return 'http://localhost:%d' % port
