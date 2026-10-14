(function () {
  var MAP = window.__BW_MAP || {}, GH = window.__BW_GITHUB || '';
  var STATIC = {}; Object.keys(MAP).forEach(function (k) { STATIC[MAP[k]] = 1; });
  function key(u) {
    var url; try { url = new URL(u, location.href); } catch (e) { return null; }
    if (url.origin !== location.origin) return null;
    var p = []; url.searchParams.forEach(function (v, k) { if (v !== '') p.push([k, v]); });
    p.sort(function (a, b) { return a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0; });
    var q = p.map(function (x) { return encodeURIComponent(x[0]).replace(/%20/g, '+') + '=' + encodeURIComponent(x[1]).replace(/%20/g, '+'); }).join('&');
    return (url.pathname.replace(/\/+$/, '') || '/') + (q ? '?' + q : '');
  }
  function target(u) { var k = key(u); if (k === null) return null; if (MAP[k]) return MAP[k]; var path = new URL(u, location.href).pathname; return STATIC[path] ? path : ''; }
  var toastEl = null, toastT = null;
  function notice(what) {
    if (!document.body) return;
    if (!toastEl) {
      toastEl = document.createElement('div');
      toastEl.style.cssText = 'position:fixed;left:50%;bottom:64px;transform:translateX(-50%);z-index:99999;max-width:min(560px,92vw);padding:12px 18px;border-radius:10px;background:#0b1622;border:1px solid #35C7F2;color:#e6f6ff;font:14px/1.45 system-ui,sans-serif;box-shadow:0 10px 30px rgba(0,0,0,.5);text-align:center';
      document.body.appendChild(toastEl);
    }
    toastEl.innerHTML = '<b>Static demo</b> — ' + (what || 'this action changes data, so it is switched off here.') +
      (GH ? ' <a href="' + GH + '" target="_blank" rel="noopener" style="color:#35C7F2">Run the full app from GitHub ↗</a>' : '');
    toastEl.style.display = 'block'; clearTimeout(toastT); toastT = setTimeout(function () { toastEl.style.display = 'none'; }, 4200);
  }
  window.__bwStaticNotice = notice;
  var ofetch = window.fetch ? window.fetch.bind(window) : null;
  window.fetch = function (input, init) {
    var url = typeof input === 'string' ? input : (input && input.url) || String(input);
    var method = ((init && init.method) || (input && input.method) || 'GET').toUpperCase();
    var t = target(url);
    if (t === null) return ofetch(input, init);
    if (method === 'GET' && t) return ofetch(t);
    var path = new URL(url, location.href).pathname;
    if (method === 'GET' && /\/events$/.test(path)) return Promise.resolve(new Response(JSON.stringify({events: [], state: 'done'}), {status: 200, headers: {'Content-Type': 'application/json'}}));
    if (method !== 'GET') notice();
    return Promise.resolve(new Response(JSON.stringify({detail: 'static demo: not available here'}), {status: method === 'GET' ? 404 : 403, headers: {'Content-Type': 'application/json'}}));
  };
  window.EventSource = function () { var self = this; this.readyState = 2; this.close = function () {}; this.addEventListener = function (t, f) { if (t === 'error') setTimeout(function () { f({}); }, 0); };
    setTimeout(function () { if (self.onerror) self.onerror({}); }, 0); };
  function go(url, hash, blank) { var t = target(url); if (!t) { notice('this page is not part of the static demo.'); return; } if (blank) window.open(t + (hash || ''), '_blank'); else location.href = t + (hash || ''); }
  document.addEventListener('click', function (e) {
    var a = e.target.closest && e.target.closest('a[href]');
    if (!a || e.defaultPrevented) return;
    var href = a.getAttribute('href') || '';
    if (!href || href.charAt(0) === '#' || /^(mailto:|tel:|javascript:)/.test(href)) return;
    var url = new URL(href, location.href);
    if (url.origin !== location.origin) return;
    var t = target(url.href);
    if (t && t === url.pathname && !url.search) return;  // already a saved page
    e.preventDefault(); e.stopImmediatePropagation();
    if (t) go(url.href, url.hash, a.target === '_blank'); else notice('this page is not part of the static demo.');
  }, true);
  function submitted(form, btn) {
    var method = (form.getAttribute('method') || 'get').toLowerCase();
    if (method !== 'get') { notice(); return; }
    var url = new URL(form.getAttribute('action') || location.pathname, location.href);
    var fd = new FormData(form); if (btn && btn.name) fd.append(btn.name, btn.value);
    url.search = ''; fd.forEach(function (v, k) { if (typeof v === 'string') url.searchParams.append(k, v); });
    go(url.href, '', false);
  }
  document.addEventListener('submit', function (e) { e.preventDefault(); e.stopImmediatePropagation(); submitted(e.target, e.submitter); }, true);
  HTMLFormElement.prototype.submit = function () { submitted(this, null); };
  HTMLFormElement.prototype.requestSubmit = function (btn) { submitted(this, btn || null); };
  document.addEventListener('DOMContentLoaded', function () {
    var pill = document.createElement('a');
    pill.href = GH || '#'; pill.target = '_blank'; pill.rel = 'noopener';
    pill.innerHTML = '<b style="color:#35C7F2">STATIC DEMO</b> · fictional brands · read-only' + (GH ? ' · GitHub ↗' : '');
    pill.style.cssText = 'position:fixed;left:14px;bottom:14px;z-index:99998;padding:7px 13px;border-radius:999px;background:rgba(8,16,26,.92);border:1px solid rgba(53,199,242,.55);color:#cfe9f5;font:12px/1.2 system-ui,sans-serif;text-decoration:none;letter-spacing:.02em;box-shadow:0 6px 18px rgba(0,0,0,.4)';
    document.body.appendChild(pill);
  });
})();
