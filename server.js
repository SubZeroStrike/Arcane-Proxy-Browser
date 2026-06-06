const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const http = require('http');
const https = require('https');
const zlib = require('zlib');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_KEYS = new Map();

app.use(cors({ origin: true, credentials: true }));
app.use(express.static('public'));

// ── Session middleware ────────────────────────────────────────────────────────
app.use((req, res, next) => {
    let sessionId = req.headers['x-session-id'] || req.query.sid;
    if (!sessionId || !SESSION_KEYS.has(sessionId)) {
        sessionId = crypto.randomUUID();
        SESSION_KEYS.set(sessionId, crypto.randomBytes(32));
    }
    req.sessionId = sessionId;
    res.setHeader('X-Session-Id', sessionId);
    next();
});

// ── Crypto ────────────────────────────────────────────────────────────────────
function xorCrypt(buf, key) {
    const out = Buffer.alloc(buf.length);
    for (let i = 0; i < buf.length; i++) out[i] = buf[i] ^ key[i % 32];
    return out;
}
function encryptUrl(url, sessionId) {
    const key = SESSION_KEYS.get(sessionId);
    if (!key) return null;
    return encodeURIComponent(xorCrypt(Buffer.from(url), key).toString('base64'));
}
function decryptUrl(encrypted, sessionId) {
    const key = SESSION_KEYS.get(sessionId);
    if (!key) return null;
    try { return xorCrypt(Buffer.from(decodeURIComponent(encrypted), 'base64'), key).toString('utf8'); }
    catch { return null; }
}

function randomUA() {
    return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
}

// ── Raw HTTP fetch (bypasses Node fetch's auto-decompression) ─────────────────
function rawFetch(url, extraHeaders = {}) {
    return new Promise((resolve, reject) => {
        const parsed = new URL(url);
        const mod = parsed.protocol === 'https:' ? https : http;
        const options = {
            hostname: parsed.hostname,
            port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
            path: parsed.pathname + parsed.search,
            method: 'GET',
            headers: {
                'User-Agent': randomUA(),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Encoding': 'gzip, deflate, br',
                'Accept-Language': 'en-US,en;q=0.9',
                'Cache-Control': 'no-cache',
                ...extraHeaders,
            },
            timeout: 15000,
        };

        const req = mod.request(options, (res) => {
            // Follow redirects (up to 10)
            if ([301,302,303,307,308].includes(res.statusCode) && res.headers.location) {
                const next = new URL(res.headers.location, url).href;
                return rawFetch(next, extraHeaders).then(resolve).catch(reject);
            }

            // Decompress based on content-encoding
            const enc = (res.headers['content-encoding'] || '').toLowerCase();
            let stream = res;
            if (enc === 'gzip') stream = res.pipe(zlib.createGunzip());
            else if (enc === 'deflate') stream = res.pipe(zlib.createInflate());
            else if (enc === 'br') stream = res.pipe(zlib.createBrotliDecompress());

            const chunks = [];
            stream.on('data', c => chunks.push(c));
            stream.on('end', () => resolve({
                status: res.statusCode,
                headers: res.headers,
                finalUrl: url,
                body: Buffer.concat(chunks),
            }));
            stream.on('error', reject);
        });

        req.on('timeout', () => { req.destroy(); reject(new Error('Request timed out')); });
        req.on('error', reject);
        req.end();
    });
}

// ── URL rewriter ──────────────────────────────────────────────────────────────
function resolveUrl(val, base) {
    if (!val || val.startsWith('data:') || val.startsWith('#') ||
        val.startsWith('javascript:') || val.startsWith('blob:') || val.startsWith('mailto:')) return null;
    try {
        if (val.startsWith('//')) return 'https:' + val;
        if (val.startsWith('/')) return base.origin + val;
        if (val.startsWith('http')) return val;
        return new URL(val, base.href).href;
    } catch { return null; }
}

function rewriteUrls(html, baseUrl, sessionId) {
    const base = new URL(baseUrl);
    const sid = sessionId;

    const assetUrl = (url) => {
        const full = resolveUrl(url, base);
        if (!full) return null;
        return `/api/proxy/asset?sid=${sid}&url=${encryptUrl(full, sid)}`;
    };
    const pageUrl = (url) => {
        const full = resolveUrl(url, base);
        if (!full) return null;
        return `/api/proxy/page?sid=${sid}&url=${encryptUrl(full, sid)}`;
    };

    const shimScript = `<script>
(function(){
  var _sid=${JSON.stringify(sid)},_orig=${JSON.stringify(base.origin)};
  function _p(u,isPage){
    try{
      if(!u||u.startsWith('blob:')||u.startsWith('data:')||u.startsWith('javascript:'))return u;
      var f=u.startsWith('//')?'https:'+u:u.startsWith('/')?_orig+u:u;
      if(!f.startsWith('http'))return u;
      var route=isPage?'/api/proxy/page':'/api/proxy/asset';
      return route+'?sid='+_sid+'&raw='+encodeURIComponent(f);
    }catch(e){return u;}
  }
  var _f=window.fetch;
  window.fetch=function(i,o){
    if(typeof i==='string')i=_p(i);
    else if(i&&i.url)i=new Request(_p(i.url),i);
    return _f.call(this,i,o);
  };
  var _x=XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open=function(m,u){
    arguments[1]=_p(u,false);return _x.apply(this,arguments);
  };
  new MutationObserver(function(ms){
    ms.forEach(function(m){m.addedNodes.forEach(function(n){
      if(!n.tagName)return;
      ['src','href'].forEach(function(a){
        if(n[a]&&(n[a].startsWith('http')||n[a].startsWith('//'))){
          n[a]=_p(n[a]);
        }
      });
    });});
  }).observe(document.documentElement,{childList:true,subtree:true});
})();
</script>`;

    let result = html;

    // Inject shim right after <head> (or prepend if no head)
    if (/<head/i.test(result)) {
        result = result.replace(/<head([^>]*)>/i, (m) => m + '\n' + shimScript);
    } else {
        result = shimScript + result;
    }

    // Rewrite attributes
    result = result.replace(/(href|src|action|data-src|data-lazy|poster|data-original)=(['"])(.*?)\2/gi, (m, attr, q, val) => {
        val = val.trim();
        if (!val) return m;
        const isPage = /^(href|action)$/i.test(attr);
        const rw = isPage ? pageUrl(val) : assetUrl(val);
        return rw ? `${attr}=${q}${rw}${q}` : m;
    });

    // srcset
    result = result.replace(/srcset=(['"])(.*?)\1/gi, (m, q, val) => {
        const parts = val.split(',').map(part => {
            const trimmed = part.trim();
            const spaceIdx = trimmed.search(/\s+/);
            const url = spaceIdx === -1 ? trimmed : trimmed.slice(0, spaceIdx);
            const desc = spaceIdx === -1 ? '' : trimmed.slice(spaceIdx);
            const rw = assetUrl(url);
            return rw ? rw + desc : part;
        });
        return `srcset=${q}${parts.join(',')}${q}`;
    });

    // CSS url()
    result = result.replace(/url\(\s*(['"]?)([^'"\)]+)\1\s*\)/gi, (m, q, val) => {
        const rw = assetUrl(val.trim());
        return rw ? `url("${rw}")` : m;
    });

    return result;
}

// ── Headers to strip from upstream responses ──────────────────────────────────
const STRIP_HEADERS = new Set([
    'x-frame-options', 'content-security-policy', 'content-security-policy-report-only',
    'x-content-security-policy', 'x-webkit-csp', 'strict-transport-security',
    'x-xss-protection', 'transfer-encoding', 'content-encoding', 'content-length',
]);

// ── ASSET proxy (images, JS, CSS, fonts) ──────────────────────────────────────
app.get('/api/proxy/asset', async (req, res) => {
    const url = req.query.raw ? req.query.raw : decryptUrl(req.query.url, req.sessionId);
    if (!url) return res.status(400).send('Bad URL');

    try {
        const upstream = await rawFetch(url, { Referer: (() => { try { return new URL(url).origin; } catch { return ''; } })() });

        for (const [k, v] of Object.entries(upstream.headers)) {
            if (!STRIP_HEADERS.has(k.toLowerCase())) res.setHeader(k, v);
        }

        const ct = (upstream.headers['content-type'] || '');

        if (ct.includes('text/html')) {
            res.setHeader('Content-Type', 'text/html; charset=utf-8');
            return res.send(rewriteUrls(upstream.body.toString('utf8'), url, req.sessionId));
        }
        if (ct.includes('text/css')) {
            let css = upstream.body.toString('utf8');
            css = css.replace(/url\(\s*(['"]?)([^'"\)]+)\1\s*\)/gi, (m, q, val) => {
                try {
                    const full = resolveUrl(val.trim(), new URL(url));
                    if (!full) return m;
                    return `url("/api/proxy/asset?sid=${req.sessionId}&raw=${encodeURIComponent(full)}")`;
                } catch { return m; }
            });
            res.setHeader('Content-Type', 'text/css');
            return res.send(css);
        }

        // Everything else: binary passthrough
        res.send(upstream.body);
    } catch (err) {
        console.error('[asset]', url, err.message);
        res.status(502).send('Asset fetch failed: ' + err.message);
    }
});

// ── PAGE proxy (HTML navigations) ─────────────────────────────────────────────
async function handlePage(req, res) {
    let url = req.query.raw ? req.query.raw : decryptUrl(req.query.url, req.sessionId);
    if (!url) return res.status(400).send('Bad URL');
    try { new URL(url); } catch { return res.status(400).send('Invalid URL'); }

    // Merge any extra query params (from GET form submissions) into the target URL
    const reserved = new Set(['sid','url','raw']);
    const extra = Object.entries(req.query).filter(([k]) => !reserved.has(k));
    if (extra.length) {
        const u = new URL(url);
        extra.forEach(([k,v]) => u.searchParams.set(k, v));
        url = u.href;
    }

    try {
        const upstream = await rawFetch(url);

        for (const [k, v] of Object.entries(upstream.headers)) {
            if (!STRIP_HEADERS.has(k.toLowerCase())) res.setHeader(k, v);
        }

        const ct = upstream.headers['content-type'] || 'text/html';
        if (ct.includes('text/html')) {
            res.setHeader('Content-Type', 'text/html; charset=utf-8');
            return res.send(rewriteUrls(upstream.body.toString('utf8'), upstream.finalUrl || url, req.sessionId));
        }
        res.send(upstream.body);
    } catch (err) {
        console.error('[page]', url, err.message);
        res.status(502).send('Page fetch failed: ' + err.message);
    }
}
app.get('/api/proxy/page', handlePage);
app.post('/api/proxy/page', express.urlencoded({ extended: true }), handlePage);

// ── Legacy routes ─────────────────────────────────────────────────────────────
app.get('/api/proxy/primary',   (req, res) => res.redirect(307, `/api/proxy/page?sid=${req.sessionId}&url=${req.query.url}`));
app.get('/api/proxy/secondary', (req, res) => res.redirect(307, `/api/proxy/page?sid=${req.sessionId}&url=${req.query.url}`));

// ── Health ────────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
    let sid = req.headers['x-session-id'] || req.query.sid || crypto.randomUUID();
    if (!SESSION_KEYS.has(sid)) SESSION_KEYS.set(sid, crypto.randomBytes(32));
    res.setHeader('X-Session-Id', sid);
    res.json({ status: 'ok', sessionKey: SESSION_KEYS.get(sid).toString('base64') });
});

app.listen(PORT, () => console.log(`Proxy running on http://localhost:${PORT}`));