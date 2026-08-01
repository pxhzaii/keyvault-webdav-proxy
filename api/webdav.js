/**
 * Vercel Serverless Function — WebDAV 代理
 * 
 * 用途：绕过 Cloudflare-to-Cloudflare 520 问题
 * 安全限制：来源校验 + 目标白名单 + 速率限制
 */

// ===== 允许的来源站点 =====
const ALLOWED_ORIGINS = [
  'https://z.5as.cn',
  'http://localhost:8788',
];

// ===== 允许代理的 WebDAV 目标域名 =====
const ALLOWED_DOMAINS = [
  'dav.jianguoyun.com',
  'webdav.pcloud.com',
  'webdav.hidrive.strato.com',
  'dav.infini-cloud.net',
];

// 速率限制
const RATE_LIMIT = { max: 60, window: 60 };
const rateLimitMap = new Map();

function isAllowed(urlStr) {
  try {
    const u = new URL(urlStr);
    if (u.protocol !== 'https:') return false;
    const h = u.hostname.toLowerCase();
    return ALLOWED_DOMAINS.some(d => h === d || h.endsWith('.' + d));
  } catch { return false; }
}

function checkRateLimit(ip) {
  const now = Math.floor(Date.now() / 1000);
  const entry = rateLimitMap.get(ip);
  if (!entry || now - entry.start > RATE_LIMIT.window) {
    rateLimitMap.set(ip, { start: now, count: 1 });
    return true;
  }
  entry.count++;
  if (entry.count > RATE_LIMIT.max) return false;
  return true;
}

function setCorsHeaders(res, req) {
  const origin = req.headers['origin'] || '';
  // 只给 z.5as.cn 返回 CORS 头，其他网站浏览器会自动拦截跨域请求
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : '';
  if (allowed) {
    res.setHeader('Access-Control-Allow-Origin', allowed);
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type, Depth');
  res.setHeader('Access-Control-Max-Age', '86400');
}

export default async function handler(req, res) {
  setCorsHeaders(res, req);
  
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  // 健康检查 — 直接 GET /api/webdav 无参数
  if (!req.query.url) {
    return res.status(200).json({ 
      ok: true, 
      service: 'keyvault-webdav-proxy',
      allowedDomains: ALLOWED_DOMAINS,
      allowedOrigins: ALLOWED_ORIGINS,
    });
  }

  const targetUrl = req.query.url;
  const method = (req.query.method || 'GET').toUpperCase();

  // 速率限制
  const clientIp = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'unknown';
  if (!checkRateLimit(clientIp)) {
    return res.status(429).json({ error: 'Rate limit exceeded' });
  }

  if (!isAllowed(targetUrl)) {
    return res.status(403).json({ error: 'Target domain not allowed' });
  }

  // 转发头
  const headers = {};
  for (const k of ['authorization', 'content-type', 'depth']) {
    if (req.headers[k]) headers[k] = req.headers[k];
  }

  const opts = { method, headers };
  if (['POST', 'PUT', 'PATCH'].includes(method) && req.body) {
    opts.body = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
  }

  try {
    const resp = await fetch(targetUrl, opts);
    const body = await resp.arrayBuffer();
    
    for (const k of ['content-type', 'dav', 'etag', 'last-modified']) {
      const v = resp.headers.get(k);
      if (v) res.setHeader(k, v);
    }
    
    res.status(resp.status);
    return res.send(Buffer.from(body));
  } catch (err) {
    return res.status(502).json({ error: 'Proxy error: ' + (err?.message || String(err)) });
  }
}

export const config = {
  api: {
    bodyParser: { sizeLimit: '10mb' },
  },
};
