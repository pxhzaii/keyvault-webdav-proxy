/**
 * Vercel Serverless Function — WebDAV 代理
 * 
 * 用途：绕过 Cloudflare-to-Cloudflare 520 问题
 * Cloudflare Worker 无法直接 fetch 另一个 Cloudflare 站点（如坚果云），
 * 所以用 Vercel（非 Cloudflare 平台）做中转代理。
 * 
 * 部署方式：推送到 GitHub，在 Vercel 导入即可
 * 调用方式：POST /api/webdav?url=<encodedUrl>&method=GET
 * 
 * 安全限制：
 * 1. 只代理白名单里的 WebDAV 域名
 * 2. 只允许 z.5as.cn 来源调用（Origin/Referer 校验）
 * 3. 每IP速率限制（60次/分钟）
 */

// ===== 允许的来源站点（只有这些站点的请求才会被代理）=====
const ALLOWED_ORIGINS = [
  'https://z.5as.cn',
  'http://localhost:8788',   // 本地开发用，部署后可删
];

// ===== 允许代理的 WebDAV 目标域名 =====
const ALLOWED_DOMAINS = [
  'dav.jianguoyun.com',       // 坚果云
  'webdav.pcloud.com',        // pCloud
  'webdav.hidrive.strato.com',// HiDrive
  'dav.infini-cloud.net',     // InfiniCLOUD
];

// 速率限制（内存，Vercel Serverless 单次调用有效，冷启动重置）
const RATE_LIMIT = { max: 60, window: 60 };
const rateLimitMap = new Map();

function checkOrigin(req) {
  const origin = req.headers['origin'] || req.headers['referer'];
  if (!origin) return true; // 非浏览器请求（如 curl）放行，仅校验浏览器
  const originBase = origin.startsWith('http://localhost') ? 'http://localhost' : origin.split('/').slice(0, 3).join('/');
  return ALLOWED_ORIGINS.some(allowed => originBase.startsWith(allowed));
}

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

export default async function handler(req, res) {
  // CORS — 只允许指定来源
  const origin = req.headers['origin'] || '';
  const corsOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  res.setHeader('Access-Control-Allow-Origin', corsOrigin);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type, Depth');
  res.setHeader('Vary', 'Origin');
  
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  // 来源校验
  if (!checkOrigin(req)) {
    return res.status(403).json({ error: 'Origin not allowed. Only z.5as.cn can use this proxy.' });
  }

  // 速率限制
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.headers['x-real-ip'] || 'unknown';
  if (!checkRateLimit(clientIp)) {
    return res.status(429).json({ error: 'Rate limit exceeded' });
  }

  const { url: targetUrl, method: targetMethod } = req.query;
  
  if (!targetUrl) {
    return res.status(400).json({ error: 'Missing url parameter' });
  }
  
  if (!isAllowed(targetUrl)) {
    return res.status(403).json({ error: 'Target domain not allowed' });
  }
  
  const method = (targetMethod || 'GET').toUpperCase();
  
  // 只转发 WebDAV 需要的头
  const headers = {};
  const fwd = ['authorization', 'content-type', 'depth'];
  for (const k of fwd) {
    if (req.headers[k]) headers[k] = req.headers[k];
  }
  
  const opts = { method, headers };
  if (['POST', 'PUT', 'PATCH'].includes(method) && req.body) {
    opts.body = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
  }
  
  try {
    const resp = await fetch(targetUrl, opts);
    const body = await resp.arrayBuffer();
    
    // 只转发安全的响应头
    const safeH = ['content-type', 'dav', 'etag', 'last-modified'];
    for (const k of safeH) {
      const v = resp.headers.get(k);
      if (v) res.setHeader(k, v);
    }
    
    res.status(resp.status);
    res.setHeader('Content-Type', resp.headers.get('content-type') || 'application/octet-stream');
    return res.send(Buffer.from(body));
  } catch (err) {
    return res.status(502).json({ error: 'Proxy error: ' + (err?.message || String(err)) });
  }
}

export const config = {
  api: {
    bodyParser: {
      sizeLimit: '10mb',
    },
  },
};
