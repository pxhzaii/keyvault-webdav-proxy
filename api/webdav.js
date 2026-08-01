/**
 * Vercel Serverless Function — WebDAV 代理
 * 
 * 用途：绕过 Cloudflare-to-Cloudflare 520 问题
 * 安全限制：目标白名单 + 速率限制
 * 
 * 响应格式：对 GET/HEAD 请求返回 JSON { status, headers, bodyB64 }
 * 其中 bodyB64 是响应体的 base64 编码，避免 CDN/代理层压缩导致前端解码错误
 * 对 PUT/POST 等写入请求直接透传原始响应
 */

// ===== 允许的 WebDAV 目标域名 =====
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

export default async function handler(req, res) {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type, Depth');
  res.setHeader('Access-Control-Max-Age', '86400');
  
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  // 手动读取原始 body（bodyParser 已禁用）
  let rawBody = null;
  if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
    rawBody = await new Promise((resolve, reject) => {
      const chunks = [];
      req.on('data', chunk => chunks.push(chunk));
      req.on('end', () => resolve(Buffer.concat(chunks)));
      req.on('error', reject);
    });
  }

  // 解析 query 参数
  const url = new URL(req.url, `https://${req.headers.host}`);
  const targetUrl = url.searchParams.get('url');
  const method = (url.searchParams.get('method') || 'GET').toUpperCase();

  // 健康检查
  if (!targetUrl) {
    return res.status(200).json({ 
      ok: true, 
      service: 'keyvault-webdav-proxy',
      allowedDomains: ALLOWED_DOMAINS,
    });
  }

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
  if (rawBody && rawBody.length > 0) {
    opts.body = rawBody;
  }

  try {
    const resp = await fetch(targetUrl, opts);
    const body = await resp.arrayBuffer();
    
    // 收集安全头
    const respHeaders = {};
    for (const k of ['content-type', 'dav', 'etag', 'last-modified']) {
      const v = resp.headers.get(k);
      if (v) respHeaders[k] = v;
    }

    // 对读取类请求（GET/HEAD），用 JSON 包装响应，bodyB64 避免压缩/编码问题
    if (['GET', 'HEAD'].includes(method)) {
      return res.status(200).json({
        status: resp.status,
        headers: respHeaders,
        bodyB64: Buffer.from(body).toString('base64'),
      });
    }
    
    // 对写入类请求（PUT/MKCOL 等），直接返回状态码
    return res.status(resp.status).json({
      status: resp.status,
      headers: respHeaders,
    });
  } catch (err) {
    return res.status(502).json({ error: 'Proxy error: ' + (err?.message || String(err)) });
  }
}

export const config = {
  api: {
    bodyParser: false,
    sizeLimit: '10mb',
  },
};
