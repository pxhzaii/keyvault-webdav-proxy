/**
 * Vercel Serverless Function — WebDAV 代理
 * 
 * 用途：绕过 Cloudflare-to-Cloudflare 520 问题
 * 安全限制：目标白名单 + 速率限制
 * 
 * 响应格式：所有请求统一返回 HTTP 200 + JSON body
 * GET/HEAD: { status, headers, bodyB64 }
 * PUT/MKCOL 等: { status, headers }
 * 始终返回 200 是因为非 2xx 或 204 的 JSON body 可能被 CDN 层破坏
 */

// ===== 允许的 WebDAV 目标域名 =====
const ALLOWED_DOMAINS = [
  
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
  
  // CORS 预检 — bodyParser:false 模式下必须手动消费请求体再响应
  if (req.method === 'OPTIONS') {
    // 消费请求体（即使 OPTIONS 通常没有 body，Vercel runtime 要求消费完流）
    await new Promise((resolve) => {
      req.on('data', () => {});
      req.on('end', resolve);
    });
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
    return res.status(200).json({ status: 429, error: 'Rate limit exceeded' });
  }

  if (!isAllowed(targetUrl)) {
    return res.status(200).json({ status: 403, error: 'Target domain not allowed' });
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
    
    // 对写入类请求（PUT/MKCOL 等），统一返回 HTTP 200 + JSON
    // 避免非 2xx 或 204 等状态码的 JSON body 被 CDN 层破坏导致前端 res.json() 解析失败
    return res.status(200).json({
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
