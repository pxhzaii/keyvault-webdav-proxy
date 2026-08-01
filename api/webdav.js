/**
 * Vercel Serverless Function — WebDAV 代理
 * 
 * 用途：绕过 Cloudflare-to-Cloudflare 520 问题
 * Cloudflare Worker 无法直接 fetch 另一个 Cloudflare 站点（如坚果云），
 * 所以用 Vercel（非 Cloudflare 平台）做中转代理。
 * 
 * 部署方式：推送到 GitHub，在 Vercel 导入即可
 * 调用方式：POST /api/webdav?url=<encodedUrl>&method=GET
 */

// 域名白名单
const ALLOWED_DOMAINS = [
  'dav.jianguoyun.com',
  'webdav.pcloud.com',
  'webdav.hidrive.strato.com',
  'dav.infini-cloud.net',
];

function isAllowed(urlStr) {
  try {
    const u = new URL(urlStr);
    if (u.protocol !== 'https:') return false;
    const h = u.hostname.toLowerCase();
    return ALLOWED_DOMAINS.some(d => h === d || h.endsWith('.' + d));
  } catch { return false; }
}

export default async function handler(req, res) {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type, Depth, X-Api-Token');
  
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  const { url: targetUrl, method: targetMethod } = req.query;
  
  if (!targetUrl) {
    return res.status(400).json({ error: 'Missing url parameter' });
  }
  
  if (!isAllowed(targetUrl)) {
    return res.status(403).json({ error: 'Domain not allowed' });
  }
  
  const method = (targetMethod || 'GET').toUpperCase();
  
  // 转发头
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
