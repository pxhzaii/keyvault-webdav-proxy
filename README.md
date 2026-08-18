
# webdav代理
解决了  [keyvault](https://github.com/pxhzaii/keyvault)和[NavSync](https://github.com/pxhzaii/NavSync) 或者其他cloudflare项目  无法使用坚果云备份的问题

## 部署
1. Fork [代理仓库](https://github.com/pxhzaii/keyvault-webdav-proxy)

2. 登录 [Vercel](https://vercel.com/) → **Add New** → **Project** → 导入该仓库
3. 直接点击 **Deploy**
4. 记录域名，如 `https://aaa.vercel.app`
5. 代理地址就是 `https://aaa.vercel.app/api/webdav`

api/webdav.js有白名单，可自行修改


