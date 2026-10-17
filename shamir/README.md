# shamir — 点击即用的文件分片工具

> 任意文件进 → n 个分片 + 1 个密文出。凑齐任意 k 个分片 → 原文件回来。
> 纯前端、零后端、零外发请求。端点：https://tdstud1o.github.io/tool/shamir/

背景与生态位调研见博客：找遍了全网的 shamir 方案，没有我要的"点击即用"的版本（2026-10-17）。

## 验收标准

- 任意文件（照片/文档/存档/压缩包），不限格式
- 混合加密：随机 key 做 AES-256-GCM 加密文件；Shamir 只分片这个 key
- 返回物：n 个分片（每片几十字节文本）+ 1 个密文（与原文件同大小）
- 恢复：任意 k 个分片 + 密文 → 原文件，校验失败明确报错
- 全程浏览器本地计算，GitHub Pages 静态部署

## 技术选型

| 层 | 选择 | 理由 |
|---|---|---|
| 分片引擎 | **privy-io/shamir-secret-sharing**（主）/ amper5and/secrets.js（备） | privy：TS 原生、直接吃 `Uint8Array`、零依赖、GF(2⁸)；secrets.js：2019 年审计过，作为备选。32B key → 每片仅 32B |
| 加密 | **Web Crypto API · AES-256-GCM** | 浏览器原生，无需引入库；key 32B 随机生成，IV 12B，AEAD 自带完整性 |
| 构建 | **Vite + TypeScript + vite-plugin-singlefile** | TS 类型安全；打包为**单个自包含 HTML**——可整页另存离线使用、可人工审计、无 CDN 运行时依赖 |
| UI | **无框架 vanilla TS + 手写 CSS** | 工具只有"拆分/恢复"两个动作，上框架是负资产；深色简洁风 |
| 分片载体 | 文本格式（带头校验），支持复制/下载/打印 | `SHAMIR1·k/n·base64` 结构，几行字符，二维码/纸面均可承载 |
| 部署 | **GitHub Actions → actions/deploy-pages** | Pages 固定 URL 为 `tdstud1o.github.io/tool/`，Vite `base=/tool/shamir/` |

### 明确不选

- **React/Vue 等框架**：两个表单不需要组件体系，徒增体积与审计成本
- **运行时 CDN 引用**：隐私工具必须整页自包含，断网可用
- **后端 / 对象存储**：k-of-n 本来就只要求凑 k 片，云端存储反而扩大攻击面
- **SLIP-39/助记词生态**：本工具面向文件，不做 BIP39 兼容

## 数据格式（v1 草案）

**密文文件**：`SMCF1` magic(5B) + version(1B) + n(1B) + k(1B) + IV(12B) + ciphertext(AES-256-GCM)。分片可独立于密文校验 n/k。

**分片文本**：

```
SHAMIR1:3:5:A9fK...base64...
   │     │ │   └─ GF(2⁸) 分片 payload（含 index）
   │     │ └─ n 总片数
   │     └─ k 阈值
   └─ 格式版本
```

恢复时：k 片 combine → 32B key → AES-GCM 解密 → magic 对不上即报"分片/密文不匹配"。

## 里程碑

- [ ] M1 骨架：Vite 子项目 + 单 HTML 构建 + Pages 部署跑通（空页面）
- [ ] M2 拆分：文件上传 → 加密 → 分片 → 下载全部产物
- [ ] M3 恢复：k 片 + 密文 → 原文件，错误分支完整
- [ ] M4 打磨：拖拽、进度、QR 分片、中英双语、移动端
