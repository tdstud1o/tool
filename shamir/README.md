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

两层同款 TLV 容器（PNG/age 风格，支持向前扩展）：

```
TLV 通用结构：magic(4B) + version(1B) + tag(1B) + len(4B 大端) + value 序列
兼容规则：解析器必须跳过未知 tag；约定 lastTag 的块必须放最后；单值上限 4 GiB
```

**内层 SMPK 载荷包**（先打包、再整体加密——元数据、存证、签名全部藏进密文）：

```
SMPK v1：
  0x01 FILENAME    utf-8 原文件名
  0x04 CREATED_AT  u64 毫秒（原文件创建/拆分时间，属于元数据，不外露）
  0x05 MIME        utf-8
  0x06 NOTE        utf-8 备注
  0x07 SHA256      原始 DATA 的 SHA-256（32B）
  0x12 OTS_RECEIPT OpenTimestamps .ots 回执原文（用户勾选才提交哈希）
  0x11 DATA        原始数据（最后一个块）
```

**外层 SMCF 密文文件**（AES-256-GCM(key, SMPK 包)；tag 编号 = 物理布局顺序，顺序可读）：

```
SMCF v1：
  0x01 FILENAME    展示用文件名
  0x02 K / 0x03 N  分片参数，无密钥可读，凑片前先交叉校验
  0x04 IV          12B
  0x05 CIPHERTEXT  密文（必须，最后一个块）
```

**分片 = 纯密钥材料**（保持最少存储）：`SHAMIR1:k:n:base64(GF(2⁸) payload)`，
payload 首字节为 x 坐标 index；每片自带 k/n 可独立校验，同一批片不一致立即报错。
分片不含任何元数据——OTS、签名、文件名都只活在密文里。

恢复时：k 片 combine → 32B key → 解开 SMCF → AES-GCM 认证失败即报
"分片/密文不匹配" → 解出 SMPK → SHA-256 校验 DATA → 原文件。
若内层含 OTS_RECEIPT：离线比对回执摘要与 DATA 哈希；可选在线完整验证（拉区块头对 merkle root）。

## 里程碑

- [ ] M1 骨架：Vite 子项目 + 单 HTML 构建 + Pages 部署跑通（空页面）
- [ ] M2 拆分：文件上传 → 加密 → 分片 → 下载全部产物
- [ ] M3 恢复：k 片 + 密文 → 原文件，错误分支完整
- [ ] M4 打磨：拖拽、进度、QR 分片、中英双语、移动端
