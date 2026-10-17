# tdstud1o/tool

tdstud1o 的 GitHub Pages 工具箱仓库。每个工具一个子目录，统一走 GitHub Actions 部署。

| 工具 | 端点 | 说明 |
|---|---|---|
| [shamir](./shamir) | https://tdstud1o.github.io/tool/shamir/ | 任意文件 → n 个分片 + 1 个密文，纯前端，点击即用 |

## 目录结构

```
tool/
├── shamir/          # shamir 文件分片工具（Vite 子项目，base=/tool/shamir/）
│   └── ...
└── <future-tool>/   # 后续工具照此模式加入
```

## 部署约定

- 每个子目录是独立的 Vite 项目，构建产物由 GitHub Actions（actions/deploy-pages）发布。
- Pages 站点 URL 固定为 `tdstud1o.github.io/tool/`，因此各子项目 `base` 必须设为 `/tool/<name>/`。
- 零后端、零外发请求，所有计算在浏览器本地完成。
