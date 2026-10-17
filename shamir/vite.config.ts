import { defineConfig } from 'vite'
import { viteSingleFile } from 'vite-plugin-singlefile'

// Pages 站点固定为 tdstud1o.github.io/tool/，本工具挂在 /tool/shamir/ 子路径
export default defineConfig({
  base: '/tool/shamir/',
  plugins: [viteSingleFile()],
  build: {
    target: 'es2020',
    outDir: 'dist',
  },
})
