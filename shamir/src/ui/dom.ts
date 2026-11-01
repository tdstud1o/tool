// DOM 小工具：所有「造一个元素」都从这里来，省得每处都写 createElement + className。
//
// 这一层不认识业务：不碰密文、不碰外观，只负责造节点、格式化大小、触发下载、
// 以及 blob URL 的生命周期。

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  cls: string,
  ...children: (Node | string)[]
): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag)
  if (cls) e.className = cls
  for (const c of children) e.append(c)
  return e
}

export function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`
  return `${(n / 1024 ** 3).toFixed(2)} GB`
}

export function baseName(name: string): string {
  const i = name.lastIndexOf('.')
  return i > 0 ? name.slice(0, i) : name
}

export function download(name: string, data: Uint8Array | Blob): void {
  const url = URL.createObjectURL(data instanceof Blob ? data : new Blob([data]))
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 3000)
}

// ===== blob URL 生命周期 =====
// 预览图都用 blob URL（CSP 的 img-src 已放行 blob:）。它们活到下一次恢复开始，
// 由 revokeTracked() 统一回收：视图不必各自记着自己造过哪些 URL。

const blobUrls: string[] = []

/** 登记一个待回收的 blob URL（原样返回，方便链式使用） */
export function trackUrl(url: string): string {
  blobUrls.push(url)
  return url
}

export function revokeTracked(): void {
  for (const u of blobUrls) URL.revokeObjectURL(u)
  blobUrls.length = 0
}
