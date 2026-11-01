// 密文外观（style）：写在 TSCF 外层 0x06，无密钥即可读
//
// 外观不是加密的一部分，它决定「拿到密文的人看到什么」：
//   默认     只有参数 + 密文，恢复后按普通文件卡呈现；
//   碎片     密文本身是一幅被打碎的画：恢复端把内容摆成 6 格碎片，解锁一格亮一格；
//   星座     一张琥珀色旧星图：一层一个星座，凑够才连得起线，星云里透出那张照片。
//
// 三条硬规则（与 TLV tag 的约定一致）：
//   1. 编号一旦发布冻结，新增风格只在尾部追加，禁止改义/回收；
//   2. 旧版恢复端遇到不认识的编号 → 按默认外观呈现，分片照样能解开（外观不影响密码学）；
//   3. 值只写 1 字节，将来要带参数（比如碎片格数、星座连线）时再用 TLV 的 len 扩展。

export const STYLE = {
  PLAIN: 0,
  FRAGMENT: 1,
  CONSTELLATION: 2,
} as const

export type StyleId = number

export interface StyleSpec {
  id: StyleId
  /** 日志/文档里的短标识 */
  key: string
  label: string
  /** 拆分端是否可以选用（未实现的风格先占编号，恢复端按默认外观兜底） */
  splitReady: boolean
  note?: string
}

export const STYLE_LIST: readonly StyleSpec[] = [
  { id: STYLE.PLAIN, key: 'plain', label: '普通', splitReady: true },
  { id: STYLE.FRAGMENT, key: 'fragment', label: '碎片', splitReady: true },
  { id: STYLE.CONSTELLATION, key: 'constellation', label: '星座', splitReady: true },
]

/** 自带界面的外观（碎片 / 星座）都摆 6 格：和拆分端的层数上限一致 */
export const STAGE_SLOTS = 6
export const FRAGMENT_SLOTS = STAGE_SLOTS

export function styleSpec(id: StyleId): StyleSpec | undefined {
  return STYLE_LIST.find((s) => s.id === id)
}

export function styleLabel(id: StyleId | null | undefined): string {
  if (id == null) return '普通'
  return styleSpec(id)?.label ?? `未知（${id}）`
}

/** 1B 值 → 外观编号；缺失/空/越界一律按默认处理（前向兼容） */
export function readStyle(bytes: Uint8Array | undefined): StyleId {
  if (!bytes || bytes.length === 0) return STYLE.PLAIN
  const id = bytes[0]!
  return styleSpec(id) ? id : STYLE.PLAIN
}

export function styleBytes(id: StyleId): Uint8Array {
  return new Uint8Array([id & 0xff])
}

// ===== 图片嗅探 =====
// 「是不是图片」按魔数判断，不看扩展名也不信内层写的 MIME：
// 一个改了名的文本文件不该被渲染成图片，反过来真正的 SVG 也要认出来。

function ascii(b: Uint8Array, off: number, text: string): boolean {
  for (let i = 0; i < text.length; i++) if (b[off + i] !== text.charCodeAt(i)) return false
  return true
}

export function sniffImageMime(b: Uint8Array): string | null {
  if (b.length >= 8 && b[0] === 0x89 && ascii(b, 1, 'PNG')) return 'image/png'
  if (b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'image/jpeg'
  if (b.length >= 6 && ascii(b, 0, 'GIF8')) return 'image/gif'
  if (b.length >= 12 && ascii(b, 0, 'RIFF') && ascii(b, 8, 'WEBP')) return 'image/webp'
  if (b.length >= 2 && ascii(b, 0, 'BM')) return 'image/bmp'
  if (b.length >= 12 && ascii(b, 4, 'ftyp')) {
    if (ascii(b, 8, 'avif') || ascii(b, 8, 'avis')) return 'image/avif'
    if (ascii(b, 8, 'heic') || ascii(b, 8, 'heix')) return 'image/heic'
  }
  if (b.length >= 4 && b[0] === 0x00 && b[1] === 0x00 && b[2] === 0x01 && b[3] === 0x00) return 'image/x-icon'
  // SVG 是文本：跳过 BOM/空白，允许 XML 声明、DOCTYPE、注释在前 1 KiB 内
  const head = new TextDecoder('utf-8', { fatal: false }).decode(b.subarray(0, 1024)).replace(/^\uFEFF/, '').trimStart()
  if (head.startsWith('<svg') || (/^<(\?xml|!doctype|!--)/i.test(head) && /<svg[\s>]/i.test(head)))
    return 'image/svg+xml'
  return null
}

/** 拆分端用：按浏览器给的 MIME 或扩展名粗筛，真正的校验在恢复端（按魔数） */
export function isImageFileLike(name: string, mime: string): boolean {
  if (mime.startsWith('image/')) return true
  return /\.(png|jpe?g|gif|webp|bmp|svg|avif|heic|ico)$/i.test(name)
}
