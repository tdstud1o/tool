// 分片文本格式：TSK1:x:组1,组2,…,组m
//   TSK       = TD Shamir Key，1 为格式版本
//   x         = 坐标（1..MAX_SHARES），一片只写一次
//   组        = "k:y"（带 k）或 "y"（不带 k），组与组用逗号分隔
//   y         = 32 字节密钥材料的 base64（44 字符，含 '='）
//
// 每组独立决定要不要写 k（拆分端按层勾选「显示k」）：
//   TSK1:04829173:3:AAAA,5:BBBB,CCCC
//   └ 组1 k=3   └ 组2 k=5   └ 组3 没写 k，恢复端从该层密文的 0x02 K 读
// 混装合法：同一条分片里有的组带 k、有的不带。
//
// 解析规则（不靠猜，靠分隔符）：
//   组内按冒号切分——1 段 = 裸 y；2 段 = k:y；3 段以上 = 密钥损坏。
//   k 必须是 1..MAX_SHARES 的十进制整数；y 必须是解码后 32 字节的 base64。
//   两者都不像（比如空段、超长数字、不是 base64）→ 报「密钥损坏」。
//
// x 有两种写法，语义相同、解析方式相同（都是十进制整数）：
//   紧凑（单层）  "7"          最长 8 位，最短 1 位
//   定宽（多层）  "04829173"   恒 8 位，左补零
// 多层一律用定宽：x 若按 n 洗牌，它的位数就直接说明"这套一共几个人"。
// 解析端不需要区分两者，Number() 会把补零读成同一个坐标。
//
// 一个密文里可以套多层（每层一个真文件，或唯一一个假文件），每层有独立的
// AES key 与独立的阈值 k；所有层共用同一套坐标，所以一个人的分片里
// 带齐了每一组的 y。末尾多出来的组是诱饵，没有对应密文。

import { MAX_SHARES } from './gfp.ts'
import { bytesEq, fromB64, toB64 } from './b64.ts'
import { readY } from './shamir.ts'

/** 当前分片格式版本（前缀 TSK1） */
export const SHARE_VERSION = 1
export const SHARE_PREFIX = `TSK${SHARE_VERSION}`

/** 定宽坐标的位数：MAX_SHARES = 16 777 215，正好 8 位 */
export const WIDE_COORD_DIGITS = 8

/** 坐标 → 文本：wide 时左补零到固定 8 位，让长度不泄露 n */
export function coordText(index: number, wide: boolean): string {
  const s = String(index)
  return wide ? s.padStart(WIDE_COORD_DIGITS, '0') : s
}

const SHARE_RE = /^TSK(\d+):(\d+):(.+)$/
const B64_RE = /^[A-Za-z0-9+/]+={0,2}$/

function corrupt(reason: string): never {
  throw new Error(`密钥损坏（${reason}）`)
}

/** 一组的密钥材料：该组阈值（未写 = null，恢复端从密文读）+ 该组 y */
export interface ShareLevel {
  k: number | null
  /** 32 字节大端的 y */
  payload: Uint8Array
}

export interface ShareEntry {
  /** x 坐标（1..MAX_SHARES），同一片的所有组共用 */
  index: number
  /** 坐标是否按定宽 8 位写（多层）；只影响复制/再导出时的写法 */
  wide: boolean
  /** 从第 1 层（最外层）到最深层；后面可能跟着诱饵组 */
  levels: ShareLevel[]
}

export function encodeShare(entry: ShareEntry): string {
  if (entry.levels.length === 0) throw new Error('分片至少要有一组密钥材料')
  const groups = entry.levels.map((lv) =>
    lv.k === null ? toB64(lv.payload) : `${lv.k}:${toB64(lv.payload)}`,
  )
  return [SHARE_PREFIX, coordText(entry.index, entry.wide), groups.join(',')].join(':')
}

/** 解析一组（"k:y" 或 "y"），校验 k 与 y 的合法性 */
function parseGroup(g: string): ShareLevel {
  const kv = g.split(':')
  let k: number | null = null
  let yText: string
  if (kv.length === 1) {
    yText = kv[0]!
  } else if (kv.length === 2) {
    k = Number(kv[0])
    if (!/^\d{1,8}$/.test(kv[0]!) || !Number.isInteger(k) || k < 1 || k > MAX_SHARES)
      corrupt(`k=${kv[0]} 不是 1..${MAX_SHARES} 的整数`)
    yText = kv[1]!
  } else {
    corrupt('一组的冒号多于一个')
  }
  if (!B64_RE.test(yText)) corrupt(`y=${yText.slice(0, 12)}… 不是 base64`)
  let payload: Uint8Array
  try {
    payload = fromB64(yText)
    // readY 校验长度必须是 32 字节、y < p
    readY(payload)
  } catch {
    corrupt('y 不是 32 字节的合法密钥材料')
  }
  return { k, payload }
}

export function parseShareLine(line: string): ShareEntry | null {
  const m = SHARE_RE.exec(line.trim())
  if (!m) return null
  const version = Number(m[1])
  if (version !== SHARE_VERSION)
    throw new Error(`不支持的分片版本 TSK${version}（当前只认 ${SHARE_PREFIX}）`)

  const raw = m[2]!
  const index = Number(raw)
  if (!Number.isInteger(index) || index < 1 || index > MAX_SHARES)
    throw new Error(`分片坐标非法：x=${raw}`)

  const levels = m[3]!.split(',').map(parseGroup)
  if (levels.length === 0) throw new Error('分片没有任何密钥材料')
  return { index, wide: raw.length >= WIDE_COORD_DIGITS, levels }
}

/** 解析一段文本里的所有分片，同坐标重复内容不同时报错 */
export function parseShares(text: string): ShareEntry[] {
  const byIndex = new Map<number, ShareEntry>()
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue
    const e = parseShareLine(line)
    if (!e) continue
    const prev = byIndex.get(e.index)
    if (prev && !sameLevels(prev.levels, e.levels))
      throw new Error(`第 ${e.index} 号分片出现两种不同内容，请检查是否拿错了`)
    byIndex.set(e.index, e)
  }
  const shares = [...byIndex.values()]
  if (shares.length === 0)
    throw new Error(`没有找到任何分片（格式应为 ${SHARE_PREFIX}:x:k:y,y,… 或 ${SHARE_PREFIX}:x:y,y,…）`)
  return shares
}

export function sameLevels(a: ShareLevel[], b: ShareLevel[]): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++)
    if (a[i]!.k !== b[i]!.k || !bytesEq(a[i]!.payload, b[i]!.payload)) return false
  return true
}

/**
 * 校验同批分片自洽：组数一致、每组的 k 写没写一致且值一致、片数够第 1 层。
 * 返回每组的 k 列表（下标 0 = 最外层；尾部可能是诱饵；没写 k 的组是 null）。
 */
export function checkConsistency(shares: ShareEntry[], ctK?: number): (number | null)[] {
  const m = shares[0]!.levels.length
  if (shares.some((s) => s.levels.length !== m))
    throw new Error('各分片的组数不一致，可能不是同一批拆出来的')
  const ks = shares[0]!.levels.map((l) => l.k)
  for (const s of shares) {
    for (let i = 0; i < m; i++) {
      const k = s.levels[i]!.k
      if ((k === null) !== (ks[i] === null) || (k !== null && k !== ks[i]))
        throw new Error(
          `第 ${i + 1} 组的 k 不一致（${k === null ? '没写' : `k=${k}`} 与 ${
            ks[i] === null ? '没写' : `k=${ks[i]}`
          }），不是同一批分片`,
        )
    }
  }
  if (ks[0] != null && ctK != null && ctK !== ks[0])
    throw new Error(`分片第 1 组 k=${ks[0]} 与密文 k=${ctK} 不一致`)
  const need = ks[0] ?? ctK
  if (need != null && shares.length < need)
    throw new Error(`第 1 层至少需要 ${need} 片，当前只有 ${shares.length} 片`)
  return ks
}
