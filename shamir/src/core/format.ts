// 分片文本格式：TSK1:x:k₁:y₁:k₂:y₂…:km:ym
//   TSK       = TD Shamir Key，1 为格式版本
//   x         = 坐标（1..MAX_SHARES），一片只写一次
//   kᵢ:yᵢ     = 第 i 组的阈值与该组密钥材料（y 为 32 字节的 base64）
//
// x 只出现一次，每组只剩 32 字节的 y，所以一片的长度 ≈ 前缀 + m × 44 字符，
// 与 n 的大小无关（旧格式每组还要多带 1~3 字节坐标，深链时白白放大几十倍）。
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

// 前缀 + 坐标 + 至少一组 :k:base64
const SHARE_RE = /^TSK(\d+):(\d+)((?::\d+:[A-Za-z0-9+/]+={0,2})+)$/

/** 一组的密钥材料：该组阈值 + 该组 y */
export interface ShareLevel {
  k: number
  /** 32 字节大端的 y */
  payload: Uint8Array
}

export interface ShareEntry {
  /** x 坐标（1..MAX_SHARES），同一片的所有组共用 */
  index: number
  /** 从第 1 层（最外层）到最深层；后面可能跟着诱饵组 */
  levels: ShareLevel[]
}

export function encodeShare(entry: ShareEntry): string {
  if (entry.levels.length === 0) throw new Error('分片至少要有一组密钥材料')
  const parts = [SHARE_PREFIX, String(entry.index)]
  for (const lv of entry.levels) parts.push(String(lv.k), toB64(lv.payload))
  return parts.join(':')
}

export function parseShareLine(line: string): ShareEntry | null {
  const m = SHARE_RE.exec(line.trim())
  if (!m) return null
  const version = Number(m[1])
  if (version !== SHARE_VERSION)
    throw new Error(`不支持的分片版本 TSK${version}（当前只认 ${SHARE_PREFIX}）`)

  const index = Number(m[2])
  if (!Number.isInteger(index) || index < 1 || index > MAX_SHARES)
    throw new Error(`分片坐标非法：x=${m[2]}`)

  // m[3] 形如 ":3:AAAA:5:BBBB"，split 后首项为空串
  const tok = m[3]!.split(':')
  const levels: ShareLevel[] = []
  for (let i = 1; i + 1 < tok.length; i += 2) {
    const k = Number(tok[i])
    const payload = fromB64(tok[i + 1]!)
    if (!Number.isInteger(k) || k < 2 || k > MAX_SHARES) throw new Error(`分片参数非法：k=${tok[i]}`)
    // readY 校验长度必须是 32 字节、y < p
    readY(payload)
    levels.push({ k, payload })
  }
  if (levels.length === 0) throw new Error('分片没有任何密钥材料')
  return { index, levels }
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
  if (shares.length === 0) throw new Error(`没有找到任何分片（格式应为 ${SHARE_PREFIX}:x:k:base64）`)
  return shares
}

export function sameLevels(a: ShareLevel[], b: ShareLevel[]): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++)
    if (a[i]!.k !== b[i]!.k || !bytesEq(a[i]!.payload, b[i]!.payload)) return false
  return true
}

/**
 * 校验同批分片自洽：组数一致、每组 k 一致、片数够第 1 层。
 * 返回每组的 k 列表（下标 0 = 最外层；尾部可能是诱饵）。
 */
export function checkConsistency(shares: ShareEntry[], ctK?: number): number[] {
  const m = shares[0]!.levels.length
  if (shares.some((s) => s.levels.length !== m))
    throw new Error('各分片的组数不一致，可能不是同一批拆出来的')
  const ks = shares[0]!.levels.map((l) => l.k)
  for (const s of shares) {
    for (let i = 0; i < m; i++)
      if (s.levels[i]!.k !== ks[i])
        throw new Error(`第 ${i + 1} 组阈值不一致（k=${s.levels[i]!.k} 与 k=${ks[i]}），不是同一批分片`)
  }
  if (ctK != null && ctK !== ks[0])
    throw new Error(`分片第 1 组 k=${ks[0]} 与密文 k=${ctK} 不一致`)
  if (shares.length < ks[0]!)
    throw new Error(`第 1 层至少需要 ${ks[0]} 片，当前只有 ${shares.length} 片`)
  return ks
}
