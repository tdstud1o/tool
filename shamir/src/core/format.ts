// 分片文本格式：TSK1:k:base64 —— TSK = TD Shamir Key，1 为格式版本
// 分片是纯密钥材料：只带 k 与 x 坐标，不含 n、文件名等任何元数据。
//
// base64 解码后的载荷 = [y: 32 字节大端][x: w 字节大端]：
// 定长在前的 y 恒 32 字节，变长在后的 x 宽度 w = 载荷长度 − 32，
// 由 n 决定（n ≤ 255 → 1 字节，n ≤ 65535 → 2 字节，否则 3）。
// 域是 secp256k1 基域 GF(2²⁵⁶ − 2³² − 977)，x 与 y 都是域元素。

import { MAX_SHARES } from './gfp.ts'
import { bytesEq, fromB64, toB64 } from './b64.ts'
import { unpackShare } from './shamir.ts'

/** 当前分片格式版本（前缀 TSK1） */
export const SHARE_VERSION = 1
export const SHARE_PREFIX = `TSK${SHARE_VERSION}`

const SHARE_RE = /^TSK(\d+):(\d+):([A-Za-z0-9+/]{4,}={0,2})$/

export interface ShareEntry {
  k: number
  /** x 坐标（1..MAX_SHARES） */
  index: number
  payload: Uint8Array
}

export function encodeShare(k: number, share: Uint8Array): string {
  return `${SHARE_PREFIX}:${k}:${toB64(share)}`
}

export function parseShareLine(line: string): ShareEntry | null {
  const m = SHARE_RE.exec(line.trim())
  if (!m) return null
  const version = Number(m[1])
  if (version !== SHARE_VERSION)
    throw new Error(`不支持的分片版本 TSK${version}（当前只认 ${SHARE_PREFIX}）`)
  const k = Number(m[2])
  const payload = fromB64(m[3]!)
  if (k < 2 || k > MAX_SHARES) throw new Error(`分片参数非法：k=${k}`)
  // unpackShare 会校验长度、坐标宽度、y < p
  const { x } = unpackShare(payload)
  if (x === 0) throw new Error('分片 index 非法（x 坐标为 0）')
  return { k, index: x, payload }
}

/** 解析一段文本里的所有分片，同 index 重复内容不同时报错 */
export function parseShares(text: string): ShareEntry[] {
  const byIndex = new Map<number, ShareEntry>()
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue
    const e = parseShareLine(line)
    if (!e) continue
    const prev = byIndex.get(e.index)
    if (prev && (prev.k !== e.k || !bytesEq(prev.payload, e.payload)))
      throw new Error(`第 ${e.index} 号分片出现两种不同内容，请检查是否拿错了`)
    byIndex.set(e.index, e)
  }
  const shares = [...byIndex.values()]
  if (shares.length === 0) throw new Error(`没有找到任何分片（格式应为 ${SHARE_PREFIX}:k:base64）`)
  return shares
}

/** 校验各分片 k 一致，并与密文头交叉校验；返回 k */
export function checkConsistency(shares: ShareEntry[], ctK?: number): number {
  const ks = new Set(shares.map((s) => s.k))
  if (ks.size > 1) throw new Error('各分片的 k 不一致，可能不是同一批拆出来的')
  const k = shares[0]!.k
  if (ctK != null && ctK !== k) throw new Error(`分片的 k=${k} 与密文 k=${ctK} 不一致`)
  if (shares.length < k) throw new Error(`至少需要 k=${k} 片，当前只有 ${shares.length} 片`)
  return k
}
