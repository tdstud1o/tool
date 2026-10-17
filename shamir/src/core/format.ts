// 分片文本格式：SHAMIR1:k:n:base64 —— 分片是纯密钥材料，不含任何元数据

import { bytesEq, fromB64, toB64 } from './b64.ts'

const SHARE_RE = /^SHAMIR1:(\d+):(\d+):([A-Za-z0-9+/]{4,}={0,2})$/

export interface ShareEntry {
  k: number
  n: number
  /** x 坐标（1..255） */
  index: number
  payload: Uint8Array
}

export function encodeShare(k: number, n: number, share: Uint8Array): string {
  return `SHAMIR1:${k}:${n}:${toB64(share)}`
}

function parseShareLine(line: string): ShareEntry | null {
  const m = SHARE_RE.exec(line.trim())
  if (!m) return null
  const k = Number(m[1])
  const n = Number(m[2])
  const payload = fromB64(m[3]!)
  if (k < 2 || n > 255 || k > n) throw new Error(`分片参数非法：k=${k} n=${n}`)
  const index = payload[0]!
  if (index === 0) throw new Error('分片 index 非法（x 坐标为 0）')
  return { k, n, index, payload }
}

/** 解析一段文本里的所有分片，同 index 重复内容不同时报错 */
export function parseShares(text: string): ShareEntry[] {
  const byIndex = new Map<number, ShareEntry>()
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue
    const e = parseShareLine(line)
    if (!e) continue
    const prev = byIndex.get(e.index)
    if (prev && (prev.k !== e.k || prev.n !== e.n || !bytesEq(prev.payload, e.payload)))
      throw new Error(`第 ${e.index} 号分片出现两种不同内容，请检查是否拿错了`)
    byIndex.set(e.index, e)
  }
  const shares = [...byIndex.values()]
  if (shares.length === 0) throw new Error('没有找到任何分片（格式应为 SHAMIR1:k:n:base64）')
  return shares
}

/** 校验分片 k/n 一致性，并与密文头交叉校验；返回 k、n */
export function checkConsistency(shares: ShareEntry[], ctK?: number, ctN?: number): { k: number; n: number } {
  const ks = new Set(shares.map((s) => s.k))
  const ns = new Set(shares.map((s) => s.n))
  if (ks.size > 1 || ns.size > 1) throw new Error('各分片的 k/n 不一致，可能不是同一批拆出来的')
  const k = shares[0]!.k
  const n = shares[0]!.n
  if (ctK != null && ctN != null && (ctK !== k || ctN !== n))
    throw new Error(`分片 k/n (${k}/${n}) 与密文 (${ctK}/${ctN}) 不一致`)
  if (shares.length < k)
    throw new Error(`至少需要 k=${k} 片，当前只有 ${shares.length} 片（共 n=${n}）`)
  return { k, n }
}
