// OpenTimestamps：可选的哈希存证（用户勾选才会联网）
//
// .ots 回执格式（依 opentimestamps 源码）：
//   HEADER_MAGIC(31B) + varuint(major) + fileHashOp(0x08 = SHA256) + fileDigest(32B) + timestamp 流
//   attestation = 8B TAG + varbytes(payload)
//     PendingAttestation  TAG 83dfe30d2ef90c8e  payload = varbytes(uri)
//     BitcoinAttestation  TAG 0588960d73d71901  payload = varuint(height)
//
// 离线可验证：回执头里的 fileDigest 与原文件 SHA-256 比对（fileDigest 明文存储）。
// 在线完整验证：重放 ops 得到被锚定摘要（= merkle root），与区块链头比对。

import { cat, toHex } from './b64.ts'
import { sha256 } from './crypto.ts'

const OTS_HEADER_MAGIC = Uint8Array.from([
  0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d,
  0x70, 0x73, 0x00, 0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2,
  0xe8, 0x84, 0xe8, 0x92, 0x94,
])
const PENDING_TAG = Uint8Array.from([0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e])
const BITCOIN_TAG = Uint8Array.from([0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01])
const OP_SHA256 = 0x08
const OP_APPEND = 0xf0
const OP_PREPEND = 0xf1
const OP_REVERSE = 0xf2
const OP_HEXLIFY = 0xf3

const CALENDAR = 'https://a.pool.opentimestamps.org/digest'
const BLOCK_SOURCE = 'https://mempool.space/api'

export interface BitcoinAnchor {
  height: number
  /** 该锚点处的被锚定摘要（= 区块 merkle root，重放得到） */
  digest: Uint8Array
}

export interface OtsParse {
  /** 回执锚定的原文件摘要（.ots 明文存储，离线比对用） */
  fileDigest: Uint8Array
  pendingUris: string[]
  anchors: BitcoinAnchor[]
  /** 结构是否完整重放（false = 有未识别的结构，仅部分解析） */
  complete: boolean
}

function readVarint(b: Uint8Array, off: number): { value: number; next: number } | null {
  let value = 0
  let shift = 0
  let i = off
  while (i < b.length) {
    const x = b[i]!
    value |= (x & 0x7f) << shift
    shift += 7
    i++
    if ((x & 0x80) === 0) return { value, next: i }
    if (shift > 35) return null
  }
  return null
}

function tagAt(b: Uint8Array, off: number, tag: Uint8Array): boolean {
  if (off + tag.length > b.length) return false
  return tag.every((t, i) => b[off + i] === t)
}

export async function parseOts(b: Uint8Array): Promise<OtsParse> {
  const r: OtsParse = { fileDigest: new Uint8Array(0), pendingUris: [], anchors: [], complete: false }
  // 头部：magic + varuint(major) + fileHashOp + fileDigest(32B)
  if (b.length < OTS_HEADER_MAGIC.length + 2 || !OTS_HEADER_MAGIC.every((m, i) => b[i] === m))
    throw new Error('不是有效的 .ots 回执')
  let off = OTS_HEADER_MAGIC.length
  const v = readVarint(b, off)
  if (!v) throw new Error('.ots 回执头损坏')
  off = v.next
  if (b[off] !== OP_SHA256) throw new Error('.ots 回执使用了不支持的哈希算子（仅支持 SHA-256）')
  off += 1
  r.fileDigest = b.slice(off, off + 32)
  if (r.fileDigest.length !== 32) throw new Error('.ots 回执缺少文件摘要')
  off += 32

  // timestamp 流线性重放（无分叉的常规回执；遇到未知结构降级为部分解析）
  let msg = r.fileDigest
  let pos = off
  while (pos < b.length) {
    const op = b[pos]!
    if (op === OP_SHA256) {
      msg = await sha256(msg)
      pos += 1
    } else if (op === OP_APPEND || op === OP_PREPEND) {
      const v2 = readVarint(b, pos + 1)
      if (!v2 || v2.next + v2.value > b.length) { pos = b.length + 1; break }
      const arg = b.slice(v2.next, v2.next + v2.value)
      msg = op === OP_APPEND ? cat(msg, arg) : cat(arg, msg)
      pos = v2.next + v2.value
    } else if (op === OP_REVERSE) {
      msg = msg.slice().reverse()
      pos += 1
    } else if (op === OP_HEXLIFY) {
      msg = new TextEncoder().encode(toHex(msg))
      pos += 1
    } else if (tagAt(b, pos, PENDING_TAG)) {
      const v2 = readVarint(b, pos + 8)
      if (!v2 || v2.next + v2.value > b.length) { pos = b.length + 1; break }
      const payload = b.slice(v2.next, v2.next + v2.value)
      const vu = readVarint(payload, 0)
      if (vu) r.pendingUris.push(new TextDecoder().decode(payload.subarray(vu.next, vu.next + vu.value)))
      pos = v2.next + v2.value
    } else if (tagAt(b, pos, BITCOIN_TAG)) {
      const v2 = readVarint(b, pos + 8)
      if (!v2 || v2.next + v2.value > b.length) { pos = b.length + 1; break }
      const vh = readVarint(b.slice(v2.next, v2.next + v2.value), 0)
      if (vh && vh.value > 0 && vh.value < 100_000_000)
        r.anchors.push({ height: vh.value, digest: msg })
      pos = v2.next + v2.value
    } else {
      pos = b.length + 1 // 未知结构
      break
    }
  }
  r.complete = pos === b.length
  return r
}

/** 向 OTS 日历提交文件摘要，返回 .ots 回执。仅在用户明确勾选时调用。 */
export async function otsStamp(fileDigest: Uint8Array, timeoutMs = 15000): Promise<Uint8Array> {
  const ctl = new AbortController()
  const timer = setTimeout(() => ctl.abort(), timeoutMs)
  try {
    const res = await fetch(CALENDAR, { method: 'POST', body: toHex(fileDigest), signal: ctl.signal })
    if (!res.ok) throw new Error(`OTS 日历返回 ${res.status}`)
    const buf = new Uint8Array(await res.arrayBuffer())
    if (buf.length < 40) throw new Error('OTS 回执异常（过短）')
    return buf
  } finally {
    clearTimeout(timer)
  }
}

export interface OtsOnlineVerify {
  height: number
  blockTime: number
  ok: boolean
  detail: string
}

/** 在线完整验证：按高度拉区块头，比对 merkle root（需联网，用户点击触发） */
export async function verifyAnchorOnline(a: BitcoinAnchor): Promise<OtsOnlineVerify> {
  const hashRes = await fetch(`${BLOCK_SOURCE}/block-height/${a.height}`)
  if (!hashRes.ok) throw new Error(`获取区块哈希失败（${hashRes.status}）`)
  const hash = (await hashRes.text()).trim()
  const headerRes = await fetch(`${BLOCK_SOURCE}/block/${hash}/header`)
  if (!headerRes.ok) throw new Error(`获取区块头失败（${headerRes.status}）`)
  const header = Uint8Array.from(
    (await headerRes.text()).match(/../g)!.map((x) => parseInt(x, 16)),
  )
  const merkleRoot = header.slice(36, 68)
  const blockTime = new DataView(header.buffer).getUint32(68, true) * 1000
  const ok = merkleRoot.every((x, i) => x === a.digest[i])
  return {
    height: a.height,
    blockTime,
    ok,
    detail: ok
      ? '回执摘要与区块 merkle root 一致'
      : '回执摘要与区块 merkle root 不一致',
  }
}
