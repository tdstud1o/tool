// OpenTimestamps：可选的哈希存证（用户勾选才会联网）
//
// 日历 POST /digest 返回的是**裸 Timestamp 流**（无 DetachedTimestampFile 头、不含摘要）：
//   序列化（依 python-opentimestamps timestamp.py）：
//     多 attestation 时除最后一个外，每个前缀 `\xff\x00` + attestation
//     无 ops：`\x00` + 最后一个 attestation
//     有 ops：有 attestation 时先 `\xff\x00` + 最后 attestation；
//             除最后一个 op 外每个前缀 `\xff` + op + 子时间戳；最后 op + 子时间戳
//   op 编码：tag 字节。0x02 SHA1 / 0x03 RIPEMD160 / 0x08 SHA256（无参）；
//            0xf0 APPEND / 0xf1 PREPEND（varbytes 参数）；0xf2 REVERSE / 0xf3 HEXLIFY
//   attestation = 8B TAG + varbytes(payload)
//     PendingAttestation  TAG 83dfe30d2ef90c8e  payload = varbytes(uri)
//     BitcoinAttestation  TAG 0588960d73d71901  payload = varuint(height)
//
// 被锚定摘要 = 初始消息（我们提交的文件 SHA-256）逐 op 重放的结果（= merkle root）。
// 本解析器同时兼容带 DetachedTimestampFile 头的 .ots（自动剥头）。

import { cat, toHex } from './b64.ts'
import { sha256 } from './crypto.ts'

const OTS_HEADER_MAGIC = Uint8Array.from([
  0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d,
  0x70, 0x73, 0x00, 0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2,
  0xe8, 0x84, 0xe8, 0x92, 0x94,
])
const PENDING_TAG = Uint8Array.from([0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e])
const BITCOIN_TAG = Uint8Array.from([0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01])

/**
 * 把日历的裸 Timestamp 回执包装成标准 .ots（DetachedTimestampFile），
 * 供官方工具/网页验证：magic(31B) + varuint(1) + OpSHA256(0x08) + fileDigest(32B) + 回执流
 */
export function toDetachedOts(receipt: Uint8Array, fileDigest: Uint8Array): Uint8Array {
  return cat(OTS_HEADER_MAGIC, new Uint8Array([1, 0x08]), fileDigest, receipt)
}

const CALENDAR = 'https://a.pool.opentimestamps.org/digest'
const BLOCK_SOURCE = 'https://mempool.space/api'

export type OtsAttestation =
  | { kind: 'pending'; uri: string; digest: Uint8Array | null }
  | { kind: 'bitcoin'; height: number; digest: Uint8Array | null }

export interface OtsParse {
  attestations: OtsAttestation[]
  /** 结构没走全（不认识的 op/attestation、无法重放等），摘要结果可能不完整 */
  degraded: boolean
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

/** 在 pos 处读取并应用一个 op；返回新消息与下一位置。无法处理返回 null（降级）。 */
async function applyOp(
  b: Uint8Array,
  msg: Uint8Array | null,
  pos: number,
): Promise<{ msg: Uint8Array; next: number } | null> {
  const op = b[pos]!
  const next = pos + 1
  if (msg === null) return null // 所有已支持 op 都需要初始消息才能重放
  switch (op) {
    case 0x08: // SHA256
      return { msg: await sha256(msg), next }
    case 0x02: // SHA1
      return { msg: new Uint8Array(await crypto.subtle.digest('SHA-1', msg)), next }
    case 0xf0: { // APPEND
      const v = readVarint(b, next)
      if (!v || v.next + v.value > b.length) return null
      return { msg: cat(msg, b.slice(v.next, v.next + v.value)), next: v.next + v.value }
    }
    case 0xf1: { // PREPEND
      const v = readVarint(b, next)
      if (!v || v.next + v.value > b.length) return null
      return { msg: cat(b.slice(v.next, v.next + v.value), msg), next: v.next + v.value }
    }
    case 0xf2: // REVERSE
      return { msg: msg.slice().reverse(), next }
    case 0xf3: // HEXLIFY
      return { msg: new TextEncoder().encode(toHex(msg)), next }
    default: // 0x03 RIPEMD160 / 0x67 KECCAK256 / 其他未知 op：WebCrypto 不支持，降级
      return null
  }
}

/** 在 pos 处读取一个 attestation（8B TAG + varbytes payload），返回下一位置 */
function readAttestation(b: Uint8Array, msg: Uint8Array | null, pos: number, r: OtsParse): number {
  if (pos + 9 > b.length) {
    r.degraded = true
    return b.length
  }
  const v = readVarint(b, pos + 8)
  if (!v || v.next + v.value > b.length) {
    r.degraded = true
    return b.length
  }
  const payload = b.slice(v.next, v.next + v.value)
  if (tagAt(b, pos, PENDING_TAG)) {
    const vu = readVarint(payload, 0)
    const uri = vu ? new TextDecoder().decode(payload.subarray(vu.next, vu.next + vu.value)) : ''
    r.attestations.push({ kind: 'pending', uri, digest: msg ? msg.slice() : null })
  } else if (tagAt(b, pos, BITCOIN_TAG)) {
    const vh = readVarint(payload, 0)
    if (vh && vh.value > 0 && vh.value < 100_000_000)
      r.attestations.push({ kind: 'bitcoin', height: vh.value, digest: msg ? msg.slice() : null })
  }
  // 其他 attestation（Litecoin / Unknown）跳过
  return v.next + v.value
}

/** 递归走一个 Timestamp 分支，返回分支结束位置 */
async function walkTs(
  b: Uint8Array,
  msg: Uint8Array | null,
  pos: number,
  r: OtsParse,
  depth: number,
): Promise<number> {
  if (depth > 256) {
    r.degraded = true
    return b.length
  }
  while (pos < b.length) {
    const tag = b[pos]!
    pos += 1
    if (tag === 0xff) {
      if (b[pos] === 0x00) {
        pos += 1
        pos = readAttestation(b, msg, pos, r)
        continue
      }
      // fork：op + 子时间戳（从 op 结果出发的另一条分支）
      const applied = await applyOp(b, msg, pos)
      if (!applied) {
        r.degraded = true
        return b.length
      }
      pos = await walkTs(b, applied.msg, applied.next, r, depth + 1)
      continue
    }
    if (tag === 0x00) {
      pos = readAttestation(b, msg, pos, r)
      continue
    }
    // 最后一个 op：其后是内层时间戳，递归消费到分支末尾
    const applied = await applyOp(b, msg, pos - 1)
    if (!applied) {
      r.degraded = true
      return b.length
    }
    return walkTs(b, applied.msg, applied.next, r, depth + 1)
  }
  return pos
}

/**
 * 解析 OTS 回执。
 * @param receipt 日历返回的裸 Timestamp 流（或带 DetachedTimestampFile 头的 .ots，自动剥头）
 * @param initialMsg 回执的初始消息（= 拆分时提交的文件 SHA-256），重放 ops 得到被锚定摘要
 */
export async function parseOts(receipt: Uint8Array, initialMsg?: Uint8Array): Promise<OtsParse> {
  const r: OtsParse = { attestations: [], degraded: false }
  let msg: Uint8Array | null = initialMsg ?? null
  let pos = 0

  if (tagAt(receipt, 0, OTS_HEADER_MAGIC)) {
    // DetachedTimestampFile：magic + varuint(major) + fileHashOp(1B) + fileDigest(32B)
    pos = OTS_HEADER_MAGIC.length
    const v = readVarint(receipt, pos)
    if (!v || v.next + 33 > receipt.length) throw new Error('.ots 回执头损坏')
    pos = v.next
    msg = receipt.slice(pos + 1, pos + 33)
    pos += 33
  }

  const end = await walkTs(receipt, msg, pos, r, 0)
  if (end !== receipt.length) r.degraded = true
  return r
}

/** 向 OTS 日历提交文件摘要，返回裸 Timestamp 回执。仅在用户明确勾选时调用。 */
export async function otsStamp(fileDigest: Uint8Array, timeoutMs = 20000): Promise<Uint8Array> {
  const ctl = new AbortController()
  const timer = setTimeout(() => ctl.abort(), timeoutMs)
  try {
    const res = await fetch(CALENDAR, { method: 'POST', body: toHex(fileDigest), signal: ctl.signal })
    if (!res.ok) throw new Error(`OTS 日历返回 ${res.status}`)
    const buf = new Uint8Array(await res.arrayBuffer())
    if (buf.length < 10) throw new Error('OTS 回执异常（过短）')
    return buf
  } finally {
    clearTimeout(timer)
  }
}

/** 日历域名白名单：回执内的 URI 完全由文件内容控制，联网查询前必须校验，防内网探测/外发 */
export function isAllowedCalendarUri(uri: string): boolean {
  try {
    const u = new URL(uri)
    if (u.protocol !== 'https:') return false
    const host = u.hostname.toLowerCase()
    return host === 'opentimestamps.org' || host.endsWith('.opentimestamps.org')
  } catch {
    return false
  }
}

/**
 * 向日历查询回执升级（OTS "upgrade" 的轻量版）：
 * GET {uri}/timestamp/<待锚定摘要hex> → 若日历已把该承诺锚上比特币，
 * 返回的 timestamp 流里会带 BitcoinAttestation。
 */
export async function upgradePending(
  p: { uri: string; digest: Uint8Array | null },
  timeoutMs = 20000,
): Promise<OtsParse> {
  if (!p.digest) throw new Error('回执结构降级，无法确定查询摘要')
  if (!isAllowedCalendarUri(p.uri)) throw new Error(`回执内日历地址不受信任，已拒绝查询：${p.uri}`)
  const ctl = new AbortController()
  const timer = setTimeout(() => ctl.abort(), timeoutMs)
  try {
    const res = await fetch(`${p.uri}/timestamp/${toHex(p.digest)}`, { signal: ctl.signal })
    if (!res.ok) throw new Error(`日历返回 ${res.status}`)
    const buf = new Uint8Array(await res.arrayBuffer())
    if (buf.length < 10) throw new Error('日历响应异常（过短）')
    return await parseOts(buf, p.digest)
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

/** 在线完整验证：按高度拉区块头，比对被锚定摘要与 merkle root（需联网，用户点击触发） */
export async function verifyAnchorOnline(a: { height: number; digest: Uint8Array | null }): Promise<OtsOnlineVerify> {
  const digest = a.digest
  if (!digest) throw new Error('回执结构降级，无法重放出被锚定摘要，不能在线验证')
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
  const ok = merkleRoot.every((x, i) => x === digest[i])
  return {
    height: a.height,
    blockTime,
    ok,
    detail: ok ? '回执摘要与区块 merkle root 一致' : '回执摘要与区块 merkle root 不一致',
  }
}
