// Shamir 秘密共享：secp256k1 基域 GF(p)，p = 2²⁵⁶ − 2³² − 977。
//
// 分片字节布局（format.ts 里的 payload 就是这个字节串）：
//   [y: 32 字节大端][x: w 字节大端]
// 定长部分在前、变长部分在后：y 恒 32 字节，x 的宽度 w 由 n 决定
// （n ≤ 255 → 1、n ≤ 65535 → 2、否则 3），w = 载荷长度 − 32。
// 解析时先拿前 32 字节当 y，剩下的全是坐标，不用从头猜宽度。
//
// 与旧实现的区别：不再依赖 shamir-secret-sharing（GF(2⁸)，n ≤ 255），
// 因此 x 不再被单字节坐标限制，n 可以到 MAX_SHARES。

import {
  FIELD_LEN,
  MAX_COORD_BYTES,
  MAX_SHARES,
  P,
  bytesToField,
  fieldToBytes,
  finv,
  fmod,
  fmul,
  randomFieldBytes,
} from './gfp.ts'

/** 被共享的秘密长度：AES-256 密钥 */
export const SECRET_LEN = FIELD_LEN

/** 载荷长度 ≥ 1 + 32 */
export const MIN_SHARE_LEN = 1 + FIELD_LEN

/** 坐标宽度：n 越大 x 越宽 */
export function coordWidth(n: number): number {
  if (n <= 0xff) return 1
  if (n <= 0xffff) return 2
  return 3
}

function randomField(): bigint {
  return bytesToField(randomFieldBytes())
}

function evalPoly(poly: bigint[], x: number): bigint {
  const xb = BigInt(x)
  let y = poly[poly.length - 1]!
  for (let d = poly.length - 2; d >= 0; d--) y = (y * xb + poly[d]!) % P
  return y
}

function packShare(x: number, y: bigint, w: number): Uint8Array {
  const out = new Uint8Array(FIELD_LEN + w)
  out.set(fieldToBytes(y), 0)
  let t = x
  for (let i = out.length - 1; i >= FIELD_LEN; i--) {
    out[i] = t & 0xff
    t = Math.floor(t / 256)
  }
  return out
}

/** 解出坐标与 y；非法内容直接抛错，不静默吞掉 */
export function unpackShare(buf: Uint8Array): { x: number; y: bigint } {
  if (buf.length <= FIELD_LEN) throw new Error('分片内容太短，不是有效的密钥材料')
  const w = buf.length - FIELD_LEN
  if (w > MAX_COORD_BYTES) throw new Error('分片内容过长，不是有效的密钥材料')
  const y = bytesToField(buf.subarray(0, FIELD_LEN))
  let x = 0
  for (let i = FIELD_LEN; i < buf.length; i++) x = x * 256 + buf[i]!
  if (y >= P) throw new Error('分片数值非法（超出 secp256k1 域范围），可能已损坏')
  return { x, y }
}

/**
 * 把 secret 拆成 n 片，任意 k 片可恢复。
 * 坐标取 1..n 洗牌后分配；x 本身不是秘密，洗牌只是沿用旧行为，
 * 让分片顺序与文件序号不对应。
 */
export async function shamirSplit(
  secret: Uint8Array,
  n: number,
  k: number,
  onProgress?: (done: number, total: number) => void,
): Promise<Uint8Array[]> {
  if (secret.length !== SECRET_LEN) throw new Error(`秘密必须是 ${SECRET_LEN} 字节，当前 ${secret.length}`)
  if (!Number.isInteger(k) || !Number.isInteger(n)) throw new Error('k 和 n 必须是整数')
  if (k < 2) throw new Error('k 至少为 2')
  if (n < k) throw new Error('n 不能小于 k')
  if (n > MAX_SHARES) throw new Error(`分片数最多 ${MAX_SHARES}`)

  const s = bytesToField(secret)
  // 正常流程不会走到这里：密钥由 randomFieldBytes 生成，天然 < P。
  // 绝不取模归约——那会把两个不同的密钥映射到同一个元素。
  if (s >= P) throw new Error('密钥数值超出 secp256k1 域范围（应由 randomFieldBytes 生成）')

  const poly: bigint[] = [s]
  for (let i = 1; i < k; i++) poly.push(randomField())

  const xs = Array.from({ length: n }, (_, i) => i + 1)
  const rnd = new Uint32Array(n)
  // getRandomValues 单次上限 65536 字节 → 每次最多 16384 个 uint32
  const CHUNK = 16384
  for (let off = 0; off < n; off += CHUNK) {
    const end = Math.min(n, off + CHUNK)
    crypto.getRandomValues(rnd.subarray(off, end))
  }
  for (let i = n - 1; i > 0; i--) {
    // 取模偏差 ≤ n/2³²，对坐标分配无实际影响
    const j = rnd[i]! % (i + 1)
    const t = xs[i]!
    xs[i] = xs[j]!
    xs[j] = t
  }

  const w = coordWidth(n)
  const shares: Uint8Array[] = new Array(n)
  // 进度回调最多报 100 次，避免 n 很大时刷屏
  const step = Math.max(1, Math.floor(n / 100))
  for (let i = 0; i < n; i++) {
    const x = xs[i]!
    shares[i] = packShare(x, evalPoly(poly, x), w)
    if (onProgress && (i + 1) % step === 0) onProgress(i + 1, n)
  }
  onProgress?.(n, n)
  return shares
}

/**
 * 用给定分片恢复秘密（传入多少片就用多少片，调用方负责至少凑够 k）。
 * 任一坐标重复、x = 0、y ≥ p 都会拒绝。
 */
export async function shamirCombine(
  shares: Uint8Array[],
  onProgress?: (done: number, total: number) => void,
): Promise<Uint8Array> {
  if (shares.length < 2) throw new Error('至少需要 2 片才能恢复')
  const pts = shares.map(unpackShare)
  const seen = new Set<number>()
  for (const p of pts) {
    if (p.x === 0) throw new Error('分片坐标非法（x = 0 会直接暴露密钥），已拒绝')
    if (seen.has(p.x)) throw new Error(`坐标 #${p.x} 出现重复分片，无法确定用哪一片`)
    seen.add(p.x)
  }

  // 拉格朗日插值求 f(0)
  const total = pts.length
  const step = Math.max(1, Math.floor(total / 100))
  let acc = 0n
  for (let i = 0; i < total; i++) {
    let num = 1n
    let den = 1n
    for (let j = 0; j < total; j++) {
      if (i === j) continue
      num = fmod(num * BigInt(-pts[j]!.x))
      den = fmod(den * BigInt(pts[i]!.x - pts[j]!.x))
    }
    acc = fmod(acc + fmul(pts[i]!.y, num) * finv(den))
    if (onProgress && (i + 1) % step === 0) onProgress(i + 1, total)
  }
  onProgress?.(total, total)
  return fieldToBytes(fmod(acc))
}
