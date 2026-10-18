// Shamir 秘密共享：secp256k1 基域 GF(p)，p = 2²⁵⁶ − 2³² − 977。
//
// 分片布局（见 format.ts）：
//   TSK1:x:k₁:y₁:k₂:y₂…      x 只写一次，每组只有 [y: 32 字节大端]
// x 是坐标，y = f(x) 的 32 字节大端。一组密钥材料恒 32 字节，
// 与 n 大小无关；x 放在前缀里，省掉每组重复一份坐标。
//
// x 的取值分两种，取决于层数：
//   m = 1（单层）   1..n 洗牌后分配，十进制直接写，最短（1~8 字符）
//   m ≥ 2（多层）   [1, MAX_SHARES] 内随机，定宽 8 位十进制
// 多层必须宽坐标：否则 x 的字节宽度（1B/2B/3B）会直接把 n 的数量级泄出去
// ——"这套分片一共几个人"本身就是不该让持片人知道的信息。
//
// 多层：一个密文里套 m 层（TSCF 链），每层有自己的 key 与阈值 k，
// 所有层共用同一套 x 坐标——所以一个人拿到的分片里带齐了 m 个 y。
//
// 槽位可以是 null（诱饵）：只写随机 y，没有多项式，也没有密文层。
// 诱饵的存在是为了把密钥串撑到固定组数，让人看不出真实层数；
// 谁拿诱饵去插值，只会解出一串随机字节。
//
// 与旧实现的区别：不再依赖 shamir-secret-sharing（GF(2⁸)，n ≤ 255），
// 因此 x 不再被单字节坐标限制，n 可以到 MAX_SHARES。

import {
  FIELD_LEN,
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

/** 一组密钥材料的长度：只有一个 32 字节的 y */
export const PAYLOAD_LEN = FIELD_LEN

function randomField(): bigint {
  return bytesToField(randomFieldBytes())
}

function evalPoly(poly: bigint[], x: number): bigint {
  const xb = BigInt(x)
  let y = poly[poly.length - 1]!
  for (let d = poly.length - 2; d >= 0; d--) y = (y * xb + poly[d]!) % P
  return y
}

/** 校验一组载荷并把 y 读成域元素；长度/范围不对直接抛错 */
export function readY(buf: Uint8Array): bigint {
  if (buf.length !== PAYLOAD_LEN)
    throw new Error(`每组密钥材料必须是 ${PAYLOAD_LEN} 字节，当前 ${buf.length}`)
  const y = bytesToField(buf)
  if (y >= P) throw new Error('分片数值非法（超出 secp256k1 域范围），可能已损坏')
  return y
}

/**
 * 多层拆分：一次算出 m 个槽位的 y，全部共用同一套洗牌坐标。
 * secrets 里为 null 的槽位是诱饵：y 直接取随机值，不建多项式，ks 对应的
 * 位置只当作标签（可以超过 n，因为本来就没有能解出来的东西）。
 *
 * 输出布局（每人 shareLen = m × 32 字节）：
 *   [y₀: 32][y₁: 32]…[y_{m−1}: 32]
 * 每组的载荷就是连续切片，主线程直接 slice → base64，不用再拼一次。
 * 坐标 x 不放进载荷，而是随结果数组返回，由分片文本写一次。
 */
/**
 * 多层用的宽坐标：在 [1, MAX_SHARES] 内不重复随机。
 * 为什么不用洗牌 1..n：那样 x 的最大值就是 n，直接暴露总片数；
 * 而 x 的十进制宽度又会被定宽成 8 位，两者叠加才真正看不出 n。
 */
function randomCoords(n: number): number[] {
  const out = new Array<number>(n)
  const seen = new Set<number>()
  // getRandomValues 单次上限 65536 字节 → 每次最多 16384 个 uint32
  const BATCH = 16384
  const buf = new Uint32Array(BATCH)
  let left = 0
  let i = 0
  // n 逼近 MAX_SHARES 时命中率会掉，给个硬上限避免空转
  const maxTries = n * 64 + 4096
  let tries = 0
  while (i < n) {
    if (++tries > maxTries)
      throw new Error(`分片数 ${n.toLocaleString()} 太大，随机坐标凑不出足够的互异值`)
    if (left === 0) {
      crypto.getRandomValues(buf)
      left = BATCH
    }
    // 取模偏差 ≤ n/2³²，对坐标分配无实际影响
    const v = 1 + (buf[--left]! % MAX_SHARES)
    if (seen.has(v)) continue
    seen.add(v)
    out[i++] = v
  }
  return out
}

/** 单层用的紧凑坐标：1..n 洗牌，让分片顺序与序号不对应 */
function compactCoords(n: number): number[] {
  const xs = Array.from({ length: n }, (_, i) => i + 1)
  const rnd = new Uint32Array(n)
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
  return xs
}

export async function shamirSplitMulti(
  secrets: (Uint8Array | null)[],
  n: number,
  ks: number[],
  onProgress?: (done: number, total: number) => void,
  /** 强制宽坐标：隐藏 n 时用（单层也随机取 1..MAX，否则 x 的位数会暴露 n） */
  wideCoords = false,
): Promise<{
  buffer: Uint8Array
  shareLen: number
  count: number
  m: number
  xs: number[]
  /** x 是否按宽坐标（定宽 8 位十进制）编码 */
  wide: boolean
}> {
  const m = secrets.length
  if (m === 0) throw new Error('至少要有一个秘密')
  if (ks.length !== m) throw new Error('k 的数量必须与秘密数量一致')
  if (!Number.isInteger(n) || n < 2) throw new Error('n 必须是 ≥ 2 的整数')
  if (n > MAX_SHARES) throw new Error(`分片数最多 ${MAX_SHARES}`)

  const polys: (bigint[] | null)[] = []
  /** 每个槽位在随机缓冲里的下标；−1 = 有真实秘密 */
  const slotOf: number[] = new Array(m).fill(-1)
  let padCount = 0
  for (let j = 0; j < m; j++) {
    const secret = secrets[j] ?? null
    const k = ks[j]!
    if (secret === null) {
      slotOf[j] = padCount++
      polys.push(null)
      continue
    }
    if (secret.length !== SECRET_LEN) throw new Error(`秘密必须是 ${SECRET_LEN} 字节，当前 ${secret.length}`)
    if (!Number.isInteger(k) || k < 1) throw new Error(`第 ${j + 1} 层 k 至少为 1`)
    if (n < k) throw new Error(`第 ${j + 1} 层 k=${k} 超过总片数 n=${n}`)
    const s = bytesToField(secret)
    // 正常流程不会走到这里：密钥由 randomFieldBytes 生成，天然 < P。
    // 绝不取模归约——那会把两个不同的密钥映射到同一个元素。
    if (s >= P) throw new Error('密钥数值超出 secp256k1 域范围（应由 randomFieldBytes 生成）')
    const poly: bigint[] = [s]
    for (let i = 1; i < k; i++) poly.push(randomField())
    polys.push(poly)
  }
  /** 每片一份新的随机 y（诱饵槽），一次取够 32 × 槽数 */
  const scratch = new Uint8Array(padCount * FIELD_LEN)
  const fillScratch = (): void => {
    // getRandomValues 单次上限 65536 字节
    for (let off = 0; off < scratch.length; off += 65536)
      crypto.getRandomValues(scratch.subarray(off, Math.min(scratch.length, off + 65536)))
  }

  // 单层用紧凑坐标（1..n 洗牌），两层及以上一律宽坐标：
  // 否则 x 的字节宽度会直接把 n 的数量级告诉持片人。
  // 隐藏 n 时单层也强制宽坐标：x 在 [1, MAX_SHARES] 里随机取。
  const useWide = wideCoords || m > 1
  const xs = useWide ? randomCoords(n) : compactCoords(n)

  const unit = PAYLOAD_LEN
  const shareLen = unit * m
  const buffer = new Uint8Array(n * shareLen)

  // 进度回调最多报 100 次，避免 n 很大时刷屏
  const step = Math.max(1, Math.floor(n / 100))
  for (let i = 0; i < n; i++) {
    const x = xs[i]!
    const base = i * shareLen
    if (padCount > 0) fillScratch()
    for (let j = 0; j < m; j++) {
      const off = base + j * unit
      const poly = polys[j]!
      const slot = slotOf[j]!
      if (poly) buffer.set(fieldToBytes(evalPoly(poly, x)), off)
      else buffer.set(scratch.subarray(slot * FIELD_LEN, (slot + 1) * FIELD_LEN), off)
    }
    if (onProgress && (i + 1) % step === 0) onProgress(i + 1, n)
  }
  onProgress?.(n, n)
  return { buffer, shareLen, count: n, m, xs, wide: useWide }
}

/**
 * 单层拆分（多层实现的薄包装，测试与旧调用方用）。
 * 只有一层，所以坐标是紧凑的 1..n 洗牌；x 本身不是秘密，洗牌只是
 * 让分片顺序与文件序号不对应。
 */
export async function shamirSplit(
  secret: Uint8Array,
  n: number,
  k: number,
  onProgress?: (done: number, total: number) => void,
): Promise<{ shares: Uint8Array[]; xs: number[]; wide: boolean }> {
  const { buffer, shareLen, count, xs, wide } = await shamirSplitMulti([secret], n, [k], onProgress)
  const shares: Uint8Array[] = new Array(count)
  for (let i = 0; i < count; i++) shares[i] = buffer.subarray(i * shareLen, (i + 1) * shareLen)
  return { shares, xs, wide }
}

/**
 * 用给定分片恢复秘密（传入多少片就用多少片，调用方负责至少凑够 k）。
 * xs 必须与 shares 一一对应；任一坐标重复、x = 0/越界、y ≥ p 都会拒绝。
 */
export async function shamirCombine(
  shares: Uint8Array[],
  xs: number[],
  onProgress?: (done: number, total: number) => void,
): Promise<Uint8Array> {
  if (shares.length < 1) throw new Error('至少需要 1 片才能恢复')
  if (xs.length !== shares.length) throw new Error('分片数量与坐标数量不一致')
  const pts = shares.map((buf, i) => ({ x: xs[i]!, y: readY(buf) }))
  const seen = new Set<number>()
  for (const p of pts) {
    if (!Number.isInteger(p.x) || p.x < 1 || p.x > MAX_SHARES)
      throw new Error(`分片坐标非法（x = ${p.x}）`)
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
