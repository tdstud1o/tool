// secp256k1 基域 GF(p)，p = 2²⁵⁶ − 2³² − 977
//
// 为什么用这个 p 而不是 2²⁵⁵−19：2²⁵⁶ − p = 2³² + 977 ≈ 4.29e9，
// 因此任意 32 字节值落在 [0, p) 之外的概率约 2⁻²²⁴（实测 2e6 次采样 0 命中），
// 秘密可以原样当域元素用，不需要取模归约 —— 而归约不是单射，
// 两个相差 p 的密钥会塌成同一个域元素，导致恢复出错误的 key。
// 2²⁵⁵−19 则有 50% 的随机密钥 ≥ p，必须降熵或归约，两条路都不干净。
//
// 全部用 BigInt（256 位 4 limb），无查表、无外部依赖。
// 不用手写快速归约（2²⁵⁶ ≡ 2³²+977）：实测 370 ns vs `%` 的 512 ns，
// 只快 1.4×，但整条链路都是毫秒级，不值得为此多担一份进位正确性。

import { randomBytes } from './crypto.ts'

/** secp256k1 基域素数 */
export const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn

/** 域元素定长字节数（秘密与 y 都是 32 字节） */
export const FIELD_LEN = 32

/** 坐标最大字节宽度；n ≤ 2²⁴−1，实际远超任何使用场景 */
export const MAX_COORD_BYTES = 3

/** 分片数上限（x 坐标上限） */
export const MAX_SHARES = 0xff_ffff

/** 取模到 [0, p)，BigInt 的 % 对负数会给负值，这里补回来 */
export function fmod(a: bigint): bigint {
  const r = a % P
  return r < 0n ? r + P : r
}

/** 模 p 乘法 */
export function fmul(a: bigint, b: bigint): bigint {
  return (a * b) % P
}

/** 模 p 求逆（扩展欧几里得）；0 不可逆，直接抛错 */
export function finv(a: bigint): bigint {
  let r0 = P
  let r1 = fmod(a)
  if (r1 === 0n) throw new Error('0 在素域中不可逆（分片坐标重复？）')
  let s0 = 0n
  let s1 = 1n
  while (r1 !== 0n) {
    const q = r0 / r1
    const r2 = r0 - q * r1
    r0 = r1
    r1 = r2
    const s2 = s0 - q * s1
    s0 = s1
    s1 = s2
  }
  if (r0 !== 1n) throw new Error('该元素在素域中不可逆')
  return fmod(s0)
}

const HEX2 = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'))

/** 大端字节 → 域元素（不取模，调用方负责校验 < p） */
export function bytesToField(b: Uint8Array): bigint {
  let s = ''
  for (let i = 0; i < b.length; i++) s += HEX2[b[i]!]
  return BigInt('0x' + s)
}

/** 域元素 → 32 字节大端定长（前导零补齐） */
export function fieldToBytes(v: bigint): Uint8Array {
  const hex = v.toString(16).padStart(FIELD_LEN * 2, '0')
  const out = new Uint8Array(FIELD_LEN)
  for (let i = 0; i < FIELD_LEN; i++) {
    const j = i << 1
    out[i] = (hexDigit(hex.charCodeAt(j)) << 4) | hexDigit(hex.charCodeAt(j + 1))
  }
  return out
}

function hexDigit(c: number): number {
  // '0'..'9' → 48..57，'a'..'f' → 97..102
  return c >= 97 ? c - 87 : c - 48
}

/**
 * 生成一个保证是合法域元素（< p）的 32 字节随机值。
 * 落在 [p, 2²⁵⁶) 的概率约 2⁻²²⁴，一旦落进去就丢弃重新取，
 * 绝不取模——取模会把两个不同的值映射到同一个元素。
 * 所有会被当作秘密分片的 32 字节随机量都必须走这里。
 */
export function randomFieldBytes(): Uint8Array {
  for (;;) {
    const b = randomBytes(FIELD_LEN)
    if (bytesToField(b) < P) return b
  }
}
