// 层规划：真文件（用户选的）+ 唯一的假文件层（必定最后一层，永远解不开），
// 以及密钥串对齐用的诱饵组（没有密文，只有随机的密钥材料）。
// 纯函数，不碰 DOM，方便单测；随机源可注入。

import { MAX_SHARES } from './gfp.ts'

export type LevelKind = 'real' | 'fake'

export interface LevelPlan {
  kind: LevelKind
  /** 展示名（真实 = 原文件名；假 = part_01.bin） */
  name: string
  /** 真实 = 文件字节数；假 = 假明文字节数 */
  size: number
  k: number
  /** 假文件：大小是否仍跟随统计值（用户手改过就变 false） */
  autoSize: boolean
}

export type Pattern = { type: 'arith' | 'geo'; step: number }

/**
 * 从已有的 k 序列里找等差/等比规律。
 * 至少两个点才谈得上"规律"：3,6,9 → 等差 3；5,10,20 → 等比 2。
 * 找不到返回 null，调用方退化成"每层 +1"。
 */
export function kPattern(ks: number[]): Pattern | null {
  if (ks.length < 2) return null
  const d = ks[1]! - ks[0]!
  if (d > 0 && ks.every((v, i) => i === 0 || v - ks[i - 1]! === d)) return { type: 'arith', step: d }
  const r = ks[1]! / ks[0]!
  if (r > 1 && Number.isInteger(r) && ks.every((v, i) => i === 0 || v === ks[i - 1]! * r))
    return { type: 'geo', step: r }
  return null
}

/** 文件大小的分布：均值，以及允许的浮动幅度 = |均值 − 中位数| */
export function sizeStats(sizes: number[]): { mean: number; spread: number } {
  if (sizes.length === 0) return { mean: 64 * 1024, spread: 8 * 1024 }
  const mean = sizes.reduce((a, b) => a + b, 0) / sizes.length
  const sorted = [...sizes].sort((a, b) => a - b)
  const mid = sorted.length >> 1
  const median = sorted.length % 2 ? sorted[mid]! : (sorted[mid - 1]! + sorted[mid]!) / 2
  let spread = Math.abs(mean - median)
  // 只有一个文件时均值恒等于中位数，差值为 0。此时给 5% 浮动，
  // 否则假文件大小与真文件分毫不差，反而比"稍大稍小"更可疑。
  if (spread < mean * 0.01) spread = mean * 0.05
  return { mean, spread }
}

/** 在 [mean − spread, mean + spread] 里取一个大小，至少 64 字节 */
export function randSize(stats: { mean: number; spread: number }, rnd: () => number = Math.random): number {
  const v = stats.mean + (rnd() * 2 - 1) * stats.spread
  return Math.max(64, Math.round(v))
}

/** 顺着规律推下一个 k（只保证 ≥ 2、不超过域上限，不压到 n 以内） */
function nextFrom(last: number, pat: Pattern | null): number {
  const v = pat
    ? pat.type === 'geo'
      ? Math.round(last * pat.step)
      : last + pat.step
    : last + 1
  return Math.min(MAX_SHARES, Math.max(2, v))
}

/** 已有 k 序列的下一层：能看出等差/等比就顺着走，看不出就 +1 */
export function nextK(ks: number[]): number {
  const last = ks[ks.length - 1]
  if (last === undefined) return 3
  return nextFrom(last, ks.length >= 2 ? kPattern(ks) : null)
}

/**
 * 假文件层的默认 k：接在真实层规律后面的那一个，默认不超过 n
 * （凑够就能"试"，试完发现解密失败）。
 * 用户可以把它改到 n 以上——假层是唯一允许 k > n 的层，那样连凑都凑不齐。
 */
export function fakeK(reals: number[], n: number): number {
  return Math.min(nextK(reals), Math.max(2, n))
}

/** 假文件的名字：像个普通分卷，不暗示真假 */
export const FAKE_NAME = 'part_01.bin'

/**
 * 密钥串对齐：在链尾继续按规律编 k，补够 total 组。
 *
 * 补出来的组没有对应密文层，只有随机密钥材料——拿到手也只能白插值一次，
 * 和"假文件层"在字节层面无法区分。目的是让持有分片的人看不出真实层数：
 * 32 组里可能只有 3 层有内容，也可能有 31 层。
 */
export function padKs(chain: number[], total: number, patternKs: number[] = chain): number[] {
  const count = Math.max(0, total - chain.length)
  const pat = kPattern(patternKs)
  const out: number[] = []
  let last = chain[chain.length - 1] ?? 3
  for (let i = 0; i < count; i++) {
    last = nextFrom(last, pat)
    out.push(last)
  }
  return out
}
