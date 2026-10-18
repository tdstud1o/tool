// 通用 TLV 容器（PNG/age 风格，支持向前扩展），TSCF 外层密文与 TSPK 内层载荷包共用
//
//   magic(nB) + version(1B) + TLV 序列：tag(1B) + len(4B 大端) + value
//
// 兼容规则：解析器必须跳过未知 tag；约定 lastTag 的块必须放最后；单值上限 4 GiB。

import { cat } from './b64.ts'

export interface Chunk {
  tag: number
  value: Uint8Array
}

export interface TlvFile {
  version: number
  chunks: Map<number, Uint8Array>
}

export function tlvBuild(
  magic: string,
  version: number,
  chunks: Chunk[],
  opts: { lastTag?: number } = {},
): Uint8Array {
  const last = opts.lastTag != null ? chunks.filter((c) => c.tag === opts.lastTag) : []
  const rest = chunks
    .filter((c) => c.tag !== opts.lastTag)
    .sort((a, b) => a.tag - b.tag)
  const magicBytes = new TextEncoder().encode(magic)
  const parts: Uint8Array[] = [magicBytes, new Uint8Array([version])]
  for (const c of [...rest, ...last]) {
    if (c.value.length > 0xffff_ffff) throw new Error('TLV 块超过 4GiB 上限')
    const len = new Uint8Array(4)
    new DataView(len.buffer).setUint32(0, c.value.length, false)
    parts.push(new Uint8Array([c.tag]), len, c.value)
  }
  return cat(...parts)
}

export function tlvParse(magic: string, b: Uint8Array): TlvFile {
  const magicBytes = new TextEncoder().encode(magic)
  if (b.length < magicBytes.length + 1 || magicBytes.some((m, i) => b[i] !== m))
    throw new Error(`文件头不匹配（期望 ${magic}）`)
  const version = b[magicBytes.length]!
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength)
  const chunks = new Map<number, Uint8Array>()
  let off = magicBytes.length + 1
  while (off + 5 <= b.length) {
    const tag = b[off]!
    const len = dv.getUint32(off + 1, false)
    if (off + 5 + len > b.length) throw new Error('TLV 块长度越界，文件已损坏')
    // 同 tag 重复时后者覆盖（向前兼容：允许新版本升级旧值）
    chunks.set(tag, b.slice(off + 5, off + 5 + len))
    off += 5 + len
  }
  return { version, chunks }
}

// ===== 外层：TSCF 密文容器 =====
// 外层 tag 编号 = 物理布局顺序（顺序读取无需跳转）：K → N → IV → CIPHERTEXT
//
// TLV tag 注册表（语义编号，一旦发布冻结，禁止改义/回收复用；加新字段挑空号）
//   TSCF: 0x01 FILENAME（已废止：v1.2 起不再写入，解析时视为未知 tag 跳过）
//         | 0x02 K（必需）| 0x03 N（可选：仅单层密文写入，多层链一律不写）
//         | 0x04 IV | 0x05 CIPHERTEXT（末块）| 0x06-0xFF 空闲
//   TSPK: 0x01 FILENAME（可选）| 0x04 CREATED_AT（可选）| 0x05 MIME（可选）| 0x06 NOTE（预留未用）
//         | 0x07 SHA256 | 0x08 ALGO（1B：0=不压缩, 1=zstd L3, 2=gzip 原生, 3=zstd L19；缺失=0）
//         | 0x11 DATA（末块，ALGO≠0 时为压缩字节流）| 0x12 OTS_RECEIPT
//         | 0x13 NEXT（完整的下一层 TSCF 字节；缺失 = 这是最后一层）| 0x14-0xFF 空闲
//   0x02/0x03 在 TSPK 中为两层拆分前的历史空洞，与 TSCF 的 K/N 含义无关。

export const TSCF = {
  MAGIC: 'TSCF',
  VERSION: 1,
  TAG: {
    K: 0x02, // 4B 大端阈值（无密钥可读，用于与分片交叉校验）
    N: 0x03, // 4B 大端总片数；只写在单层密文上（多层链不写，恢复端也就无从得知 n）
    IV: 0x04, // 12B
    CIPHERTEXT: 0x05, // AES-256-GCM(key, TSPK 包)，必须，最后一个块
  },
  LAST_TAG: 0x05,
} as const

// ===== 内层：TSPK 载荷包（解密后才能读到，承载原数据 + 元数据 + 存证/签名）=====

export const TSPK = {
  MAGIC: 'TSPK',
  VERSION: 1,
  TAG: {
    FILENAME: 0x01, // utf-8 原文件名
    CREATED_AT: 0x04, // u64 毫秒，原文件创建/拆分时间
    MIME: 0x05, // utf-8
    NOTE: 0x06, // utf-8 备注
    SHA256: 0x07, // 原始 DATA 的 SHA-256（32B）
    ALGO: 0x08, // 1B：DATA 压缩算法（0=不压缩, 1=zstd L3, 2=gzip, 3=zstd L19；缺失=0）
    DATA: 0x11, // 原文件数据（ALGO≠0 时为压缩流），约定最后一个块
    OTS_RECEIPT: 0x12, // OpenTimestamps .ots 回执原文
    NEXT: 0x13, // 完整的下一层 TSCF 字节（多层级密文链）；缺失 = 最后一层
    // 未来扩展（签名、KDF 等）直接加新 tag，旧版解析器自动跳过
  },
  LAST_TAG: 0x11,
} as const

export function u64beBytes(n: number): Uint8Array {
  const out = new Uint8Array(8)
  new DataView(out.buffer).setBigUint64(0, BigInt(n), false)
  return out
}

/** 大端无符号整数 → 固定 4 字节。k / n 用它（n 可到 16,777,215，一字节装不下） */
export function u32beBytes(n: number): Uint8Array {
  const out = new Uint8Array(4)
  new DataView(out.buffer).setUint32(0, n, false)
  return out
}

/** 大端无符号整数 → number，接受 1..4 字节（旧的单字节写法也能读） */
export function beBytesToUint(b: Uint8Array): number {
  let v = 0
  for (const x of b) v = v * 256 + x
  return v
}

export function beBytesToU64(b: Uint8Array): number {
  return Number(new DataView(b.buffer, b.byteOffset, b.byteLength).getBigUint64(0, false))
}
