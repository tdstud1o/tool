// 载荷压缩：只压 TSPK 的 DATA 块，算法编号写进 0x08 ALGO（缺省 0 = 不压缩）。
//
// 编号与实测（24 文件 / 281.6 MB，详见 zipbench/RESULTS.md）：
//   0x00 不压缩   旧密文缺省；采样收益 <1% 时也用它
//   0x01 zstd L3  默认：约 47% 压缩率，~97 MB/s
//   0x02 gzip     浏览器原生 CompressionStream，无额外体积
//   0x03 zstd L19 极限：约 50%，2.5 MB/s
//
// zstd 的 wasm 由 Vite 在构建期内联成 data: URL（库自身 new URL('./zstd.wasm', import.meta.url)），
// 单文件产物里没有任何外部请求。


export const ALGO = { NONE: 0, ZSTD_L3: 1, GZIP: 2, ZSTD_L19: 3 } as const
export type AlgoId = (typeof ALGO)[keyof typeof ALGO]

export const ALGO_LABEL: Record<number, string> = {
  [ALGO.NONE]: '不压缩',
  [ALGO.ZSTD_L3]: 'zstd L3',
  [ALGO.GZIP]: 'gzip',
  [ALGO.ZSTD_L19]: 'zstd L19',
}

/** 采样长度：先压 256 KiB 判断值不值得压整份 */
const SAMPLE_LEN = 256 * 1024
/** 收益低于 1% 就当不可压缩（已压过的 jpg/zip/mp4 都是 0 附近） */
const MIN_GAIN = 0.01
/** 太小不压：gzip/zstd 帧头尾开销反而变大 */
const MIN_LEN = 512

interface ZstdModule {
  compress(data: Uint8Array, level?: number): Uint8Array
  decompress(data: Uint8Array): Uint8Array
  init(path?: string): Promise<void>
}

let zstdMod: ZstdModule | null = null

async function getZstd(): Promise<ZstdModule> {
  if (zstdMod) return zstdMod
  const mod = await import('@bokuweb/zstd-wasm')
  await (mod as unknown as ZstdModule).init()
  zstdMod = mod as unknown as ZstdModule
  return zstdMod
}

function gzipStream(): TransformStream<Uint8Array, Uint8Array> {
  return new CompressionStream('gzip') as unknown as TransformStream<Uint8Array, Uint8Array>
}

function gunzipStream(): TransformStream<Uint8Array, Uint8Array> {
  return new DecompressionStream('gzip') as unknown as TransformStream<Uint8Array, Uint8Array>
}

async function through(
  stream: TransformStream<Uint8Array, Uint8Array>,
  bytes: Uint8Array,
): Promise<Uint8Array> {
  const src = new Blob([bytes as unknown as BlobPart]).stream()
  return new Uint8Array(await new Response(src.pipeThrough(stream)).arrayBuffer())
}

async function pack(data: Uint8Array, algo: AlgoId): Promise<Uint8Array> {
  switch (algo) {
    case ALGO.ZSTD_L3:
      return (await getZstd()).compress(data, 3)
    case ALGO.ZSTD_L19:
      return (await getZstd()).compress(data, 19)
    case ALGO.GZIP:
      return through(gzipStream(), data)
    default:
      return data
  }
}

export interface CompressResult {
  bytes: Uint8Array
  algo: AlgoId
  /** 写进日志的说明：压缩率或跳过原因 */
  note: string
}

/**
 * 按用户选择压缩 DATA：
 * - 明确选「不压缩」→ 原样
 * - 采样收益 <1% → 原样（避免对已压缩文件白跑）
 * - 压完反而更大 → 原样
 */
export async function compressData(data: Uint8Array, wanted: AlgoId): Promise<CompressResult> {
  if (wanted === ALGO.NONE) return { bytes: data, algo: ALGO.NONE, note: '按选择不压缩' }
  if (data.length < MIN_LEN) return { bytes: data, algo: ALGO.NONE, note: '文件太小，未压缩' }

  const sample = data.subarray(0, Math.min(data.length, SAMPLE_LEN))
  const samplePacked = await pack(sample, wanted)
  if (1 - samplePacked.length / sample.length < MIN_GAIN)
    return { bytes: data, algo: ALGO.NONE, note: '收益低于 1%，按原样存储' }

  const packed = await pack(data, wanted)
  if (packed.length >= data.length)
    return { bytes: data, algo: ALGO.NONE, note: '压缩后反而更大，按原样存储' }

  const saved = ((1 - packed.length / data.length) * 100).toFixed(1)
  return { bytes: packed, algo: wanted, note: `省 ${saved}%` }
}

/** 恢复侧：按 ALGO 还原 DATA；未知编号直接报错，不猜测 */
export async function decompressData(data: Uint8Array, algo: number): Promise<Uint8Array> {
  switch (algo) {
    case ALGO.NONE:
      return data
    case ALGO.ZSTD_L3:
    case ALGO.ZSTD_L19:
      return (await getZstd()).decompress(data)
    case ALGO.GZIP:
      return through(gunzipStream(), data)
    default:
      throw new Error(`不支持的压缩算法编号 ${algo}`)
  }
}
