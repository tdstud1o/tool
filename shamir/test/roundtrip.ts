// 端到端往返测试：node --experimental-strip-types test/roundtrip.ts
import { randomBytes, aesEncrypt, aesDecrypt, sha256 } from '../src/core/crypto.ts'
import { TSPK, TSCF, tlvBuild, tlvParse, u64beBytes } from '../src/core/tlv.ts'
import { shamirSplit, shamirCombine, unpackShare } from '../src/core/shamir.ts'
import { MAX_SHARES, P, bytesToField, randomFieldBytes } from '../src/core/gfp.ts'
import { encodeShare, parseShareLine, parseShares, checkConsistency } from '../src/core/format.ts'
import { parseOts, isAllowedCalendarUri } from '../src/core/ots.ts'
import { bytesEq, cat, toHex } from '../src/core/b64.ts'

const PENDING_TAG = Uint8Array.from([0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e])
const BITCOIN_TAG = Uint8Array.from([0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01])

function varuint(n: number): Uint8Array {
  const out: number[] = []
  do {
    let x = n & 0x7f
    n >>>= 7
    if (n) x |= 0x80
    out.push(x)
  } while (n)
  return new Uint8Array(out)
}

/** 裸 Timestamp（日历 /digest 返回的形态）：无 ops → 0x00 + PendingAttestation */
function fakePendingOts(digest: Uint8Array): Uint8Array {
  const uri = new TextEncoder().encode('https://a.pool.opentimestamps.org')
  return cat(
    new Uint8Array([0x00]),
    PENDING_TAG,
    new Uint8Array([uri.length + 1, uri.length]), // varbytes(payload)；payload = varbytes(uri)
    uri,
  )
}

/** 带 ops 的裸 Timestamp：append(8B) → sha256 → BitcoinAttestation */
async function fakeBitcoinOts(digest: Uint8Array, height: number): Promise<{ receipt: Uint8Array; attested: Uint8Array }> {
  const arg = randomBytes(8)
  const attested = await sha256(cat(digest, arg))
  const vu = varuint(height)
  const receipt = cat(
    new Uint8Array([0xf0, arg.length]),
    arg,
    new Uint8Array([0x08, 0x00]), // sha256 → 内层无 ops，0x00 后跟 attestation
    BITCOIN_TAG,
    new Uint8Array([vu.length]),
    vu,
  )
  return { receipt, attested }
}

/** 旧式 DetachedTimestampFile 头（兼容路径） */
function magicWrappedOts(digest: Uint8Array): Uint8Array {
  const magic = Uint8Array.from([
    0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d,
    0x70, 0x73, 0x00, 0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2,
    0xe8, 0x84, 0xe8, 0x92, 0x94,
  ])
  return cat(magic, new Uint8Array([1, 0x08]), digest, fakePendingOts(digest))
}

let failed = 0
function check(name: string, cond: boolean): void {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}`)
  if (!cond) failed++
}

// 1) TLV 容器（测试数据用伪随机填充即可，getRandomValues 单次上限 64KB）
const data = new Uint8Array(64 * 1024 + 7)
for (let i = 0; i < data.length; i++) data[i] = (i * 2654435761) % 256
const iv = randomBytes(12)
const outer = tlvBuild(
  TSCF.MAGIC,
  TSCF.VERSION,
  [
    { tag: TSCF.TAG.CIPHERTEXT, value: new Uint8Array([9, 9, 9]) },
    { tag: TSCF.TAG.K, value: new Uint8Array([3]) },
    { tag: TSCF.TAG.IV, value: iv },
    { tag: TSCF.TAG.N, value: new Uint8Array([5]) },
    { tag: 0x77, value: new Uint8Array([1, 2, 3]) }, // 未知 tag，解析器必须跳过
  ],
  { lastTag: TSCF.LAST_TAG },
)
const back = tlvParse(TSCF.MAGIC, outer)
check('TSCF magic/version', back.version === 1)
check('未知 tag 保留', bytesEq(back.chunks.get(0x77)!, new Uint8Array([1, 2, 3])))
check('物理顺序 K,N,IV,CT', (() => {
  const find = (pat: number[]) => outer.join(',').indexOf(pat.join(','))
  const kPos = find([0x02, 0, 0, 0, 1])
  const nPos = find([0x03, 0, 0, 0, 1])
  const ivPos = find([0x04, 0, 0, 0, 12])
  const ctPos = find([0x05, 0, 0, 0, 3])
  return kPos > 0 && kPos < nPos && nPos < ivPos && ivPos < ctPos
})())

// 2) 内层包 + 加密 + 分片 + 恢复 全链路
const fileHash = await sha256(data)
const key = randomBytes(32)
const otsFixture = fakePendingOts(fileHash)
const inner = tlvBuild(
  TSPK.MAGIC,
  TSPK.VERSION,
  [
    { tag: TSPK.TAG.FILENAME, value: new TextEncoder().encode('cat.jpg') },
    { tag: TSPK.TAG.CREATED_AT, value: u64beBytes(1729000000000) },
    { tag: TSPK.TAG.SHA256, value: fileHash },
    { tag: TSPK.TAG.OTS_RECEIPT, value: otsFixture },
    { tag: TSPK.TAG.DATA, value: data },
  ],
  { lastTag: TSPK.TAG.DATA },
)
const ct = await aesEncrypt(key, iv, inner)
const ctFile = tlvBuild(TSCF.MAGIC, TSCF.VERSION, [
  { tag: 0x01, value: new TextEncoder().encode('cat.jpg') }, // 旧版 FILENAME：新解析器应按未知 tag 跳过
  { tag: TSCF.TAG.K, value: new Uint8Array([3]) },
  { tag: TSCF.TAG.N, value: new Uint8Array([5]) },
  { tag: TSCF.TAG.IV, value: iv },
  { tag: TSCF.TAG.CIPHERTEXT, value: ct },
], { lastTag: TSCF.LAST_TAG })

// —— 模拟恢复侧 ——
const shares = await shamirSplit(key, 5, 3)
const texts = shares.map((s) => encodeShare(3, s))
const parsed = parseShares(texts.join('\n'))
const k = checkConsistency(parsed, 3)
const recoveredKey = await shamirCombine(parsed.slice(0, k).map((s) => s.payload))
check('Shamir combine = 原 key', bytesEq(recoveredKey, key))
check('分片载荷 = 32 字节 y + 1 字节坐标', parsed.every((s) => s.payload.length === 33))

/** 按布局 [y: 32][x: w] 独立读坐标，不复用实现里的解析 */
function readTailCoord(b: Uint8Array): number {
  let v = 0
  for (let i = 32; i < b.length; i++) v = v * 256 + b[i]!
  return v
}

check('坐标在载荷末尾且互不相同', (() => {
  const idx = parsed.map((s) => s.index)
  return (
    idx.every((v, i) => v === readTailCoord(parsed[i]!.payload)) &&
    new Set(idx).size === idx.length &&
    idx.every((v) => v >= 1 && v <= 5)
  )
})())
check('y 在载荷前 32 字节（用固定密钥可反推 f(x) 一致性）', (() => {
  const u = unpackShare(parsed[0]!.payload)
  return u.y === bytesToField(parsed[0]!.payload.subarray(0, 32))
})())
check('unpackShare 坐标与解析结果一致', parsed.every((s) => unpackShare(s.payload).x === s.index))

const outerBack = tlvParse(TSCF.MAGIC, ctFile)
const ctBack = outerBack.chunks.get(TSCF.TAG.CIPHERTEXT)!
const innerBack = await aesDecrypt(recoveredKey, outerBack.chunks.get(TSCF.TAG.IV)!, ctBack)
const pack = tlvParse(TSPK.MAGIC, innerBack)
check('DATA 完整', bytesEq(pack.chunks.get(TSPK.TAG.DATA)!, data))
check('文件名还原', new TextDecoder().decode(pack.chunks.get(TSPK.TAG.FILENAME)!) === 'cat.jpg')
check('CREATED_AT 还原', beNumber(pack.chunks.get(TSPK.TAG.CREATED_AT)!) === 1729000000000)
check('SHA256 匹配', bytesEq(pack.chunks.get(TSPK.TAG.SHA256)!, fileHash))

function beNumber(b: Uint8Array): number {
  let v = 0
  for (const x of b) v = v * 256 + x
  return v
}

// 3) OTS 解析（日历真实格式：裸 Timestamp，初始消息 = 文件哈希）
const otsPending = await parseOts(pack.chunks.get(TSPK.TAG.OTS_RECEIPT)!, fileHash)
check('OTS pending 解析', otsPending.attestations.length === 1 && otsPending.attestations[0]!.kind === 'pending')
check('OTS pending digest = 文件哈希', otsPending.attestations[0]!.digest !== null && toHex(otsPending.attestations[0]!.digest!) === toHex(fileHash))
check('OTS pending uri', otsPending.attestations[0]!.kind === 'pending' && otsPending.attestations[0]!.uri.includes('opentimestamps.org'))
check('OTS 完整解析', !otsPending.degraded)

const btc = await fakeBitcoinOts(fileHash, 870000)
const otsBtc = await parseOts(btc.receipt, fileHash)
const a0 = otsBtc.attestations[0]
check('OTS bitcoin 锚定高度', a0?.kind === 'bitcoin' && a0.height === 870000)
check('OTS bitcoin 重放摘要', a0?.digest !== null && a0?.digest !== undefined && toHex(a0.digest) === toHex(btc.attested))

const otsWrapped = await parseOts(magicWrappedOts(fileHash), undefined)
check('OTS 兼容 DetachedTimestampFile 头', otsWrapped.attestations[0]?.kind === 'pending' && toHex(otsWrapped.attestations[0]!.digest!) === toHex(fileHash))

// 3b) 日历 URI 白名单（防恶意回执发起任意请求）
check('OTS 白名单放行官方日历', isAllowedCalendarUri('https://alice.btc.calendar.opentimestamps.org') && isAllowedCalendarUri('https://a.pool.opentimestamps.org/digest'))
check('OTS 白名单拒绝内网/外域/非 https', !isAllowedCalendarUri('http://a.pool.opentimestamps.org/digest') && !isAllowedCalendarUri('https://192.168.1.1/timestamp') && !isAllowedCalendarUri('https://evil.example.com/timestamp') && !isAllowedCalendarUri('not a url'))

// 4) 分片文本异常分支
check('少于 k 片报错', (() => {
  try { checkConsistency(parsed.slice(0, 2)); return false } catch { return true }
})())
check('同 index 不同 k 报错', (() => {
  try {
    parseShares(texts.join('\n') + '\nTSK1:4:' + texts[0]!.split(':')[2])
    return false
  } catch { return true }
})())
check('未知分片版本报错', (() => {
  try { parseShareLine('TSK2:3:AAAA'); return false } catch { return true }
})())
check('垃圾文本报错', (() => {
  try { parseShares('hello world'); return false } catch { return true }
})())

// 4b) 换成 secp256k1 基域后，n 不再受 255 限制
const big = await shamirSplit(key, 300, 5)
check('n=300 坐标宽度升到 2 字节', big.every((s) => s.length === 34))
check('n=300 坐标占末 2 字节并与解析一致', big.every((s) => {
  const tail = readTailCoord(s)
  return tail === unpackShare(s).x && tail >= 1 && tail <= 300
}))
const bigParsed = parseShares(big.map((s) => encodeShare(5, s)).join('\n'))
check('n=300 解析出 300 个互异坐标', bigParsed.length === 300 && new Set(bigParsed.map((s) => s.index)).size === 300)
check('n=300 坐标落在 1..300', bigParsed.every((s) => s.index >= 1 && s.index <= 300))
check('n=300 前 5 片可恢复', bytesEq(await shamirCombine(bigParsed.slice(0, 5).map((s) => s.payload)), key))
check('n=300 末 5 片可恢复', bytesEq(await shamirCombine(bigParsed.slice(-5).map((s) => s.payload)), key))
check('n=300 跨区间挑片可恢复', bytesEq(
  await shamirCombine([bigParsed[0]!, bigParsed[150]!, bigParsed[299]!, bigParsed[7]!, bigParsed[42]!].map((s) => s.payload)),
  key,
))
check('n=65536 坐标宽度升到 3 字节', (await shamirSplit(key, 65536, 3)).every((s) => s.length === 35))
check('k=1 报错', await shamirSplit(key, 3, 1).then(() => false, () => true))
check('k > n 报错', await shamirSplit(key, 3, 4).then(() => false, () => true))

// 4c) 素域下的损坏 / 恶意分片
check('y ≥ p 的分片被拒绝', (() => {
  const bad = new Uint8Array(33)
  bad.fill(0xff, 0, 32) // y = 2²⁵⁶ − 1 > p（y 在前 32 字节）
  bad[32] = 1 // x = 1
  try { unpackShare(bad); return false } catch { return true }
})())
check('x=0 的分片被 combine 拒绝', await shamirCombine([
  Uint8Array.from([0, ...new Uint8Array(32)]),
  parsed[0]!.payload,
]).then(() => false, () => true))
check('重复坐标被 combine 拒绝', await shamirCombine([parsed[0]!.payload, parsed[0]!.payload]).then(() => false, () => true))
check('长度不足 33 字节被拒绝', (() => {
  try { unpackShare(new Uint8Array(32)); return false } catch { return true }
})())
check('秘密 ≥ p 时拒绝分片（绝不取模）', await shamirSplit(new Uint8Array(32).fill(0xff), 3, 2).then(() => false, () => true))
check('randomFieldBytes 2000 次全部 < p', (() => {
  for (let i = 0; i < 2000; i++) {
    const b = randomFieldBytes()
    if (b.length !== 32 || bytesToField(b) >= P) return false
  }
  return true
})())
check('MAX_SHARES 与坐标宽度自洽', MAX_SHARES === 0xffffff)

// 5) 错误 key 解密必须失败（GCM 认证）
const wrongKey = randomBytes(32)
check('错 key 解密被 GCM 拒绝', await aesDecrypt(wrongKey, iv, ct).then(() => false, () => true))


// 6) 压缩：ALGO 编码、跳过策略、未知编号（zstd 需 wasm，交由浏览器 E2E）
const { ALGO, compressData, decompressData } = await import('../src/core/compress.ts')
const compressible = new TextEncoder().encode('压缩测试 compressible payload '.repeat(2000))
const gz = await compressData(compressible, ALGO.GZIP)
check('gzip 压缩生效且可还原', gz.algo === ALGO.GZIP && bytesEq(await decompressData(gz.bytes, gz.algo), compressible))
const keep = await compressData(compressible, ALGO.NONE)
check('选择不压缩时原样返回', keep.algo === ALGO.NONE && bytesEq(keep.bytes, compressible))
const noise = randomBytes(64 * 1024)
const skipped = await compressData(noise, ALGO.GZIP)
check('不可压缩数据自动跳过', skipped.algo === ALGO.NONE && bytesEq(skipped.bytes, noise))
check('未知算法编号报错', await decompressData(compressible, 9).then(() => false, () => true))
const packNoAlgo = tlvBuild(TSPK.MAGIC, TSPK.VERSION, [{ tag: TSPK.TAG.DATA, value: compressible }], {
  lastTag: TSPK.TAG.DATA,
})
check('缺 ALGO 的旧文件视为不压缩', (tlvParse(TSPK.MAGIC, packNoAlgo).chunks.get(TSPK.TAG.ALGO)?.[0] ?? 0) === ALGO.NONE)

// 7) k / n 的 4 字节大端编码（n 可到 16,777,215，一字节装不下）
const { u32beBytes, beBytesToUint } = await import('../src/core/tlv.ts')
check('u32beBytes / beBytesToUint 往返', [2, 255, 256, 65535, 100000, 16777215].every((v) => beBytesToUint(u32beBytes(v)) === v))
check('旧的单字节 k 也能读', beBytesToUint(Uint8Array.from([7])) === 7)

// 8) ZIP 打包：store 模式 + 十万条目时的 ZIP64 头
const { buildZip } = await import('../src/core/zip.ts')
const zipSmall = buildZip([
  { name: 'a.txt', data: new TextEncoder().encode('hello\n') },
  { name: '中文_b.txt', data: new TextEncoder().encode('世界\n') },
])
const zs = new Uint8Array(await zipSmall.arrayBuffer())
const zsv = new DataView(zs.buffer)
check('小 zip 的 EOCD 条目数正确', zsv.getUint16(zs.length - 22 + 10, true) === 2 && zsv.getUint32(zs.length - 22, true) === 0x06054b50)

const zipMany = buildZip(
  Array.from({ length: 70000 }, (_, i) => ({ name: `share_${i + 1}.txt`, data: new TextEncoder().encode(`TSK1:3:A${i}`) })),
)
const zm = new Uint8Array(await zipMany.arrayBuffer())
const zmv = new DataView(zm.buffer)
const eocdPos = zm.length - 22
check(
  '7 万条目时 EOCD 写 0xffff 并带 ZIP64 记录',
  zmv.getUint16(eocdPos + 10, true) === 0xffff &&
    zmv.getUint32(eocdPos - 20, true) === 0x07064b50 &&
    zmv.getUint32(eocdPos - 76, true) === 0x06064b50 &&
    Number(zmv.getBigUint64(eocdPos - 76 + 32, true)) === 70000,
)

process.exit(failed ? 1 : 0)
