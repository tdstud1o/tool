// 端到端往返测试：node --experimental-strip-types test/roundtrip.ts
import { randomBytes, aesEncrypt, aesDecrypt, sha256 } from '../src/core/crypto.ts'
import { TSPK, TSCF, tlvBuild, tlvParse, u32beBytes, u64beBytes } from '../src/core/tlv.ts'
import { shamirSplit, shamirSplitMulti, shamirCombine, readY } from '../src/core/shamir.ts'
import { fakeK, kPattern, nextK, padKs, sizeStats } from '../src/core/levels.ts'
import { toB64 } from '../src/core/b64.ts'
import { MAX_SHARES, P, bytesToField, randomFieldBytes } from '../src/core/gfp.ts'
import { coordText, encodeShare, parseShareLine, parseShares, checkConsistency } from '../src/core/format.ts'
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
  { lastTag: TSCF.TAG.CIPHERTEXT },
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
], { lastTag: TSCF.TAG.CIPHERTEXT })

// —— 模拟恢复侧 ——
const { shares, xs } = await shamirSplit(key, 5, 3)
const texts = shares.map((s, i) => encodeShare({ index: xs[i]!, wide: false, levels: [{ k: 3, payload: s }] }))
const parsed = parseShares(texts.join('\n'))
const ks0 = checkConsistency(parsed, 3)
const k = ks0[0]!
const recoveredKey = await shamirCombine(
  parsed.slice(0, k).map((s) => s.levels[0]!.payload),
  parsed.slice(0, k).map((s) => s.index),
)
check('Shamir combine = 原 key', bytesEq(recoveredKey, key))
check('每组密钥材料恒 32 字节', parsed.every((s) => s.levels[0]!.payload.length === 32))
check('分片文本形如 TSK1:x:k:y', /^TSK1:\d+:\d+:[A-Za-z0-9+/=]+$/.test(texts[0]!))

check('坐标在分片前缀里且互不相同', (() => {
  const idx = parsed.map((s) => s.index)
  return new Set(idx).size === idx.length && idx.every((v) => v >= 1 && v <= 5)
})())
check('y 就是载荷本身（32 字节大端）', (() => {
  const pay = parsed[0]!.levels[0]!.payload
  return readY(pay) === bytesToField(pay)
})())
check('解析出的坐标与拆分时给的 x 一致', parsed.every((s, i) => s.index === xs[i]))

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
    const s0 = parsed[0]!
    parseShares(texts.join('\n') + `\nTSK1:${s0.index}:4:${toB64(s0.levels[0]!.payload)}`)
    return false
  } catch { return true }
})())
check('未知分片版本报错', (() => {
  try { parseShareLine('TSK2:3:3:AAAA'); return false } catch { return true }
})())
check('垃圾文本报错', (() => {
  try { parseShares('hello world'); return false } catch { return true }
})())

// 4b) 换成 secp256k1 基域后，n 不再受 255 限制；坐标只写在文本前缀里
const big = await shamirSplit(key, 300, 5)
check('n=300 每组仍恒 32 字节', big.shares.every((s) => s.length === 32))
check('n=300 坐标占 1..300 且互异', big.xs.length === 300 && new Set(big.xs).size === 300 && big.xs.every((v) => v >= 1 && v <= 300))
const bigParsed = parseShares(
  big.shares.map((s, i) => encodeShare({ index: big.xs[i]!, wide: false, levels: [{ k: 5, payload: s }] })).join('\n'),
)
check('n=300 解析出 300 个互异坐标', bigParsed.length === 300 && new Set(bigParsed.map((s) => s.index)).size === 300)
check('n=300 坐标落在 1..300', bigParsed.every((s) => s.index >= 1 && s.index <= 300))
check('n=300 前 5 片可恢复', bytesEq(
  await shamirCombine(bigParsed.slice(0, 5).map((s) => s.levels[0]!.payload), bigParsed.slice(0, 5).map((s) => s.index)),
  key,
))
check('n=300 末 5 片可恢复', bytesEq(
  await shamirCombine(bigParsed.slice(-5).map((s) => s.levels[0]!.payload), bigParsed.slice(-5).map((s) => s.index)),
  key,
))
check('n=300 跨区间挑片可恢复', bytesEq(
  await shamirCombine(
    [bigParsed[0]!, bigParsed[150]!, bigParsed[299]!, bigParsed[7]!, bigParsed[42]!].map((s) => s.levels[0]!.payload),
    [bigParsed[0]!, bigParsed[150]!, bigParsed[299]!, bigParsed[7]!, bigParsed[42]!].map((s) => s.index),
  ),
  key,
))
check('n=65536 时每组依然 32 字节（x 不进载荷）', (await shamirSplit(key, 65536, 3)).shares.every((s) => s.length === 32))
check('k=1 合法：单片即秘密本身', await (async () => {
  const r = await shamirSplit(key, 4, 1)
  return (await shamirCombine([r.shares[2]!], [r.xs[2]!])).every((b, i) => b === key[i])
})())
check('0 片报错', await shamirCombine([], []).then(() => false, () => true))
check('k > n 报错', await shamirSplit(key, 3, 4).then(() => false, () => true))

// 4c) 素域下的损坏 / 恶意分片
check('y ≥ p 的分片被拒绝', (() => {
  const bad = new Uint8Array(32)
  bad.fill(0xff) // y = 2²⁵⁶ − 1 > p
  try { readY(bad); return false } catch { return true }
})())
check('x=0 的分片被 combine 拒绝', await shamirCombine(
  [randomFieldBytes(), parsed[0]!.levels[0]!.payload],
  [0, parsed[0]!.index],
).then(() => false, () => true))
check('重复坐标被 combine 拒绝', await shamirCombine(
  [parsed[0]!.levels[0]!.payload, parsed[0]!.levels[0]!.payload],
  [parsed[0]!.index, parsed[0]!.index],
).then(() => false, () => true))
check('载荷长度不是 32 字节被拒绝', (() => {
  try { readY(new Uint8Array(31)); return false } catch { return true }
})())
check('载荷长度不是 32 字节被拒绝（33 字节）', (() => {
  try { readY(new Uint8Array(33)); return false } catch { return true }
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
const { beBytesToUint } = await import('../src/core/tlv.ts')
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

// 9) 多层：一个密文套多份明文，一片里带齐每一组的密钥材料
const keyA = randomFieldBytes()
const keyB = randomFieldBytes()
const keyC = randomFieldBytes()
const LEVEL_KS = [2, 4, 6]
const multi = await shamirSplitMulti([keyA, keyB, keyC], 7, LEVEL_KS)
check('多层拆分：每人 = 3 × 32 字节', multi.shareLen === 3 * 32 && multi.count === 7 && multi.m === 3)
check('多层拆分：每人一个坐标', multi.xs.length === 7 && new Set(multi.xs).size === 7)

const UNIT = 32
const multiTexts: string[] = []
for (let i = 0; i < multi.count; i++) {
  const groups: string[] = []
  for (let j = 0; j < 3; j++) {
    const from = i * multi.shareLen + j * UNIT
    groups.push(`${LEVEL_KS[j]}:${toB64(multi.buffer.subarray(from, from + UNIT))}`)
  }
  multiTexts.push(['TSK1', String(multi.xs[i]), groups.join(',')].join(':'))
}
const mp = parseShares(multiTexts.join('\n'))
check('多层分片解析出 3 组', mp.length === 7 && mp.every((s) => s.levels.length === 3))
check('多层各组 k 正确', mp.every((s) => s.levels.map((l) => l.k).join('/') === '2/4/6'))
check('多层共用一个坐标（x 只在文本里出现一次）', mp.every((s, i) => s.index === multi.xs[i]))
check('多层 k 一致性校验通过', checkConsistency(mp, 2).join('/') === '2/4/6')

// 9b) 坐标：单层紧凑（1..n），多层定宽随机（不泄露 n）
check('coordText 单层不补零', coordText(7, false) === '7')
check('coordText 多层补到 8 位', coordText(7, true) === '00000007')
check('多层拆分标记 wide', multi.wide === true)
check(
  '多层坐标落在 [1, MAX_SHARES] 且远不只是 1..n',
  multi.xs.every((x) => x >= 1 && x <= MAX_SHARES) && multi.xs.some((x) => x > 1000),
)
const single = await shamirSplit(keyA, 5, 3)
check(
  '单层仍是 1..n 紧凑坐标',
  single.wide === false && [...single.xs].sort((a, b) => a - b).join(',') === '1,2,3,4,5',
)
check('8 位补零坐标可解析且数值不变', parseShareLine(`TSK1:00000007:3:${toB64(keyA)}`)?.index === 7)
check('补零坐标解析后标记 wide', parseShareLine(`TSK1:00000007:3:${toB64(keyA)}`)?.wide === true)
check('第 1 层 2 片还原 keyA', bytesEq(
  await shamirCombine(mp.slice(0, 2).map((s) => s.levels[0]!.payload), mp.slice(0, 2).map((s) => s.index)),
  keyA,
))
check('第 2 层 4 片还原 keyB', bytesEq(
  await shamirCombine(mp.slice(0, 4).map((s) => s.levels[1]!.payload), mp.slice(0, 4).map((s) => s.index)),
  keyB,
))
check('第 3 层 6 片还原 keyC', bytesEq(
  await shamirCombine(mp.slice(0, 6).map((s) => s.levels[2]!.payload), mp.slice(0, 6).map((s) => s.index)),
  keyC,
))
check('第 2 层只给 2 片时插值出错误密钥（不是 keyB）', !bytesEq(
  await shamirCombine(mp.slice(0, 2).map((s) => s.levels[1]!.payload), mp.slice(0, 2).map((s) => s.index)),
  keyB,
))
check('组数不一致的分片被拒绝', (() => {
  try {
    checkConsistency([mp[0]!, { ...mp[1]!, levels: mp[1]!.levels.slice(0, 2) }], 2)
    return false
  } catch { return true }
})())
check('坐标越界被解析器拒绝', (() => {
  try {
    parseShareLine(`TSK1:0:2:${toB64(mp[0]!.levels[0]!.payload)}`)
    return false
  } catch { return true }
})())
check('诱饵组：没有秘密也能拆，y 照样是 32 字节随机值', await (async () => {
  const pad = await shamirSplitMulti([keyA, null, null], 5, [2, 999, 1000])
  if (pad.m !== 3 || pad.shareLen !== 96) return false
  const texts = Array.from({ length: pad.count }, (_, i) => {
    const groups: string[] = []
    for (let j = 0; j < 3; j++) {
      const from = i * pad.shareLen + j * UNIT
      const b64 = toB64(pad.buffer.subarray(from, from + UNIT))
      // 混装：第 1 组带 k，后两组是裸 y（没勾「显示k」的层长这样）
      groups.push(j === 0 ? `2:${b64}` : b64)
    }
    return ['TSK1', String(pad.xs[i]), groups.join(',')].join(':')
  })
  const p = parseShares(texts.join('\n'))
  const recovered = await shamirCombine(
    [p[0]!.levels[0]!.payload, p[1]!.levels[0]!.payload],
    [p[0]!.index, p[1]!.index],
  )
  return (
    bytesEq(recovered, keyA) &&
    p.every(
      (s) =>
        s.levels.length === 3 &&
        s.levels[0]!.k === 2 &&
        s.levels[1]!.k === null &&
        s.levels[2]!.k === null &&
        s.levels[1]!.payload.length === 32,
    )
  )
})())

// 9c) 「显示k」：每层独立决定写不写 k；损坏格式一律报「密钥损坏」
const yB9 = toB64(randomBytes(32))
const yC9 = toB64(randomBytes(32))
check('裸 y 组解析为 k=null', parseShareLine(`TSK1:7:${yB9}`)?.levels[0]?.k === null)
check('k:y 组解析出 k', parseShareLine(`TSK1:7:5:${yB9}`)?.levels[0]?.k === 5)
check('混装：带 k 与裸 y 组混排', (() => {
  const e = parseShareLine(`TSK1:7:3:${yB9},${yC9},9:${yB9}`)
  return !!e && e.levels.map((l) => String(l.k)).join('/') === '3/null/9'
})())
check('encodeShare/parse 往返（k=null 与 k 混装）', (() => {
  const text = encodeShare({
    index: 7,
    wide: true,
    levels: [{ k: null, payload: keyA }, { k: 4, payload: randomBytes(32) }],
  })
  const p = parseShareLine(text)
  return p?.index === 7 && p.wide === true && p.levels[0]?.k === null && p.levels[1]?.k === 4
})())
check('一组的冒号多于一个 → 密钥损坏', (() => {
  try {
    parseShareLine(`TSK1:7:3:${yB9}:5`)
    return false
  } catch (e) {
    return String(e).includes('密钥损坏')
  }
})())
check('既不是 k 也不是 y 的段 → 密钥损坏', (() => {
  try {
    parseShareLine(`TSK1:7:hello,${yB9}`)
    return false
  } catch (e) {
    return String(e).includes('密钥损坏')
  }
})())
check('k=0 / k 超上限 → 密钥损坏', (() => {
  try {
    parseShareLine(`TSK1:7:0:${yB9}`)
    return false
  } catch {
    return true
  }
})())
check('checkConsistency：没写 k 的组返回 null，首层片数用密文 k 判断', (() => {
  const t1 = parseShareLine(`TSK1:3:${yB9},${yC9}`)!
  const t2 = parseShareLine(`TSK1:4:${yB9},${yC9}`)!
  const ks = checkConsistency([t1, t2], 2)
  return ks.map((k) => String(k)).join(',') === 'null,null'
})())
check('checkConsistency：一端写 k 一端没写 → 不是同一批', (() => {
  const t1 = parseShareLine(`TSK1:3:2:${yB9}`)!
  const t2 = parseShareLine(`TSK1:4:${yB9}`)!
  try {
    checkConsistency([t1, t2])
    return false
  } catch {
    return true
  }
})())

// 10) 密文链：NEXT 在 TSPK 内层，且是末块
/** 按物理顺序读出 tag 序列（不做排序），用来断言块的真实排布 */
function tagOrder(b: Uint8Array): number[] {
  const out: number[] = []
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength)
  let off = 5
  while (off + 5 <= b.length) {
    const tag = b[off]!
    const len = dv.getUint32(off + 1, false)
    out.push(tag)
    off += 5 + len
  }
  return out
}

const ivA = randomBytes(12)
const ivB = randomBytes(12)
// 最深层：内层没有 NEXT
const innerB = tlvBuild(TSPK.MAGIC, TSPK.VERSION, [{ tag: TSPK.TAG.DATA, value: new TextEncoder().encode('B') }], {
  lastTag: TSPK.TAG.DATA,
})
const tscfB = tlvBuild(
  TSCF.MAGIC,
  TSCF.VERSION,
  [
    { tag: TSCF.TAG.K, value: u32beBytes(4) },
    // 真实的多层链里没有 N：n 只写在单层密文上，链里不出现
    { tag: TSCF.TAG.IV, value: ivB },
    { tag: TSCF.TAG.CIPHERTEXT, value: await aesEncrypt(keyB, ivB, innerB) },
  ],
  { lastTag: TSCF.TAG.CIPHERTEXT },
)
// 上一层：下一层的整段 TSCF 塞进内层最后一块，再整体加密
const innerA = tlvBuild(
  TSPK.MAGIC,
  TSPK.VERSION,
  [
    { tag: TSPK.TAG.FILENAME, value: new TextEncoder().encode('a.bin') },
    { tag: TSPK.TAG.DATA, value: new TextEncoder().encode('A') },
    { tag: TSPK.TAG.NEXT, value: tscfB },
  ],
  { lastTag: TSPK.TAG.NEXT },
)
const tscfA = tlvBuild(
  TSCF.MAGIC,
  TSCF.VERSION,
  [
    { tag: TSCF.TAG.K, value: u32beBytes(3) },
    { tag: TSCF.TAG.IV, value: ivA },
    { tag: TSCF.TAG.CIPHERTEXT, value: await aesEncrypt(keyA, ivA, innerA) },
  ],
  { lastTag: TSCF.TAG.CIPHERTEXT },
)
const packA = tlvParse(TSPK.MAGIC, innerA)
const packOuter = tlvParse(TSCF.MAGIC, tscfA)
check('0x13 NEXT 在内层并原样保存下一层密文', bytesEq(packA.chunks.get(TSPK.TAG.NEXT)!, tscfB))
check('内层块序 FILENAME→DATA→NEXT，NEXT 垫底', tagOrder(innerA).join(',') === '1,17,19')
check('外层只剩 K→IV→CIPHERTEXT，不暴露链结构', tagOrder(tscfA).join(',') === '2,4,5')
check(
  '外层出现 0x13 时说明写错了层',
  packOuter.chunks.get(0x13) === undefined,
)
check('内层 DATA 不再是末块但有完整长度', packA.chunks.get(TSPK.TAG.DATA)!.length === 1)
check('嵌套的 TSCF 可独立解析', (() => {
  const n = tlvParse(TSCF.MAGIC, packA.chunks.get(TSPK.TAG.NEXT)!)
  let k = 0
  for (const b of n.chunks.get(TSCF.TAG.K)!) k = k * 256 + b
  return k === 4 && n.chunks.get(TSCF.TAG.CIPHERTEXT) !== undefined
})())
check('多层链里的 TSCF 不含 N，解析端不依赖它', (() => {
  const n = tlvParse(TSCF.MAGIC, tscfB)
  return n.chunks.get(TSCF.TAG.N) === undefined && n.chunks.get(TSCF.TAG.K) !== undefined
})())
check('最深层内层没有 NEXT（DATA 仍垫底）', tagOrder(innerB).join(',') === '17')
check('单层密文的末块仍是 CIPHERTEXT', tagOrder(tscfB).join(',') === '2,4,5')
// 11) 假层 k 与密钥串对齐（诱饵组）
check('nextK：只有一个真层时 +1', nextK([3]) === 4)
check('nextK：等差序列顺着走（3,4 → 5）', nextK([3, 4]) === 5)
// 两个点时等差/等比都能解释（4,8 既 +4 也 ×2），约定优先按等差走
check('nextK：两点歧义时按等差续（4,8 → 12）', nextK([4, 8]) === 12)
check('nextK：三点等比继续放大（4,8,16 → 32）', nextK([4, 8, 16]) === 32)
check('nextK：无规律时 +1（3,7,8 → 9）', nextK([3, 7, 8]) === 9)
check('fakeK 必定大于最后一层真层 k（等差续接）', fakeK([3, 4], 5) === 5 && fakeK([3], 5) === 4)
check('fakeK 跟随等比规律，不被 n 封顶', fakeK([4, 8, 16], 10) === 32)

check('k 等差规律被识别', kPattern([3, 5, 7])?.type === 'arith' && kPattern([3, 5, 7])?.step === 2)
check('k 等比规律被识别', kPattern([4, 8, 16])?.type === 'geo' && kPattern([4, 8, 16])?.step === 2)
check('k 无规律时返回 null', kPattern([3, 7, 8]) === null && kPattern([5]) === null)
const stats2 = sizeStats([1000, 1000, 4000])
check('sizeStats 浮动幅度 = |均值 − 中位数|', stats2.mean === 2000 && stats2.spread === 1000)
check('单文件时给 5% 浮动（差值恒为 0）', (() => {
  const s1 = sizeStats([1000])
  return s1.mean === 1000 && s1.spread === 50
})())

check('padKs 补够 32 组：真 2 + 假 1 → 29 组诱饵', (() => {
  const chain = [3, 4, 5]
  const pad = padKs(chain, 32, [3, 4])
  return pad.length === 29 && pad[0] === 6 && pad[28] === 34
})())
check('padKs 已够长时不补', padKs([3, 4, 5], 3, [3, 4]).length === 0)
check('padKs 顺着等比规律放大', (() => {
  const pad = padKs([4, 8, 16], 6, [4, 8, 16])
  return pad.join(',') === '32,64,128'
})())
check('假层 k 恒大于末层真层 k，允许超过 n（唯一允许的一层）', fakeK([3, 4], 5) > 4 && fakeK([4, 8, 16], 10) > 10)

// kPattern 本身对 3 点等比给出 geo
check('三点等比被识别为等比', kPattern([4, 8, 16])?.type === 'geo')

// 12) 假层永远解不开：共享的密钥 ≠ 加密用的密钥 → GCM 校验失败
const fakeTrueKey = randomFieldBytes()
const fakeSplitKey = randomFieldBytes()
const fakeIv = randomBytes(12)
const fakeBody = tlvBuild(
  TSPK.MAGIC,
  TSPK.VERSION,
  [{ tag: TSPK.TAG.DATA, value: new TextEncoder().encode('乱码') }],
  { lastTag: TSPK.TAG.DATA },
)
const fakeCt = await aesEncrypt(fakeTrueKey, fakeIv, fakeBody)
const fakeShares = await shamirSplit(fakeSplitKey, 5, 3)
const fakeP1 = {
  index: fakeShares.xs[0]!,
  levels: [{ k: 3, payload: fakeShares.shares[0]! }],
}
const fakeP2 = {
  index: fakeShares.xs[1]!,
  levels: [{ k: 3, payload: fakeShares.shares[1]! }],
}
const fakeP3 = {
  index: fakeShares.xs[2]!,
  levels: [{ k: 3, payload: fakeShares.shares[2]! }],
}
const fakeBack = await shamirCombine(
  [fakeP1, fakeP2, fakeP3].map((s) => s.levels[0]!.payload),
  [fakeP1, fakeP2, fakeP3].map((s) => s.index),
)
check('假层：3 片确实插值出了那把"假密钥"', bytesEq(fakeBack, fakeSplitKey))
check('假层：拿这把密钥解密真密文必定失败', await aesDecrypt(fakeBack, fakeIv, fakeCt).then(() => false, () => true))

process.exit(failed ? 1 : 0)
