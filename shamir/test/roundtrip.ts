// 端到端往返测试：node --experimental-strip-types test/roundtrip.ts
import { randomBytes, aesEncrypt, aesDecrypt, sha256 } from '../src/core/crypto.ts'
import { SMPK, SMCF, tlvBuild, tlvParse, u64beBytes } from '../src/core/tlv.ts'
import { shamirSplit, shamirCombine } from '../src/core/shamir.ts'
import { encodeShare, parseShares, checkConsistency } from '../src/core/format.ts'
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
  SMCF.MAGIC,
  SMCF.VERSION,
  [
    { tag: SMCF.TAG.CIPHERTEXT, value: new Uint8Array([9, 9, 9]) },
    { tag: SMCF.TAG.K, value: new Uint8Array([3]) },
    { tag: SMCF.TAG.IV, value: iv },
    { tag: SMCF.TAG.N, value: new Uint8Array([5]) },
    { tag: 0x77, value: new Uint8Array([1, 2, 3]) }, // 未知 tag，解析器必须跳过
  ],
  { lastTag: SMCF.LAST_TAG },
)
const back = tlvParse(SMCF.MAGIC, outer)
check('SMCF magic/version', back.version === 1)
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
  SMPK.MAGIC,
  SMPK.VERSION,
  [
    { tag: SMPK.TAG.FILENAME, value: new TextEncoder().encode('cat.jpg') },
    { tag: SMPK.TAG.CREATED_AT, value: u64beBytes(1729000000000) },
    { tag: SMPK.TAG.SHA256, value: fileHash },
    { tag: SMPK.TAG.OTS_RECEIPT, value: otsFixture },
    { tag: SMPK.TAG.DATA, value: data },
  ],
  { lastTag: SMPK.TAG.DATA },
)
const ct = await aesEncrypt(key, iv, inner)
const ctFile = tlvBuild(SMCF.MAGIC, SMCF.VERSION, [
  { tag: 0x01, value: new TextEncoder().encode('cat.jpg') }, // 旧版 FILENAME：新解析器应按未知 tag 跳过
  { tag: SMCF.TAG.K, value: new Uint8Array([3]) },
  { tag: SMCF.TAG.N, value: new Uint8Array([5]) },
  { tag: SMCF.TAG.IV, value: iv },
  { tag: SMCF.TAG.CIPHERTEXT, value: ct },
], { lastTag: SMCF.LAST_TAG })

// —— 模拟恢复侧 ——
const shares = await shamirSplit(key, 5, 3)
const texts = shares.map((s) => encodeShare(3, 5, s))
const parsed = parseShares(texts.join('\n'))
const { k } = checkConsistency(parsed, 3, 5)
const recoveredKey = await shamirCombine(parsed.slice(0, k).map((s) => s.payload))
check('Shamir combine = 原 key', bytesEq(recoveredKey, key))

const outerBack = tlvParse(SMCF.MAGIC, ctFile)
const ctBack = outerBack.chunks.get(SMCF.TAG.CIPHERTEXT)!
const innerBack = await aesDecrypt(recoveredKey, outerBack.chunks.get(SMCF.TAG.IV)!, ctBack)
const pack = tlvParse(SMPK.MAGIC, innerBack)
check('DATA 完整', bytesEq(pack.chunks.get(SMPK.TAG.DATA)!, data))
check('文件名还原', new TextDecoder().decode(pack.chunks.get(SMPK.TAG.FILENAME)!) === 'cat.jpg')
check('CREATED_AT 还原', beNumber(pack.chunks.get(SMPK.TAG.CREATED_AT)!) === 1729000000000)
check('SHA256 匹配', bytesEq(pack.chunks.get(SMPK.TAG.SHA256)!, fileHash))

function beNumber(b: Uint8Array): number {
  let v = 0
  for (const x of b) v = v * 256 + x
  return v
}

// 3) OTS 解析（日历真实格式：裸 Timestamp，初始消息 = 文件哈希）
const otsPending = await parseOts(pack.chunks.get(SMPK.TAG.OTS_RECEIPT)!, fileHash)
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
check('k/n 不一致报错', (() => {
  try {
    parseShares(texts.join('\n') + '\nSHAMIR1:4:7:' + texts[0]!.split(':')[3])
    return false
  } catch { return true }
})())
check('垃圾文本报错', (() => {
  try { parseShares('hello world'); return false } catch { return true }
})())

// 5) 错误 key 解密必须失败（GCM 认证）
const wrongKey = randomBytes(32)
check('错 key 解密被 GCM 拒绝', await aesDecrypt(wrongKey, iv, ct).then(() => false, () => true))

process.exit(failed ? 1 : 0)
