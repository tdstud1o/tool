// 最小 ZIP 写入器：只做 store（不压缩）——分片是 base64 文本，压不动多少，
// 而我们要的是「一次下载拿到 n 个文件」，不是省那几个 KB。
//
// 为什么需要 ZIP64：ZIP 经典 EOCD 的条目数是 16 位，上限 65535 个文件。
// n 可以到 16,777,215，十万片就已经超了，所以条目数超限时写 ZIP64 记录。
// 单文件大小与偏移仍按 32 位写（总量不可能超 4 GB）。

const CRC_TABLE = (() => {
  const t = new Uint32Array(256)
  for (let i = 0; i < 256; i++) {
    let c = i
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
    t[i] = c >>> 0
  }
  return t
})()

function crc32(buf: Uint8Array): number {
  let c = 0xffffffff
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]!) & 0xff]! ^ (c >>> 8)
  return (c ^ 0xffffffff) >>> 0
}

export interface ZipEntry {
  name: string
  data: Uint8Array
}

export function buildZip(entries: ZipEntry[]): Blob {
  const enc = new TextEncoder()
  const parts: BlobPart[] = []
  const central: Uint8Array[] = []
  let offset = 0

  for (const e of entries) {
    const name = enc.encode(e.name)
    const crc = crc32(e.data)

    const local = new Uint8Array(30 + name.length)
    const lv = new DataView(local.buffer)
    lv.setUint32(0, 0x04034b50, true) // local file header
    lv.setUint16(4, 20, true) // version needed
    lv.setUint16(6, 0x0800, true) // flag: 文件名为 UTF-8
    lv.setUint16(8, 0, true) // method: store
    lv.setUint16(10, 0, true) // mod time
    lv.setUint16(12, 0x21, true) // mod date = 1980-01-01
    lv.setUint32(14, crc, true)
    lv.setUint32(18, e.data.length, true) // compressed
    lv.setUint32(22, e.data.length, true) // uncompressed
    lv.setUint16(26, name.length, true)
    lv.setUint16(28, 0, true) // extra len
    local.set(name, 30)
    parts.push(local, e.data)

    const cd = new Uint8Array(46 + name.length)
    const cv = new DataView(cd.buffer)
    cv.setUint32(0, 0x02014b50, true) // central directory header
    cv.setUint16(4, 20, true) // version made by
    cv.setUint16(6, 20, true) // version needed
    cv.setUint16(8, 0x0800, true)
    cv.setUint16(10, 0, true)
    cv.setUint16(12, 0, true)
    cv.setUint16(14, 0x21, true)
    cv.setUint32(16, crc, true)
    cv.setUint32(20, e.data.length, true)
    cv.setUint32(24, e.data.length, true)
    cv.setUint16(28, name.length, true)
    // 30 extra len / 32 comment len / 34 disk / 36 internal attr / 38 external attr 都为 0
    cv.setUint32(42, offset, true) // 本地头在文件中的偏移
    cd.set(name, 46)
    central.push(cd)

    offset += local.length + e.data.length
  }

  const cdSize = central.reduce((a, c) => a + c.length, 0)
  const cdOffset = offset
  for (const c of central) parts.push(c)

  const count = entries.length
  const needZip64 = count > 0xffff
  if (needZip64) {
    // ZIP64 EOCD record（56 字节）
    const z = new Uint8Array(56)
    const zv = new DataView(z.buffer)
    zv.setUint32(0, 0x06064b50, true)
    zv.setBigUint64(4, 44n, true) // 记录体长度
    zv.setUint16(12, 45, true) // version made by
    zv.setUint16(14, 45, true) // version needed
    zv.setUint32(16, 0, true) // this disk
    zv.setUint32(20, 0, true) // cd start disk
    zv.setBigUint64(24, BigInt(count), true)
    zv.setBigUint64(32, BigInt(count), true)
    zv.setBigUint64(40, BigInt(cdSize), true)
    zv.setBigUint64(48, BigInt(cdOffset), true)
    parts.push(z)

    // ZIP64 EOCD locator（20 字节）
    const loc = new Uint8Array(20)
    const lcv = new DataView(loc.buffer)
    lcv.setUint32(0, 0x07064b50, true)
    lcv.setUint32(4, 0, true)
    lcv.setBigUint64(8, BigInt(cdOffset + cdSize), true)
    lcv.setUint32(16, 1, true)
    parts.push(loc)
  }

  // EOCD（22 字节）。条目数超限时写 0xffff，让解压器转去读 ZIP64 记录
  const eocd = new Uint8Array(22)
  const ev = new DataView(eocd.buffer)
  ev.setUint32(0, 0x06054b50, true)
  ev.setUint16(8, Math.min(count, 0xffff), true)
  ev.setUint16(10, Math.min(count, 0xffff), true)
  ev.setUint32(12, cdSize, true)
  ev.setUint32(16, cdOffset, true)
  parts.push(eocd)

  return new Blob(parts, { type: 'application/zip' })
}
