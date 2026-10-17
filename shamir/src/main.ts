import './style.css'
import { SMCF, SMPK, tlvBuild, tlvParse, u64beBytes, beBytesToU64 } from './core/tlv.ts'
import { IV_LEN, KEY_LEN, aesDecrypt, aesEncrypt, randomBytes, sha256 } from './core/crypto.ts'
import { shamirSplit, shamirCombine } from './core/shamir.ts'
import { checkConsistency, encodeShare, parseShares, type ShareEntry } from './core/format.ts'
import { otsStamp, parseOts, verifyAnchorOnline } from './core/ots.ts'
import { toHex } from './core/b64.ts'

// ===== 工具 =====

const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T

function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`
  return `${(n / 1024 ** 3).toFixed(2)} GB`
}

function download(name: string, data: Uint8Array): void {
  const url = URL.createObjectURL(new Blob([data]))
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 3000)
}

async function copyText(text: string, btn: HTMLButtonElement): Promise<void> {
  try {
    await navigator.clipboard.writeText(text)
  } catch {
    const ta = document.createElement('textarea')
    ta.value = text
    document.body.appendChild(ta)
    ta.select()
    document.execCommand('copy')
    ta.remove()
  }
  const old = btn.textContent
  btn.textContent = '已复制'
  setTimeout(() => (btn.textContent = old), 1200)
}

function baseName(name: string): string {
  const i = name.lastIndexOf('.')
  return i > 0 ? name.slice(0, i) : name
}

function uuid(): string {
  if (crypto.randomUUID) return crypto.randomUUID()
  const b = randomBytes(16)
  b[6] = (b[6]! & 0x0f) | 0x40
  b[8] = (b[8]! & 0x3f) | 0x80
  const h = toHex(b)
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`
}

// ===== 主题 =====

const root = document.documentElement
$<HTMLButtonElement>('themeToggle').addEventListener('click', () => {
  const cur = root.dataset.theme === 'dark' ? 'dark' : 'light'
  const next = cur === 'dark' ? 'light' : 'dark'
  root.dataset.theme = next
  try { localStorage.setItem('shamir-theme', next) } catch { /* ignore */ }
})

// ===== Tab 切换 =====

for (const tab of document.querySelectorAll<HTMLButtonElement>('.tab')) {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((t) => t.classList.remove('is-active'))
    tab.classList.add('is-active')
    const v = tab.dataset.view!
    $('view-split').hidden = v !== 'split'
    $('view-restore').hidden = v !== 'restore'
  })
}

// ===== 运行状态：进度条 + 日志 + 控件禁用 =====

class Run {
  private logEl: HTMLElement
  private progEl: HTMLElement
  private barEl: HTMLElement
  private controls: { disable: () => void; restore: () => void }[] = []
  private t0 = 0

  constructor(logId: string, progId: string, controls: { disable: () => void; restore: () => void }[]) {
    this.logEl = $(logId)
    this.progEl = $(progId)
    this.barEl = this.progEl.firstElementChild as HTMLElement
    this.controls = controls
  }

  line(text: string, cls = ''): void {
    const t = ((performance.now() - this.t0) / 1000).toFixed(1)
    const div = document.createElement('div')
    if (cls) div.className = cls
    div.textContent = `[${t}s] ${text}`
    this.logEl.appendChild(div)
    this.logEl.scrollTop = this.logEl.scrollHeight
  }

  prog(pct: number): void {
    this.progEl.hidden = false
    this.progEl.classList.remove('indet')
    this.barEl.style.width = `${pct}%`
  }

  /** 不确定进度（网络等待） */
  indet(): void {
    this.progEl.hidden = false
    this.progEl.classList.add('indet')
  }

  begin(): void {
    this.t0 = performance.now()
    this.logEl.innerHTML = ''
    this.logEl.hidden = false
    this.progEl.hidden = false
    this.prog(3)
    for (const c of this.controls) c.disable()
  }

  end(): void {
    this.prog(100)
    for (const c of this.controls) c.restore()
  }

  fail(): void {
    for (const c of this.controls) c.restore()
    this.progEl.hidden = true
  }
}

// ===== 拆分 =====

let splitFile: File | null = null

function bindDrop(dropId: string, onFile: (f: File) => void): HTMLInputElement {
  const drop = $(dropId)
  const input = document.createElement('input')
  input.type = 'file'
  input.hidden = true
  drop.addEventListener('click', () => { if (!drop.classList.contains('is-disabled')) input.click() })
  drop.addEventListener('keydown', (e) => e.key === 'Enter' && !drop.classList.contains('is-disabled') && input.click())
  input.addEventListener('change', () => input.files![0] && onFile(input.files![0]))
  for (const ev of ['dragover', 'dragenter'] as const)
    drop.addEventListener(ev, (e) => {
      e.preventDefault()
      drop.classList.add('is-drag')
    })
  for (const ev of ['dragleave', 'drop'] as const)
    drop.addEventListener(ev, () => drop.classList.remove('is-drag'))
  drop.addEventListener('drop', (e) => {
    e.preventDefault()
    if (drop.classList.contains('is-disabled')) return
    const f = e.dataTransfer?.files?.[0]
    if (f) onFile(f)
  })
  drop.after(input)
  return input
}

function showSplitFile(f: File): void {
  splitFile = f
  const drop = $('dropSplit')
  drop.classList.add('has-file')
  $('dropSplitText').textContent = `📄 ${f.name} · ${fmtSize(f.size)}${f.type ? ` · ${f.type}` : ''}`
  refreshSplitBtn()
}

const fileSplitInput = bindDrop('dropSplit', showSplitFile)

const inK = $<HTMLInputElement>('inK')
const inN = $<HTMLInputElement>('inN')

function readKn(): { k: number; n: number } | null {
  const k = Math.round(Number(inK.value))
  const n = Math.round(Number(inN.value))
  if (!Number.isFinite(k) || !Number.isFinite(n) || k < 2 || n < 2 || n > 255 || k > n) return null
  return { k, n }
}

function refreshSplitBtn(): void {
  $<HTMLButtonElement>('btnSplit').disabled = !splitFile || !readKn()
}

for (const el of [inK, inN])
  el.addEventListener('input', () => {
    const v = readKn()
    if (v) {
      if (Number(inN.value) < Number(inK.value)) inK.value = inN.value
      if (Number(inK.value) < 2) inK.value = '2'
      if (Number(inN.value) > 255) inN.value = '255'
    }
    refreshSplitBtn()
  })

// ===== 产物命名（本地记住上次选择）=====

const nameOpt = $<HTMLSelectElement>('nameOpt')
const namePrefix = $<HTMLInputElement>('namePrefix')

try {
  const savedOpt = localStorage.getItem('shamir-name-opt')
  if (savedOpt) nameOpt.value = savedOpt
  namePrefix.value = localStorage.getItem('shamir-name-prefix') ?? ''
  $<HTMLInputElement>('otsCheck').checked = localStorage.getItem('shamir-ots') === '1'
} catch { /* ignore */ }

nameOpt.addEventListener('change', () => {
  namePrefix.hidden = nameOpt.value !== 'custom'
  try { localStorage.setItem('shamir-name-opt', nameOpt.value) } catch { /* ignore */ }
  renderProductNames()
})
namePrefix.addEventListener('input', () => {
  try { localStorage.setItem('shamir-name-prefix', namePrefix.value) } catch { /* ignore */ }
  renderProductNames()
})
$<HTMLInputElement>('otsCheck').addEventListener('change', (e) => {
  try { localStorage.setItem('shamir-ots', (e.target as HTMLInputElement).checked ? '1' : '0') } catch { /* ignore */ }
})

/** 按命名选项生成产物词干（不含扩展名） */
function productStem(): string {
  const base = splitFile ? baseName(splitFile.name) : 'file'
  switch (nameOpt.value) {
    case 'date': {
      const d = new Date()
      const ymd = `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, '0')}${String(d.getDate()).padStart(2, '0')}`
      return `${ymd}-${base}`
    }
    case 'uuid':
      return uuid()
    case 'custom':
      return `${namePrefix.value}${base}`
    default:
      return base
  }
}

interface SplitResult {
  stem: string
  ciphertext: Uint8Array
  shareTexts: string[]
}

let splitResult: SplitResult | null = null

const splitRun = new Run('runLog', 'runProg', [
  {
    disable: () => {
      $<HTMLButtonElement>('btnSplit').disabled = true
      inK.disabled = inN.disabled = true
      $<HTMLInputElement>('otsCheck').disabled = true
      fileSplitInput.disabled = true
      $('dropSplit').classList.add('is-disabled')
    },
    restore: () => {
      inK.disabled = inN.disabled = false
      $<HTMLInputElement>('otsCheck').disabled = false
      fileSplitInput.disabled = false
      $('dropSplit').classList.remove('is-disabled')
      refreshSplitBtn()
    },
  },
])

$<HTMLButtonElement>('btnSplit').addEventListener('click', async () => {
  const err = $('splitError')
  const warn = $('splitWarn')
  err.hidden = warn.hidden = true
  const f = splitFile
  const kn = readKn()
  if (!f || !kn) return
  const { k, n } = kn
  const run = splitRun
  run.begin()
  try {
    run.line('读取文件…')
    run.prog(5)
    const fileBytes = new Uint8Array(await f.arrayBuffer())

    run.line(`计算 SHA-256（${fmtSize(f.size)}）…`)
    run.prog(15)
    const fileHash = await sha256(fileBytes)
    run.line(`SHA-256 = ${toHex(fileHash)}`, 'lg-ok')

    // OTS 存证（唯一可能联网的一步，失败不阻断主流程）
    let ots: Uint8Array | null = null
    if ($<HTMLInputElement>('otsCheck').checked) {
      run.line('OTS：向公共日历提交哈希（联网，最长等 20s）…')
      run.indet()
      try {
        ots = await otsStamp(fileHash)
        run.line(`OTS：回执已收到（${ots.length} 字节），将藏进密文`, 'lg-ok')
      } catch (e) {
        run.line(`OTS：提交失败（${e instanceof Error ? e.message : e}），已跳过`, 'lg-err')
        warn.hidden = false
        warn.textContent = `OTS 存证失败（${e instanceof Error ? e.message : e}），已跳过，不影响分片。可稍后重试。`
      }
    }

    run.line('生成 key 并 AES-256-GCM 加密…')
    run.prog(80)
    const key = randomBytes(KEY_LEN)
    const iv = randomBytes(IV_LEN)

    // 内层载荷包：原数据 + 元数据 + 存证，整体进密文
    const innerChunks = [
      { tag: SMPK.TAG.FILENAME, value: new TextEncoder().encode(f.name) },
      { tag: SMPK.TAG.CREATED_AT, value: u64beBytes(Date.now()) },
      { tag: SMPK.TAG.SHA256, value: fileHash },
      ...(f.type ? [{ tag: SMPK.TAG.MIME, value: new TextEncoder().encode(f.type) }] : []),
      ...(ots ? [{ tag: SMPK.TAG.OTS_RECEIPT, value: ots }] : []),
      { tag: SMPK.TAG.DATA, value: fileBytes },
    ]
    const inner = tlvBuild(SMPK.MAGIC, SMPK.VERSION, innerChunks, { lastTag: SMPK.TAG.DATA })
    const ciphertext = await aesEncrypt(key, iv, inner)

    const outer = tlvBuild(
      SMCF.MAGIC,
      SMCF.VERSION,
      [
        { tag: SMCF.TAG.FILENAME, value: new TextEncoder().encode(f.name) },
        { tag: SMCF.TAG.K, value: new Uint8Array([k]) },
        { tag: SMCF.TAG.N, value: new Uint8Array([n]) },
        { tag: SMCF.TAG.IV, value: iv },
        { tag: SMCF.TAG.CIPHERTEXT, value: ciphertext },
      ],
      { lastTag: SMCF.LAST_TAG },
    )

    run.line(`Shamir 分片（k=${k}/n=${n}）…`)
    run.prog(92)
    const shares = await shamirSplit(key, n, k)
    const shareTexts = shares.map((s) => encodeShare(k, n, s))

    splitResult = { stem: productStem(), ciphertext: outer, shareTexts }
    run.line('完成 ✓', 'lg-ok')
    run.end()
    renderSplitResult(f, k, n, ots)
  } catch (e) {
    run.fail()
    err.hidden = false
    err.textContent = `拆分失败：${e instanceof Error ? e.message : String(e)}`
  }
})

function renderProductNames(): void {
  if (!splitResult) return
  const stem = productStem()
  splitResult.stem = stem
  $('ctName').textContent = `${stem}.smcf`
  document.querySelectorAll('.share-row').forEach((row, i) => {
    const span = row.querySelector('.share-name') as HTMLElement | null
    if (span) span.textContent = `${stem}_第${i + 1}片.txt`
  })
}

function renderSplitResult(f: File, k: number, n: number, ots: Uint8Array | null): void {
  namePrefix.hidden = nameOpt.value !== 'custom'
  const card = $('resultCard')
  card.hidden = false
  $('ctName').textContent = `${splitResult!.stem}.smcf`
  $('ctMeta').textContent = `${fmtSize(f.size)} → ${fmtSize(splitResult!.ciphertext.length)} · k=${k}/n=${n}`

  const box = $('otsBox')
  if (ots) {
    box.hidden = false
    box.innerHTML = ''
    const line = document.createElement('div')
    line.className = 'ots-line'
    line.innerHTML = `<span class="ots-status pending">OTS 存证已提交</span><span>哈希已发送至公共日历，比特币锚定约需数小时；回执已藏进密文，恢复时自动显示。</span>`
    box.appendChild(line)
  } else {
    box.hidden = true
  }

  const list = $('shareList')
  list.innerHTML = ''
  splitResult!.shareTexts.forEach((text, i) => {
    const row = document.createElement('div')
    row.className = 'share-row'
    const idx = document.createElement('div')
    idx.className = 'share-idx'
    idx.textContent = String(i + 1)
    const span = document.createElement('div')
    span.className = 'share-text'
    span.textContent = text
    const name = document.createElement('div')
    name.className = 'share-name'
    name.hidden = true
    name.textContent = `${splitResult!.stem}_第${i + 1}片.txt`
    const bCopy = document.createElement('button')
    bCopy.className = 'btn share-btn'
    bCopy.type = 'button'
    bCopy.textContent = '复制'
    bCopy.addEventListener('click', () => copyText(text, bCopy))
    const bDl = document.createElement('button')
    bDl.className = 'btn share-btn'
    bDl.type = 'button'
    bDl.textContent = '下载'
    bDl.addEventListener('click', () => download(`${splitResult!.stem}_第${i + 1}片.txt`, new TextEncoder().encode(text + '\n')))
    row.append(idx, span, name, bCopy, bDl)
    list.appendChild(row)
  })

  $<HTMLButtonElement>('btnDlCt').onclick = () =>
    download(`${splitResult!.stem}.smcf`, splitResult!.ciphertext)

  $<HTMLButtonElement>('btnDlAll').onclick = async () => {
    download(`${splitResult!.stem}.smcf`, splitResult!.ciphertext)
    for (let i = 0; i < splitResult!.shareTexts.length; i++) {
      await new Promise((r) => setTimeout(r, 250))
      download(`${splitResult!.stem}_第${i + 1}片.txt`, new TextEncoder().encode(splitResult!.shareTexts[i]! + '\n'))
    }
  }

  card.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
}

// ===== 恢复：先密文，后分片 =====

let ctBytes: Uint8Array | null = null
let ctHeader: { k: number; n: number; name: string; size: number } | null = null
let restoreOk: { name: string; data: Uint8Array } | null = null

function showCtFile(f: File): void {
  ctHeader = null
  ctBytes = null
  const drop = $('dropCt')
  drop.classList.add('has-file')
  $('dropCtText').textContent = `🔐 ${f.name} · ${fmtSize(f.size)}`
  const info = $('ctInfo')
  info.hidden = false
  info.innerHTML = '<span class="ots-status pending">解析密文头…</span>'
  f.arrayBuffer()
    .then(async (buf) => {
      ctBytes = new Uint8Array(buf)
      const outer = tlvParse(SMCF.MAGIC, ctBytes)
      if (outer.version !== SMCF.VERSION) throw new Error(`不支持的密文版本 v${outer.version}`)
      const k = outer.chunks.get(SMCF.TAG.K)?.[0]
      const n = outer.chunks.get(SMCF.TAG.N)?.[0]
      if (!k || !n) throw new Error('密文缺少 k/n 参数')
      const nm = outer.chunks.get(SMCF.TAG.FILENAME)
      ctHeader = { k, n, name: nm ? new TextDecoder().decode(nm) : f.name, size: f.size }
      info.innerHTML = `<b>${ctHeader.name}</b> · ${fmtSize(ctHeader.size)} · 需要 <b>k=${k}</b> 片分片（共 n=${n}），在下面贴入或导入`
      refreshRestoreBtn()
    })
    .catch((e) => {
      ctBytes = ctHeader = null
      info.innerHTML = `<span class="ots-status pending">⚠️ ${e instanceof Error ? e.message : e}</span>`
      refreshRestoreBtn()
    })
}

const fileCtInput = bindDrop('dropCt', showCtFile)

function currentShares(): ShareEntry[] | null {
  try {
    return parseShares($<HTMLTextAreaElement>('shareText').value)
  } catch {
    return null
  }
}

function refreshRestoreBtn(): void {
  const ta = $<HTMLTextAreaElement>('shareText')
  const status = $('shareStatus')
  const shares = currentShares()
  const btn = $<HTMLButtonElement>('btnRestore')

  if (!ctHeader) {
    status.textContent = shares ? `已识别 ${shares.length} 片 — 请先选择密文文件` : ''
    btn.disabled = true
    return
  }
  if (!shares) {
    status.textContent = ta.value.trim() ? '分片格式不对（应为 SHAMIR1:k:n:base64）' : ''
    btn.disabled = true
    return
  }
  const { k, n } = ctHeader
  const ks = new Set(shares.map((s) => s.k))
  const ns = new Set(shares.map((s) => s.n))
  if (ks.size > 1 || ns.size > 1) {
    status.textContent = '⚠️ 各分片 k/n 不一致，可能不是同一批拆出来的'
    btn.disabled = true
    return
  }
  if (shares[0]!.k !== k || shares[0]!.n !== n) {
    status.textContent = `⚠️ 分片 k/n (${shares[0]!.k}/${shares[0]!.n}) 与密文 (${k}/${n}) 不一致`
    btn.disabled = true
    return
  }
  status.textContent = `已识别 ${shares.length} 片（k=${k}，n=${n}${shares.length >= k ? '，够用 ✓' : `，还差 ${k - shares.length} 片`}）`
  btn.disabled = shares.length < k
}

$<HTMLTextAreaElement>('shareText').addEventListener('input', refreshRestoreBtn)

$<HTMLInputElement>('shareFiles').addEventListener('change', async (e) => {
  const files = (e.target as HTMLInputElement).files
  if (!files) return
  const parts: string[] = [$<HTMLTextAreaElement>('shareText').value]
  for (const f of files) parts.push(await f.text())
  $<HTMLTextAreaElement>('shareText').value = parts.join('\n')
  refreshRestoreBtn()
  ;(e.target as HTMLInputElement).value = ''
})

const restoreRun = new Run('restoreLog', 'restoreProg', [
  {
    disable: () => {
      $<HTMLButtonElement>('btnRestore').disabled = true
      $<HTMLTextAreaElement>('shareText').disabled = true
      $<HTMLInputElement>('shareFiles').disabled = true
      fileCtInput.disabled = true
      $('dropCt').classList.add('is-disabled')
      $<HTMLInputElement>('shareFiles').closest('.file-label')?.classList.add('is-disabled')
    },
    restore: () => {
      $<HTMLTextAreaElement>('shareText').disabled = false
      $<HTMLInputElement>('shareFiles').disabled = false
      fileCtInput.disabled = false
      $('dropCt').classList.remove('is-disabled')
      $<HTMLInputElement>('shareFiles').closest('.file-label')?.classList.remove('is-disabled')
      refreshRestoreBtn()
    },
  },
])

$<HTMLButtonElement>('btnRestore').addEventListener('click', async () => {
  const err = $('restoreError')
  err.hidden = true
  const run = restoreRun
  run.begin()
  try {
    run.line('解析分片…')
    run.prog(10)
    const shares = parseShares($<HTMLTextAreaElement>('shareText').value)
    checkConsistency(shares, ctHeader!.k, ctHeader!.n)

    run.line('重放 Shamir 合并密钥…')
    run.prog(35)
    const key = await shamirCombine(shares.slice(0, shares[0]!.k).map((s) => s.payload))

    run.line(`AES-256-GCM 解密（${fmtSize(ctBytes!.length)}）…`)
    run.prog(60)
    const outer = tlvParse(SMCF.MAGIC, ctBytes!)
    const iv = outer.chunks.get(SMCF.TAG.IV)
    const ct = outer.chunks.get(SMCF.TAG.CIPHERTEXT)
    if (!iv || iv.length !== IV_LEN) throw new Error('密文缺少 IV 或长度不对')
    if (!ct) throw new Error('密文缺少 CIPHERTEXT 块')
    const inner = await aesDecrypt(key, iv, ct)

    run.line('解析载荷包…')
    run.prog(85)
    const pack = tlvParse(SMPK.MAGIC, inner)
    if (pack.version !== SMPK.VERSION) throw new Error(`不支持的载荷包版本 v${pack.version}`)
    const data = pack.chunks.get(SMPK.TAG.DATA)
    if (!data) throw new Error('载荷包缺少 DATA 块')
    const nameBytes = pack.chunks.get(SMPK.TAG.FILENAME)
    const name = nameBytes ? new TextDecoder().decode(nameBytes) : 'restored.bin'

    // SHA-256 完整性
    const expect = pack.chunks.get(SMPK.TAG.SHA256)
    const actual = await sha256(data)
    const hashOk = expect ? toHex(expect) === toHex(actual) : null

    restoreOk = { name, data }
    run.line('完成 ✓', 'lg-ok')
    run.end()
    await renderRestore(pack, data, name, hashOk, actual)
  } catch (e) {
    run.fail()
    err.hidden = false
    err.textContent = `恢复失败：${e instanceof Error ? e.message : String(e)}`
  }
})

async function renderRestore(
  pack: { chunks: Map<number, Uint8Array> },
  data: Uint8Array,
  name: string,
  hashOk: boolean | null,
  actualHash: Uint8Array,
): Promise<void> {
  const card = $('restoreCard')
  card.hidden = false
  $('restName').textContent = name
  const createdAtBytes = pack.chunks.get(SMPK.TAG.CREATED_AT)
  const createdAt = createdAtBytes ? beBytesToU64(createdAtBytes) : null
  $('restMeta').textContent = `${fmtSize(data.length)}${createdAt ? ` · ${new Date(createdAt).toLocaleString()}` : ''}`
  $('hashLine').textContent = `SHA-256：${toHex(actualHash)}${hashOk === false ? '\n⚠️ 与打包时记录的哈希不一致，文件可能被篡改！' : ''}`

  // OTS：回执在内层，解密后才可见；初始消息 = 原文件哈希，重放 ops 得到被锚定摘要
  const otsBytes = pack.chunks.get(SMPK.TAG.OTS_RECEIPT)
  const box = $('otsRestBox')
  if (otsBytes) {
    box.hidden = false
    box.innerHTML = ''
    try {
      const ots = await parseOts(otsBytes, actualHash)
      const pending = ots.attestations.filter((a) => a.kind === 'pending') as { kind: 'pending'; uri: string }[]
      const anchors = ots.attestations.filter((a) => a.kind === 'bitcoin') as { kind: 'bitcoin'; height: number; digest: Uint8Array | null }[]

      const status = document.createElement('div')
      status.className = 'ots-line'
      if (anchors.length > 0) {
        status.innerHTML =
          `<span class="ots-status ok">OTS 已锚定 Bitcoin 区块 #${anchors.map((a) => a.height).join(' / #')}</span>` +
          `<span>点击下方按钮做完整区块链验证。</span>`
      } else if (pending.length > 0) {
        status.innerHTML =
          `<span class="ots-status pending">OTS 待锚定</span>` +
          `<span>已提交日历（${pending.map((p) => p.uri).join('、')}），比特币锚定约需数小时。</span>`
      } else {
        status.innerHTML = `<span class="ots-status pending">OTS 回执存在，但未识别出 attestation</span>`
      }
      box.appendChild(status)

      if (anchors.length > 0 && anchors.every((a) => a.digest)) {
        const btn = document.createElement('button')
        btn.className = 'btn btn-ghost'
        btn.type = 'button'
        btn.textContent = '在线完整验证（需联网）'
        btn.addEventListener('click', async () => {
          btn.disabled = true
          btn.textContent = '验证中…'
          const line = document.createElement('div')
          line.className = 'ots-line'
          try {
            const results = await Promise.all(
              anchors.map((a) => verifyAnchorOnline({ height: a.height, digest: a.digest! })),
            )
            const ok = results.some((r) => r.ok)
            line.innerHTML =
              `<span class="ots-status ${ok ? 'ok' : 'pending'}">${ok ? '✓ 区块链验证通过' : '✗ 验证未通过'}</span>` +
              results.map((r) => `<span>#${r.height} @ ${new Date(r.blockTime).toLocaleString()}：${r.detail}</span>`).join('')
          } catch (e) {
            line.innerHTML = `<span class="ots-status pending">在线验证失败：${e instanceof Error ? e.message : e}</span>`
          }
          box.appendChild(line)
          btn.hidden = true
        })
        box.appendChild(btn)
      }
      if (ots.degraded) {
        const note = document.createElement('div')
        note.className = 'ots-line'
        note.innerHTML = `<span class="ots-status pending">回执含未识别结构，以上仅部分解析；建议用官方验证器复核。</span>`
        box.appendChild(note)
      }
    } catch (e) {
      box.innerHTML = `<div class="ots-line"><span class="ots-status pending">OTS 回执解析失败：${e instanceof Error ? e.message : e}</span></div>`
    }
  } else {
    box.hidden = true
  }

  $<HTMLButtonElement>('btnDlRest').onclick = () => restoreOk && download(restoreOk.name, restoreOk.data)
  card.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
}
