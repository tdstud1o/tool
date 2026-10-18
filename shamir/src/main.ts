import './style.css'
import { SMCF, SMPK, tlvBuild, tlvParse, u64beBytes, beBytesToU64 } from './core/tlv.ts'
import { IV_LEN, KEY_LEN, aesDecrypt, aesEncrypt, randomBytes, sha256 } from './core/crypto.ts'
import { shamirSplit, shamirCombine } from './core/shamir.ts'
import { checkConsistency, encodeShare, parseShareLine, type ShareEntry } from './core/format.ts'
import { otsStamp, parseOts, upgradePending, verifyAnchorOnline } from './core/ots.ts'
import { bytesEq, toHex } from './core/b64.ts'

// ===== 工具 =====

const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T

/** 安全构建元素：外部数据（文件名、回执 URI、API 响应、错误消息）一律走 textContent */
function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  cls: string,
  ...children: (Node | string)[]
): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag)
  if (cls) e.className = cls
  for (const c of children) e.append(c)
  return e
}

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

function bindDrop(dropId: string, multiple: boolean, onFiles: (files: File[]) => void): HTMLInputElement {
  const drop = $(dropId)
  const input = document.createElement('input')
  input.type = 'file'
  input.hidden = true
  input.multiple = multiple
  drop.addEventListener('click', () => { if (!drop.classList.contains('is-disabled')) input.click() })
  drop.addEventListener('keydown', (e) => e.key === 'Enter' && !drop.classList.contains('is-disabled') && input.click())
  input.addEventListener('change', () => {
    if (input.files!.length) onFiles(Array.from(input.files!))
    input.value = ''
  })
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
    const files = Array.from(e.dataTransfer?.files ?? [])
    if (files.length) onFiles(files)
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

const fileSplitInput = bindDrop('dropSplit', false, (files) => {
  if (files[0]) showSplitFile(files[0])
})

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

// k/n 联动：调高 k 时 n 跟随到 k；调低 n 时 k 跟随到 n（恒保证 2 ≤ k ≤ n ≤ 255）
inK.addEventListener('input', () => {
  const k = Math.round(Number(inK.value))
  if (Number.isFinite(k)) {
    const kc = Math.min(255, Math.max(2, k))
    if (String(kc) !== inK.value) inK.value = String(kc)
    if (Number(inN.value) < kc) inN.value = String(kc)
  }
  refreshSplitBtn()
})
inN.addEventListener('input', () => {
  const n = Math.round(Number(inN.value))
  if (Number.isFinite(n)) {
    const nc = Math.min(255, Math.max(2, n))
    if (String(nc) !== inN.value) inN.value = String(nc)
    if (Number(inK.value) > nc) inK.value = String(nc)
  }
  refreshSplitBtn()
})

// ===== 产物命名（段式按钮，本地记住上次选择）=====

const nameSeg = $('nameSeg')
const nameCustom = $<HTMLInputElement>('nameCustom')

function nameMode(): string {
  return nameSeg.querySelector('button.is-active')!.getAttribute('data-name')!
}

function setNameMode(mode: string): void {
  for (const b of nameSeg.querySelectorAll('button'))
    b.classList.toggle('is-active', b.getAttribute('data-name') === mode)
  nameCustom.hidden = mode !== 'custom'
  try {
    localStorage.setItem('shamir-name-opt', mode)
    localStorage.setItem('shamir-name-custom', nameCustom.value)
  } catch { /* ignore */ }
}

try {
  const savedOpt = localStorage.getItem('shamir-name-opt')
  if (savedOpt) setNameMode(savedOpt)
  nameCustom.value = localStorage.getItem('shamir-name-custom') ?? ''
  nameCustom.hidden = nameMode() !== 'custom'
  $<HTMLInputElement>('otsCheck').checked = localStorage.getItem('shamir-ots') === '1'
} catch { /* ignore */ }

for (const b of nameSeg.querySelectorAll('button'))
  b.addEventListener('click', () => {
    setNameMode(b.getAttribute('data-name')!)
    renderProductNames()
  })
nameCustom.addEventListener('input', () => {
  try { localStorage.setItem('shamir-name-custom', nameCustom.value) } catch { /* ignore */ }
  renderProductNames()
})
$<HTMLInputElement>('otsCheck').addEventListener('change', (e) => {
  try { localStorage.setItem('shamir-ots', (e.target as HTMLInputElement).checked ? '1' : '0') } catch { /* ignore */ }
})

/** 按命名选项生成产物词干（不含扩展名） */
function productStem(): string {
  const base = splitFile ? baseName(splitFile.name) : 'file'
  switch (nameMode()) {
    case 'date': {
      const d = new Date()
      const ymd = `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, '0')}${String(d.getDate()).padStart(2, '0')}`
      return `${ymd}-${base}`
    }
    case 'uuid':
      return uuid()
    case 'custom': {
      const custom = nameCustom.value.trim()
      return custom || base // 自定义文件名；为空时回退原文件名
    }
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
  $('ctName').textContent = `${stem}.tsss`
  document.querySelectorAll('.share-row').forEach((row, i) => {
    const span = row.querySelector('.share-name') as HTMLElement | null
    if (span) span.textContent = `${stem}_share${i + 1}.txt`
  })
}

function renderSplitResult(f: File, k: number, n: number, ots: Uint8Array | null): void {
  nameCustom.hidden = nameMode() !== 'custom'
  const card = $('resultCard')
  card.hidden = false
  $('ctName').textContent = `${splitResult!.stem}.tsss`
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
    name.textContent = `${splitResult!.stem}_share${i + 1}.txt`
    const bCopy = document.createElement('button')
    bCopy.className = 'btn share-btn'
    bCopy.type = 'button'
    bCopy.textContent = '复制'
    bCopy.addEventListener('click', () => copyText(text, bCopy))
    const bDl = document.createElement('button')
    bDl.className = 'btn share-btn'
    bDl.type = 'button'
    bDl.textContent = '下载'
    bDl.addEventListener('click', () => download(`${splitResult!.stem}_share${i + 1}.txt`, new TextEncoder().encode(text + '\n')))
    row.append(idx, span, name, bCopy, bDl)
    list.appendChild(row)
  })

  $<HTMLButtonElement>('btnDlCt').onclick = () =>
    download(`${splitResult!.stem}.tsss`, splitResult!.ciphertext)

  $<HTMLButtonElement>('btnDlAll').onclick = async () => {
    download(`${splitResult!.stem}.tsss`, splitResult!.ciphertext)
    for (let i = 0; i < splitResult!.shareTexts.length; i++) {
      await new Promise((r) => setTimeout(r, 250))
      download(`${splitResult!.stem}_share${i + 1}.txt`, new TextEncoder().encode(splitResult!.shareTexts[i]! + '\n'))
    }
  }

  card.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
}

// ===== 恢复：密文/分片统一入口（按内容自动分流）=====

interface CtEntry {
  name: string
  size: number
  bytes: Uint8Array
  k: number
  n: number
}

let ctEntries: CtEntry[] = []
let activeCt: CtEntry | null = null
const shareMap = new Map<number, ShareEntry>()
let restoreOk: { name: string; data: Uint8Array } | null = null

const SHARE_RE = /SHAMIR\d?:/

/** 追加分片文本（多行），返回新增数与错误消息；同 index 内容冲突保留原片 */
function importShareText(text: string): { added: number; errors: string[] } {
  let added = 0
  const errors: string[] = []
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    if (!line) continue
    try {
      const entry = parseShareLine(line)
      if (!entry) continue
      const prev = shareMap.get(entry.index)
      if (prev && (prev.k !== entry.k || prev.n !== entry.n || !bytesEq(prev.payload, entry.payload))) {
        errors.push(`第 ${entry.index} 号分片内容冲突，已保留原片`)
      } else if (!prev) {
        shareMap.set(entry.index, entry)
        added++
      }
    } catch (err) {
      errors.push(err instanceof Error ? err.message : String(err))
    }
  }
  return { added, errors }
}

/** 摄取文件：.tsss/.smcf 或 SMCF 头 → 密文；含分片文本 → 逐片导入；其余报错 */
async function ingestFiles(files: File[]): Promise<void> {
  const info = $('ctInfo')
  info.hidden = false
  const messages: HTMLElement[] = []
  for (const f of files) {
    try {
      const buf = new Uint8Array(await f.arrayBuffer())
      let handled = false
      try {
        const outer = tlvParse(SMCF.MAGIC, buf)
        if (outer.version !== SMCF.VERSION) throw new Error(`不支持的密文版本 v${outer.version}`)
        const k = outer.chunks.get(SMCF.TAG.K)?.[0]
        const n = outer.chunks.get(SMCF.TAG.N)?.[0]
        if (!k || !n) throw new Error('密文缺少 k/n 参数')
        const entry: CtEntry = { name: f.name, size: f.size, bytes: buf, k, n }
        ctEntries.push(entry)
        activeCt = entry
        handled = true
      } catch (ctErr) {
        // 不是密文 → 尝试按分片文本处理；带密文扩展名却解析失败则直接报错
        const text = new TextDecoder('utf-8', { fatal: false }).decode(buf)
        if (!SHARE_RE.test(text)) {
          if (/\.(tsss|smcf)$/i.test(f.name)) throw ctErr
          throw new Error(`无法识别的文件（既不是密文也不含分片）`)
        }
        const { added, errors } = importShareText(text)
        messages.push(
          el('span', 'ots-status ' + (errors.length ? 'pending' : 'ok'),
            `${f.name}：导入 ${added} 片${errors.length ? `；${errors.join('；')}` : ''}`),
        )
        renderShareList()
      }
      if (handled) messages.push(el('span', 'ots-status ok', `🔐 ${f.name}（${fmtSize(f.size)}）已加入密文列表`))
    } catch (e) {
      messages.push(el('span', 'ots-status pending', `⚠️ ${f.name}：${e instanceof Error ? e.message : String(e)}`))
    }
  }
  info.textContent = ''
  if (messages.length) info.append(...messages)
  else info.hidden = true
  renderCtList()
  refreshRestoreBtn()
}

function renderCtList(): void {
  const list = $('ctList')
  list.textContent = ''
  list.hidden = ctEntries.length === 0
  for (const c of ctEntries) {
    const row = el('div', 'mini-row' + (c === activeCt ? ' is-active' : ''))
    const del = el('button', 'btn share-btn', '移除')
    del.type = 'button'
    del.addEventListener('click', (e) => {
      e.stopPropagation()
      ctEntries = ctEntries.filter((x) => x !== c)
      if (activeCt === c) activeCt = ctEntries[ctEntries.length - 1] ?? null
      renderCtList()
      refreshRestoreBtn()
    })
    row.append(
      el('span', 'mini-name', `🔐 ${c.name}`),
      el('span', 'mini-meta', `${fmtSize(c.size)} · k=${c.k}/n=${c.n}`),
      del,
    )
    row.addEventListener('click', () => {
      activeCt = c
      renderCtList()
      refreshRestoreBtn()
    })
    list.append(row)
  }
}

function renderShareList(): void {
  const list = $('shareMiniList')
  list.textContent = ''
  const shares = [...shareMap.values()].sort((a, b) => a.index - b.index)
  list.hidden = shares.length === 0
  for (const s of shares) {
    const row = el('div', 'mini-row')
    const text = encodeShare(s.k, s.n, s.payload)
    const del = el('button', 'btn share-btn', '移除')
    del.type = 'button'
    del.addEventListener('click', () => {
      shareMap.delete(s.index)
      renderShareList()
      refreshRestoreBtn()
    })
    row.append(
      el('span', 'mini-idx', `#${s.index}`),
      el('span', 'mini-name', text.slice(0, 60) + (text.length > 60 ? '…' : '')),
      del,
    )
    list.append(row)
  }
}

function refreshRestoreBtn(): void {
  const status = $('shareStatus')
  const btn = $<HTMLButtonElement>('btnRestore')

  if (!activeCt) {
    status.textContent = shareMap.size ? `已导入 ${shareMap.size} 片 — 请先选择密文文件` : ''
    btn.disabled = true
    return
  }
  const { k, n } = activeCt
  const shares = [...shareMap.values()]
  const bad = shares.find((s) => s.k !== k || s.n !== n)
  if (bad) {
    status.textContent = `⚠️ 有分片 k/n (${bad.k}/${bad.n}) 与密文 (${k}/${n}) 不一致`
    btn.disabled = true
    return
  }
  status.textContent = `已导入 ${shares.length} 片（k=${k}，n=${n}${shares.length >= k ? '，够用 ✓' : `，还差 ${k - shares.length} 片`}）`
  btn.disabled = shares.length < k
}

const fileCtInput = bindDrop('dropCt', true, (files) => void ingestFiles(files))

function addShareFromInput(): void {
  const input = $<HTMLInputElement>('shareInput')
  if (!input.value.trim()) return
  importShareText(input.value)
  input.value = ''
  input.focus() // 回车/添加后焦点回到输入框，继续贴下一条
  renderShareList()
  refreshRestoreBtn()
}

$<HTMLButtonElement>('btnAddShare').addEventListener('click', addShareFromInput)
$<HTMLInputElement>('shareInput').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault()
    addShareFromInput()
  }
})

$<HTMLInputElement>('shareFiles').addEventListener('change', async (e) => {
  const files = (e.target as HTMLInputElement).files
  if (files?.length) await ingestFiles(Array.from(files))
  ;(e.target as HTMLInputElement).value = ''
})

const restoreRun = new Run('restoreLog', 'restoreProg', [
  {
    disable: () => {
      $<HTMLButtonElement>('btnRestore').disabled = true
      $<HTMLInputElement>('shareInput').disabled = true
      $<HTMLButtonElement>('btnAddShare').disabled = true
      $<HTMLInputElement>('shareFiles').disabled = true
      fileCtInput.disabled = true
      $('dropCt').classList.add('is-disabled')
      $<HTMLInputElement>('shareFiles').closest('.file-label')?.classList.add('is-disabled')
    },
    restore: () => {
      $<HTMLInputElement>('shareInput').disabled = false
      $<HTMLButtonElement>('btnAddShare').disabled = false
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
    const shares = [...shareMap.values()].sort((a, b) => a.index - b.index)
    checkConsistency(shares, activeCt!.k, activeCt!.n)

    run.line('重放 Shamir 合并密钥…')
    run.prog(35)
    const key = await shamirCombine(shares.slice(0, shares[0]!.k).map((s) => s.payload))

    run.line(`AES-256-GCM 解密（${fmtSize(activeCt!.bytes.length)}）…`)
    run.prog(60)
    const outer = tlvParse(SMCF.MAGIC, activeCt!.bytes)
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

  // OTS：回执在内层，解密后才可见；初始消息 = 原文件哈希，重放 ops 得到被锚定摘要。
  // 检测到回执就自动后台查询（不阻塞文件下载）：pending → 查日历升级；已锚定 → 直接链上验证。
  const otsBytes = pack.chunks.get(SMPK.TAG.OTS_RECEIPT)
  const box = $('otsRestBox')
  if (otsBytes) {
    box.hidden = false
    box.textContent = ''
    try {
      const ots = await parseOts(otsBytes, actualHash)
      const pending = ots.attestations.filter((a) => a.kind === 'pending') as { kind: 'pending'; uri: string; digest: Uint8Array | null }[]
      const anchors = ots.attestations.filter((a) => a.kind === 'bitcoin') as { kind: 'bitcoin'; height: number; digest: Uint8Array | null }[]

      const spinner = () => {
        const s = el('span', 'spinner')
        s.setAttribute('aria-hidden', 'true')
        return s
      }
      const status = el('div', 'ots-line')
      if (anchors.length > 0) {
        status.append(
          el('span', 'ots-status ok', `OTS 已锚定 Bitcoin 区块 #${anchors.map((a) => a.height).join(' / #')}`),
          spinner(),
          el('span', '', '正在比对区块链…'),
        )
      } else if (pending.length > 0) {
        status.append(
          el('span', 'ots-status pending', 'OTS 待锚定'),
          spinner(),
          el('span', '', '拆分时已提交日历，正在后台查询最新状态…'),
        )
      } else {
        status.append(el('span', 'ots-status pending', 'OTS 回执存在，但未识别出 attestation'))
      }
      box.append(status)

      // 后台查询：完成后原地更新状态行（成功/失败都不打扰用户下载文件）
      void (async () => {
        try {
          let toVerify: { height: number; digest: Uint8Array | null }[] = anchors
          if (anchors.length === 0) {
            // 日历升级查询：拿到含 BitcoinAttestation 的新回执再上链验证
            const upgraded = await Promise.all(pending.map((p) => upgradePending(p)))
            toVerify = upgraded.flatMap((u) =>
              u.attestations.filter((a) => a.kind === 'bitcoin'),
            ) as { kind: 'bitcoin'; height: number; digest: Uint8Array | null }[]
            if (toVerify.length === 0) {
              status.textContent = ''
              status.append(
                el('span', 'ots-status pending', 'OTS 待锚定'),
                el('span', '', `已查日历（${pending.map((p) => p.uri).join('、')}）：尚未上链，比特币锚定通常需 1~3 小时，之后重新恢复本密文可自动再查。`),
              )
              return
            }
          }
          const results = await Promise.all(
            toVerify.map((a) => verifyAnchorOnline({ height: a.height, digest: a.digest })),
          )
          const ok = results.some((r) => r.ok)
          status.textContent = ''
          status.append(
            el('span', `ots-status ${ok ? 'ok' : 'pending'}`,
              ok ? '✓ OTS 存证有效（区块链验证通过）' : '⚠️ OTS 上链但验证未通过，请警惕文件来源'),
            ...results.map((r) =>
              el('span', '', `#${r.height} @ ${new Date(r.blockTime).toLocaleString()}：${r.detail}`),
            ),
          )
        } catch (e) {
          status.textContent = ''
          status.append(
            el('span', 'ots-status pending', `OTS 待锚定（后台查询失败：${e instanceof Error ? e.message : String(e)}）`),
            el('span', '', '查询不影响文件本身；网络可用时可重新恢复本密文再查。'),
          )
        }
      })()

      if (ots.degraded) {
        box.append(el('div', 'ots-line', el('span', 'ots-status pending', '回执含未识别结构，以上仅部分解析；建议用官方验证器复核。')))
      }
    } catch (e) {
      box.textContent = ''
      box.append(el('div', 'ots-line', el('span', 'ots-status pending', `OTS 回执解析失败：${e instanceof Error ? e.message : String(e)}`)))
    }
  } else {
    box.hidden = true
  }

  $<HTMLButtonElement>('btnDlRest').onclick = () => restoreOk && download(restoreOk.name, restoreOk.data)
  card.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
}
