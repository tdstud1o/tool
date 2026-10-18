import './style.css'
import { TSCF, TSPK, beBytesToU64, beBytesToUint, tlvBuild, tlvParse, u32beBytes, u64beBytes } from './core/tlv.ts'
import { ALGO, ALGO_LABEL, compressData, decompressData, type AlgoId } from './core/compress.ts'
import { IV_LEN, KEY_LEN, aesDecrypt, aesEncrypt, randomBytes, sha256 } from './core/crypto.ts'
import { splitInWorker, combineInWorker } from './core/jobs.ts'
import { MAX_SHARES, randomFieldBytes } from './core/gfp.ts'
import { checkConsistency, encodeShare, parseShareLine, type ShareEntry } from './core/format.ts'
import { otsStamp, parseOts, toDetachedOts, upgradePending, verifyAnchorOnline } from './core/ots.ts'
import { bytesEq, toHex } from './core/b64.ts'
import { buildZip } from './core/zip.ts'

/** 拆分结果里最多渲染多少行分片；超出部分折叠（n 可达十万级） */
const SHARE_ROWS = 50

// ===== 工具 =====

const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T

/** 向指定日志框追加一行（非流程消息：导入结果、错误等），与 Run.line 同一处展示 */
function logLine(boxId: string, text: string, cls = ''): void {
  const box = $(boxId)
  box.hidden = false
  const d = new Date()
  const t = [d.getHours(), d.getMinutes(), d.getSeconds()]
    .map((x) => String(x).padStart(2, '0'))
    .join(':')
  const div = document.createElement('div')
  if (cls) div.className = cls
  div.textContent = `[${t}] ${text}`
  box.append(div)
  box.scrollTop = box.scrollHeight
}
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

function download(name: string, data: Uint8Array | Blob): void {
  const url = URL.createObjectURL(data instanceof Blob ? data : new Blob([data]))
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

// ===== Tab 切换（记住上次选中，刷新后恢复）=====

function switchView(v: string): void {
  for (const t of document.querySelectorAll<HTMLButtonElement>('.tab'))
    t.classList.toggle('is-active', t.dataset.view === v)
  $('view-split').hidden = v !== 'split'
  $('view-restore').hidden = v !== 'restore'
  try { localStorage.setItem('shamir-view', v) } catch { /* ignore */ }
}

for (const tab of document.querySelectorAll<HTMLButtonElement>('.tab'))
  tab.addEventListener('click', () => switchView(tab.dataset.view!))

try {
  const savedView = localStorage.getItem('shamir-view')
  if (savedView === 'restore' || savedView === 'split') switchView(savedView)
} catch { /* ignore */ }

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

/**
 * 把后台线程的进度映射到进度条区间，并按每 10% 打一行日志。
 * n 很大时 worker 会回调上百次，逐次写日志会把日志框刷爆。
 */
function stageProgress(run: Run, from: number, to: number, label: string): (done: number, total: number) => void {
  let nextLog = 10
  return (done, total) => {
    const pct = total > 0 ? done / total : 1
    run.prog(from + (to - from) * pct)
    const mark = Math.floor(pct * 10) * 10
    if (mark >= nextLog) {
      nextLog = mark + 10
      run.line(`${label} ${done.toLocaleString()} / ${total.toLocaleString()}（${Math.round(pct * 100)}%）`)
    }
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
  if (!Number.isFinite(k) || !Number.isFinite(n) || k < 2 || n < 2 || n > MAX_SHARES || k > n) return null
  return { k, n }
}

function refreshSplitBtn(): void {
  $<HTMLButtonElement>('btnSplit').disabled = !splitFile || !readKn()
}

// k/n 联动：调高 k 时 n 跟随到 k；调低 n 时 k 跟随到 n（恒保证 2 ≤ k ≤ n ≤ MAX_SHARES）
inK.addEventListener('input', () => {
  const k = Math.round(Number(inK.value))
  if (Number.isFinite(k)) {
    const kc = Math.min(MAX_SHARES, Math.max(2, k))
    if (String(kc) !== inK.value) inK.value = String(kc)
    if (Number(inN.value) < kc) inN.value = String(kc)
  }
  refreshSplitBtn()
})
inN.addEventListener('input', () => {
  const n = Math.round(Number(inN.value))
  if (Number.isFinite(n)) {
    const nc = Math.min(MAX_SHARES, Math.max(2, n))
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
// ===== 压缩算法选择（默认 zstd L3，记忆上次选择）=====
const zipSeg = $('zipSeg')
function currentAlgo(): AlgoId {
  const active = zipSeg.querySelector<HTMLButtonElement>('button.is-active')
  const v = Number(active?.dataset.algo ?? ALGO.ZSTD_L3)
  return (v in ALGO_LABEL ? v : ALGO.ZSTD_L3) as AlgoId
}
try {
  const raw = localStorage.getItem('shamir-zip-algo')
  const saved = raw == null ? NaN : Number(raw)
  if (saved in ALGO_LABEL) {
    zipSeg.querySelectorAll<HTMLButtonElement>('button').forEach((b) => {
      b.classList.toggle('is-active', Number(b.dataset.algo) === saved)
    })
  }
} catch { /* ignore */ }
zipSeg.addEventListener('click', (e) => {
  const btn = (e.target as HTMLElement).closest<HTMLButtonElement>('button')
  if (!btn) return
  zipSeg.querySelectorAll('button').forEach((b) => b.classList.remove('is-active'))
  btn.classList.add('is-active')
  try { localStorage.setItem('shamir-zip-algo', String(Number(btn.dataset.algo))) } catch { /* ignore */ }
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
        run.line(`OTS：提交失败（${e instanceof Error ? e.message : e}），已跳过，不影响分片`, 'lg-warn')
      }
    }

    run.line(`压缩（${ALGO_LABEL[currentAlgo()]}）…`)
    run.prog(50)
    const packed = await compressData(fileBytes, currentAlgo())
    run.line(
      `载荷：${fmtSize(fileBytes.length)} → ${fmtSize(packed.bytes.length)}（${packed.note}）`,
      packed.algo === ALGO.NONE ? 'lg-warn' : 'lg-ok',
    )

    run.line('生成 key 并 AES-256-GCM 加密…')
    run.prog(68)
    const key = randomFieldBytes() // 保证 < p，落在域外就丢弃重取
    const iv = randomBytes(IV_LEN)

    // 内层载荷包：原数据 + 元数据 + 存证，整体进密文
    const innerChunks = [
      { tag: TSPK.TAG.FILENAME, value: new TextEncoder().encode(f.name) },
      { tag: TSPK.TAG.CREATED_AT, value: u64beBytes(Date.now()) },
      { tag: TSPK.TAG.SHA256, value: fileHash },
      ...(f.type ? [{ tag: TSPK.TAG.MIME, value: new TextEncoder().encode(f.type) }] : []),
      { tag: TSPK.TAG.ALGO, value: new Uint8Array([packed.algo]) },
      ...(ots ? [{ tag: TSPK.TAG.OTS_RECEIPT, value: ots }] : []),
      { tag: TSPK.TAG.DATA, value: packed.bytes },
    ]
    const inner = tlvBuild(TSPK.MAGIC, TSPK.VERSION, innerChunks, { lastTag: TSPK.TAG.DATA })
    const ciphertext = await aesEncrypt(key, iv, inner)

    const outer = tlvBuild(
      TSCF.MAGIC,
      TSCF.VERSION,
      [
        { tag: TSCF.TAG.K, value: u32beBytes(k) },
        { tag: TSCF.TAG.N, value: u32beBytes(n) },
        { tag: TSCF.TAG.IV, value: iv },
        { tag: TSCF.TAG.CIPHERTEXT, value: ciphertext },
      ],
      { lastTag: TSCF.LAST_TAG },
    )

    run.line(`Shamir 分片（k=${k}/n=${n}）…`)
    run.prog(72)
    const shares = await splitInWorker(key, n, k, stageProgress(run, 72, 99, '分片'))
    const shareTexts = shares.map((s) => encodeShare(k, s))

    splitResult = { stem: productStem(), ciphertext: outer, shareTexts }
    run.line('完成 ✓', 'lg-ok')
    run.end()
    renderSplitResult(f, k, n, ots)
  } catch (e) {
    run.line(`拆分失败：${e instanceof Error ? e.message : String(e)}`, 'lg-err')
    run.fail()
  }
})

function renderProductNames(): void {
  if (!splitResult) return
  const stem = productStem()
  splitResult.stem = stem
  $('ctName').textContent = `${stem}.tscf`
  document.querySelectorAll('.share-row').forEach((row, i) => {
    const span = row.querySelector('.share-name') as HTMLElement | null
    if (span) span.textContent = `${stem}_share${i + 1}.txt`
  })
}

function renderSplitResult(f: File, k: number, n: number, ots: Uint8Array | null): void {
  nameCustom.hidden = nameMode() !== 'custom'
  const card = $('resultCard')
  card.hidden = false
  $('ctName').textContent = `${splitResult!.stem}.tscf`
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
  const texts = splitResult!.shareTexts
  // n 可以到十万：逐行渲染会创建十万个 DOM 节点，浏览器直接卡死。
  // 只渲染前 50 行，其余交给「打包下载」——真要一片片发，文件比列表有用。
  const shown = Math.min(texts.length, SHARE_ROWS)
  for (let i = 0; i < shown; i++) {
    const text = texts[i]!
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
  }
  if (shown < texts.length) {
    const more = document.createElement('div')
    more.className = 'share-more'
    more.textContent = `共 ${texts.length.toLocaleString()} 片，已折叠其余 ${(texts.length - shown).toLocaleString()} 片 —— 用下面的一键打包拿全部分片。`
    list.appendChild(more)
  }

  $<HTMLButtonElement>('btnDlCt').onclick = () =>
    download(`${splitResult!.stem}.tscf`, splitResult!.ciphertext)

  const btnAll = $<HTMLButtonElement>('btnDlAll')
  const canLoop = texts.length <= 20
  btnAll.textContent = canLoop ? '下载全部（密文 + 分片）' : `打包下载全部（zip · ${texts.length.toLocaleString()} 片）`
  btnAll.onclick = async () => {
    const stem = splitResult!.stem
    // 片数少就逐个下载，省得用户还要解压；片数多只能打包，
    // 因为浏览器会拦截连续几十上百次自动下载。
    if (canLoop) {
      download(`${stem}.tscf`, splitResult!.ciphertext)
      for (let i = 0; i < texts.length; i++) {
        await new Promise((r) => setTimeout(r, 250))
        download(`${stem}_share${i + 1}.txt`, new TextEncoder().encode(texts[i]! + '\n'))
      }
      return
    }
    const label = btnAll.textContent
    btnAll.disabled = true
    btnAll.textContent = '打包中…'
    await new Promise((r) => setTimeout(r, 30)) // 先让按钮状态渲染出来
    try {
      const enc = new TextEncoder()
      const entries = [
        { name: `${stem}/${stem}.tscf`, data: splitResult!.ciphertext },
        ...texts.map((t, i) => ({ name: `${stem}/share${i + 1}.txt`, data: enc.encode(t + '\n') })),
      ]
      download(`${stem}.zip`, buildZip(entries))
    } finally {
      btnAll.disabled = false
      btnAll.textContent = label
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
  n?: number // 外层 0x03 N 可省略：缺失时只用分片自带的 n 做一致性校验
}

let ctEntries: CtEntry[] = []
let activeCt: CtEntry | null = null
const shareMap = new Map<number, ShareEntry>()
let restoreOk: { name: string; data: Uint8Array } | null = null

const SHARE_RE = /TSK\d+:/

/** 追加分片文本（多行），返回新增数与错误消息；同 index 内容冲突保留原片 */
function importShareText(text: string): { added: number; errors: string[] } {
  let added = 0
  let recognized = 0
  const errors: string[] = []
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    if (!line) continue
    try {
      const entry = parseShareLine(line)
      if (!entry) continue
      recognized++
      const prev = shareMap.get(entry.index)
      if (prev && (prev.k !== entry.k || !bytesEq(prev.payload, entry.payload))) {
        errors.push(`第 ${entry.index} 号分片内容冲突，已保留原片`)
      } else if (!prev) {
        shareMap.set(entry.index, entry)
        added++
      }
    } catch (err) {
      errors.push(err instanceof Error ? err.message : String(err))
    }
  }
  if (recognized === 0) errors.push('没有识别到分片（格式应为 TSK1:k:base64…，一条一行）')
  return { added, errors }
}

/** 摄取文件：TSCF 头 → 密文；含 TSK1 分片文本 → 逐片导入；其余报错（结果全进按钮下方日志） */
async function ingestFiles(files: File[]): Promise<void> {
  // 一次拖进上万个文件是真实场景（k 很大时要凑很多片）：
  // 逐个文件写日志 + 逐个重渲染列表会把界面拖死，所以只在文件少时逐条记。
  const verbose = files.length <= 20
  let shareFiles = 0
  let shareCount = 0
  for (const f of files) {
    try {
      const buf = new Uint8Array(await f.arrayBuffer())
      let handled = false
      try {
        const outer = tlvParse(TSCF.MAGIC, buf)
        if (outer.version !== TSCF.VERSION) throw new Error(`不支持的密文版本 v${outer.version}`)
        const kBytes = outer.chunks.get(TSCF.TAG.K)
        const nBytes = outer.chunks.get(TSCF.TAG.N)
        const k = kBytes ? beBytesToUint(kBytes) : 0
        const n = nBytes ? beBytesToUint(nBytes) : undefined
        if (!k) throw new Error('密文缺少 k 参数')
        const entry: CtEntry = { name: f.name, size: f.size, bytes: buf, k, n }
        ctEntries.push(entry)
        activeCt = entry
        handled = true
      } catch (ctErr) {
        // 不是密文 → 尝试按分片文本处理；带密文扩展名却解析失败则直接报错
        const text = new TextDecoder('utf-8', { fatal: false }).decode(buf)
        if (!SHARE_RE.test(text)) {
          if (/\.tscf$/i.test(f.name)) throw ctErr
          throw new Error(`无法识别的文件（既不是密文也不含分片）`)
        }
        const { added, errors } = importShareText(text)
        shareFiles++
        shareCount += added
        if (verbose || errors.length)
          logLine(
            'restoreLog',
            `${f.name}：导入 ${added} 片${errors.length ? `；${errors.join('；')}` : ''}`,
            errors.length ? 'lg-warn' : 'lg-ok',
          )
      }
      if (handled && verbose) logLine('restoreLog', `🔐 ${f.name}（${fmtSize(f.size)}）已加入密文列表`, 'lg-ok')
    } catch (e) {
      logLine('restoreLog', `⚠️ ${f.name}：${e instanceof Error ? e.message : String(e)}`, 'lg-err')
    }
  }
  if (!verbose && shareFiles > 0)
    logLine('restoreLog', `已从 ${shareFiles.toLocaleString()} 个文件导入 ${shareCount.toLocaleString()} 片，当前共 ${shareMap.size.toLocaleString()} 片`, 'lg-ok')
  renderShareList()
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
      el('span', 'mini-meta', `${fmtSize(c.size)} · k=${c.k}/n=${c.n ?? '?'}`),
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
  // 同上：几万片时逐行渲染会卡死，只画前 50 行，剩下用计数交代
  for (const s of shares.slice(0, SHARE_ROWS)) {
    const row = el('div', 'mini-row')
    const text = encodeShare(s.k, s.payload)
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
  if (shares.length > SHARE_ROWS) {
    list.append(
      el('div', 'share-more', `共 ${shares.length.toLocaleString()} 片，这里只按坐标显示前 ${SHARE_ROWS} 片`),
    )
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
  const bad = shares.find((s) => s.k !== k)
  if (bad) {
    status.textContent = `⚠️ 有分片的 k=${bad.k} 与密文 k=${k} 不一致`
    btn.disabled = true
    return
  }
  const nText = n != null ? `，n=${n}` : '，n 未记录'
  status.textContent = `已导入 ${shares.length} 片（k=${k}${nText}${shares.length >= k ? '，够用 ✓' : `，还差 ${k - shares.length} 片`}）`
  btn.disabled = shares.length < k
}

const fileCtInput = bindDrop('dropCt', true, (files) => void ingestFiles(files))

function addShareFromInput(): void {
  const input = $<HTMLInputElement>('shareInput')
  const text = input.value.trim()
  if (!text) return
  const { added, errors } = importShareText(text)
  if (added > 0) {
    logLine(
      'restoreLog',
      `已添加 ${added} 片${errors.length ? `；${errors.join('；')}` : ''}`,
      errors.length ? 'lg-warn' : 'lg-ok',
    )
  } else {
    const reason = errors.length
      ? errors.join('；')
      : '没有新增（内容为空，或该分片已存在）'
    logLine('restoreLog', `未能添加：${reason}`, 'lg-err')
  }
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
  const run = restoreRun
  run.begin()
  try {
    run.line('解析分片…')
    run.prog(10)
    const shares = [...shareMap.values()].sort((a, b) => a.index - b.index)
    checkConsistency(shares, activeCt!.k)

    run.line('重放 Shamir 合并密钥…')
    run.prog(15)
    const key = await combineInWorker(
      shares.slice(0, shares[0]!.k).map((s) => s.payload),
      stageProgress(run, 15, 70, '插值'),
    )

    run.line(`AES-256-GCM 解密（${fmtSize(activeCt!.bytes.length)}）…`)
    run.prog(78)
    const outer = tlvParse(TSCF.MAGIC, activeCt!.bytes)
    const iv = outer.chunks.get(TSCF.TAG.IV)
    const ct = outer.chunks.get(TSCF.TAG.CIPHERTEXT)
    if (!iv || iv.length !== IV_LEN) throw new Error('密文缺少 IV 或长度不对')
    if (!ct) throw new Error('密文缺少 CIPHERTEXT 块')
    const inner = await aesDecrypt(key, iv, ct)

    run.line('解析载荷包…')
    run.prog(86)
    const pack = tlvParse(TSPK.MAGIC, inner)
    if (pack.version !== TSPK.VERSION) throw new Error(`不支持的载荷包版本 v${pack.version}`)
    const stored = pack.chunks.get(TSPK.TAG.DATA)
    if (!stored) throw new Error('载荷包缺少 DATA 块')
    const algo = pack.chunks.get(TSPK.TAG.ALGO)?.[0] ?? ALGO.NONE
    let data = stored
    if (algo !== ALGO.NONE) {
      run.line(`解压（${ALGO_LABEL[algo] ?? `算法 ${algo}`}，${fmtSize(stored.length)}）…`)
      run.prog(90)
      data = await decompressData(stored, algo)
    }
    const nameBytes = pack.chunks.get(TSPK.TAG.FILENAME)
    const createdAtBytes = pack.chunks.get(TSPK.TAG.CREATED_AT)
    const createdAt = createdAtBytes ? beBytesToU64(createdAtBytes) : null
    const name = nameBytes ? new TextDecoder().decode(nameBytes) : defaultName(createdAt)

    // SHA-256 完整性
    const expect = pack.chunks.get(TSPK.TAG.SHA256)
    const actual = await sha256(data)
    const hashOk = expect ? toHex(expect) === toHex(actual) : null

    restoreOk = { name, data }
    run.line('完成 ✓', 'lg-ok')
    run.end()
    await renderRestore(pack, data, name, hashOk, actual)
  } catch (e) {
    run.line(`恢复失败：${e instanceof Error ? e.message : String(e)}`, 'lg-err')
    run.fail()
  }
})

/** 内层没写 FILENAME 时的默认下载名：YYYY-MM-DD.bin（拆分时间优先，否则用当前时间） */
function defaultName(createdAt: number | null): string {
  const d = new Date(createdAt ?? Date.now())
  const ymd = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
  return `${ymd}.bin`
}

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
  const createdAtBytes = pack.chunks.get(TSPK.TAG.CREATED_AT)
  const createdAt = createdAtBytes ? beBytesToU64(createdAtBytes) : null
  // CREATED_AT / MIME 均为可选：缺失时只留白，不报错
  $('restMeta').textContent = `${fmtSize(data.length)}${createdAt ? ` · ${new Date(createdAt).toLocaleString()}` : ' · 时间未记录'}`
  $('hashLine').textContent = `SHA-256：${toHex(actualHash)}${hashOk === false ? '\n⚠️ 与打包时记录的哈希不一致，文件可能被篡改！' : ''}`

  // OTS：回执在内层，解密后才可见；初始消息 = 原文件哈希，重放 ops 得到被锚定摘要。
  // 检测到回执就自动后台查询（不阻塞文件下载）：pending → 查日历升级；已锚定 → 直接链上验证。
  const otsBytes = pack.chunks.get(TSPK.TAG.OTS_RECEIPT)
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
            el('span', '', '公开日历通常未开放跨域读取，浏览器端多半只能拿到"待锚定"状态；可点「下载 ots 文件」交给官方工具（ots verify）复核。'),
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
  // 有 OTS 回执时，额外提供「下载 ots 文件」：包装成标准 DetachedTimestampFile，
  // 官方 ots 工具与 opentimestamps.org 网页可直接验证
  const otsBtn = $<HTMLButtonElement>('btnDlOts')
  if (otsBytes) {
    otsBtn.hidden = false
    otsBtn.onclick = () => download(`${name}.ots`, toDetachedOts(otsBytes, actualHash))
  } else {
    otsBtn.hidden = true
    otsBtn.onclick = null
  }
  card.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
}
