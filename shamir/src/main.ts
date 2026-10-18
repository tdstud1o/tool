import './style.css'
import { TSCF, TSPK, beBytesToU64, beBytesToUint, tlvBuild, tlvParse, u32beBytes, u64beBytes } from './core/tlv.ts'
import { ALGO, ALGO_LABEL, compressData, decompressData, type AlgoId } from './core/compress.ts'
import { IV_LEN, KEY_LEN, aesDecrypt, aesEncrypt, randomBytes, sha256 } from './core/crypto.ts'
import { splitInWorker, combineInWorker } from './core/jobs.ts'
import { MAX_SHARES, randomFieldBytes } from './core/gfp.ts'
import {
  SHARE_PREFIX,
  checkConsistency,
  coordText,
  parseShareLine,
  sameLevels,
  type ShareEntry,
} from './core/format.ts'
import { fakeK, padKs, randSize, sizeStats, type LevelPlan } from './core/levels.ts'
import {
  OtsNoCorsError,
  calendarHasCors,
  otsStamp,
  parseOts,
  toDetachedOts,
  upgradePending,
  verifyAnchorOnline,
} from './core/ots.ts'
import { bytesEq, toB64, toHex } from './core/b64.ts'
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

// ===== Tab 切换（记住上次选中；第一次来默认「恢复」）=====

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
  // 上次用过 → 记住；第一次来 → 默认「恢复」
  switchView(savedView === 'split' ? 'split' : 'restore')
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

/**
 * 层：真实文件，或唯一的假文件（必定最后一层，且解不开）。
 * k 每层独立；n 整套共用一个，所以只在这里出现一次。
 */
interface LevelRow extends LevelPlan {
  file?: File
  /** 分片文本里这组要不要写 k（默认不写；恢复端从密文 0x02 K 读） */
  showK: boolean
}

let levels: LevelRow[] = []
/** 整套分片的份数：所有层共用（一个人只拿一片，片里带齐每一组的 y） */
let nShares = 5
/** 假文件层加入后封口：不再允许加入真文件 */
let sealed = false
let fakeAlign: '32' | '256' | 'custom' = '32'
let fakeCustom = 32
/** 密钥串对齐开关：勾上后每片补齐固定组数（多出来的组没有密文） */
let alignEnabled = false
/** 隐藏总片数开关：勾上后密文明文部分不写 0x03 N（n 是否进明文结构，权威看这里） */
let hideN = false
/** 假层的 k 被用户手改过之后，就不再跟随真实层的规律 */
let fakeKDirty = false

/** 每层 k 输入框，n 变化时回写上限（真层 k ≤ n，假层不受限） */
const kInputs = new Map<LevelRow, HTMLInputElement>()
/** 假层「k > n」角标，n 变了要跟着重算 */
const kOver = new Map<LevelRow, HTMLElement>()

const realLevels = (): LevelRow[] => levels.filter((l) => l.kind === 'real')
const fakeLevel = (): LevelRow | undefined => levels.find((l) => l.kind === 'fake')

function clampK(v: number, cap: number): number {
  // k 允许 1（单人即可解开，实际没用，但能直观演示工具原理）；上限由调用方给
  return Math.min(cap, Math.max(1, Math.round(v) || 1))
}

function setNShares(v: number): void {
  const nc = Math.min(MAX_SHARES, Math.max(2, Math.round(v) || 2))
  nShares = nc
  // k 抬升会拉 n：全局输入框要跟着显示新值
  nSharesInput.value = String(nc)
  for (const [lv, inp] of kInputs) {
    if (lv.kind === 'fake') continue // 假层可以 k > n
    inp.max = String(nc)
    if (lv.k > nc) {
      lv.k = nc
      inp.value = String(nc)
    }
  }
  const f = fakeLevel()
  if (f && !fakeKDirty) {
    f.k = fakeK(realLevels().map((l) => l.k), nc)
    const inp = kInputs.get(f)
    if (inp) inp.value = String(f.k)
  }
  // n 变了，假层"k > n（永远凑不齐）"的角标要跟着重算
  for (const [lv, badge] of kOver) badge.hidden = lv.k <= nc
  refreshSplitBtn()
}

const nSharesInput = $<HTMLInputElement>('nShares')
nSharesInput.value = String(nShares)
nSharesInput.addEventListener('input', () => {
  const v = Number(nSharesInput.value)
  if (Number.isFinite(v)) setNShares(v)
})
nSharesInput.addEventListener('blur', () => { nSharesInput.value = String(nShares) })

function bindDrop(hosts: HTMLElement[], multiple: boolean, onFiles: (files: File[]) => void): HTMLInputElement {
  const input = document.createElement('input')
  input.type = 'file'
  input.hidden = true
  input.multiple = multiple
  input.addEventListener('change', () => {
    if (input.files!.length) onFiles(Array.from(input.files!))
    input.value = ''
  })
  for (const host of hosts) {
    host.addEventListener('click', () => { if (!host.classList.contains('is-disabled')) input.click() })
    host.addEventListener('keydown', (e) => e.key === 'Enter' && !host.classList.contains('is-disabled') && input.click())
    for (const ev of ['dragover', 'dragenter'] as const)
      host.addEventListener(ev, (e) => {
        e.preventDefault()
        host.classList.add('is-drag')
      })
    for (const ev of ['dragleave', 'drop'] as const)
      host.addEventListener(ev, () => host.classList.remove('is-drag'))
    host.addEventListener('drop', (e) => {
      e.preventDefault()
      if (host.classList.contains('is-disabled')) return
      const files = Array.from(e.dataTransfer?.files ?? [])
      if (files.length) onFiles(files)
    })
  }
  hosts[0]!.after(input)
  return input
}

function addRealFiles(files: File[]): void {
  if (sealed) return
  for (const f of files) {
    // 后续层默认比上一层多一片门槛：既符合"越深越难"的直觉，
    // 也让假文件能顺着这个等差规律往下接
    const prev = levels.length ? levels[levels.length - 1]!.k : Math.min(3, nShares)
    // 新层默认 k 顺着链 +1；超过 n 不压平，而是把 n 拉到一样大
    const k = levels.length ? prev + 1 : prev
    if (k > nShares) setNShares(k)
    levels.push({ kind: 'real', name: f.name, size: f.size, k, showK: false, file: f })
  }
  // 有了文件，大拖放框就让位给下面的分半按钮（左半继续拖/选，右半加假层）
  $('dropSplit').hidden = true
  renderLevels()
}

const fileSplitInput = bindDrop([$<HTMLElement>('dropSplit'), $<HTMLElement>('btnAddMore')], true, addRealFiles)

$<HTMLInputElement>('alignCheck').addEventListener('change', (e) => {
  alignEnabled = (e.target as HTMLInputElement).checked
  syncAlignUi()
})
$<HTMLInputElement>('hideNCheck').addEventListener('change', (e) => {
  hideN = (e.target as HTMLInputElement).checked
  syncAlignUi()
})
syncAlignUi()

/**
 * 真层链严格递增（k₁ < k₂ < … ，至少相差 1；假层不参与）。
 * 从被编辑的层向两边传播：向后只抬不降（后面 ≥ 本层+1），
 * 向前只降不升（前面 ≤ 本层−1，最低压到 1——k 允许 1）。
 */
function normalizeChain(edited: LevelRow): void {
  const m = realLevels().length
  const idx = levels.indexOf(edited)
  for (let j = idx + 1; j < m; j++) {
    const cur = levels[j]!
    const min = levels[j - 1]!.k + 1
    if (cur.k < min) {
      cur.k = min
      const inp = kInputs.get(cur)
      if (inp) inp.value = String(cur.k)
    }
  }
  for (let j = idx - 1; j >= 0; j--) {
    const cur = levels[j]!
    const max = levels[j + 1]!.k - 1
    if (cur.k > max) {
      cur.k = Math.max(1, max)
      const inp = kInputs.get(cur)
      if (inp) inp.value = String(cur.k)
    }
  }
  // 向前压到 1 后可能和后一层撞平（如 [2,3] 第 2 层改 1 → [1,1]）：
  // 再从左到右补一轮「只抬不降」，恢复严格递增
  for (let j = 1; j < m; j++) {
    const cur = levels[j]!
    const min = levels[j - 1]!.k + 1
    if (cur.k < min) {
      cur.k = min
      const inp = kInputs.get(cur)
      if (inp) inp.value = String(cur.k)
    }
  }
}

/** 假文件层的 k 必定大于最后一层真层的 k；不够就顶到 末层+1 */
function enforceFakeK(): void {
  const f = fakeLevel()
  if (!f) return
  const reals = realLevels()
  const last = reals[reals.length - 1]
  if (!last) return
  if (f.k <= last.k) {
    f.k = last.k + 1
    const inp = kInputs.get(f)
    if (inp) inp.value = String(f.k)
  }
  const badge = kOver.get(f)
  if (badge) badge.hidden = f.k <= nShares
}

/** 一层的一行：两行布局——第一行主信息（文件名…大小），第二行设置项（k…显示k） */
function levelRow(lv: LevelRow, idx: number): HTMLElement {
  const isFake = lv.kind === 'fake'
  const row = el('div', `lv-row${isFake ? ' is-fake' : ''}`)
  // 左侧 5% 固定放序号
  row.append(el('span', 'lv-idx', String(idx + 1)))

  const main = el('div', 'lv-main')

  // 第一行（主信息）：文件名 (99.4 KB)；假文件就是一段随机乱码，没有文件名，
  // 显示成"假文件层"，大小可编辑（用户不改就用默认值）
  const line1 = el('div', 'lv-line')
  line1.append(el('span', 'lv-name', isFake ? '假文件层' : `${lv.name} (${fmtSize(lv.size)})`))
  if (isFake) {
    const sizeIn = document.createElement('input')
    sizeIn.type = 'number'
    sizeIn.className = 'lv-size-in'
    sizeIn.min = '1'
    sizeIn.value = String(Math.max(1, Math.round(lv.size / 1024)))
    sizeIn.title = '假文件大小（KB），默认取真实文件的均值并随机浮动'
    sizeIn.addEventListener('input', () => {
      const kb = Number(sizeIn.value)
      if (Number.isFinite(kb) && kb > 0) {
        lv.size = Math.max(64, Math.round(kb * 1024))
      }
    })
    line1.append(el('label', 'lv-cell lv-size-edit', '大小 ', sizeIn, ' KB'))
  }

  const kIn = document.createElement('input')
  kIn.type = 'number'
  kIn.className = 'lv-k-in'
  kIn.min = '1'
  kIn.max = String(MAX_SHARES)
  kIn.value = String(lv.k)
  kIn.title = isFake
    ? '这一层永远解不开；可以设到 n 以上，那就连凑都凑不齐'
    : '这一层至少需要多少片才能解开；超过 n 会把整套的 n 拉到和它一样大'
  // 假层的 k 允许超过 n：那意味着这套分片永远凑不齐它。
  // n 不写进多层密文，所以恢复端没法自己判断，只能在拆分端把话说明白。
  let overHint: HTMLElement | null = null
  if (isFake) {
    overHint = el('span', 'lv-over', '> n')
    overHint.hidden = lv.k <= nShares
    overHint.title = `整套只拆成 ${nShares} 片，这一层要的片数超过总数，永远凑不齐`
    kOver.set(lv, overHint)
  }
  const syncOver = () => {
    if (!overHint) return
    overHint.hidden = lv.k <= nShares
    overHint.title = `整套只拆成 ${nShares} 片，这一层要的片数超过总数，永远凑不齐`
  }
  kIn.addEventListener('input', () => {
    const v = Number(kIn.value)
    if (Number.isFinite(v)) lv.k = clampK(v, MAX_SHARES)
    if (isFake) {
      fakeKDirty = true
      // 假文件层的 k 必定大于最后一层真层的 k：输入小了就顶回去
      const reals = realLevels()
      const last = reals[reals.length - 1]
      if (last && lv.k <= last.k) {
        lv.k = last.k + 1
        kIn.value = String(lv.k)
      }
    }
    // 真层链严格递增（k₁ < k₂ < … ，至少相差 1；假层不在此列）：
    // 本层改大越过后面 → 后面逐层 +1 抬上去；本层改小低于前面 → 前面逐层 −1 压下来
    if (!isFake) normalizeChain(lv)
    // 链抬完后最大真层 k 可能超过 n：拉 n 到和它一样大（假层例外，它允许 > n）
    if (!isFake) {
      const maxK = Math.max(...realLevels().map((l) => l.k))
      if (maxK > nShares) setNShares(maxK)
      // 真层抬升后假层可能不再大于末层：跟着顶上去
      enforceFakeK()
    }
    syncOver()
    refreshSplitBtn()
  })
  kIn.addEventListener('blur', () => { kIn.value = String(lv.k) })
  kInputs.set(lv, kIn)
  // 第二行（设置项）：需要 [k] 人才能解锁 …… ☑ 显示k
  const line2 = el('div', 'lv-line')
  line2.append(el('label', 'lv-cell lv-k', '需要 ', kIn, ' 人才能解锁'))
  if (overHint) line2.append(overHint)

  const del = el('button', 'lv-del', '×') as HTMLButtonElement
  del.type = 'button'
  del.title = isFake ? '移除假文件层（重新允许添加文件）' : '移除这一层'
  del.addEventListener('click', () => {
    levels = levels.filter((l) => l !== lv)
    kInputs.delete(lv)
    kOver.delete(lv)
    if (isFake) sealed = false
    if (levels.length === 0) {
      // 一层不剩，大拖放框回来
      $('dropSplit').hidden = false
      $('dropSplitText').textContent = '拖文件到这里，或点击选择（可多选）'
    }
    renderLevels()
  })
  // 「显示k」：勾上才把这一层的 k 写进分片文本；默认不写，
  // 恢复端从该层密文的 0x02 K 读。参与者看到的就变成「1万 - ? - ? - 2万」。
  const showK = document.createElement('input')
  showK.type = 'checkbox'
  showK.className = 'lv-showk'
  showK.checked = lv.showK
  showK.title = '显示解密本层所需的密钥分片数量'
  const showKLabel = el('label', 'lv-showk-cell', '显示k', showK)
  showK.addEventListener('change', () => {
    lv.showK = showK.checked
  })
  line2.append(showKLabel)

  main.append(line1, line2)
  row.append(main, del)
  return row
}

function renderLevels(): void {
  const list = $('levelList')
  list.textContent = ''
  kInputs.clear()
  kOver.clear()
  list.hidden = levels.length === 0
  levels.forEach((lv, i) => {
    if (lv.kind === 'real') list.append(levelRow(lv, i))
  })

  $('nRow').hidden = levels.length === 0
  $('levelMore').hidden = levels.length === 0 || sealed

  const f = fakeLevel()
  const box = $('fakeBox')
  box.hidden = !f
  const fakeList = $('fakeList')
  fakeList.textContent = ''
  if (f) fakeList.append(levelRow(f, levels.length - 1))

  syncAlignUi()
  refreshSplitBtn()
}

/** 密钥串对齐目标：一片里一共几组 k:v（真层 + 假层 + 没有密文的补位组） */
function targetKv(): number {
  const chain = levels.length
  if (!alignEnabled) return chain
  if (fakeAlign === '256') return Math.max(256, chain)
  if (fakeAlign === '32') return chain >= 32 ? Math.max(256, chain) : 32
  return Math.max(fakeCustom, chain)
}

/**
 * 对齐开关的可见性：
 *   0 层、1 层 → 可勾可取消，默认关；
 *   ≥2 层 → 强制勾选且不可取消（多层不对齐会从组数反推真实层数）。
 */
function syncAlignUi(): void {
  const cb = $<HTMLInputElement>('alignCheck')
  const n = levels.length
  if (n >= 2) alignEnabled = true
  cb.disabled = n >= 2
  cb.checked = alignEnabled
  $<HTMLElement>('alignOpts').hidden = !alignEnabled
  // 「隐藏 n」开关与对齐同一规则：0/1 层可选，≥2 层强制勾选锁定
  const hn = $<HTMLInputElement>('hideNCheck')
  if (n >= 2) hideN = true
  hn.disabled = n >= 2
  hn.checked = hideN
  syncFakeUi()
}

function syncFakeUi(): void {
  $<HTMLInputElement>('fakeCount').hidden = fakeAlign !== 'custom'
  const warn = $('fakeWarn')
  // 只有"自定义"是实验性的：32 / 256 是固定档位，跑过完整测试
  if (fakeAlign === 'custom' && alignEnabled) {
    const total = targetKv()
    // 每组 = 32 字节 y → base64 ≈ 44 字符，再加 ":k" 前缀；坐标只写一次
    const perShare = total * 48 + String(nShares).length + 8
    warn.hidden = false
    warn.textContent = `⚠️ 自定义对齐是实验性功能，未经过完整测试：一片会带 ${total.toLocaleString()} 组密钥材料，约 ${fmtSize(perShare)}。`
  } else {
    warn.hidden = true
  }
  if (!alignEnabled) {
    $('fakeSummary').textContent = ''
    return
  }
  const total = targetKv()
  const fake = Math.max(0, total - realLevels().length)
  $('fakeSummary').textContent =
    `密钥串 ${total.toLocaleString()} 组：真 ${realLevels().length} · 假 ${fake.toLocaleString()}`
}

/** 加入唯一的假文件层：必定最后一层，之后不能再加文件 */
function addFake(): void {
  if (sealed || levels.length === 0) return
  const reals = realLevels()
  const stats = sizeStats(reals.map((l) => l.size))
  levels.push({
    kind: 'fake',
    name: '',
    size: randSize(stats),
    k: fakeK(reals.map((l) => l.k), nShares),
    showK: false,
  })
  sealed = true
  fakeKDirty = false
  renderLevels()
}

/** 把假层的大小与 k 拨回默认值（用户手改过才需要） */
function resetFake(): void {
  const f = fakeLevel()
  if (!f) return
  const reals = realLevels()
  f.size = randSize(sizeStats(reals.map((l) => l.size)))
  f.k = fakeK(reals.map((l) => l.k), nShares)
  fakeKDirty = false
  renderLevels()
}

$<HTMLButtonElement>('btnAddFake').addEventListener('click', addFake)

$<HTMLSelectElement>('fakeAlign').addEventListener('change', (e) => {
  fakeAlign = (e.target as HTMLSelectElement).value as typeof fakeAlign
  syncFakeUi()
})

$<HTMLInputElement>('fakeCount').addEventListener('change', (e) => {
  const v = Math.round(Number((e.target as HTMLInputElement).value))
  if (Number.isFinite(v) && v >= 2) fakeCustom = Math.min(4096, v)
  syncFakeUi()
})

$<HTMLButtonElement>('btnApplyFake').addEventListener('click', resetFake)

function refreshSplitBtn(): void {
  const ok =
    levels.length > 0 &&
    realLevels().every((l) => l.file && l.k >= 1 && l.k <= nShares) &&
    (fakeLevel()?.k ?? 1) >= 1
  $<HTMLButtonElement>('btnSplit').disabled = !ok
}


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
  } catch { /* ignore */ }
}

try {
  const savedOpt = localStorage.getItem('shamir-name-opt')
  if (savedOpt) setNameMode(savedOpt)
  // 自定义文件名不记忆：只活在当前页面，刷新即清空（顺带清掉旧版本存过的值）
  localStorage.removeItem('shamir-name-custom')
  nameCustom.hidden = nameMode() !== 'custom'
  $<HTMLInputElement>('otsCheck').checked = localStorage.getItem('shamir-ots') === '1'
} catch { /* ignore */ }

for (const b of nameSeg.querySelectorAll('button'))
  b.addEventListener('click', () => {
    setNameMode(b.getAttribute('data-name')!)
    renderProductNames()
  })
nameCustom.addEventListener('input', () => {
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

/** 按命名选项生成产物词干（不含扩展名）；以第 1 层的真实文件为基准 */
function productStem(): string {
  const first = realLevels()[0]
  const base = first ? baseName(first.name) : 'file'
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
  /** 密钥串里每一组的 k（真 + 假 + 诱饵） */
  ks: number[]
  /** 有密文层的组数（真 + 假） */
  chain: number
  /** 真实层数 / 假层数 / 诱饵组数 */
  realCount: number
  fakeCount: number
  padCount: number
}

let splitResult: SplitResult | null = null

const splitRun = new Run('runLog', 'runProg', [
  {
    disable: () => {
      $<HTMLButtonElement>('btnSplit').disabled = true
      $<HTMLButtonElement>('btnAddMore').disabled = true
      $<HTMLButtonElement>('btnAddFake').disabled = true
      $<HTMLButtonElement>('btnApplyFake').disabled = true
      $<HTMLInputElement>('otsCheck').disabled = true
      $<HTMLInputElement>('alignCheck').disabled = true
      $<HTMLSelectElement>('fakeAlign').disabled = true
      $<HTMLInputElement>('fakeCount').disabled = true
      fileSplitInput.disabled = true
      $('dropSplit').classList.add('is-disabled')
    },
    restore: () => {
      $<HTMLButtonElement>('btnAddMore').disabled = false
      $<HTMLButtonElement>('btnAddFake').disabled = false
      $<HTMLButtonElement>('btnApplyFake').disabled = false
      $<HTMLInputElement>('otsCheck').disabled = false
      $<HTMLSelectElement>('fakeAlign').disabled = false
      $<HTMLInputElement>('fakeCount').disabled = false
      fileSplitInput.disabled = false
      $('dropSplit').classList.remove('is-disabled')
      syncAlignUi()
      refreshSplitBtn()
    },
  },
])

/** 一层加密前的明文材料 */
interface LevelPayload {
  name: string
  /** 原始长度（真 = 文件长度；假 = 乱码长度） */
  origSize: number
  stored: Uint8Array
  algo: number
  hash: Uint8Array
  ots: Uint8Array | null
  mime: string
  /** AES 加密用的密钥 */
  key: Uint8Array
  /** 参与 Shamir 的密钥；假层故意与 key 不同，所以凑够 k 片也解不开 */
  splitKey: Uint8Array
}

function randomGarbage(n: number): Uint8Array {
  const out = new Uint8Array(n)
  // getRandomValues 单次上限 65536 字节
  for (let off = 0; off < n; off += 65536) crypto.getRandomValues(out.subarray(off, Math.min(n, off + 65536)))
  return out
}

$<HTMLButtonElement>('btnSplit').addEventListener('click', async () => {
  const run = splitRun
  const plan = levels.slice()
  if (plan.length === 0) return
  const chain = plan.length
  // 密钥串里除了真层与假层，还要按"对齐档位"补一批诱饵组
  const total = targetKv()
  const padCount = Math.max(0, total - chain)
  const ksChain = plan.map((l) => l.k)
  const ksAll = [...ksChain, ...padKs(ksChain, total, realLevels().map((l) => l.k))]
  const n = nShares
  run.begin()
  try {
    if (realLevels().some((l) => l.k > n)) throw new Error('有真文件层的 k 超过总片数 n')

    // 分片文本体积预估：一组 = base64(32) + ":k" 前缀，坐标只写一次
    const unit = 32
    const estText = n * (total * unit * (4 / 3) + total * 4)
    if (estText > 256 * 1024 * 1024)
      throw new Error(
        `这个组合会生成约 ${fmtSize(estText)} 的分片文本，浏览器撑不住；请降低 n、层数或对齐档位`,
      )
    if (estText > 32 * 1024 * 1024)
      run.line(`⚠️ 分片文本预计 ${fmtSize(estText)}，生成会偏慢`, 'lg-warn')

    // 密文是嵌套的：总大小 ≈ 各层明文之和（假文件只有一层，诱饵不带数据）。
    const estPlain = plan.reduce((a, l) => a + l.size, 0)
    if (estPlain > 2 * 1024 ** 3)
      throw new Error(`各层明文合计约 ${fmtSize(estPlain)}，密文会长到同等量级，浏览器撑不住；请减少层数或假文件大小`)
    if (estPlain > 256 * 1024 ** 2)
      run.line(`⚠️ 各层明文合计 ${fmtSize(estPlain)}，密文也会接近这个大小`, 'lg-warn')

    const mulmods = n * plan.reduce((a, l) => a + Math.min(l.k, n) - 1, 0)
    run.line(
      `第 ${chain} 层 · n=${n} · 预计 ${mulmods.toLocaleString()} 次模乘`,
    )
    if (mulmods > 2e7) run.line(`⚠️ 计算量偏大，可能要几十秒到几分钟，页面可以继续滚动`, 'lg-warn')

    // ---------- 逐层准备明文 ----------
    const from = 8
    const to = 55
    const payloads: LevelPayload[] = []
    for (let i = 0; i < chain; i++) {
      const lv = plan[i]!
      const pct = from + ((to - from) * i) / chain
      if (lv.kind === 'real') {
        const f = lv.file!
        run.line(`[${i + 1}/${chain}] ${f.name}（${fmtSize(f.size)}）读取…`)
        run.prog(pct)
        const bytes = new Uint8Array(await f.arrayBuffer())
        const hash = await sha256(bytes)

        let ots: Uint8Array | null = null
        if ($<HTMLInputElement>('otsCheck').checked) {
          run.line(`[${i + 1}/${chain}] OTS：提交哈希到公共日历（联网，最长 20s）…`)
          run.indet()
          try {
            ots = await otsStamp(hash)
          } catch (e) {
            run.line(`OTS 提交失败（${e instanceof Error ? e.message : e}），已跳过`, 'lg-warn')
          }
        }

        run.line(`[${i + 1}/${chain}] 压缩（${ALGO_LABEL[currentAlgo()]}）…`)
        run.prog(pct + (to - from) / chain / 3)
        const packed = await compressData(bytes, currentAlgo())
        run.line(
          `[${i + 1}/${chain}] ${fmtSize(bytes.length)} → ${fmtSize(packed.bytes.length)}（${packed.note}）`,
          packed.algo === ALGO.NONE ? 'lg-warn' : 'lg-ok',
        )
        const key = randomFieldBytes()
        payloads.push({
          name: f.name,
          origSize: f.size,
          stored: packed.bytes,
          algo: packed.algo,
          hash,
          ots,
          mime: f.type,
          key,
          splitKey: key,
        })
      } else {
        // 假文件层：结构与真文件一模一样（真 SHA-256、真的 AES-GCM 密文），
        // 唯一的区别是"分片共享的密钥"和"加密用的密钥"不是同一把——
        // 所以凑够 k 片能插值出密钥，但 AES-GCM 校验必然失败。
        // 乱码天然压不动，直接按"不压缩"存，省掉一次无意义的压缩尝试。
        run.line(`[${i + 1}/${chain}] 生成假文件（${fmtSize(lv.size)}）…`)
        run.prog(pct)
        const garbage = randomGarbage(Math.max(64, Math.round(lv.size)))
        payloads.push({
          // 假文件没有名字可言：它就是一段 k 无意义的随机二进制，
          // 内层因此不写 FILENAME，谁也看不到一个"假名字"
          name: '',
          origSize: garbage.length,
          stored: garbage,
          algo: ALGO.NONE,
          hash: await sha256(garbage),
          ots: null,
          mime: '',
          key: randomFieldBytes(),
          splitKey: randomFieldBytes(),
        })
      }
    }

    // ---------- 反向建链：最深层先加密，逐层包进上一层 ----------
    run.line('加密并串成密文链…')
    run.prog(to)
    let nested: Uint8Array | null = null
    const now = Date.now()
    for (let i = chain - 1; i >= 0; i--) {
      const p = payloads[i]!
      const iv = randomBytes(IV_LEN)
      // 下一层的整段 TSCF 放在**内层**最后一块：链结构属于元数据，
      // 跟着载荷一起被加密。外层因此只剩 K + IV + 密文，看不出这套有几层。
      const nextLayer = nested
      const chunks = [
        // 假层 name 为空 → 不写 FILENAME（它没有名字可言）
        ...(p.name ? [{ tag: TSPK.TAG.FILENAME, value: new TextEncoder().encode(p.name) }] : []),
        { tag: TSPK.TAG.CREATED_AT, value: u64beBytes(now) },
        { tag: TSPK.TAG.SHA256, value: p.hash },
        ...(p.mime ? [{ tag: TSPK.TAG.MIME, value: new TextEncoder().encode(p.mime) }] : []),
        { tag: TSPK.TAG.ALGO, value: new Uint8Array([p.algo]) },
        ...(p.ots ? [{ tag: TSPK.TAG.OTS_RECEIPT, value: p.ots }] : []),
        { tag: TSPK.TAG.DATA, value: p.stored },
        ...(nextLayer ? [{ tag: TSPK.TAG.NEXT, value: nextLayer }] : []),
      ]
      const inner = tlvBuild(TSPK.MAGIC, TSPK.VERSION, chunks, {
        // 有 NEXT 时它是末块（0x13 > 0x11，排序后天然垫底）
        lastTag: nextLayer ? TSPK.TAG.NEXT : TSPK.TAG.DATA,
      })
      const ciphertext = await aesEncrypt(p.key, iv, inner)
      nested = tlvBuild(TSCF.MAGIC, TSCF.VERSION, [
        { tag: TSCF.TAG.K, value: u32beBytes(ksChain[i]!) },
        // n 只写在单层密文的这一层上。多层链里绝不写：那会让"总片数"这种
        // 全局信息出现在每一层，既多占字节，又与"每层只暴露自己 k"的设想相悖。
        // 0x03 N 是否写进明文结构，唯一权威是「隐藏总共分发的密钥数量」开关：
        // 勾上（或多层强制隐藏）就不写，恢复端只知道「还差 x 片」；
        // 不勾且单层才写，恢复端能据此断言「永远凑不齐」。
        ...(chain === 1 && !hideN ? [{ tag: TSCF.TAG.N, value: u32beBytes(n) }] : []),
        { tag: TSCF.TAG.IV, value: iv },
        { tag: TSCF.TAG.CIPHERTEXT, value: ciphertext },
      ])
      run.prog(to + ((60 - to) * (chain - i)) / chain)
    }
    const outer = nested!

    run.line(`Shamir 分片（${total} 组，n=${n}）…`)
    run.prog(62)
    // 假层的 k 可能大于 n：多项式最多做到 n−1 次，文本里仍写用户设的 k
    // （那样连凑都凑不齐）；诱饵位传 null，只写随机 y。
    const secrets: (Uint8Array | null)[] = payloads.map((p) => p.splitKey)
    for (let i = 0; i < padCount; i++) secrets.push(null)
    const splitKs = [...plan.map((l) => Math.min(l.k, n)), ...ksAll.slice(chain)]
    const { buffer, shareLen, count, xs, wide } = await splitInWorker(
      secrets,
      n,
      splitKs,
      stageProgress(run, 62, 98, '分片'),
      // 隐藏 n 时单层也用宽坐标：x 在 [1, MAX_SHARES] 里随机，位数不暴露 n
      hideN,
    )
    const view = new Uint8Array(buffer)
    const unitBytes = 32
    const shareTexts: string[] = new Array(count)
    for (let i = 0; i < count; i++) {
      const base = i * shareLen
      // x 只写一次；组与组用逗号分隔，组内 "k:y" 或裸 "y"（该层没勾「显示k」）
      const groups: string[] = []
      for (let j = 0; j < total; j++) {
        const b64 = toB64(view.subarray(base + j * unitBytes, base + (j + 1) * unitBytes))
        groups.push(j < chain && plan[j]!.showK ? `${ksAll[j]}:${b64}` : b64)
      }
      shareTexts[i] = [SHARE_PREFIX, coordText(xs[i]!, wide), groups.join(',')].join(':')
    }

    splitResult = {
      stem: productStem(),
      ciphertext: outer,
      shareTexts,
      ks: ksAll,
      chain,
      realCount: realLevels().length,
      fakeCount: chain - realLevels().length,
      padCount,
    }
    run.line(`完成 ✓ 密文 ${fmtSize(outer.length)} · ${count.toLocaleString()} 片`, 'lg-ok')
    run.end()
    renderSplitResult(payloads, otsAny(payloads))
  } catch (e) {
    run.line(`拆分失败：${e instanceof Error ? e.message : String(e)}`, 'lg-err')
    run.fail()
  }
})

function otsAny(payloads: LevelPayload[]): boolean {
  return payloads.some((p) => p.ots)
}

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

function renderSplitResult(payloads: LevelPayload[], hasOts: boolean): void {
  nameCustom.hidden = nameMode() !== 'custom'
  const r = splitResult!
  const card = $('resultCard')
  card.hidden = false
  $('ctName').textContent = `${r.stem}.tscf`
  const totalOrig = payloads.reduce((a, p) => a + p.origSize, 0)
  const chainKs = r.ks.slice(0, r.chain)
  const kText = chainKs.length > 4 ? `${chainKs.slice(0, 3).join('/')}…/${chainKs[chainKs.length - 1]}` : chainKs.join('/')
  $('ctMeta').textContent =
    `第 ${r.chain} 层 · 明文合计 ${fmtSize(totalOrig)} → 密文 ${fmtSize(r.ciphertext.length)} · k=${kText} · n=${nShares}`

  const box = $('otsBox')
  if (hasOts) {
    box.hidden = false
    box.innerHTML = ''
    const line = document.createElement('div')
    line.className = 'ots-line'
    line.innerHTML = `<span class="ots-status pending">OTS 存证已提交</span><span>哈希已发送至公共日历，比特币锚定约需数小时；回执藏进了对应层的密文，恢复时自动显示。</span>`
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
    // 多层时一条分片有一两 KB，列表里只给前缀 + 组数/长度摘要
    span.textContent =
      r.ks.length > 1
        ? `${text.slice(0, 48)}…（${r.ks.length} 组 · ${text.length} 字符）`
        : text
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
      if (prev && !sameLevels(prev.levels, entry.levels)) {
        errors.push(`第 ${entry.index} 号分片内容冲突，已保留原片`)
      } else if (!prev) {
        shareMap.set(entry.index, entry)
        added++
      }
    } catch (err) {
      errors.push(err instanceof Error ? err.message : String(err))
    }
  }
  if (recognized === 0) errors.push('没有识别到分片（格式应为 TSK1:x:k:y,y,…，一条一行）')
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

/** 把一条分片重新拼成文本（列表展示 / 复制用） */
function shareTextOf(s: ShareEntry): string {
  const parts = [SHARE_PREFIX, coordText(s.index, s.wide)]
  for (const lv of s.levels) parts.push(String(lv.k), toB64(lv.payload))
  return parts.join(':')
}

function renderShareList(): void {
  const list = $('shareMiniList')
  list.textContent = ''
  const shares = [...shareMap.values()].sort((a, b) => a.index - b.index)
  list.hidden = shares.length === 0
  // 同上：几万片时逐行渲染会卡死，只画前 50 行，剩下用计数交代
  for (const s of shares.slice(0, SHARE_ROWS)) {
    const row = el('div', 'mini-row')
    const text = shareTextOf(s)
    const del = el('button', 'btn share-btn', '移除')
    del.type = 'button'
    del.addEventListener('click', () => {
      shareMap.delete(s.index)
      renderShareList()
      refreshRestoreBtn()
    })
    const ks = s.levels.map((l) => l.k ?? '?')
    const kBrief = ks.length > 3 ? `${ks[0]}…${ks[ks.length - 1]}` : ks.join('/')
    row.append(
      el('span', 'mini-idx', `#${s.index}`),
      el('span', 'mini-meta', `${s.levels.length} 组密钥 · k=${kBrief} · ${text.length} 字符`),
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
  const shares = [...shareMap.values()]
  // 第 1 层的 k（分片里写了的话）必须与最外层密文一致；没写就由密文说了算
  const bad = shares.find((s) => s.levels[0]!.k != null && s.levels[0]!.k !== activeCt!.k)
  if (bad) {
    status.textContent = `⚠️ 有分片第 1 层 k=${bad.levels[0]!.k} 与密文 k=${activeCt.k} 不一致`
    btn.disabled = true
    return
  }
  const slots = shares[0]?.levels.length ?? 0
  // n 只有单层密文才记录；多层时链里根本没有这个字段，就别假装"未记录"
  const nText = activeCt.n != null ? `，n=${activeCt.n}` : ''
  status.textContent =
    `已导入 ${shares.length} 片（每片 ${slots || '?'} 组密钥，k=${activeCt.k}${nText}` +
    `${shares.length >= activeCt.k ? '，够用 ✓' : `，还差 ${activeCt.k - shares.length} 片`}）`
  btn.disabled = shares.length < activeCt.k
}

const fileCtInput = bindDrop([$<HTMLElement>('dropCt')], true, (files) => void ingestFiles(files))

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
    const shares = [...shareMap.values()].sort((a, b) => a.index - b.index)
    const ks = checkConsistency(shares, activeCt!.k)
    // 分片里的组数 ≠ 层数：多出来的是诱饵（没有对应密文）
    const slots = ks.length
    const kText = ks.map((k) => k ?? '?').join('/')
    run.line(`分片自洽：${shares.length} 片 · 每片 ${slots} 组密钥 · k=${kText.slice(0, 18)}${kText.length > 18 ? '…' : ''}`)

    const card = $('restoreCard')
    const list = $('restoreList')
    list.textContent = ''
    card.hidden = false
    const more = $('restoreMore')
    more.hidden = true
    more.textContent = ''

    const band = (92 - 8) / slots
    let bytes = activeCt!.bytes
    let unlocked = 0
    /** 真正取到密文的层数（诱饵没有密文，不计入） */
    let chainLayers = 0
    /** 链走到哪儿停的：locked = 片不够，fake = 假层，end = 没有下一层 */
    let endedBy: 'locked' | 'fake' | 'end' | 'slots' = 'slots'

    for (let j = 0; j < slots; j++) {
      const tscf = tlvParse(TSCF.MAGIC, bytes)
      chainLayers++
      const kBytes = tscf.chunks.get(TSCF.TAG.K)
      const kHere = kBytes ? beBytesToUint(kBytes) : 0
      // n 只可能来自**单层**密文；多层链里根本没有这个字段（拆分时就不写）。
      // 缺失就是"不知道这套一共多少片"，绝不能拿当前导入的片数冒充 ——
      // 用户完全可能只导入了 n 片里的 3 片，那样会把"还差几片"误报成"永远凑不齐"。
      const nBytes = tscf.chunks.get(TSCF.TAG.N)
      const nHere = nBytes ? beBytesToUint(nBytes) : null
      // 分片里写了 k 就和密文交叉核对；没写（该层没勾「显示k」）就由密文说了算
      if (ks[j] != null && ks[j] !== kHere)
        throw new Error(`第 ${j + 1} 层密文的 k=${kHere} 与分片 k=${ks[j]} 不一致，可能拿错了分片`)

      // 不够就停：更深层套在这一层里面，没有这一层的密钥连字节都拿不到
      if (shares.length < kHere) {
        // 只有"密文自己声明了总片数"且 k 超过它，才是确凿的永远凑不齐
        const impossible = nHere !== null && kHere > nHere
        list.append(lockedRow(j + 1, kHere, shares.length, impossible ? nHere : null))
        more.hidden = false
        more.textContent = impossible
          ? `第 ${j + 1} 层写着要 ${kHere} 片，可这套密文只拆成 ${nHere} 片：永远凑不齐，这是假层，密文到这儿就结束了。`
          : `第 ${j + 1} 层起需要至少 ${kHere} 片才能揭开，当前 ${shares.length} 片。凑够后重新点「恢复文件」就能接着往下解锁。` +
            (nHere === null ? '（多层密文不记录总片数，这里只能按你导入的片数计算；如果这层本就是假层，k 可能被故意设得比总片数还大。）' : '')
        endedBy = 'locked'
        break
      }

      run.line(`第 ${j + 1} 层：用 ${kHere} 片插值…`)
      run.prog(8 + band * j)
      const slice = shares.slice(0, kHere)
      const key = await combineInWorker(
        slice.map((s) => s.levels[j]!.payload),
        slice.map((s) => s.index),
        stageProgress(run, 8 + band * j, 8 + band * (j + 0.65), `第 ${j + 1} 层`),
      )

      const iv = tscf.chunks.get(TSCF.TAG.IV)
      const ct = tscf.chunks.get(TSCF.TAG.CIPHERTEXT)
      if (!iv || iv.length !== IV_LEN) throw new Error(`第 ${j + 1} 层密文缺少 IV 或长度不对`)
      if (!ct) throw new Error(`第 ${j + 1} 层密文缺少 CIPHERTEXT 块`)

      // 假层：插值出来的是"另一把密钥"，AES-GCM 校验必然不过。
      // 这不是程序出错，所以单独给一行说明，而不是抛异常。
      let inner: Uint8Array
      try {
        inner = await aesDecrypt(key, iv, ct)
      } catch {
        list.append(fakeRow(j + 1, kHere))
        more.hidden = false
        more.textContent =
          `第 ${j + 1} 层用 ${kHere} 片解出来的密钥打不开它：它是假层（拆分时特意用另一把密钥加密）。` +
          (unlocked > 0 ? `前 ${unlocked} 个文件不受影响。` : '') +
          '如果你确信这层本应是真文件，那更可能是分片被改动过。'
        endedBy = 'fake'
        break
      }

      const pack = tlvParse(TSPK.MAGIC, inner)
      if (pack.version !== TSPK.VERSION) throw new Error(`不支持的载荷包版本 v${pack.version}`)
      const stored = pack.chunks.get(TSPK.TAG.DATA)
      if (!stored) throw new Error(`第 ${j + 1} 层载荷包缺少 DATA 块`)
      const algo = pack.chunks.get(TSPK.TAG.ALGO)?.[0] ?? ALGO.NONE
      let data = stored
      if (algo !== ALGO.NONE) {
        run.line(`第 ${j + 1} 层解压（${ALGO_LABEL[algo] ?? `算法 ${algo}`}，${fmtSize(stored.length)}）…`)
        data = await decompressData(stored, algo)
      }

      const nameBytes = pack.chunks.get(TSPK.TAG.FILENAME)
      const createdAtBytes = pack.chunks.get(TSPK.TAG.CREATED_AT)
      const createdAt = createdAtBytes ? beBytesToU64(createdAtBytes) : null
      const name = nameBytes ? new TextDecoder().decode(nameBytes) : defaultName(createdAt)

      // SHA-256 完整性：假文件也带自己那份（对乱码算的），所以照样能对上，
      // 不会因为"校验失败"提前暴露它是假的
      const expect = pack.chunks.get(TSPK.TAG.SHA256)
      const actual = await sha256(data)
      const hashOk = expect ? toHex(expect) === toHex(actual) : null

      const otsBytes = pack.chunks.get(TSPK.TAG.OTS_RECEIPT) ?? null
      const item = levelCard({
        index: j + 1,
        name,
        data,
        createdAt,
        hashOk,
        hash: actual,
        ots: otsBytes,
      })
      list.append(item)
      if (otsBytes) await renderOtsInto(item.querySelector('.ots-box') as HTMLElement, otsBytes, actual)

      unlocked++
      run.prog(8 + band * (j + 0.9))

      const next = pack.chunks.get(TSPK.TAG.NEXT)
      if (!next) {
        endedBy = 'end'
        break
      }
      bytes = next
    }

    // 链走完后，剩下的组都是诱饵——说清楚它们为什么存在，免得用户以为丢数据了
    const rest = slots - chainLayers
    if ((endedBy === 'end' || endedBy === 'fake') && rest > 0) {
      list.append(
        el(
          'div',
          'hint',
          `另外 ${rest} 组密钥是假的：没有对应的密文，只是把密钥串撑到固定组数，让人看不出真实层数。`,
        ),
      )
    }

    run.line(`完成 ✓ 解锁 ${unlocked} 层`, 'lg-ok')
    run.end()
    card.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
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

/** 已解锁的一层 */
function levelCard(r: {
  index: number
  name: string
  data: Uint8Array
  createdAt: number | null
  hashOk: boolean | null
  hash: Uint8Array
  ots: Uint8Array | null
}): HTMLElement {
  const box = el('div', 'rest-item')
  const head = el('div', 'rest-head')
  head.append(el('span', 'rest-lv', `第 ${r.index} 层`), el('span', 'prod-name', r.name))
  box.append(head)
  box.append(
    el('div', 'prod-meta', `${fmtSize(r.data.length)}${r.createdAt ? ` · ${new Date(r.createdAt).toLocaleString()}` : ' · 时间未记录'}`),
  )
  box.append(
    el(
      'div',
      'hash-line',
      `SHA-256：${toHex(r.hash)}${r.hashOk === false ? '\n⚠️ 与打包时记录的哈希不一致，文件可能被篡改！' : ''}`,
    ),
  )
  const otsBox = el('div', 'ots-box')
  otsBox.hidden = true
  box.append(otsBox)

  const row = el('div', 'dl-row')
  const dl = el('button', 'btn btn-primary', '下载') as HTMLButtonElement
  dl.type = 'button'
  dl.addEventListener('click', () => download(r.name, r.data))
  row.append(dl)
  if (r.ots) {
    // 包装成标准 DetachedTimestampFile，官方 ots 工具与 opentimestamps.org 可直接验证
    const b = el('button', 'btn btn-ghost', '下载 ots 文件') as HTMLButtonElement
    b.type = 'button'
    b.addEventListener('click', () => download(`${r.name}.ots`, toDetachedOts(r.ots!, r.hash)))
    row.append(b)
  }
  box.append(row)
  return box
}

/** 还没凑够片的那一层 */
/**
 * 还没凑够片的那一层。
 * total 非 null = 密文自己声明了总片数（只有单层密文才有 N 字段），
 * 此时 k > total 是确凿的"永远凑不齐"；否则只能说"还差几片"。
 */
function lockedRow(level: number, k: number, have: number, total: number | null): HTMLElement {
  const box = el('div', 'rest-item is-locked')
  box.append(
    el('span', 'rest-lv', `第 ${level} 层`),
    el(
      'span',
      'mini-meta',
      total !== null
        ? `🔒 需要 ${k} 片，这套密文只拆成 ${total} 片：永远凑不齐`
        : `🔒 需要 ${k} 片，当前 ${have} 片（还差 ${k - have} 片）`,
    ),
  )
  return box
}

/** 凑够片、密钥也插出来了，但解不开的那一层：假层 */
function fakeRow(level: number, k: number): HTMLElement {
  const box = el('div', 'rest-item is-locked is-fake-layer')
  box.append(
    el('span', 'rest-lv', `第 ${level} 层`),
    el('span', 'mini-meta', `🔒 解密失败 · 假层（${k} 片插出来的密钥对不上）`),
  )
  return box
}

async function renderOtsInto(box: HTMLElement, otsBytes: Uint8Array, actualHash: Uint8Array): Promise<void> {
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
    // 只有白名单里（实测带 CORS 头）的日历才值得发请求；否则请求发出去也读不到响应，
    // 纯粹白送一次外发。这类回执直接给"本地已校验、可交官方工具复核"的静态结论。
    const queryable = pending.filter((p) => calendarHasCors(p.uri))
    const hostOf = (uri: string) => {
      try {
        return new URL(uri).hostname
      } catch {
        return uri
      }
    }
    if (anchors.length > 0) {
      status.append(
        el('span', 'ots-status ok', `OTS 已锚定 Bitcoin 区块 #${anchors.map((a) => a.height).join(' / #')}`),
        spinner(),
        el('span', '', '正在比对区块链…'),
      )
    } else if (queryable.length > 0) {
      status.append(
        el('span', 'ots-status pending', 'OTS 待锚定'),
        spinner(),
        el('span', '', '拆分时已提交日历，正在后台查询最新状态…'),
      )
    } else if (pending.length > 0) {
      status.append(
        el('span', 'ots-status pending', 'OTS 待锚定'),
        el('span', '', `回执里的日历（${[...new Set(pending.map((p) => hostOf(p.uri)))].join('、')}）不允许浏览器跨域读取，因此没有做在线查询。回执本身已随密文一起存好，可用「下载 ots 文件」交给官方工具（ots verify）复核。`),
      )
    } else {
      status.append(el('span', 'ots-status pending', 'OTS 回执存在，但未识别出 attestation'))
    }
    box.append(status)

    // 没有可查的日历就直接收工，一次请求都不发
    if (pending.length > 0 && queryable.length === 0) {
      if (ots.degraded) box.append(el('div', 'hint', '回执里有暂不支持的 op/attestation，离线校验只走通了一部分。'))
      return
    }

    // 后台查询：完成后原地更新状态行（成功/失败都不打扰用户下载文件）
    void (async () => {
      try {
        let toVerify: { height: number; digest: Uint8Array | null }[] = anchors
        if (anchors.length === 0) {
          // 日历升级查询：只查白名单里的（外面已过滤掉不支持 CORS 的）
          const upgraded = await Promise.all(queryable.map((p) => upgradePending(p)))
          toVerify = upgraded.flatMap((u) =>
            u.attestations.filter((a) => a.kind === 'bitcoin'),
          ) as { kind: 'bitcoin'; height: number; digest: Uint8Array | null }[]
          if (toVerify.length === 0) {
            status.textContent = ''
            status.append(
              el('span', 'ots-status pending', 'OTS 待锚定'),
              el('span', '', `已查日历（${queryable.map((p) => p.uri).join('、')}）：尚未上链，比特币锚定通常需 1~3 小时，之后重新恢复本密文可自动再查。`),
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
        const noCors = e instanceof OtsNoCorsError
        status.append(
          el('span', 'ots-status pending', noCors
            ? 'OTS 待锚定（该日历不支持浏览器跨域读取，已跳过在线查询）'
            : `OTS 待锚定（后台查询失败：${e instanceof Error ? e.message : String(e)}）`),
          el('span', '', '可点「下载 ots 文件」交给官方工具（ots verify）复核，那条路径不受浏览器跨域限制。'),
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
}

