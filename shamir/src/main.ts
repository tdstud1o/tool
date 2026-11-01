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
import { STYLE, STYLE_LIST, readStyle, styleBytes, styleLabel, type StyleId } from './core/styles.ts'
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
import { buildZip, isZipBuffer, readZip, type ZipReadEntry } from './core/zip.ts'
import { baseName, download, el, fmtSize, revokeTracked } from './ui/dom.ts'
import { renderOtsInto } from './ui/otsBox.ts'
import { createRestoreView, createSplitView, splitPolicy } from './appearance/index.ts'
import type { RestoreView, ShareIntent, SplitCell, SplitView } from './appearance/types.ts'

/** 拆分结果里最多渲染多少行分片；超出部分折叠（n 可达十万级） */
const SHARE_ROWS = 50

/**
 * 恢复端**唯一**的筛选器：密文 `.tscf` 与分片文本一起选。
 *
 * 恢复端只有一只文件输入框（`fileCtInput`，挂在 #dropCt 上），① 点击、星图/玻璃点格子
 * 都打开它，所以筛选器只有这一份，不存在"两个入口两套规则"的可能。
 * 筛选器只是给系统文件框的提示，真正的分辨在 `ingestFiles` 里（TSCF 魔数 / TSK1 头）。
 * 别放宽成 `''` 或加 `image/*`：那会让照片混进密文选择框（2026-11-01 用户明确否掉）。
 */
const RESTORE_ACCEPT = '.tscf,.txt,.share,.shares,text/plain'

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

function toggleTheme(): void {
  const cur = root.dataset.theme === 'dark' ? 'dark' : 'light'
  const next = cur === 'dark' ? 'light' : 'dark'
  root.dataset.theme = next
  try { localStorage.setItem('shamir-theme', next) } catch { /* ignore */ }
}

// 头卡右上角那一枚（图标直接在 index.html 里，暗色看太阳、亮色看月亮）
$<HTMLButtonElement>('themeToggle').addEventListener('click', toggleTheme)

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

// ===== 密文外观（style）=====
// 外观写在 TSCF 外层，拆分时选，恢复时读回来决定怎么呈现。
//
// 这里只管"当前选的是哪个"：外观自己的规矩（收什么文件、最多几层、说什么话）
// 和恢复端怎么画，都在 src/appearance/ 里，通过 splitPolicy()/createRestoreView() 取。
let styleId: StyleId = STYLE.PLAIN
/**
 * 普通模式下的「密文外观覆写」：界面照旧走普通模式（层列表、任意文件、任意层数、假文件层、高级操作），
 * 只把密文外层记的那个外观换成这里选的，让恢复端按目标外观渲染。
 * 和 styleId 是两件事——styleId 决定"怎么插入"，它决定"恢复端看到什么"。null = 不覆写。
 */
let ctStyleOverride: StyleId | null = null
/** 拆分端的碎片舞台（只有碎片外观有）；换外观时整份扔掉 */
/** 这一步拆分视图是按哪套外观建的：换外观（碎片 ↔ 星座）要重建，不能接着用 */
let splitViewStyle: StyleId | null = null
let splitView: SplitView | null = null

/**
 * 这套外观自带整套界面（碎片 / 星座）：拆分端用它自己的格子，
 * 恢复端也接管 ① 卡（② 导入分片、③ 结果卡都让位）。
 *
 * 主流程不认识"长什么样"，只认识"它要不要接管"——新外观只要在
 * appearance/index.ts 里带了 splitView 或 attachShare，就自动归到这一类。
 */
function ownsStage(style: StyleId | null | undefined): boolean {
  return style === STYLE.FRAGMENT || style === STYLE.CONSTELLATION
}
/** 拆分运行中不许再往里塞文件 */
let splitBusy = false

/** 外观选项永远来自 STYLE_LIST：编号、名字、能不能选，都只有那一份清单说了算 */
function buildStyleSeg(host: HTMLElement): void {
  host.textContent = ''
  for (const s of STYLE_LIST) {
    const b = document.createElement('button')
    b.type = 'button'
    b.dataset.style = String(s.id)
    b.textContent = s.label
    if (s.id === styleId) b.classList.add('is-active')
    if (!s.splitReady) {
      b.disabled = true
      b.title = s.note ?? '暂未开放'
    }
    host.append(b)
  }
}

const styleSeg = $('styleSeg')
buildStyleSeg(styleSeg)
const styleRules = () => splitPolicy(styleId)

// ===== 密文外观覆写（普通模式专属）=====
// 普通模式要给的是"随你插"：什么文件都能放、想几层几层、还能塞假文件层。
// 但恢复端长什么样是密文外层那个 tag 说了算，两件事本来捆在一起。
// 覆写把它们解开：插入仍按普通模式走，只有写进密文的外观换了名字。
const OV_NONE = 'none'

function syncOverrideUi(): void {
  const seg = $('ovStyleSeg')
  const cur = ctStyleOverride === null ? OV_NONE : String(ctStyleOverride)
  for (const b of seg.querySelectorAll<HTMLButtonElement>('button[data-ov]'))
    b.classList.toggle('is-active', b.dataset.ov === cur)
  // 自带界面的外观下，界面本来就是它自己，覆写无从谈起（这一块也已经被 .adv 收起了）
  $('ovStyleRow').hidden = ownsStage(styleId)
  $('ovStyleHint').textContent =
    ctStyleOverride === null
      ? '不覆写：密文按当前模式记成「普通」，恢复端就是标准列表。'
      : `密文记成「${styleLabel(ctStyleOverride)}」，恢复端按这套外观呈现；插入流程仍是普通模式——任意文件、任意层数、假文件层全部照旧。`
}

function buildOverrideSeg(): void {
  const seg = $('ovStyleSeg')
  seg.textContent = ''
  const none = document.createElement('button')
  none.type = 'button'
  none.dataset.ov = OV_NONE
  none.textContent = '不覆写'
  seg.append(none)
  for (const s of STYLE_LIST) {
    const b = document.createElement('button')
    b.type = 'button'
    b.dataset.ov = String(s.id)
    b.textContent = s.label
    if (!s.splitReady) {
      b.disabled = true
      b.title = s.note ?? '暂未开放'
    }
    seg.append(b)
  }
  syncOverrideUi()
}
// 记住上次的覆写（星座没实现，读到它当作不覆写）
try {
  const saved = localStorage.getItem('shamir-style-override') ?? OV_NONE
  const id = Number(saved)
  if (saved !== OV_NONE && STYLE_LIST.some((s) => s.id === id && s.splitReady)) ctStyleOverride = id
} catch { /* ignore */ }
buildOverrideSeg()

$('ovStyleSeg').addEventListener('click', (e) => {
  const b = (e.target as HTMLElement).closest<HTMLButtonElement>('button[data-ov]')
  if (!b || b.disabled) return
  const raw = b.dataset.ov ?? OV_NONE
  ctStyleOverride = raw === OV_NONE ? null : (Number(raw) as StyleId)
  try { localStorage.setItem('shamir-style-override', raw) } catch { /* ignore */ }
  syncOverrideUi()
})

function applyStyle(id: StyleId): void {
  styleId = id
  for (const b of styleSeg.querySelectorAll<HTMLButtonElement>('button'))
    b.classList.toggle('is-active', Number(b.dataset.style) === id)
  const rules = splitPolicy(id)
  // accept 只是给系统的提示，真正的拦截在 addRealFiles 里
  fileSplitInput.accept = rules.accept
  $('dropSplitText').textContent = rules.dropText
  $<HTMLButtonElement>('btnAddMore').textContent = rules.dropText
  try { localStorage.setItem('shamir-style', String(id)) } catch { /* ignore */ }
  // 碎片外观有自己的一套片数规矩（第 i 块要 i 片），切进来就先把 k/n 排好；
  // 排完必须重画层列表——输入框里写的是上一套外观留下的数字，不能让它停在界面上
  reclampFragmentShares()
  syncOverrideUi()
  // 碎片外观有自己的插入界面（同一套玻璃），其余外观用层列表
  if (levels.length) {
    renderLevels()
    return
  }
  syncSplitMode()
  refreshSplitBtn()
}

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

/**
 * 碎片外观的片数规矩：**第 i 块要 i 片**（1、2、3…），n 正好等于文件数。
 *
 * 于是每多一片就多解开一个文件：1 片开第 1 块，2 片连第 2 块一起开，凑齐 n 片全开。
 * 六块之间没有"拼图"关系，各自是一份独立内容，所以这里也不需要"越深越难"那套
 * 递增规律——门槛就是它在舞台上的位置。
 *
 * 这是外观自己的语义，不是通用链规则：普通模式的层列表照旧 3、4、5… 随便改；
 * 只在"切到碎片"和"层有任何增减"时重排一次，把 k 与 n 一起拨回来。
 */
function reclampFragmentShares(): void {
  if (!ownsStage(styleId)) return
  const reals = realLevels()
  if (reals.length === 0) return
  reals.forEach((l, i) => { l.k = i + 1 })
  // 假层恒定排在最后一个真层之后：照例是"永远解不开"的那一块
  const f = fakeLevel()
  if (f && !fakeKDirty) f.k = reals.length + 1
  const n = Math.max(2, reals.length)
  if (nShares === n) return
  nShares = n
  nSharesInput.value = String(n)
}

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
  // 外观可以规定"只收某类文件 / 最多几层"：不合规的先剔掉，但每类都写日志——
  // 静默丢文件比报错更讨厌。
  const rules = styleRules()
  const kept = files.filter((f) => rules.accepts(f))
  if (kept.length < files.length)
    logLine(
      'runLog',
      `「${styleLabel(styleId)}」外观只收${rules.acceptLabel}，已忽略 ${files.length - kept.length} 个文件`,
      'lg-warn',
    )
  if (Number.isFinite(rules.maxLayers)) {
    const room = rules.maxLayers - realLevels().length
    if (kept.length > room) {
      logLine(
        'runLog',
        `「${styleLabel(styleId)}」外观最多 ${rules.maxLayers} 层，已忽略后 ${kept.length - Math.max(0, room)} 个文件`,
        'lg-warn',
      )
      kept.length = Math.max(0, room)
    }
  }
  if (kept.length === 0) return
  for (const f of kept) {
    // 后续层默认比上一层多一片门槛：既符合"越深越难"的直觉，
    // 也让假文件能顺着这个等差规律往下接。
    // 自带界面的外观是另一套语义：k 就是"第几格"（第 1 格 1 片、第 2 格 2 片…），
    // 所以这里直接按位置给，最后 renderLevels 里还会再统一拨一次。
    const prev = levels.length ? levels[levels.length - 1]!.k : Math.min(3, nShares)
    // 新层默认 k 顺着链 +1；超过 n 不压平，而是把 n 拉到一样大
    const k = ownsStage(styleId) ? levels.length + 1 : levels.length ? prev + 1 : prev
    if (k > nShares) setNShares(k)
    levels.push({ kind: 'real', name: f.name, size: f.size, k, showK: false, file: f })
  }
  // 有了文件，大拖放框就让位给下面的分半按钮（左半继续拖/选，右半加假层）
  $('dropSplit').hidden = true
  renderLevels()
}

const fileSplitInput = bindDrop([$<HTMLElement>('dropSplit'), $<HTMLElement>('btnAddMore')], true, addRealFiles)

styleSeg.addEventListener('click', (e) => {
  const btn = (e.target as HTMLElement).closest<HTMLButtonElement>('button')
  if (!btn || btn.disabled) return
  const id = Number(btn.dataset.style)
  if (!STYLE_LIST.some((s) => s.id === id && s.splitReady)) return
  // 已经加进来的层如果不符合新外观的规矩，就不静默切过去：留着它们只会让恢复端
  // 出现"没有内容的一格"，用户根本不知道为什么。
  const rules = splitPolicy(id)
  // 层数也不能超：碎片只有 6 格，第 7 层（含假层）在恢复端根本没有落脚的地方
  if (Number.isFinite(rules.maxLayers) && levels.length > rules.maxLayers) {
    logLine(
      'runLog',
      `「${styleLabel(id)}」外观只有 ${rules.maxLayers} 格，当前有 ${levels.length} 层，请先撤掉多出来的层`,
      'lg-warn',
    )
    return
  }
  const bad = realLevels().filter((l) => l.file && !rules.accepts(l.file))
  if (bad.length) {
    logLine(
      'runLog',
      `「${styleLabel(id)}」外观只收${rules.acceptLabel}：「${bad[0]!.name}」${bad.length > 1 ? ` 等 ${bad.length} 个` : ''}不符合，请先移除这几层`,
      'lg-warn',
    )
    return
  }
  applyStyle(id)
})

// 记住上次选的外观（星座还没实现，读到它按默认处理）
try {
  const saved = Number(localStorage.getItem('shamir-style') ?? STYLE.PLAIN)
  if (STYLE_LIST.some((s) => s.id === saved && s.splitReady)) applyStyle(saved)
} catch { /* ignore */ }

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
  del.addEventListener('click', () => dropLevel(lv))
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

/** 撤掉一层：层列表里的 × 和碎片舞台上的 × 走的是同一条路 */
function dropLevel(lv: LevelRow): void {
  const wasFake = lv.kind === 'fake'
  levels = levels.filter((l) => l !== lv)
  kInputs.delete(lv)
  kOver.delete(lv)
  if (wasFake) sealed = false
  if (levels.length === 0) {
    // 一层不剩，大拖放框回来
    $('dropSplit').hidden = false
    $('dropSplitText').textContent = styleRules().dropText
  }
  renderLevels()
}

function renderLevels(): void {
  // 层的增减先过一遍外观规矩：碎片模式下 k 就是"第几块"，n 跟着文件数走
  reclampFragmentShares()
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
  syncSplitMode()
  refreshSplitBtn()
}

// ===== 拆分端的碎片舞台 =====
//
// 碎片外观下，"插入"和"恢复"是同一块六格拼图：恢复端往外取图，拆分端往里塞图。
// 这里只做三件事——把层数据喂给舞台、把舞台的动作接回主流程、样式切换时挂/摘。
function splitCells(): SplitCell[] {
  return levels.map((l, i) => ({
    index: i + 1,
    name: l.kind === 'fake' ? '假文件层' : l.name,
    size: l.size,
    k: l.k,
    fake: l.kind === 'fake',
    file: l.kind === 'fake' ? null : (l.file ?? null),
  }))
}

function syncSplitMode(): void {
  const staged = ownsStage(styleId)
  $('splitMain').classList.toggle('is-staged-split', staged)
  $('fragSplitHost').hidden = !staged
  if (!staged) {
    if (splitView) {
      $('fragSplitHost').textContent = ''
      splitView = null
      splitViewStyle = null
    }
    return
  }
  // 碎片 ↔ 星座：视图得按当前外观重建，不能把上一套的格子接着用
  if (splitView && splitViewStyle !== styleId) {
    $('fragSplitHost').textContent = ''
    splitView = null
  }
  if (!splitView) {
    const view = createSplitView(styleId)
    if (!view) return
    view.attach({
      pick: () => fileSplitInput.click(),
      drop: (files) => addRealFiles(files),
      // 舞台上的 × 是"第几格"，层数组里就是第几个（假层也占一格）
      remove: (i) => {
        const lv = levels[i]
        if (lv) dropLevel(lv)
      },
      allowed: () => !splitBusy,
    })
    $('fragSplitHost').append(view.root)
    splitView = view
    splitViewStyle = styleId
  }
  splitView.render(splitCells())
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
  // 有的外观格数是死的：假层也占一格，凑不出第 7 格
  const cap = styleRules().maxLayers
  if (Number.isFinite(cap) && realLevels().length >= cap) {
    logLine('runLog', `「${styleLabel(styleId)}」外观只有 ${cap} 层，已经排满了`, 'lg-warn')
    return
  }
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
  /** 拆分时选的外观（产物文案据此写，之后改选择不影响已产出的文件） */
  style: StyleId
}

let splitResult: SplitResult | null = null

const splitRun = new Run('runLog', 'runProg', [
  {
    disable: () => {
      splitBusy = true
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
      splitBusy = false
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
  // 外观在这一刻定下来：拆分过程中改选择不该影响这一批产物
  const style = styleId
  // 覆写只换"写进密文的那个外观"，不动插入方式：普通模式照旧不受限（任意文件、
  // 任意层数、假文件层、高级操作都在），恢复端却会按目标外观呈现。
  // 碎片模式自己就是碎片，不需要也不接受覆写。
  const emit = style === STYLE.PLAIN ? (ctStyleOverride ?? STYLE.PLAIN) : style
  // 自带界面的外观把「高级操作」整块收起来了，那就得真用默认值：
  // 压缩固定 zstd L3、不碰 OTS——否则之前在普通模式勾过的 OTS 会在用户看不见的地方联网。
  const quiet = ownsStage(style)
  const algo = quiet ? ALGO.ZSTD_L3 : currentAlgo()
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
    if (emit !== style)
      run.line(`外观覆写：密文记成「${styleLabel(emit)}」，插入仍是普通模式`)
    // 自带界面的外观各有各的格数上限（碎片 6 格；星座不设限，路会往下长），
    // 所以这里不能写死，得问那个外观自己要多少
    const emitCap = splitPolicy(emit).maxLayers
    if (Number.isFinite(emitCap) && chain > emitCap)
      run.line(
        `⚠️ 覆写成「${styleLabel(emit)}」外观，但恢复端只有 ${emitCap} 格：第 ${emitCap + 1} 层起不会出现在那些格子上，只能在「文件信息与校验」里看`,
        'lg-warn',
      )

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
        if (!quiet && $<HTMLInputElement>('otsCheck').checked) {
          run.line(`[${i + 1}/${chain}] OTS：提交哈希到公共日历（联网，最长 20s）…`)
          run.indet()
          try {
            ots = await otsStamp(hash)
          } catch (e) {
            run.line(`OTS 提交失败（${e instanceof Error ? e.message : e}），已跳过`, 'lg-warn')
          }
        }

        run.line(`[${i + 1}/${chain}] 压缩（${ALGO_LABEL[algo]}${quiet ? '，碎片外观的默认值' : ''}）…`)
        run.prog(pct + (to - from) / chain / 3)
        const packed = await compressData(bytes, algo)
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
        // 外观只写最外层（i === 0 是循环里最后生成的那一个）：
        // 内层密文被封在上一层的 TSPK 里，谁也看不见，写了也白写。
        ...(i === 0 && emit !== STYLE.PLAIN ? [{ tag: TSCF.TAG.STYLE, value: styleBytes(emit) }] : []),
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
      style: emit,
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
    `第 ${r.chain} 层 · 明文合计 ${fmtSize(totalOrig)} → 密文 ${fmtSize(r.ciphertext.length)} · k=${kText} · n=${nShares}` +
    (r.style !== STYLE.PLAIN ? ` · ${styleLabel(r.style)}外观` : '')

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
  /** 外层 0x06 STYLE：外观编号（缺失 = 默认） */
  style: StyleId
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

/** 摄取单个文件内容：TSCF 头 → 密文；含 TSK1 分片文本 → 逐片导入；其余报错（结果全进按钮下方日志） */
async function ingestBlob(
  name: string,
  size: number,
  buf: Uint8Array,
  verbose: boolean,
  tally: { shareFiles: number; shareCount: number },
): Promise<void> {
  try {
    let handled = false
    try {
      const outer = tlvParse(TSCF.MAGIC, buf)
      if (outer.version !== TSCF.VERSION) throw new Error(`不支持的密文版本 v${outer.version}`)
      const kBytes = outer.chunks.get(TSCF.TAG.K)
      const nBytes = outer.chunks.get(TSCF.TAG.N)
      const k = kBytes ? beBytesToUint(kBytes) : 0
      const n = nBytes ? beBytesToUint(nBytes) : undefined
      if (!k) throw new Error('密文缺少 k 参数')
      const entry: CtEntry = { name, size, bytes: buf, k, n, style: readStyle(outer.chunks.get(TSCF.TAG.STYLE)) }
      ctEntries.push(entry)
      activeCt = entry
      handled = true
    } catch (ctErr) {
      // 不是密文 → 尝试按分片文本处理；带密文扩展名却解析失败则直接报错
      const text = new TextDecoder('utf-8', { fatal: false }).decode(buf)
      if (!SHARE_RE.test(text)) {
        if (/\.tscf$/i.test(name)) throw ctErr
        throw new Error(`无法识别的文件（既不是密文也不含分片）`)
      }
      const { added, errors } = importShareText(text)
      tally.shareFiles++
      tally.shareCount += added
      if (verbose || errors.length)
        logLine(
          'restoreLog',
          `${name}：导入 ${added} 片${errors.length ? `；${errors.join('；')}` : ''}`,
          errors.length ? 'lg-warn' : 'lg-ok',
        )
    }
    if (handled && verbose) logLine('restoreLog', `🔐 ${name}（${fmtSize(size)}）已加入密文列表`, 'lg-ok')
  } catch (e) {
    logLine('restoreLog', `⚠️ ${name}：${e instanceof Error ? e.message : String(e)}`, 'lg-err')
  }
}

/** 取 zip「当前层级」的文件：只列当前层；若当前层只有 1 个文件夹，下钻一层取其直接子文件 */
function pickZipLevel(entries: ZipReadEntry[]): ZipReadEntry[] {
  const files = entries.filter((e) => !e.isDir)
  const loose = files.filter((e) => !e.name.includes('/'))
  const rootDirs = entries.filter((e) => e.isDir && !e.name.slice(0, -1).includes('/'))
  // 显式目录条目：当前层只有 1 个文件夹、没有散文件 → 下钻
  if (rootDirs.length === 1 && loose.length === 0 && files.length === 0)
    return files.filter((e) => e.name.startsWith(rootDirs[0]!.name) && !e.name.slice(rootDirs[0]!.name.length).includes('/'))
  // 没有目录条目（很多打 zip 工具不写）：所有文件共享唯一路径前缀 → 视作同一个文件夹，下钻
  if (loose.length === 0 && files.length > 0) {
    const tops = new Set(files.map((e) => e.name.slice(0, e.name.indexOf('/') + 1)))
    if (tops.size === 1) {
      const prefix = [...tops][0]!
      return files.filter((e) => !e.name.slice(prefix.length).includes('/'))
    }
  }
  return loose
}

/** 摄取文件：zip → 解压取当前层级逐个导入；TSCF 头 → 密文；含 TSK1 分片文本 → 逐片导入；其余报错 */
async function ingestFiles(files: File[]): Promise<void> {
  // 一次拖进上万个文件是真实场景（k 很大时要凑很多片）：
  // 逐个文件写日志 + 逐个重渲染列表会把界面拖死，所以只在文件少时逐条记。
  const verbose = files.length <= 20
  const tally = { shareFiles: 0, shareCount: 0 }
  /** 这批里有没有换过密文：换了就得重新判断要不要自动开解（见函数末尾） */
  const ctBefore = activeCt
  let quiet = false
  for (const f of files) {
    try {
      const buf = new Uint8Array(await f.arrayBuffer())
      if (isZipBuffer(buf)) {
        // zip：解压后把当前层级的文件逐个按密文/分片导入
        const picked = pickZipLevel(await readZip(buf))
        if (!picked.length) throw new Error('压缩包当前层级没有可导入的文件')
        const v = verbose && picked.length <= 20
        if (!v) quiet = true
        logLine('restoreLog', `📦 ${f.name}：解出 ${picked.length.toLocaleString()} 个文件`, 'lg-ok')
        for (const e of picked) await ingestBlob(e.name, e.data.length, e.data, v, tally)
      } else {
        await ingestBlob(f.name, f.size, buf, verbose, tally)
      }
    } catch (e) {
      logLine('restoreLog', `⚠️ ${f.name}：${e instanceof Error ? e.message : String(e)}`, 'lg-err')
    }
  }
  if (tally.shareFiles > 0 && (!verbose || quiet))
    logLine('restoreLog', `已从 ${tally.shareFiles.toLocaleString()} 个文件导入 ${tally.shareCount.toLocaleString()} 片，当前共 ${shareMap.size.toLocaleString()} 片`, 'lg-ok')
  renderShareList()
  renderCtList()
  refreshRestoreBtn()
  syncRestoreMode()
  // 碎片外观没有「恢复文件」按钮（拼图就是入口）：片够了就直接开解。
  // 除了"这批里有新片"，还要管**先放片、后放密文**的顺序——密文一进来，
  // 外壳声明的外观才把界面切成碎片，而那一刻片往往早就够了；
  // 只认新片的话，这一步永远等不到，用户会以为得再补一片才会开始。
  if ((tally.shareFiles > 0 && tally.shareCount > 0) || activeCt !== ctBefore) autoRestoreIfReady()
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
      syncRestoreMode()
    })
    row.append(
      el('span', 'mini-name', `🔐 ${c.name}`),
      el('span', 'mini-meta', `${fmtSize(c.size)}${c.style !== STYLE.PLAIN ? ` · ${styleLabel(c.style)}` : ''} · k=${c.k}/n=${c.n ?? '?'}`),
      del,
    )
    row.addEventListener('click', () => {
      const changed = activeCt !== c
      activeCt = c
      renderCtList()
      refreshRestoreBtn()
      syncRestoreMode()
      // 换到这份密文之后界面可能刚变成碎片（片可能早就够了）：这里补一次自动开解。
      // 点的是已选中的那一行就不重跑——那只是"确认"，不该把已经解锁的结果推倒重来。
      if (changed) autoRestoreIfReady()
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
    // 外观可以先选：说清楚"已经记下了，等密文进来生效"，不然点一下像没反应
    const parts: string[] = []
    if (shareMap.size) parts.push(`已导入 ${shareMap.size} 片 — 请先选择密文文件`)
    if (ownsStage(styleOverride))
      // 这套界面不靠密文成立，它已经摆在那儿了——这时候再说"选好密文后生效"是错的
      parts.push(`${styleLabel(styleOverride)}界面已就绪：点格子或把文件拖进来，密文、分片都行`)
    else if (styleOverride !== null)
      parts.push(`呈现外观：${styleLabel(styleOverride)}（选好密文后生效）`)
    status.textContent = parts.join('；')
    btn.disabled = true
    return
  }
  // 自带界面的外观没有「② 导入分片」那一块，入口就是那几格本身：这句是唯一的说明
  if (ownsStage(restoreStyle()) && shareMap.size === 0) {
    status.textContent = '点一下格子、把分片文件拖进来，都可以补片'
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
// ① 的输入框就是恢复端唯一的选择器：星图点格子/点纸面也打开它，筛选器自然同一份
fileCtInput.accept = RESTORE_ACCEPT

// ===== 恢复界面：外观接管 =====
//
// 密文外壳里声明了外观（0x06），就由那套外观决定"恢复界面长什么样"：
// 碎片外观直接摆一块碎玻璃在 ① 卡里，点格子或背景就能补分片，
// 所以「② 导入分片」那一整块（列表 / 输入框 / 从文件导入）都不出现。

/** 外观要补充分片时的两个动作：交给主流程才认识密文与分片格式 */
const shareIntent: ShareIntent = {
  // 复用 ① 的那个 input，而不是另一只「补片专用」的：
  // 两个入口两套 accept 正是筛选器打架的根源（一个漏 .tscf、一个什么都能选）。
  pick: () => {
    if (!fileCtInput.disabled) fileCtInput.click()
  },
  drop: (files) => void ingestFiles(files),
  // 恢复跑着的时候控件全禁用（Run 里那一套），这里跟着它走
  allowed: () => !fileCtInput.disabled,
}

/** 视图挂在哪儿：碎片摆进 ① 卡（② 那块消失），其余外观仍用下面的结果卡 */
function viewHost(style: StyleId): HTMLElement {
  return ownsStage(style) ? $('fragHost') : $('restoreList')
}

let liveView: RestoreView | null = null
/** 这份视图属于哪个密文：换密文就得换一份，不能接着用旧的格子状态 */
let liveCt: CtEntry | null = null
/** 这份视图是按哪套外观挂的：外观被手动改过也要重挂 */
let liveStyle: StyleId = STYLE.PLAIN

/** 挂一份干净视图（每次恢复都重挂：视图内部有状态，复用它会把上一轮的结果带过来） */
function mountRestoreView(style: StyleId): RestoreView {
  // 上一轮预览图的 blob URL 回收（预览不撤销，反复恢复会攒一堆）
  revokeTracked()
  $('fragHost').textContent = ''
  $('restoreList').textContent = ''
  const view = createRestoreView(style)
  view.attachShare?.(shareIntent)
  viewHost(style).append(view.root)
  liveView = view
  liveCt = activeCt
  liveStyle = style
  return view
}

/** 密文变了就换界面：自带界面的外观下，选了密文立刻能看见那几格 */
function syncRestoreMode(): void {
  const style = restoreStyle()
  // 碎片外观是一整套界面，不是"给密文配的皮肤"：它的入口（点格子 / 拖文件）走的就是
  // ingestFiles 这个通用入口，密文和分片一起吃得下。所以选中它就立刻换过去，
  // 别让人先对着「② 导入分片」等一份密文进来。
  const staged = ownsStage(style)
  paintRestoreSeg()
  $('restoreMain').classList.toggle('is-staged', staged)
  // 有密文之后 ① 卡的密文投放框才收起来（那之前它是唯一的密文入口）
  $('restoreMain').classList.toggle('has-ct', activeCt !== null)
  $('fragHost').hidden = !staged
  $('restoreCard').hidden = true

  if (!staged) {
    if (liveView) {
      revokeTracked()
      $('restoreList').textContent = ''
      $('fragHost').textContent = ''
      liveView = null
      liveCt = null
    }
    return
  }
  // 视图带状态（哪一格亮了），换密文或换外观都得重挂一份干净的
  if (liveView && liveCt === activeCt && liveStyle === style) return
  mountRestoreView(style)
}

// ===== 恢复端的外观：密文声明的那份是默认值，用户在 ① 标题右侧还能手动改 =====
//
// 外观只决定"这块恢复界面怎么呈现"，跟密码学完全无关：换成哪一套都不会解错文件，
// 所以允许手动覆盖。换一份密文就恢复成"听密文的"，不把上一份的选择带过去。
let styleOverride: StyleId | null = null
let overrideFor: CtEntry | null = null

/**
 * 这一屏该用哪套外观：用户手选的优先，否则听密文的。
 *
 * 手选可以发生在**还没有密文**的时候（那组按钮一开始就在）。这时 overrideFor 是 null，
 * 意思是"待定"：等第一份密文进来就认它，手选直接生效。之后再换一份密文就恢复成
 * 听密文的——那是换了一份文件，上一份上的选择不该跟过去。
 */
function restoreStyle(): StyleId {
  if (!activeCt) return styleOverride ?? STYLE.PLAIN
  if (overrideFor !== activeCt) {
    if (overrideFor !== null) styleOverride = null
    overrideFor = activeCt
  }
  return styleOverride ?? activeCt.style
}

/** 分段控件的状态：手选只决定"怎么摆"，跟有没有密文无关，所以永远显示 */
function paintRestoreSeg(): void {
  const seg = $('restoreStyleSeg')
  const cur = restoreStyle()
  for (const b of seg.querySelectorAll<HTMLButtonElement>('button[data-style]'))
    b.classList.toggle('is-active', Number(b.dataset.style) === cur)
}

/**
 * 恢复跑着的时候这组也锁上：中途换外观会重挂一份视图，正在解锁的那份就白解了
 * （第 7 层起才有的"只在文件信息里列出"也跟着丢）。没开放的选项关掉后保持关。
 */
function setRestoreSegDisabled(on: boolean): void {
  for (const b of $('restoreStyleSeg').querySelectorAll<HTMLButtonElement>('button[data-style]')) {
    const ready = STYLE_LIST.find((s) => s.id === Number(b.dataset.style))?.splitReady ?? false
    b.disabled = on || !ready
  }
}

buildStyleSeg($('restoreStyleSeg'))
$('restoreStyleSeg').addEventListener('click', (e) => {
  const b = (e.target as HTMLElement).closest<HTMLButtonElement>('button[data-style]')
  if (!b || b.disabled) return
  const id = Number(b.dataset.style)
  if (id === restoreStyle()) return
  // 已经摆出来的结果会被换掉（拼图得重拼、结果卡要重画），所以先把话说明白
  const hadResult = !$('restoreCard').hidden || liveView !== null
  styleOverride = id
  // 还没选密文时 overrideFor 留在 null = 待定，等密文进来直接认它
  overrideFor = activeCt
  syncRestoreMode()
  refreshRestoreBtn()
  // 切成碎片外观、片又已经够：那儿没有按钮，直接开解
  if (autoRestoreIfReady()) return
  if (!activeCt)
    logLine(
      'restoreLog',
      ownsStage(id)
        ? `已切到「${styleLabel(id)}」：点格子或把文件拖进来，密文、分片都行（够 k 片自动开始）`
        : `已选「${styleLabel(id)}」：等选了密文就按这套呈现`,
      'lg-warn',
    )
  else if (hadResult)
    logLine(
      'restoreLog',
      `外观已改成「${styleLabel(id)}」：` +
        (ownsStage(id)
          ? '继续补片，够 k 片会自动开始'
          : '再点一次「恢复文件」就会按这套外观呈现'),
      'lg-warn',
    )
})
paintRestoreSeg()

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
      setRestoreSegDisabled(true)
      $('dropCt').classList.add('is-disabled')
      $<HTMLInputElement>('shareFiles').closest('.file-label')?.classList.add('is-disabled')
    },
    restore: () => {
      $<HTMLInputElement>('shareInput').disabled = false
      $<HTMLButtonElement>('btnAddShare').disabled = false
      $<HTMLInputElement>('shareFiles').disabled = false
      fileCtInput.disabled = false
      setRestoreSegDisabled(false)
      $('dropCt').classList.remove('is-disabled')
      $<HTMLInputElement>('shareFiles').closest('.file-label')?.classList.remove('is-disabled')
      refreshRestoreBtn()
    },
  },
])

$<HTMLButtonElement>('btnRestore').addEventListener('click', () => void runRestore())

/**
 * 自带界面的外观没有「恢复文件」按钮 —— 那几格本身就是操作台：
 * 拖进/点选补上片，只要片数够 k（btnRestore 的 disabled 就是这件事），就自动开解。
 * 非碎片外观一律不自动跑，仍由用户按按钮决定。
 */
function autoRestoreIfReady(): boolean {
  if (!ownsStage(restoreStyle()) || !activeCt || restoreBusy) return false
  if ($<HTMLButtonElement>('btnRestore').disabled) return false
  void runRestore()
  return true
}

/** 一次完整的恢复：按钮点它，自带界面的外观补完片也自动点它 */
let restoreBusy = false

async function runRestore(): Promise<void> {
  if (restoreBusy) return
  restoreBusy = true
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
    const more = $('restoreMore')
    more.hidden = true
    more.textContent = ''

    // 外观：密文声明的（0x06，只有最外层才有）或用户在 ① 右侧手选的，
    // 渲染细节全在 src/appearance/：这里只按"还差片 / 假层 / 解开一层"三种事件喂给视图。
    const style = restoreStyle()
    if (style !== STYLE.PLAIN || styleOverride !== null)
      run.line(`外观：${styleLabel(style)}${styleOverride !== null ? '（手动选择）' : ''}`)
    // 自带界面的外观不在这张结果卡里画（格子就摆在 ① 卡），其余外观照旧
    if (!ownsStage(style)) card.hidden = false
    // 每次恢复都是一份干净视图：上一轮的格子状态不能带过来
    const view = mountRestoreView(style)
    const host = viewHost(style)

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
        view.lock(j + 1, kHere, shares.length, impossible ? nHere : null)
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
        view.fake(j + 1, kHere)
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
      const mimeBytes = pack.chunks.get(TSPK.TAG.MIME)
      const mime = mimeBytes ? new TextDecoder().decode(mimeBytes) : ''

      // SHA-256 完整性：假文件也带自己那份（对乱码算的），所以照样能对上，
      // 不会因为"校验失败"提前暴露它是假的
      const expect = pack.chunks.get(TSPK.TAG.SHA256)
      const actual = await sha256(data)
      const hashOk = expect ? toHex(expect) === toHex(actual) : null

      const otsBytes = pack.chunks.get(TSPK.TAG.OTS_RECEIPT) ?? null
      const info = {
        index: j + 1,
        name,
        data,
        mime,
        createdAt,
        hashOk,
        hash: actual,
        ots: otsBytes,
      }
      // 内容怎么摆由外观决定；回执统一渲染进它给的容器
      const otsHost = view.unlock(info)
      if (otsBytes) await renderOtsInto(otsHost, otsBytes, actual)

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
      host.append(
        el(
          'div',
          'hint',
          `另外 ${rest} 组密钥是假的：没有对应的密文，只是把密钥串撑到固定组数，让人看不出真实层数。`,
        ),
      )
    }

    run.line(`完成 ✓ 解锁 ${unlocked} 层`, 'lg-ok')
    run.end()
    host.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
  } catch (e) {
    run.line(`恢复失败：${e instanceof Error ? e.message : String(e)}`, 'lg-err')
    run.fail()
  } finally {
    restoreBusy = false
  }
}

/** 内层没写 FILENAME 时的默认下载名：YYYY-MM-DD.bin（拆分时间优先，否则用当前时间） */
function defaultName(createdAt: number | null): string {
  const d = new Date(createdAt ?? Date.now())
  const ymd = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
  return `${ymd}.bin`
}
