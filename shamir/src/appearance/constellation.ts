// 外观「星座」：一张琥珀色的古代星图，星星自上而下连成一条「星光之路」。
//
// 一层 = 一颗星。放/解开一层，那颗星就从虚变实；两颗之间那段路，也才跟着亮起来。
// 所以这条路的长度就是"已经走到第几层"，不是装饰。
//
// **颗数不封顶**：一开始先摆六颗虚星等你填，六颗都实了，第七颗才在下面长出来——
// 路是往下延伸的，不是走到第六颗就到头。星图的高度因此跟着行数走（CSS 的
// `--rows`），而落脚点的纵向百分比始终按 `(i+0.5)/rows` 算：两者一乘，每颗星
// 之间的像素距离是常数，往下的星越长越远，前面的星却一步也不动。
//
// 与碎片的分工一样：几何（星位、曲线、路上的光点）全在本文件里算，CSS 只管材质。
// 不一样的是这里不切块——星图是一整张纸，星与星之间是路，不是缝。

import './constellation.css'
import { isImageFileLike, sniffImageMime } from '../core/styles.ts'
import { baseName, download, el, fmtSize, trackUrl } from '../ui/dom.ts'
import { levelCard, otsHost } from './card.ts'
import type { LayerInfo, RestoreView, ShareIntent, SplitCell, SplitIntent, SplitPolicy, SplitView } from './types.ts'

const NS = 'http://www.w3.org/2000/svg'

/** 一开始就摆六颗虚星：还没放东西时，这张图也得看起来是一条要走的路 */
const MIN_ROWS = 6

/**
 * 拆分端规矩：**任意文件**，层数不设上限（一颗星 = 一层，路一直往下载）。
 *
 * 星图不是画廊——一颗星只是"这一层放在哪儿"的记号，它收什么内容与外观无关。
 * 图片会在悬停时浮出来（见下），其余格式落成一张档案卡，名字照样写在星下面。
 */
export const CONSTELLATION_SPLIT: SplitPolicy = {
  accept: '',
  acceptLabel: '任意文件',
  maxLayers: Number.POSITIVE_INFINITY,
  accepts: () => true,
  dropText: '把文件拖到星图上，或点击选择（可多选）',
}

type Pt = readonly [number, number]

/**
 * 横向摆位（舞台百分比），一圈用完再轮回。
 *
 * 一路直下会读成刻度尺，所以绕弯：先向右送出去，到 3 号折回左边，再往右下走。
 * **只有一条线、不分叉**——分叉的路线一眼读成"地图"，单线的才像天蝎那条尾巴：
 * 沿着走，一颗接一颗。前六个是调过的，后六个把幅度接着摆开，不至于看着像
 * "六颗一组重复"。
 */
const X_SEQ: readonly number[] = [26, 55, 66, 44, 27, 50, 62, 35, 30, 58, 68, 45]

/** 每颗星的"星等"（核心直径的基准，px）：大小错开才像星空，不像一排灯泡 */
const MAGNITUDE_SEQ: readonly number[] = [3.0, 3.6, 3.3, 4.0, 3.4, 3.7]

const xAt = (i: number): number => X_SEQ[i % X_SEQ.length]!
/** 纵向：行数越多，每颗星分到的高度越薄；舞台高度同步变成 rows × gap，于是像素间距恒定 */
const yAt = (i: number, rows: number): number => round1(((i + 0.5) / rows) * 100)
const station = (i: number, rows: number): Pt => [xAt(i), yAt(i, rows)]

// ===== 曲线 =====
//
// 用 Catmull-Rom 把落脚点穿成一条光滑的线：每一段换算成一条三次贝塞尔，
// 于是"整条路"（淡墨虚线）、"每一段路"（会被点亮的那一段）、
// 以及撒在段上的小星点，都从同一份数据里取。

interface Cubic {
  a: Pt
  c1: Pt
  c2: Pt
  b: Pt
}

/** 第 i 段（从第 i 个落脚点到第 i+1 个）的三次贝塞尔控制点 */
function segment(i: number, rows: number): Cubic {
  const p0 = station(Math.max(0, i - 1), rows)
  const p1 = station(i, rows)
  const p2 = station(i + 1, rows)
  const p3 = station(Math.min(rows - 1, i + 2), rows)
  return {
    a: p1,
    c1: [p1[0] + (p2[0] - p0[0]) / 6, p1[1] + (p2[1] - p0[1]) / 6],
    c2: [p2[0] - (p3[0] - p1[0]) / 6, p2[1] - (p3[1] - p1[1]) / 6],
    b: p2,
  }
}

function cubicAt(k: Cubic, t: number): Pt {
  const u = 1 - t
  const a = u * u * u
  const b = 3 * u * u * t
  const c = 3 * u * t * t
  const d = t * t * t
  return [
    a * k.a[0] + b * k.c1[0] + c * k.c2[0] + d * k.b[0],
    a * k.a[1] + b * k.c1[1] + c * k.c2[1] + d * k.b[1],
  ]
}

/** 一段路（不含起点的 M）——用来把几段拼成整条路 */
function legC(k: Cubic): string {
  const f = round1
  return `C${f(k.c1[0])} ${f(k.c1[1])} ${f(k.c2[0])} ${f(k.c2[1])} ${f(k.b[0])} ${f(k.b[1])}`
}

/** 一段路的 d 属性（坐标直接是 0..100 的百分比） */
function legD(k: Cubic): string {
  const f = round1
  return `M${f(k.a[0])} ${f(k.a[1])}${legC(k)}`
}

/** 整条路：所有星串成的一条线 */
function fullD(rows: number): string {
  let d = `M${round1(xAt(0))} ${round1(yAt(0, rows))}`
  for (let i = 0; i < rows - 1; i++) d += legC(segment(i, rows))
  return d
}

/** 定死的伪随机：每次重画都是同一片星空，不会"眨一下换了位置" */
function rnd(seed: number): number {
  const x = Math.sin(seed * 127.1 + 11.7) * 43758.5453
  return x - Math.floor(x)
}

const round1 = (n: number): number => Math.round(n * 10) / 10

/** 第 i 颗星的标注挂在哪一侧：避开从它出发（或通向它）的那一段路 */
function labelSide(i: number, rows: number): 'left' | 'right' {
  const cur = xAt(i)
  const next = xAt(i + 1 < rows ? i + 1 : Math.max(0, i - 1))
  const dx = i + 1 < rows ? next - cur : cur - next
  return dx > 0 ? 'left' : 'right'
}

// ===== DOM =====

function svgEl<K extends keyof SVGElementTagNameMap>(tag: K): SVGElementTagNameMap[K] {
  return document.createElementNS(NS, tag)
}

interface Stage {
  stage: HTMLElement
  road: SVGSVGElement
  guide: SVGPathElement
  /** 新节点一律插在它前面：它是"压在最上层"的那一层的第一个 */
  before: HTMLElement
  /** 0 起：第 i 颗星 */
  nodes: HTMLElement[]
  /** 每颗星的标注容器、主标题、副标题 */
  tags: HTMLElement[]
  mains: HTMLElement[]
  metas: HTMLElement[]
  /** 0 起：第 i 段路（连第 i 与 i+1 颗星） */
  legs: SVGPathElement[]
  /** 每一段路上的小星点 */
  embers: HTMLElement[][]
  /** 当前摆了几行（= 星星颗数） */
  rows: number
}

/** 造一颗星（不含位置：位置由 relayout 统一摆） */
function addNode(s: Stage, i: number): void {
  const node = el('span', 'con-node')
  node.dataset.i = String(i + 1)
  node.dataset.state = 'empty'
  node.tabIndex = 0
  node.setAttribute('role', 'button')

  // 星云垫在最底下：照片若隐若现地"压在纸里"，星星浮在它上面
  node.append(el('span', 'con-halo'))
  node.append(el('span', 'con-ring'))

  const d = MAGNITUDE_SEQ[i % MAGNITUDE_SEQ.length]!
  // 三个尺寸都挂在 node 上：星、光晕、星芒共用一份星等。
  // 7.0 是量出来的：再小四角形的角就读不出来了，整枚星退化成一颗白点。
  node.style.setProperty('--d', `${round1(d * 7)}px`)
  node.style.setProperty('--ray', `${round1(d * 15)}px`)
  node.style.setProperty('--ray2', `${round1(d * 7.5)}px`)
  // 错开呼吸：整片一起闪就成灯牌了
  node.style.setProperty('--tw', `${round1(-1.9 * i)}s`)
  // 光晕是单独一层：clip-path 会把同一元素上的 drop-shadow 一起裁掉，
  // 所以发光不能靠星的 filter，得在它背后铺一层真的光
  node.append(el('i', 'con-bloom'))
  const spark = el('i', 'con-spark')
  spark.append(el('i', 'con-diag'))
  node.append(spark)

  // 标注挂在星星的**外侧**：路往哪边走，字就避开哪边，否则永远压在线上
  const tag = el('span', 'con-tag')
  // 名字和 × 同一行（× 是拆分端才有的，按需 append 到这一行里）
  const line = el('span', 'con-line')
  const main = el('b', 'con-main')
  line.append(main)
  const meta = el('small', 'con-meta')
  tag.append(line, meta)
  node.append(tag)

  s.stage.insertBefore(node, s.before)
  s.nodes.push(node)
  s.tags.push(tag)
  s.mains.push(main)
  s.metas.push(meta)
}

/** 造一段路（两层路径：光带 + 墨金线） */
function addLeg(s: Stage): void {
  const box = svgEl('g')
  box.setAttribute('class', 'con-leg-pair')
  const halo = svgEl('path')
  halo.setAttribute('class', 'con-leg-halo')
  halo.setAttribute('vector-effect', 'non-scaling-stroke')
  const leg = svgEl('path')
  leg.setAttribute('class', 'con-leg')
  leg.setAttribute('vector-effect', 'non-scaling-stroke')
  box.append(halo, leg)
  s.road.append(box)
  s.legs.push(leg)
}

/** 一段路上撒几颗小星点：数量按段序号变一点，免得每段都一模一样 */
const emberCount = (i: number): number => 4 + (i % 3)

/**
 * 把一个舞台摆到 `rows` 行。
 *
 * 幂等：行数没变就直接返回（大多数时候是这样——只有层数跨过当前行数才会长）。
 * 要改的东西有六样：星的位置、标签挂哪侧、整条路的 d、每段的 d、路上的星点、
 * 以及舞台自己的高度（CSS 变量 `--rows`）。
 */
function relayout(s: Stage, rows: number): void {
  const n = Math.max(MIN_ROWS, rows)
  if (s.rows === n) return
  s.rows = n

  while (s.nodes.length < n) addNode(s, s.nodes.length)
  while (s.legs.length < n - 1) addLeg(s)

  s.nodes.forEach((node, i) => {
    const x = xAt(i)
    node.style.left = `${x}%`
    node.style.top = `${yAt(i, n)}%`
    // 标签躲开路线：路往哪边走，字就挂另一边
    const side = labelSide(i, n)
    const tag = s.tags[i] as HTMLElement
    tag.className = `con-tag is-${side}`
    // 名字能吃多宽，取决于这一侧还剩多少纸。给个死值 150px 的话，
    // 「合同-2026-第 3 季度-最终签署版」一律截成「合同-2026-第 3 季…」——
    // 而标签是每颗星独占一行的，长一点根本不会撞到邻居。
    tag.style.setProperty('--tag-room', String(round1(side === 'right' ? 100 - x : x)))
  })

  s.guide.setAttribute('d', fullD(n))
  s.legs.forEach((leg, i) => {
    const d = legD(segment(i, n))
    leg.setAttribute('d', d)
    leg.previousElementSibling?.setAttribute('d', d)
  })

  for (let i = 0; i < n - 1; i++) syncEmbers(s, i, n)

  s.stage.style.setProperty('--rows', String(n))
  s.stage.setAttribute('aria-label', `星座外观：${n} 颗星连成一条路`)
}

/** 第 i 段路上的星点：位置跟着曲线重算，元素本身复用（亮了就不会再暗下去） */
function syncEmbers(s: Stage, i: number, rows: number): void {
  const count = emberCount(i)
  let list = s.embers[i]
  if (!list) {
    list = []
    s.embers[i] = list
  }
  while (list.length < count) {
    const dot = el('i', 'con-ember')
    dot.style.setProperty('--s', `${round1(1.3 + rnd(i * 13 + list.length) * 1.6)}px`)
    // 一段路亮起来时，路上的星点按行走的方向依次亮，像脚步
    dot.style.transitionDelay = `${(list.length + 1) * 70}ms`
    s.stage.insertBefore(dot, s.before)
    list.push(dot)
  }
  const k = segment(i, rows)
  list.forEach((dot, idx) => {
    const p = cubicAt(k, (idx + 1) / (count + 1))
    dot.style.left = `${round1(p[0] + (rnd(i * 31 + idx) - 0.5) * 2.4)}%`
    dot.style.top = `${round1(p[1] + (rnd(i * 57 + idx + 7) - 0.5) * 2.8)}%`
  })
}

/**
 * 星图骨架：纸面 + 一条穿起所有星的路 + 六颗（起步时）虚星。
 *
 * 恢复端（往外取）和拆分端（往里塞）共用这一份，差别只在喂进去的事件。
 */
function buildStage(): Stage {
  const stage = el('div', 'con-stage')
  stage.setAttribute('role', 'group')
  stage.style.setProperty('--rows', String(MIN_ROWS))

  // 纸的五层：底色 → 深浅 → 纤维 → 满天暗星 → 刻度盘 → 折痕 → 陈年痕迹 → 颗粒
  stage.append(
    el('div', 'con-sky'),
    el('div', 'con-mottle'),
    el('div', 'con-fiber'),
    el('div', 'con-field'),
    el('div', 'con-chart'),
    el('div', 'con-crease'),
    el('div', 'con-stain'),
    el('div', 'con-grain'),
  )

  // 整条路先铺一层淡墨：还没走到的那一段也看得见，路才是"路"
  const road = svgEl('svg')
  road.setAttribute('class', 'con-road')
  road.setAttribute('viewBox', '0 0 100 100')
  // 非等比拉伸：星点用 div 摆（永远正圆），线被拉一下没人在意；
  // 反过来用 meet 会在纸上留一圈空白，线就跟星星对不齐了
  road.setAttribute('preserveAspectRatio', 'none')
  road.setAttribute('aria-hidden', 'true')

  const guide = svgEl('path')
  guide.setAttribute('class', 'con-guide')
  guide.setAttribute('vector-effect', 'non-scaling-stroke')
  road.append(guide)
  stage.append(road)

  // 压在最上层：纸边、卷轴的阴影、纸屑。星星在纸下面，才像印上去的
  const dust = el('div', 'con-dust')

  stage.append(dust, el('div', 'con-edge'))

  const s: Stage = {
    stage,
    road,
    guide,
    before: dust,
    nodes: [],
    tags: [],
    mains: [],
    metas: [],
    legs: [],
    embers: [],
    rows: MIN_ROWS,
  }
  // 先按初始行数摆好：空着的时候也得是一条看得见的路
  s.rows = 0
  relayout(s, MIN_ROWS)
  return s
}

function setState(node: HTMLElement, state: string): void {
  node.dataset.state = state
}

type TagState = 'empty' | 'locked' | 'image' | 'file' | 'fake'

function paintTag(s: Stage, i: number, state: TagState, main: string, meta: string): void {
  const m = s.mains[i]
  const t = s.metas[i]
  if (!m || !t) return
  m.textContent = main
  t.textContent = meta
  const tag = s.tags[i]
  // 只换状态，不碰左右：className 是 relayout 管的（它还带着 is-left / is-right）
  if (tag) tag.dataset.state = state
}

/** 走到第几颗星为止：把前面几段路点亮（含路上的星点） */
function walkTo(s: Stage, reached: number): void {
  s.legs.forEach((leg, i) => {
    const lit = i < reached - 1
    // 点在整段上：两层（光晕 + 墨金线）一起亮
    leg.parentElement?.classList.toggle('is-lit', lit)
    for (const e of s.embers[i] ?? []) e.classList.toggle('is-lit', lit)
  })
}

// ===== 恢复端：往外出图 =====

export function createConstellationView(): RestoreView {
  const root = el('div', 'con-view')
  const s = buildStage()
  const { stage, nodes } = s

  let intent: ShareIntent | null = null
  const canAdd = (): boolean => intent !== null && intent.allowed()
  const action = new Map<number, () => void>()

  const pick = (): void => {
    if (!canAdd()) return
    intent!.pick()
  }

  stage.addEventListener('click', (e) => {
    const node = (e.target as HTMLElement).closest<HTMLElement>('.con-node')
    if (!node) {
      // 点纸面（没点到星）= 补分片：整张图都是入口
      pick()
      return
    }
    const act = action.get(Number(node.dataset.i))
    if (act) act()
    else pick()
  })
  stage.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' && e.key !== ' ') return
    const node = (e.target as HTMLElement).closest<HTMLElement>('.con-node')
    if (!node) return
    const act = action.get(Number(node.dataset.i))
    if (!act) return
    e.preventDefault()
    act()
  })
  stage.addEventListener('dragover', (e) => {
    if (!canAdd()) return
    e.preventDefault()
    stage.classList.add('is-drop')
  })
  stage.addEventListener('dragleave', (e) => {
    if (e.target === stage) stage.classList.remove('is-drop')
  })
  stage.addEventListener('drop', (e) => {
    stage.classList.remove('is-drop')
    if (!canAdd()) return
    e.preventDefault()
    const files = Array.from(e.dataTransfer?.files ?? [])
    if (files.length) intent!.drop(files)
  })

  const info = document.createElement('details')
  info.className = 'con-details'
  info.hidden = true
  const sum = document.createElement('summary')
  sum.textContent = '文件信息与校验'
  info.append(sum)

  root.append(stage, info)
  let opened = 0
  let reached = 0

  const fill = (i: number, l: LayerInfo): void => {
    const node = nodes[i - 1]
    if (!node) return
    const halo = node.querySelector('.con-halo') as HTMLElement
    halo.textContent = ''

    const mime = sniffImageMime(l.data)
    const state: TagState = mime ? 'image' : 'file'
    setState(node, state)
    paintTag(s, i - 1, state, baseName(l.name), `第 ${i} 层`)
    node.title = `${l.name} · ${fmtSize(l.data.length)} · 点击下载`
    const grab = (): void => download(l.name, l.data)
    action.set(i, grab)

    if (mime) {
      const url = trackUrl(URL.createObjectURL(new Blob([l.data], { type: mime })))
      const img = document.createElement('img')
      img.className = 'con-img'
      img.src = url
      img.alt = l.name
      img.decoding = 'sync'
      halo.append(img)
      // 和碎片踩过的同一个坑：带遮罩/动画的子树里 img.decode() 不 settle，用 load 兜底
      const show = (): void => halo.classList.add('is-shown')
      if (img.complete) show()
      else {
        img.addEventListener('load', show, { once: true })
        img.addEventListener('error', show, { once: true })
      }
    }
    // 非图片：星云里什么都不放。名字已经常显在标签上，图片才值得浮出来看。
  }

  return {
    root,
    attachShare(next) {
      intent = next
      stage.classList.add('is-shareable')
    },
    lock(i, k, have) {
      // 这一层真的存在（只是片不够），所以星也就该在：行数不够就先长出来
      relayout(s, i)
      const node = nodes[i - 1]
      if (!node) return
      setState(node, 'locked')
      node.title = `第 ${i} 颗星还差 ${k} 片（已有 ${have} 片）· 点一下补充分片`
      paintTag(s, i - 1, 'locked', `需要 ${k} 片`, `第 ${i} 层`)
    },
    fake(i) {
      relayout(s, i)
      const node = nodes[i - 1]
      if (!node) return
      setState(node, 'fake')
      node.title = `第 ${i} 颗星是假层：凑够也解不开`
      paintTag(s, i - 1, 'fake', '解不开', `第 ${i} 层`)
      action.delete(i)
      reached = Math.max(reached, i - 1)
      walkTo(s, reached)
    },
    unlock(layer) {
      // 恢复端只知道"已经解到第几层"，不知道后面还有几层——所以路是一段一段长出来的：
      // 第六层解开时本来就摆着六颗星，第七层真来了，才往下多长一颗
      relayout(s, layer.index)
      fill(layer.index, layer)
      reached = Math.max(reached, layer.index)
      walkTo(s, reached)
      // 图层里才给大图预览：星图上只留星，要看内容在下面这张卡里看
      const card = levelCard(layer, { unit: '颗' })
      info.hidden = false
      info.append(card)
      opened++
      sum.textContent = `文件信息与校验（${opened} 层）`
      return otsHost(card)
    },
  }
}

// ===== 拆分端：把文件往星图上放 =====

export function createConstellationSplitView(): SplitView {
  const root = el('div', 'con-view con-split')
  const s = buildStage()
  const { stage, nodes } = s
  stage.classList.add('is-shareable')

  const note = el('div', 'hint con-split-note')
  root.append(stage, note)

  let intent: SplitIntent | null = null
  const canAdd = (): boolean => intent !== null && intent.allowed()
  let urls: string[] = []
  const release = (): void => {
    for (const u of urls) URL.revokeObjectURL(u)
    urls = []
  }

  const reset = (i: number): void => {
    const node = nodes[i - 1]!
    setState(node, 'empty')
    node.title = `第 ${i} 颗星还空着：点一下放一个文件`
    const halo = node.querySelector('.con-halo') as HTMLElement
    halo.textContent = ''
    halo.classList.remove('is-shown')
    // × 是上一轮 append 进去的：不扫掉的话，每重画一次就多一颗
    for (const x of s.tags[i - 1]!.querySelectorAll('.con-x')) x.remove()
    paintTag(s, i - 1, 'empty', '放文件', `第 ${i} 层`)
  }

  const fill = (c: SplitCell): void => {
    const i = c.index
    const node = nodes[i - 1]
    if (!node) return
    const halo = node.querySelector('.con-halo') as HTMLElement
    halo.textContent = ''
    halo.classList.remove('is-shown')

    const remove = el('button', 'con-x', '×') as HTMLButtonElement
    remove.type = 'button'
    remove.dataset.i = String(i)
    remove.title = '把这一颗撤掉'

    if (c.fake) {
      setState(node, 'fake')
      node.title = `第 ${i} 层是假文件层：凑够 ${c.k} 片也解不开`
      paintTag(s, i - 1, 'fake', '假文件层', `第 ${i} 层`)
      s.tags[i - 1]!.querySelector('.con-line')!.append(remove)
      return
    }

    const file = c.file
    const image = file !== null && isImageFileLike(file.name, file.type)
    const state: TagState = image ? 'image' : 'file'
    setState(node, state)
    node.title = `${c.name} · ${fmtSize(c.size)} · 第 ${i} 层，需要 ${c.k} 片`
    paintTag(s, i - 1, state, baseName(c.name), `第 ${i} 层 · ${c.k} 片`)
    if (image && file) {
      const url = URL.createObjectURL(file)
      urls.push(url)
      const img = document.createElement('img')
      img.className = 'con-img'
      img.src = url
      img.alt = c.name
      img.decoding = 'sync'
      halo.append(img)
      halo.classList.add('is-shown')
    }
    s.tags[i - 1]!.querySelector('.con-line')!.append(remove)
  }

  stage.addEventListener('click', (e) => {
    const x = (e.target as HTMLElement).closest<HTMLElement>('.con-x')
    if (x) {
      e.stopPropagation()
      intent?.remove(Number(x.dataset.i) - 1)
      return
    }
    const node = (e.target as HTMLElement).closest<HTMLElement>('.con-node')
    if (node && node.dataset.state !== 'empty') return
    if (!canAdd()) return
    intent!.pick()
  })
  stage.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' && e.key !== ' ') return
    const node = (e.target as HTMLElement).closest<HTMLElement>('.con-node')
    if (!node || node.dataset.state !== 'empty') return
    if (!canAdd()) return
    e.preventDefault()
    intent!.pick()
  })
  stage.addEventListener('dragover', (e) => {
    if (!canAdd()) return
    e.preventDefault()
    stage.classList.add('is-drop')
  })
  stage.addEventListener('dragleave', (e) => {
    if (e.target === stage) stage.classList.remove('is-drop')
  })
  stage.addEventListener('drop', (e) => {
    stage.classList.remove('is-drop')
    if (!canAdd()) return
    e.preventDefault()
    const files = Array.from(e.dataTransfer?.files ?? [])
    if (files.length) intent!.drop(files)
  })

  return {
    root,
    attach(next) {
      intent = next
    },
    render(cells) {
      release()
      // 永远多摆一颗虚星：六颗都填满了，下面那颗"下一颗"就该出现了，
      // 不然用户看不出这条路还能往下走
      relayout(s, Math.max(MIN_ROWS, cells.length + 1))
      for (let i = 1; i <= s.nodes.length; i++) reset(i)
      for (const c of cells) fill(c)
      walkTo(s, cells.length)
      const total = s.nodes.length
      note.textContent = cells.length
        ? `${cells.length} 颗星已亮，第 ${cells.length + 1} 颗还空着：第 1 颗要 1 片，第 ${cells.length} 颗要 ${cells.length} 片。`
        : `${total} 颗星都还暗着：点任意一颗放一个文件。放满之后路会继续往下长。`
    },
  }
}
