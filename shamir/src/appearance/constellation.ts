// 外观「星座」：六个星座排在一张琥珀色的旧星图上。
//
// 一层 = 一个星座。凑够这一层要求的几片，那个星座的连线才连得起来、
// 星云里才透出那张照片。没凑齐的星座只剩几个暗星点——「还没被观测到」。
//
// 与碎片的分工一样：形状（星点、连线、位置）全在本文件里算，CSS 只管材质。
// 不同的是碎片是「一块玻璃 = 一层」，这里「一个星座 = 一层」，星图本身不切块：
// 六块之间的空隙是天空，不是玻璃的缝。

import './constellation.css'
import { isImageFileLike, sniffImageMime, STAGE_SLOTS } from '../core/styles.ts'
import { baseName, download, el, fmtSize, trackUrl } from '../ui/dom.ts'
import { levelCard, otsHost } from './card.ts'
import type { LayerInfo, RestoreView, ShareIntent, SplitCell, SplitIntent, SplitPolicy, SplitView } from './types.ts'

const NS = 'http://www.w3.org/2000/svg'
const SLOTS = STAGE_SLOTS

/** 拆分端规矩：只收图片，最多 6 层（假层也占一格） */
export const CONSTELLATION_SPLIT: SplitPolicy = {
  accept: 'image/*',
  acceptLabel: '图片',
  maxLayers: SLOTS,
  accepts: (f) => isImageFileLike(f.name, f.type),
  dropText: '把照片拖到星图上，或点击选择（可多选）',
}

// ===== 六个星座 =====
//
// 星点是 0..1 的归一化坐标（对**自己那一格**而言），连线是星点下标对。
// 形状按真实星座摆的近似图（不必天文精确，要的是「一眼认得出是个星座」）：
// 白羊的折线、金牛的 V 与两只角、双子的两条腿、狮子的镰刀、处女的 Y、
// 天蝎那条长长的尾巴。由简到繁，正好对上 k = 1..6 的递增。
//
// box 是这一格在舞台上的位置与大小（%）：六格排成 3 列 2 行，但不严格对齐——
// 星图上的星座本来就各占各的角落，横平竖直反而像表格。

interface Sign {
  cn: string
  en: string
  /** 星云尺寸（相对自己这一格）与偏移（%）：六个一般大就成了六个气泡 */
  cloud: readonly [number, number, number]
  /** 星点：坐标 0..1，r 是直径（屏幕 px，舞台宽度 800 左右时的观感基准） */
  stars: readonly { x: number; y: number; r: number }[]
  /** 连线：星点下标对 */
  lines: readonly (readonly [number, number])[]
  /** x, y, w, h（舞台百分比） */
  box: readonly [number, number, number, number]
}

const SIGNS: readonly Sign[] = [
  {
    // 白羊：一根折线，末端甩出第三颗
    cn: '白羊座',
    en: 'Aries',
    box: [1.5, 5, 27, 36],
    cloud: [74, 0, -2],
    stars: [
      { x: 0.08, y: 0.64, r: 3.0 },
      { x: 0.34, y: 0.46, r: 2.4 },
      { x: 0.54, y: 0.62, r: 1.9 },
      { x: 0.88, y: 0.24, r: 2.5 },
    ],
    lines: [[0, 1], [1, 2], [1, 3]],
  },
  {
    // 金牛：毕宿五那颗橙红的亮星 + V 形的脸 + 两只角，右上是昴星团
    cn: '金牛座',
    en: 'Taurus',
    box: [30.5, 1, 31, 40],
    cloud: [80, 2, 0],
    stars: [
      { x: 0.26, y: 0.52, r: 3.4 },
      { x: 0.40, y: 0.36, r: 2.5 },
      { x: 0.54, y: 0.44, r: 2.0 },
      { x: 0.44, y: 0.60, r: 2.0 },
      { x: 0.30, y: 0.62, r: 1.8 },
      { x: 0.36, y: 0.08, r: 2.7 },
      { x: 0.58, y: 0.78, r: 2.2 },
      { x: 0.80, y: 0.28, r: 1.5 },
      { x: 0.86, y: 0.35, r: 1.3 },
      { x: 0.82, y: 0.40, r: 1.3 },
      { x: 0.88, y: 0.22, r: 1.2 },
    ],
    lines: [[0, 1], [1, 2], [1, 3], [3, 4], [4, 0], [1, 5], [3, 6], [7, 8], [8, 9]],
  },
  {
    // 双子：北河二、北河三两颗并排的亮星，各自往下拖出一条腿
    cn: '双子座',
    en: 'Gemini',
    box: [64.5, 5, 28, 36],
    cloud: [72, -2, 1],
    stars: [
      { x: 0.30, y: 0.16, r: 3.0 },
      { x: 0.46, y: 0.28, r: 3.2 },
      { x: 0.14, y: 0.44, r: 2.1 },
      { x: 0.20, y: 0.70, r: 1.9 },
      { x: 0.12, y: 0.88, r: 1.9 },
      { x: 0.42, y: 0.54, r: 2.1 },
      { x: 0.48, y: 0.78, r: 2.3 },
      { x: 0.60, y: 0.92, r: 1.8 },
    ],
    lines: [[0, 1], [0, 2], [2, 3], [3, 4], [1, 5], [5, 6], [6, 7]],
  },
  {
    // 狮子：镰刀形的头颈 + 后半身的三角，尾巴尖是五帝座一
    cn: '狮子座',
    en: 'Leo',
    box: [0.5, 51, 31, 40],
    cloud: [78, 1, 1],
    stars: [
      { x: 0.16, y: 0.80, r: 3.2 },
      { x: 0.12, y: 0.60, r: 2.3 },
      { x: 0.22, y: 0.42, r: 2.5 },
      { x: 0.38, y: 0.36, r: 2.1 },
      { x: 0.50, y: 0.50, r: 2.1 },
      { x: 0.44, y: 0.68, r: 1.9 },
      { x: 0.60, y: 0.74, r: 2.1 },
      { x: 0.78, y: 0.54, r: 2.5 },
      { x: 0.94, y: 0.70, r: 2.9 },
    ],
    lines: [[0, 1], [1, 2], [2, 3], [3, 4], [4, 5], [0, 5], [5, 6], [6, 7], [7, 8], [6, 8]],
  },
  {
    // 处女：角宿一在最下面，往上收成一个 Y
    cn: '处女座',
    en: 'Virgo',
    box: [32.5, 47.5, 31, 42],
    cloud: [73, -1, -1],
    stars: [
      { x: 0.52, y: 0.88, r: 3.4 },
      { x: 0.42, y: 0.62, r: 2.0 },
      { x: 0.30, y: 0.44, r: 2.4 },
      { x: 0.14, y: 0.34, r: 2.0 },
      { x: 0.20, y: 0.14, r: 1.8 },
      { x: 0.50, y: 0.38, r: 2.1 },
      { x: 0.70, y: 0.26, r: 1.8 },
      { x: 0.84, y: 0.10, r: 1.8 },
    ],
    lines: [[0, 1], [1, 2], [2, 3], [3, 4], [2, 5], [5, 6], [6, 7]],
  },
  {
    // 天蝎：心宿二（红）在中间偏上，长长的尾巴甩回来带个钩
    cn: '天蝎座',
    en: 'Scorpio',
    box: [65.5, 48.5, 32, 43],
    cloud: [81, 0, 2],
    stars: [
      { x: 0.14, y: 0.20, r: 2.2 },
      { x: 0.22, y: 0.27, r: 2.0 },
      { x: 0.29, y: 0.35, r: 2.4 },
      { x: 0.40, y: 0.40, r: 3.6 },
      { x: 0.50, y: 0.47, r: 2.0 },
      { x: 0.57, y: 0.58, r: 2.0 },
      { x: 0.55, y: 0.71, r: 2.0 },
      { x: 0.63, y: 0.81, r: 2.0 },
      { x: 0.75, y: 0.85, r: 1.8 },
      { x: 0.86, y: 0.77, r: 2.4 },
      { x: 0.90, y: 0.64, r: 2.2 },
    ],
    lines: [[0, 1], [1, 2], [2, 3], [3, 4], [4, 5], [5, 6], [6, 7], [7, 8], [8, 9], [9, 10]],
  },
]

/** 星点整体放大系数：归一化的 r 是"星等"，真正画出来还得再大一圈才看得见光晕 */
const STAR_SCALE = 1.28

/** 非图片格里的文件图标（内联 SVG，不依赖字体/emoji） */
function fileGlyph(): SVGSVGElement {
  const svg = document.createElementNS(NS, 'svg')
  svg.setAttribute('viewBox', '0 0 24 24')
  svg.setAttribute('width', '26')
  svg.setAttribute('height', '26')
  svg.setAttribute('fill', 'none')
  svg.setAttribute('stroke', 'currentColor')
  svg.setAttribute('stroke-width', '1.6')
  svg.setAttribute('stroke-linecap', 'round')
  svg.setAttribute('stroke-linejoin', 'round')
  const body = document.createElementNS(NS, 'path')
  body.setAttribute('d', 'M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z')
  const fold = document.createElementNS(NS, 'polyline')
  fold.setAttribute('points', '14 3 14 8 19 8')
  svg.append(body, fold)
  return svg
}

const round1 = (n: number): number => Math.round(n * 10) / 10

/** 一个星座的连线：铺满整格的 SVG，坐标 0..100（x/y 各自拉伸，线摔不断就行） */
function signLines(sign: Sign): SVGSVGElement {
  const svg = document.createElementNS(NS, 'svg')
  svg.setAttribute('class', 'con-lines')
  svg.setAttribute('viewBox', '0 0 100 100')
  // 非等比拉伸：星点是用 div 摆的（永远正圆），线被拉一下没人在意；
  // 反过来用 meet 会在窄格子里留一圈白边，线就跟星星对不齐了。
  svg.setAttribute('preserveAspectRatio', 'none')
  svg.setAttribute('aria-hidden', 'true')
  for (const [a, b] of sign.lines) {
    const p = sign.stars[a]!
    const q = sign.stars[b]!
    const line = document.createElementNS(NS, 'line')
    line.setAttribute('x1', String(round1(p.x * 100)))
    line.setAttribute('y1', String(round1(p.y * 100)))
    line.setAttribute('x2', String(round1(q.x * 100)))
    line.setAttribute('y2', String(round1(q.y * 100)))
    // 不跟随缩放：线宽恒定 1px，舞台上放大缩小都是同一根细线
    line.setAttribute('vector-effect', 'non-scaling-stroke')
    svg.append(line)
  }
  return svg
}

interface Stage {
  stage: HTMLElement
  signs: Map<number, HTMLElement>
  names: Map<number, HTMLElement>
}

/**
 * 六格星图的骨架：琥珀底 + 星尘 + 六个星座 + 名字。
 *
 * 恢复端（往外取图）和拆分端（往里塞图）共用这一份，差别只在喂进去的事件——
 * 和碎片那套同一个思路，只是这里一格是一个星座而不是一块玻璃。
 */
function buildStage(): Stage {
  const stage = el('div', 'con-stage')
  stage.setAttribute('role', 'group')
  stage.setAttribute('aria-label', `星座外观：${SLOTS} 个星座`)

  // 底：旧星图的琥珀色纸面 + 一层很淡的星尘
  stage.append(el('div', 'con-sky'), el('div', 'con-dust'))

  const signs = new Map<number, HTMLElement>()
  const names = new Map<number, HTMLElement>()

  SIGNS.slice(0, SLOTS).forEach((sign, k) => {
    const i = k + 1
    const box = el('div', 'con-sign is-empty')
    box.dataset.i = String(i)
    box.style.left = `${sign.box[0]}%`
    box.style.top = `${sign.box[1]}%`
    box.style.width = `${sign.box[2]}%`
    box.style.height = `${sign.box[3]}%`

    // 星云（照片的容身之处）在最底下：星座的线压在它上面，像照片被星图盖住一角
    const cloud = el('div', 'con-cloud')
    cloud.style.width = `${sign.cloud[0]}%`
    cloud.style.height = `${sign.cloud[0]}%`
    cloud.style.setProperty('--dx', `${sign.cloud[1]}%`)
    cloud.style.setProperty('--dy', `${sign.cloud[2]}%`)
    // 「+ 放图」跟着星点的重心走：按格子正中摆的话，狮子座那种上密下疏的星座
    // 会把加号顶到星座外面去
    cloud.style.setProperty('--ay', `${round1((sign.stars.reduce((a, s) => a + s.y, 0) / sign.stars.length) * 100)}%`)
    box.append(cloud)
    box.append(signLines(sign))

    // 星点：div 摆位，永远正圆；光晕交给 CSS
    for (const s of sign.stars) {
      const star = el('i', 'con-star')
      star.style.left = `${round1(s.x * 100)}%`
      star.style.top = `${round1(s.y * 100)}%`
      const d = round1(s.r * STAR_SCALE)
      star.style.width = `${d}px`
      star.style.height = `${d}px`
      // 光晕大小跟着星点大小走，不然大星和小星的晕一样粗
      star.style.setProperty('--r', `${d}px`)
      box.append(star)
    }
    stage.append(box)
    signs.set(i, box)

    // 名字挂在舞台上而不是格子里：格子的定位只够装星座，名字要落在它下面，
    // 而且不能被格子的宽度切断
    const name = el('div', 'con-name is-empty')
    name.dataset.i = String(i)
    name.append(el('span', 'con-cn', sign.cn), el('span', 'con-sub', sign.en))
    stage.append(name)
    names.set(i, name)
  })

  // 名字在星座的正下方居中
  const placeNames = (): void => {
    SIGNS.slice(0, SLOTS).forEach((sign, k) => {
      const name = names.get(k + 1)
      if (!name) return
      name.style.left = `${sign.box[0] + sign.box[2] / 2}%`
      // 贴在**星点**的最低处而不是格子的底边：星图上的标注就该紧跟着那个星座，
      // 按格子算会空出一大截，名字看起来像另一样东西的标题
      const low = Math.max(...sign.stars.map((s) => s.y))
      name.style.top = `${round1(sign.box[1] + sign.box[3] * low + 2)}%`
    })
  }
  placeNames()

  return { stage, signs, names }
}

/** 换一个星座的状态（类名 + 让 CSS 决定星点亮到什么程度） */
function setSignState(sign: HTMLElement, cls: string): void {
  sign.className = `con-sign ${cls}`
}

export function createConstellationView(): RestoreView {
  const root = el('div', 'con-view')
  const { stage, signs, names } = buildStage()

  let intent: ShareIntent | null = null
  const canAdd = (): boolean => intent !== null && intent.allowed()
  const filled = (hit: HTMLElement | null): boolean =>
    !!hit && (hit.classList.contains('is-image') || hit.classList.contains('is-file'))

  // 点空白天空或还没亮的星座 = 补分片；点亮了的星座点了是下载
  stage.addEventListener('click', (e) => {
    const hit = (e.target as HTMLElement).closest<HTMLElement>('.con-sign')
    if (filled(hit)) return
    if (!canAdd()) return
    intent!.pick()
  })
  stage.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' && e.key !== ' ') return
    const hit = (e.target as HTMLElement).closest<HTMLElement>('.con-sign')
    if (filled(hit)) return
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

  const info = document.createElement('details')
  info.className = 'con-details'
  info.hidden = true
  const sum = document.createElement('summary')
  sum.textContent = '文件信息与校验'
  info.append(sum)

  root.append(stage, info)
  let opened = 0

  /** 副标题写文件名（或状态）；主标题永远是星座名——星图上的字是星座的名字，
      不是文件的名字，文件名挤掉它，这张图就不像星图了。 */
  const setSub = (i: number, text: string, kind: string): void => {
    const name = names.get(i)
    if (!name) return
    name.className = `con-name ${kind}`
    const sub = name.querySelector('.con-sub') as HTMLElement
    sub.textContent = text
    sub.classList.toggle('is-file', kind === 'is-image' || kind === 'is-file')
  }

  const fill = (i: number, l: LayerInfo): void => {
    const sign = signs.get(i)
    if (!sign) return
    const cloud = sign.querySelector('.con-cloud') as HTMLElement
    cloud.textContent = ''
    const mime = sniffImageMime(l.data)
    const kind = mime ? 'is-image' : 'is-file'
    setSignState(sign, kind)
    setSub(i, baseName(l.name), kind)
    sign.title = `${l.name} · ${fmtSize(l.data.length)} · 点击下载`
    sign.tabIndex = 0
    sign.setAttribute('role', 'button')
    const grab = (): void => download(l.name, l.data)
    sign.addEventListener('click', grab)
    sign.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault()
        grab()
      }
    })
    if (mime) {
      const url = trackUrl(URL.createObjectURL(new Blob([l.data], { type: mime })))
      const img = document.createElement('img')
      img.className = 'con-img'
      img.src = url
      img.alt = l.name
      img.decoding = 'sync'
      cloud.append(img)
      // 和碎片踩过的同一个坑：带遮罩/动画的子树里 img.decode() 不 settle，用 load 兜底
      const show = (): void => cloud.classList.add('is-shown')
      if (img.complete) show()
      else {
        img.addEventListener('load', show, { once: true })
        img.addEventListener('error', show, { once: true })
      }
    } else {
      cloud.append(el('div', 'con-doc', fileGlyph(), el('div', 'con-file', l.name)))
      cloud.classList.add('is-shown')
    }
  }

  return {
    root,
    attachShare(next) {
      intent = next
      stage.classList.add('is-shareable')
      for (const s of signs.values()) if (s.tabIndex < 0) s.tabIndex = 0
    },
    lock(i, k, have) {
      const sign = signs.get(i)
      if (!sign) return
      setSignState(sign, 'is-locked')
      sign.title = `第 ${i} 个星座需要 ${k} 片，当前 ${have} 片 · 点一下补充分片`
      sign.tabIndex = 0
      sign.setAttribute('role', 'button')
      setSub(i, `需要 ${k} 片`, 'is-locked')
    },
    fake(i, k) {
      const sign = signs.get(i)
      if (!sign) return
      setSignState(sign, 'is-fake')
      sign.title = `第 ${i} 个星座是假层：${k} 片插出来的密钥对不上`
      setSub(i, '解不开', 'is-fake')
    },
    unlock(layer) {
      fill(layer.index, layer)
      const card = levelCard(layer, { preview: false, unit: '个' })
      info.hidden = false
      info.append(card)
      opened++
      sum.textContent = `文件信息与校验（${opened} 个）`
      return otsHost(card)
    },
  }
}

// ===== 拆分端：同一张星图，往里放照片 =====
export function createConstellationSplitView(): SplitView {
  const root = el('div', 'con-view con-split')
  const { stage, signs, names } = buildStage()
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

  const cloudOf = (i: number): HTMLElement => signs.get(i)!.querySelector('.con-cloud') as HTMLElement
  const nameOf = (i: number): HTMLElement => names.get(i)!

  const resetSign = (i: number): void => {
    const sign = signs.get(i)!
    setSignState(sign, 'is-empty')
    sign.title = `第 ${i} 个星座还空着：点一下放一张图`
    sign.tabIndex = 0
    sign.setAttribute('role', 'button')
    const cloud = cloudOf(i)
    cloud.textContent = ''
    cloud.classList.remove('is-shown')
    cloud.append(el('div', 'con-add', el('div', 'con-add-plus', '+'), el('div', 'con-add-text', '放图')))
    const name = nameOf(i)
    name.className = 'con-name is-empty'
    const sub = name.querySelector('.con-sub') as HTMLElement
    sub.textContent = SIGNS[i - 1]!.en
    sub.classList.remove('is-file')
  }

  const fillSign = (c: SplitCell): void => {
    const i = c.index
    if (i > SLOTS) return
    const sign = signs.get(i)!
    const cloud = cloudOf(i)
    cloud.textContent = ''
    cloud.classList.remove('is-shown')
    const name = nameOf(i)
    const sub = name.querySelector('.con-sub') as HTMLElement

    const remove = el('button', 'con-x', '×') as HTMLButtonElement
    remove.type = 'button'
    remove.dataset.i = String(i)
    remove.title = '把这一层撤掉'

    if (c.fake) {
      setSignState(sign, 'is-fake')
      sign.title = `第 ${i} 层是假文件层：凑够 ${c.k} 片也解不开`
      name.className = 'con-name is-fake'
      sub.textContent = '假文件层'
      sub.classList.add('is-file')
      cloud.append(el('div', 'con-doc', fileGlyph(), el('div', 'con-file', '假文件层')))
      cloud.classList.add('is-shown')
      name.append(remove)
      return
    }

    const file = c.file
    const image = file !== null && isImageFileLike(file.name, file.type)
    setSignState(sign, image ? 'is-image' : 'is-file')
    sign.title = `${c.name} · ${fmtSize(c.size)} · 第 ${i} 层，需要 ${c.k} 片`
    name.className = `con-name ${image ? 'is-image' : 'is-file'}`
    if (image && file) {
      const url = URL.createObjectURL(file)
      urls.push(url)
      const img = document.createElement('img')
      img.className = 'con-img'
      img.src = url
      img.alt = c.name
      img.decoding = 'sync'
      cloud.append(img)
      cloud.classList.add('is-shown')
    } else {
      cloud.append(el('div', 'con-doc', fileGlyph(), el('div', 'con-file', c.name)))
      cloud.classList.add('is-shown')
    }
    sub.textContent = baseName(c.name)
    sub.classList.add('is-file')
    name.append(remove)
  }

  stage.addEventListener('click', (e) => {
    const x = (e.target as HTMLElement).closest<HTMLElement>('.con-x')
    if (x) {
      e.stopPropagation()
      intent?.remove(Number(x.dataset.i) - 1)
      return
    }
    const hit = (e.target as HTMLElement).closest<HTMLElement>('.con-sign')
    if (hit && !hit.classList.contains('is-empty')) return
    if (!canAdd()) return
    intent!.pick()
  })
  stage.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' && e.key !== ' ') return
    const hit = (e.target as HTMLElement).closest<HTMLElement>('.con-sign')
    if (hit && !hit.classList.contains('is-empty')) return
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
      for (let i = 1; i <= SLOTS; i++) resetSign(i)
      for (const c of cells) fillSign(c)
      note.textContent = cells.length
        ? `${cells.length} 个星座已就位：第 1 个要 1 片，第 ${cells.length} 个要 ${cells.length} 片。`
        : '六个星座都还空着：点任意一个放一张照片。'
    },
  }
}
