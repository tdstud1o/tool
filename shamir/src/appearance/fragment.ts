// 外观「碎片」：六张照片被剪碎，贴在同一片夜空上。
//
// 一块 = 一层。解锁一层点亮一块，凑不够的块一直暗着——碎的正是"还没凑齐"这件事。
// **形状共用、内容独立**：六块轮廓都在下面的 SHARDS 里，各自还带一点自转，
// 拼起来铺满舞台；但每块装的是自己那份密文，谁也拼不出整体——像一趟旅行在六个
// 地方拍的照片摆在一起，内容有关联，却从来不是同一张。标签是舞台的孩子（碎片带
// clip-path，标签挂在里面会被切线切掉一半），位置由几何算出来。
//
// 「每块默认是一张图」：拆分端只收图片，但恢复端不信任这一点——按魔数嗅探，
// 不是图片就不画图，退化成文件格，点一下下载原文件。

import './fragment.css'
import { FRAGMENT_SLOTS, isImageFileLike, sniffImageMime } from '../core/styles.ts'
import { baseName, download, el, fmtSize, trackUrl } from '../ui/dom.ts'
import { levelCard, otsHost } from './card.ts'
import type { LayerInfo, RestoreView, ShareIntent, SplitCell, SplitIntent, SplitPolicy, SplitView } from './types.ts'

const SLOTS = FRAGMENT_SLOTS

/** 拆分端规矩：只收图片，最多 6 层（假层也占一格） */
export const FRAGMENT_SPLIT: SplitPolicy = {
  accept: 'image/*',
  acceptLabel: '图片',
  maxLayers: SLOTS,
  accepts: (f) => isImageFileLike(f.name, f.type),
  dropText: '拖入图片，或点击选择（可多选）',
}

// ===== 六块碎片的轮廓 =====
//
// 一份几何，三处用：clip-path 的切形、边缘高光那条折线、以及内容/取景的锚点。
// 写在一处而不是散进 CSS，是因为这三样必须严丝合缝——差 0.2% 就是一条白线错位。
// 坐标是 0..100 的相对值（宽高各算 100；舞台 16:10，x 被拉长，所以"看着 45°"的
// 边在百分比里斜率约 1.6）。顶点可以越界，舞台 overflow 会把它裁掉。
//
// 造型是照参考图摆的：长直边 + 少数几个狠折角，别做成均匀毛边——均匀的锯齿读起来
// 是"齿轮"，只有长短边悬殊、折角互成锐角才读作玻璃断面。
//
// 六块**互相咬着**摆：相邻两块的凹凸对着长，缝最宽处也只有 3%~4%（再宽就成了
// "六张小图排在格子里"，玻璃本身反而显小）。只有 5 号整片浮在夜空里不碰画框——
// 六块全部顶到边上时剪影就是一个大矩形，怎么切都像拼图；留一块浮着，读到的
// 才是"几片玻璃飘在那儿"。
//
// 6 号（左下最大那块）特意拉出一道**长而锐的尖刺**，刺尖落在画布中心 (48.6, 47.6)
// 附近：六块里只有它是"指向中间"的，剪影因此有方向，不再是一堆随机多边形。
type Pt = readonly [number, number]

const SHARDS: readonly (readonly Pt[])[] = [
  // 1 左上：出血到顶和左，右侧一路锯齿
  [[-6.9, -2.8], [33.4, -4.2], [32.4, 7.8], [38.2, 15.6], [32.6, 25.8], [38.6, 33.6], [32.6, 44.6], [14.2, 50.4], [-3.1, 38.6]],
  // 2 上中：竖直长条，右侧两个尖齿
  [[35.6, -5.1], [60.4, -1.8], [56.4, 9.4], [62.4, 18.2], [56.4, 29.4], [62.8, 43.6], [44.2, 45.8], [34.8, 26.4]],
  // 3 右上：顶边压出画框，左下角被啃掉一块
  [[63.4, -3.8], [101.9, -6.6], [104.4, 23.8], [95.4, 29.2], [102.6, 39.4], [96.4, 48.6], [85.4, 52.6], [69.4, 56.4], [69.6, 42.4], [64.6, 26.6], [65.2, 13.9]],
  // 4 右下：出血到右和下
  [[75.4, 57.2], [90.4, 52.4], [103.2, 55.8], [96.4, 67.8], [106.4, 78.4], [94.6, 99.4], [77.2, 98.2], [70.6, 66.2]],
  // 5 中下：整片浮在夜空里，不碰画框
  [[42.6, 54.2], [54.6, 51.0], [66.6, 52.6], [62.2, 69.2], [69.6, 78.6], [62.4, 96.6], [47.6, 98.6], [40.8, 88.2], [44.6, 64.4]],
  // 6 左下：最大的一块，左/下都出血；右上拉出一道细尖，直指画布中心
  [[-4.9, 41.8], [10.8, 53.8], [20.6, 49.8], [29.4, 52.4], [31.6, 46.4], [48.6, 47.6], [38.2, 54.6], [33.6, 76.4], [37.4, 93.8], [30.8, 107.6], [-4.9, 104.4]],
]

const round1 = (n: number): number => Math.round(n * 10) / 10
const round2 = (n: number): number => Math.round(n * 100) / 100

/** 面积重心：不规则多边形的"看得见的中心"，比包围盒中心靠谱 */
function centroid(pts: readonly Pt[]): Pt {
  let a = 0
  let cx = 0
  let cy = 0
  for (let i = 0; i < pts.length; i++) {
    const [x1, y1] = pts[i]
    const [x2, y2] = pts[(i + 1) % pts.length]
    const f = x1 * y2 - x2 * y1
    a += f
    cx += (x1 + x2) * f
    cy += (y1 + y2) * f
  }
  a /= 2
  return [cx / (6 * a), cy / (6 * a)]
}

interface ShardGeom {
  /** clip-path 用 */
  clip: string
  /** SVG polygon 用（viewBox 0 0 100 100） */
  points: string
  /** 取景框 = 这块的包围盒 */
  bx: number
  by: number
  bw: number
  bh: number
  /** 内容锚点（重心） */
  cx: number
  cy: number
  /** 标签锚点：最上面那个顶点往重心方向缩一点，落在玻璃上而不是悬崖边 */
  lx: number
  ly: number
  /** 靠右的块改成右对齐，否则标签会被舞台的 overflow 裁掉半截 */
  right: boolean
}

const GEOM: readonly ShardGeom[] = SHARDS.map((pts) => {
  const xs = pts.map((p) => p[0])
  const ys = pts.map((p) => p[1])
  const bx = Math.min(...xs)
  const by = Math.min(...ys)
  const bw = Math.max(...xs) - bx
  const bh = Math.max(...ys) - by
  const [cx, cy] = centroid(pts)
  // 最靠上的顶点：标签就往那儿摆（参考图里编号都压在碎片的上缘）
  const top = pts.reduce((best, p) => (p[1] < best[1] ? p : best), pts[0])
  return {
    clip: `polygon(${pts.map(([x, y]) => `${round1(x)}% ${round1(y)}%`).join(', ')})`,
    points: pts.map(([x, y]) => `${round1(x)},${round1(y)}`).join(' '),
    bx: round1(bx),
    by: round1(by),
    bw: round1(bw),
    bh: round1(bh),
    cx: round1(cx),
    cy: round1(cy),
    // 夹进画框：出血块的顶点在舞台外，照原样摆标签会被裁掉
    lx: round1(Math.min(96, Math.max(2, top[0] + (cx - top[0]) * 0.22))),
    ly: round1(Math.min(94, Math.max(2, top[1] + (cy - top[1]) * 0.22))),
    right: top[0] + (cx - top[0]) * 0.22 > 56,
  }
})

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

const NS = 'http://www.w3.org/2000/svg'

/**
 * 虚拟光源：舞台正中偏右上的一点（0..100 相对坐标）。
 *
 * 六片玻璃都由它在背后打光——**不是**每块自带一圈白边。
 * 光源决定了每块"哪几条边发亮、亮多长"：正对着它的那几个断口被点着，
 * 背过去的一侧几乎全黑，只在拐角留一丝冷色余辉。
 *
 * 这个点**只活在算法里，不画出来**。曾经在星空层按这个坐标糊过一团光，
 * 结果是画布中间顶着一盏灯：眼睛先看见灯，再看见玻璃，反射反而成了陪衬。
 * 光要有来处、但不能被看见——所以现在夜空是纯夜空，只有断口上的反射。
 */
const LIGHT: Pt = [47, 47]

/**
 * 六块各自的前后距离（0 = 最远，1 = 最前）。
 *
 * 这是假的 3D：不做透视，只让"离眼睛近"的几块受光更强、断口更宽、亮段更长，
 * 远的几块只剩一道细而短的微光。块与块因此不在同一层上，
 * 读到的才是"六片错落地浮着"，而不是"六块拼在一个平面上"。
 * 数值刻意和位置错开——按距离排队就成了一圈光晕，错落才有纵深。
 */
const DEPTH: readonly number[] = [0.62, 0.92, 0.4, 1, 0.72, 0.3]

/** 舞台是 16:10，x 方向的 1% 比 y 方向的 1% 长得多；算朝向/距离必须按屏幕比例来，否则法线是歪的 */
const ASPECT = 16 / 10

/** 卡片宽度上限 900px 时的舞台实际宽度（估算值：只用来把"屏幕 px 的模糊半径"
    换算成 SVG 用户单位，差几十像素不影响观感） */
const STAGE_W = 805

interface RimEdge {
  a: Pt
  b: Pt
  /** 0 = 完全背光，1 = 正对光源 */
  lit: number
}

/**
 * 把一块轮廓按**弧长**切成小段，逐段算受光强度。
 *
 * 只看"离光源多远"是不够的：一块正好压在光源上的玻璃，整圈距离都近，
 * 于是又变成了一圈白边——那正是要避免的。所以再乘一个朝向：
 * 外法线朝着光源的那段才亮，背过去的一侧暗下去。玻璃断面不是发光体，
 * 它只是把背后那束光折回来，方向不对就什么都看不见。
 *
 * 为什么按弧长切而不是按"边"切：按边切的话，长边被一个 lit 值管住，整条边
 * 从头到尾一样亮；短边又只有一段。两种都会在边上留下"亮到这里就没了"的突然
 * 截止——那就是看得见的光的分界线。按固定弧长切，明暗是**一段一段连续过渡**的，
 * 走到哪儿暗到看不见就在哪儿消失，没有截止线可看。
 */
function rimEdges(pts: readonly Pt[], depth: number, step: number): RimEdge[] {
  const [ccx, ccy] = centroid(pts)
  // 亮段能走多远：靠前的块光跑得远，靠后的块几步就没了
  const reach = 40 + depth * 62
  const out: RimEdge[] = []
  pts.forEach((a, i) => {
    const b = pts[(i + 1) % pts.length]
    const dx = (b[0] - a[0]) * ASPECT
    const dy = b[1] - a[1]
    const len = Math.hypot(dx, dy) || 1
    let nx = dy / len
    let ny = -dx / len
    // 法线翻到背离重心的一侧（轮廓的绕向不统一，不能靠符号猜）
    const mx = ((a[0] + b[0]) / 2) * ASPECT
    const my = (a[1] + b[1]) / 2
    if (nx * (mx - ccx * ASPECT) + ny * (my - ccy) < 0) {
      nx = -nx
      ny = -ny
    }
    const count = Math.max(1, Math.round(len / step))
    for (let k = 0; k < count; k++) {
      // 相邻段互相多走一截：宽度不同的两段在接头处，圆头会鼓出一节，
      // 顺着边看过去就是一串小疙瘩。
      const t0 = Math.max(0, k / count - 0.35 / count)
      const t1 = Math.min(1, (k + 1) / count + 0.35 / count)
      const p0: Pt = [a[0] + (b[0] - a[0]) * t0, a[1] + (b[1] - a[1]) * t0]
      const p1: Pt = [a[0] + (b[0] - a[0]) * t1, a[1] + (b[1] - a[1]) * t1]
      const qx = ((p0[0] + p1[0]) / 2) * ASPECT
      const qy = (p0[1] + p1[1]) / 2
      const vx = qx - LIGHT[0] * ASPECT
      const vy = qy - LIGHT[1]
      const dist = Math.hypot(vx, vy) || 1
      // 这一段朝向光源的程度：法线与"光→点"方向反向就是正对
      const facing = Math.max(0, -(nx * (vx / dist) + ny * (vy / dist)))
      const fall = Math.max(0, 1 - dist / reach)
      // 0.05 是环境光：全黑的边也要留一丝，否则形状会整个散在夜空里
      const lit = 0.05 + 0.95 * Math.pow(facing, 1.05) * Math.pow(0.15 + 0.85 * fall, 1.2)
      out.push({ a: p0, b: p1, lit })
    }
  })

  // 沿轮廓做几轮环形平滑。用处只有一个：抹掉**拐角**两侧的亮度突变——
  // 折角两边的法线不同，受光本来就该不同，可取值为两个数、中间没有过渡，
  // 那在画面上的表现就是"亮到这里戛然而止"，也就是所谓光的分界线。
  // 平滑只在相邻的几段之间搬一点亮度，亮段的长短、位置都不变。
  let cur = out.map((e) => e.lit)
  for (let pass = 0; pass < 3; pass++) {
    const src = cur
    cur = src.map((v, k) => (src[(k - 1 + src.length) % src.length] + 2 * v + src[(k + 1) % src.length]) / 4)
  }
  return out.map((e, k) => ({ ...e, lit: Math.round(cur[k] * 1000) / 1000 }))
}

/**
 * 高斯模糊的三档半径（屏幕 CSS px）。
 *
 * 描边本身是一条**实心**色带，边上有清晰的截止线——哪怕把透明度压到 0.05，
 * 那条"光到这里就没了"的分界照样看得见，这正是"突兀"的来由。
 * 唯一的解法是把色带的边缘糊开，让它从有到无走完一整段渐变。
 *
 * 三档各管一段：halo 是断口外泄的那团雾（糊得最开），glow 是断面本体的亮带，
 * line 是断口最里侧那根反光——它也得糊一点，只是不能糊到看不出是条线。
 */
const BLUR_PX = { halo: 6, glow: 2.6, line: 0.8 } as const

/**
 * 三道描边各自的份量。宽度和透明度都**不写进 CSS**：它们要跟着这一段的受光
 * 逐段变（靠光源那头粗而亮、远端收成一根细线），只能在这里算完直接写成属性。
 * step  沿轮廓每隔多少（按屏幕比例的弧长，1 ≈ 舞台宽度的 1%）切一段：
 *       halo 糊得最开，宽窄变化反正看不出来，切粗一点就够；glow 必须切细，
 *       它就是"断面亮带"，宽窄连续变化才像玻璃。
 * gamma 受光强度取几次幂。> 1 收得更紧（远一点就真的没了），< 1 抬暗部
 *       （亮段上始终留得住一根断口反光，不会糊成一团雾）。
 */
const RIM_LAYERS = [
  { cls: 'frag-rim-halo', w: 22, o: 0.5, blur: 'halo', step: 16, gamma: 1.35 },
  { cls: 'frag-rim-glow', w: 8.5, o: 0.5, blur: 'glow', step: 5, gamma: 0.95 },
  { cls: 'frag-rim-line', w: 2.1, o: 0.9, blur: 'line', step: 7, gamma: 0.7 },
] as const

/**
 * 舞台是 16:10，但 viewBox 是 0..100 的正方形：x 方向 1 个单位有 W/100 个 CSS px，
 * y 方向只有 H/100 个——y 单位比 x 单位短 ASPECT 倍。feGaussianBlur 的 stdDeviation
 * 吃的是用户单位，直接给同一个值会得到一个横躺的椭圆模糊，亮带横着糊竖向却还带硬边。
 * 所以按 1 : ASPECT 拆开给。
 */
function blurFilter(id: string, sigmaPx: number): SVGFilterElement {
  const f = document.createElementNS(NS, 'filter')
  f.setAttribute('id', id)
  // 默认的 -10%/120% 只够装描边本身，装不下糊出去的那一圈，光会被 filter 的
  // 区域边界直接切平——那就白糊了。放宽到 -35%/170%。
  f.setAttribute('x', '-35%')
  f.setAttribute('y', '-35%')
  f.setAttribute('width', '170%')
  f.setAttribute('height', '170%')
  // 默认的 linearRGB 里糊出来会偏暗偏脏，sRGB 才和看到的颜色一致
  f.setAttribute('color-interpolation-filters', 'sRGB')
  const blur = document.createElementNS(NS, 'feGaussianBlur')
  const unitPx = STAGE_W / 100
  blur.setAttribute('stdDeviation', `${round2(sigmaPx / unitPx)} ${round2((sigmaPx * ASPECT) / unitPx)}`)
  f.append(blur)
  return f
}

/**
 * 边缘高光：和碎片完全同形的折线，压在碎玻璃的最上层。
 *
 * 为什么不用 box-shadow / border：碎片是 clip-path 裁出来的，描边会被自己裁掉一半；
 * 而 filter 在 clip 之前做（同元素上），drop-shadow 同样会被切走。所以用 SVG：
 * 一张覆盖整个舞台的 SVG（viewBox 0 0 100 100 + preserveAspectRatio none），
 * 百分比坐标和 clip-path 的百分比是同一套映射，画出来的线严丝合缝。
 *
 * 画的是**一段段边**而不是闭合的多边形：
 *   - 每段的透明度由这一段的朝向决定（rimEdges），背光的那几条直接暗掉；
 *   - 颜色是以 LIGHT 为心的径向渐变，沿位置取样，一条边靠近光源的那截最亮、
 *     往远端衰减到零——亮段的长短于是自己就出来了，不用逐点算。
 * 每块各有一份自己的渐变，半径随 DEPTH 变：靠前的块亮到更远才熄。
 *
 * 三档一律过一遍高斯模糊（BLUR_PX）。层次是"糊开程度"给的，不是"叠几根实心线"：
 * 实心线叠得再多，最粗那根的外缘仍然是一条直线，那就是眼睛看到的"光的分界线"。
 */
function buildRims(): SVGSVGElement {
  const svg = document.createElementNS(NS, 'svg')
  svg.setAttribute('class', 'frag-rims')
  svg.setAttribute('viewBox', '0 0 100 100')
  svg.setAttribute('preserveAspectRatio', 'none')
  svg.setAttribute('aria-hidden', 'true')

  const defs = document.createElementNS(NS, 'defs')
  const gradients = GEOM.map((_, i) => {
    const depth = DEPTH[i] ?? 0.6
    const grad = document.createElementNS(NS, 'radialGradient')
    const id = `fragLit${i + 1}`
    grad.setAttribute('id', id)
    grad.setAttribute('gradientUnits', 'userSpaceOnUse')
    grad.setAttribute('cx', String(LIGHT[0]))
    grad.setAttribute('cy', String(LIGHT[1]))
    grad.setAttribute('r', String(round1(20 + depth * 52)))
    for (const [offset, opacity] of [
      ['0', '1'],
      ['0.3', '0.9'],
      ['0.55', '0.62'],
      ['0.75', '0.3'],
      ['0.9', '0.08'],
      ['1', '0'],
    ] as const) {
      const stop = document.createElementNS(NS, 'stop')
      stop.setAttribute('offset', offset)
      stop.setAttribute('stop-color', '#cfe2ff')
      stop.setAttribute('stop-opacity', opacity)
      grad.append(stop)
    }
    defs.append(grad)
    return id
  })
  // 高光要留在玻璃**里面**：描边是以边线为中心对称的，一半会泼到缝里，
  // 远看就成了几根发光的白管子。按同一份轮廓裁一刀，只剩内侧那一半——
  // 那才是"光在这块玻璃的断口上折回来"的样子。
  // 裁在**外层**、糊在**内层**：先糊开再裁，断口处（光最强的地方）正好是切边，
  // 所以不会切出一条可见的分界线；反过来先裁后糊，切口会被糊成一个外扩的亮圈。
  GEOM.forEach((geom, i) => {
    const clip = document.createElementNS(NS, 'clipPath')
    clip.setAttribute('id', `fragClip${i + 1}`)
    const poly = document.createElementNS(NS, 'polygon')
    poly.setAttribute('points', geom.points)
    // 裁剪区比形状**多出一圈**（描边 + non-scaling-stroke 让这圈正好是 3.5px）。
    // 精确裁在边线上的话，边线处正是最亮的地方，往外一步却是黑的——
    // 那条突然消失的亮，就是"光的分界线"。多留 3.5px，光在缝里走完最后一段衰减。
    poly.setAttribute('stroke', '#000')
    poly.setAttribute('stroke-width', '7')
    poly.setAttribute('stroke-linejoin', 'round')
    poly.setAttribute('vector-effect', 'non-scaling-stroke')
    clip.append(poly)
    defs.append(clip)
  })
  for (const [layer, sigma] of Object.entries(BLUR_PX)) defs.append(blurFilter(`fragBlur-${layer}`, sigma))
  svg.append(defs)

  GEOM.forEach((_, i) => {
    const depth = DEPTH[i] ?? 0.6
    // 近的块断口更宽更亮：它挡在别人前面，断面自然也更大
    const rimW = 0.6 + depth * 0.7
    const rimO = 0.55 + depth * 0.45
    const g = document.createElementNS(NS, 'g')
    g.setAttribute('class', 'frag-rim-shard')
    g.dataset.i = String(i + 1)
    g.setAttribute('stroke', `url(#${gradients[i]})`)
    g.setAttribute('clip-path', `url(#fragClip${i + 1})`)

    for (const layer of RIM_LAYERS) {
      const sub = document.createElementNS(NS, 'g')
      sub.setAttribute('filter', `url(#fragBlur-${layer.blur})`)
      for (const e of rimEdges(SHARDS[i], depth, layer.step)) {
        // 亮处粗、暗处细；再乘上受光强度，暗到几乎没有时就真的收没了
        const t = 0.38 + 0.62 * e.lit
        const line = document.createElementNS(NS, 'line')
        line.setAttribute('class', layer.cls)
        line.setAttribute('x1', String(round1(e.a[0])))
        line.setAttribute('y1', String(round1(e.a[1])))
        line.setAttribute('x2', String(round1(e.b[0])))
        line.setAttribute('y2', String(round1(e.b[1])))
        line.setAttribute('stroke-width', String(round2(layer.w * rimW * t)))
        line.setAttribute('stroke-opacity', String(round2(layer.o * rimO * Math.pow(e.lit, layer.gamma))))
        // 圆头：相邻段在接头处以圆弧接上，糊开之后不会留下一个方角或错位
        line.setAttribute('stroke-linecap', 'round')
        line.setAttribute('vector-effect', 'non-scaling-stroke')
        sub.append(line)
      }
      g.append(sub)
    }
    svg.append(g)
  })
  return svg
}

/**
 * 每一格的边缘高光组，挂在 slot 元素上（不放进 slot 里：slot 带 clip-path，
 * 会把 rim 自己那圈 3.5px 的外扩裁掉，白糊一场）。
 */
const rimOf = new WeakMap<HTMLElement, SVGGElement>()

/**
 * 换一格的状态。状态的样式在 CSS 里（.frag-slot.is-xxx），但这还不够：
 * 边缘高光是舞台上一层独立的 SVG，看不见 slot 换了什么类，得跟着同步一份，
 * 否则空的玻璃也会顶着两道光——那正是"白描边"最刺眼的地方。
 */
function setSlotState(slot: HTMLElement, cls: string): void {
  slot.className = cls
  const g = rimOf.get(slot)
  if (g) g.dataset.state = cls.replace('frag-slot is-', '')
}

/**
 * 六块舞台的骨架：星空层 + 六个碎片 + 边缘高光 + 六个标签。
 * 恢复端（往外取图）和拆分端（往里塞图）**共用这一份**——所谓"同一套组件"，
 * 指的就是形状、命中区、悬停反馈全在这里，两端的差别只有喂进去的事件。
 */
function buildStage(): { stage: HTMLElement; slots: Map<number, HTMLElement>; tags: Map<number, HTMLElement> } {
  const stage = el('div', 'frag-stage')
  stage.setAttribute('role', 'group')
  stage.setAttribute('aria-label', `碎片外观：${SLOTS} 格`)
  const slots = new Map<number, HTMLElement>()
  const tags = new Map<number, HTMLElement>()

  // 星空：整块舞台的底。碎片是"浮在夜空里的玻璃"，所以它必须是最下面那层，
  // 连碎片内部也要能透出来（face 是半透明的）。
  stage.append(el('div', 'frag-sky'))

  for (let i = 1; i <= SLOTS; i++) {
    const g = GEOM[i - 1]
    const slot = el('div', 'frag-slot is-empty')
    slot.dataset.i = String(i)
    // 形状与取景框都挂在这一格上：--poly 给碎片本体/面子/光晕共用，
    // 其余四个是这一格自己的包围盒（六块装六张不同的照片，谁也不该用别人的框）
    slot.style.setProperty('--poly', g.clip)
    slot.style.setProperty('--bx', `${g.bx}%`)
    slot.style.setProperty('--by', `${g.by}%`)
    slot.style.setProperty('--bw', `${g.bw}%`)
    slot.style.setProperty('--bh', `${g.bh}%`)
    slot.style.setProperty('--cx', `${g.cx}%`)
    slot.style.setProperty('--cy', `${g.cy}%`)
    // 假景深的另一半：靠前的那块画面更亮一档（边缘光那一半在 buildRims 里）
    slot.style.setProperty('--lit', String(round1(0.92 + (DEPTH[i - 1] ?? 0.6) * 0.14)))
    slot.append(el('div', 'frag-face'))
    stage.append(slot)
    slots.set(i, slot)
  }

  // 高光要在碎片之上（要盖住照片的边缘），在标签之下
  const rims = buildRims()
  stage.append(rims)
  rims.querySelectorAll<SVGGElement>('g.frag-rim-shard').forEach((g) => {
    const slot = slots.get(Number(g.dataset.i))
    if (slot) rimOf.set(slot, g)
  })

  for (let i = 1; i <= SLOTS; i++) {
    const g = GEOM[i - 1]
    // 标签不能塞进碎片里：碎片带 clip-path，挂在里面会被切线切掉半个字。
    // 所以它是舞台的孩子，位置由几何算出来（贴着这块的上缘）。
    // 初始文案是"空着"而不是"未解锁"：这套界面可以在没有密文的时候就摆出来，
    // 一上来就写"未解锁"会像"已经有东西、只是没凑够片"。
    const tag = el('div', 'frag-tag is-empty')
    tag.dataset.i = String(i)
    // 右半边的块从右往左长，长名字不会顶出舞台
    if (g.right) {
      tag.style.left = 'auto'
      tag.style.right = `${round1(100 - g.lx)}%`
    } else {
      tag.style.left = `${g.lx}%`
    }
    tag.style.top = `${g.ly}%`
    tag.append(el('span', 'frag-num', String(i)), el('span', 'frag-name', '空着'))
    stage.append(tag)
    tags.set(i, tag)
  }
  return { stage, slots, tags }
}

export function createFragmentView(): RestoreView {
  const root = el('div', 'frag-view')
  const { stage, slots, tags } = buildStage()

  // 「补充分片」的入口由主流程交过来：碎片自己只负责"点哪儿"和"拖进来"。
  let intent: ShareIntent | null = null
  const canAdd = (): boolean => intent !== null && intent.allowed()

  // 点空格子或点玻璃之间的夜空 = 补分片；点到已解锁的格子仍然走那格自己的下载。
  // 监听挂在 stage 上而不是每个格子上：格子之间那块夜空不属于任何一格。
  stage.addEventListener('click', (e) => {
    const hit = (e.target as HTMLElement).closest('.frag-slot')
    if (hit && (hit.classList.contains('is-image') || hit.classList.contains('is-file'))) return
    if (!canAdd()) return
    intent!.pick()
  })
  stage.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' && e.key !== ' ') return
    const hit = (e.target as HTMLElement).closest('.frag-slot')
    if (hit && (hit.classList.contains('is-image') || hit.classList.contains('is-file'))) return
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

  // 碎片外观下，校验信息收进折叠框：拼图是主角，哈希不是
  const info = document.createElement('details')
  info.className = 'frag-details'
  // 一格都没解开时没有"文件信息"可讲（拼图自己会先摆出来），先藏起来
  info.hidden = true
  const sum = document.createElement('summary')
  sum.textContent = '文件信息与校验'
  info.append(sum)

  root.append(stage, info)
  let opened = 0

  const setTag = (i: number, text: string, kind: string): void => {
    const tag = tags.get(i)
    if (!tag) return
    tag.className = `frag-tag ${kind}`
    ;(tag.querySelector('.frag-name') as HTMLElement).textContent = text
  }

  const fill = (i: number, l: LayerInfo): void => {
    // 普通模式可以"覆写成碎片外观"，那样层数不受 6 格限制：多出来的层没有格子，
    // 但仍然会进下面的「文件信息与校验」，不在这里炸掉。
    const slot = slots.get(i)
    if (!slot) return
    const face = slot.querySelector('.frag-face') as HTMLElement
    face.textContent = ''
    // 是不是图片只看字节：内层写的 MIME 与扩展名都可能被改，不拿它们当证据
    const mime = sniffImageMime(l.data)
    const kind = mime ? 'is-image' : 'is-file'
    setSlotState(slot, `frag-slot ${kind}`)
    setTag(i, baseName(l.name), kind)
    slot.title = `${l.name} · ${fmtSize(l.data.length)} · 点击下载`
    slot.tabIndex = 0
    slot.setAttribute('role', 'button')
    const grab = (): void => download(l.name, l.data)
    slot.addEventListener('click', grab)
    slot.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault()
        grab()
      }
    })
    if (mime) {
      const url = trackUrl(URL.createObjectURL(new Blob([l.data], { type: mime })))
      const img = document.createElement('img')
      img.className = 'frag-img'
      img.src = url
      img.alt = l.name
      // 同步解码：异步解码会让格子先空着几百毫秒，六格一起恢复时后半排明显是黑的
      img.decoding = 'sync'
      face.append(img)
      // 原图直接铺进舞台，不做任何自动抠图：图里 alpha = 0 的地方本身就透出玻璃，
      // 主体边界完全由用户那张图决定，猜错的可能性归零。
      // 取景范围与缩放全在 CSS（--bx/--bw + object-fit: cover），这里不算尺寸：
      // 舞台缩放、字体变化都不需要重算，浏览器自己管。
      // 不用 img.decode() 当闸门：它在带 clip-path / 动画的子树里会一直不 settle。
      const show = (): void => img.classList.add('is-shown')
      if (img.complete) show()
      else {
        img.addEventListener('load', show, { once: true })
        img.addEventListener('error', show, { once: true })
      }
    } else {
      // 非图片格的内容就摆在这块玻璃的正中：框体是独立的，中心点自然在框里。
      face.append(el('div', 'frag-doc-box', fileGlyph(), el('div', 'frag-file', l.name)))
    }
  }

  return {
    root,
    attachShare(next) {
      intent = next
      stage.classList.add('is-shareable')
      // 空格子也要能 Tab 到：键盘用户没有"点背景"这条路
      for (const slot of slots.values()) if (slot.tabIndex < 0) slot.tabIndex = 0
    },
    lock(i, k, have) {
      const slot = slots.get(i)
      if (!slot) return
      setSlotState(slot, 'frag-slot is-locked')
      slot.title = `第 ${i} 格需要 ${k} 片，当前 ${have} 片 · 点一下补充分片`
      slot.tabIndex = 0
      slot.setAttribute('role', 'button')
      setTag(i, `需要 ${k} 片`, 'is-locked')
    },
    fake(i, k) {
      const slot = slots.get(i)
      if (!slot) return
      setSlotState(slot, 'frag-slot is-fake')
      slot.title = `第 ${i} 格是假层：${k} 片插出来的密钥对不上`
      setTag(i, '解不开', 'is-fake')
    },
    unlock(layer) {
      fill(layer.index, layer)
      const card = levelCard(layer, { preview: false, unit: '格' })
      info.hidden = false
      info.append(card)
      opened++
      sum.textContent = `文件信息与校验（${opened} 格）`
      return otsHost(card)
    },
  }
}

// ===== 拆分端：同一套玻璃，往里塞图 =====
//
// 恢复端是"凑够 k 片，一块一块亮出来"；拆分端是反过来——先把要藏的东西摆进六块，
// 每块各自加密、各自设门槛，然后拆成 n 片。两端的框体、命中区、悬停反馈完全同一份
// （都来自 buildStage + fragment.css），差别只在喂进去的事件。
export function createFragmentSplitView(): SplitView {
  const root = el('div', 'frag-view frag-split')
  const { stage, slots, tags } = buildStage()
  // 复用"能补素材"那套指针与投放反馈：空格子看起来就是可以按的
  stage.classList.add('is-shareable')
  const note = el('div', 'hint frag-split-note')
  root.append(stage, note)

  let intent: SplitIntent | null = null
  const canAdd = (): boolean => intent !== null && intent.allowed()
  /** 缩略图的对象 URL：每次重画先撤销上一批，不然反复增删会一路攒着 */
  let urls: string[] = []
  const release = (): void => {
    for (const u of urls) URL.revokeObjectURL(u)
    urls = []
  }

  const faceOf = (i: number): HTMLElement => slots.get(i)!.querySelector('.frag-face') as HTMLElement
  const tagOf = (i: number): HTMLElement => tags.get(i)!

  const resetSlot = (i: number): void => {
    const slot = slots.get(i)!
    setSlotState(slot, 'frag-slot is-empty')
    slot.title = `第 ${i} 格还空着：点一下放一张图`
    slot.tabIndex = 0
    slot.setAttribute('role', 'button')
    const face = faceOf(i)
    face.textContent = ''
    face.append(el('div', 'frag-add', el('div', 'frag-add-plus', '+'), el('div', 'frag-add-text', '放图')))
    const tag = tagOf(i)
    tag.className = 'frag-tag is-empty'
    tag.textContent = ''
    tag.append(el('span', 'frag-num', String(i)), el('span', 'frag-name', '空着'))
  }

  const fillSlot = (c: SplitCell): void => {
    const i = c.index
    if (i > SLOTS) return
    const slot = slots.get(i)!
    const face = faceOf(i)
    face.textContent = ''
    const tag = tagOf(i)
    tag.textContent = ''
    tag.append(el('span', 'frag-num', String(i)))

    const remove = el('button', 'frag-x', '×') as HTMLButtonElement
    remove.type = 'button'
    remove.dataset.i = String(i)
    remove.title = '把这一层撤掉'

    if (c.fake) {
      setSlotState(slot, 'frag-slot is-fake')
      slot.title = `第 ${i} 层是假文件层：凑够 ${c.k} 片也解不开`
      tag.className = 'frag-tag is-fake'
      face.append(el('div', 'frag-doc-box', fileGlyph(), el('div', 'frag-file', '假文件层')))
      tag.append(el('span', 'frag-name', '假文件层'), remove)
      return
    }

    const file = c.file
    const image = file !== null && isImageFileLike(file.name, file.type)
    setSlotState(slot, `frag-slot ${image ? 'is-image' : 'is-file'}`)
    slot.title = `${c.name} · ${fmtSize(c.size)} · 第 ${i} 层，需要 ${c.k} 片`
    tag.className = `frag-tag ${image ? 'is-image' : 'is-file'}`
    if (image && file) {
      const url = URL.createObjectURL(file)
      urls.push(url)
      const img = document.createElement('img')
      img.className = 'frag-img'
      img.src = url
      img.alt = c.name
      img.decoding = 'sync'
      face.append(img)
      // 和恢复端同样的坑：裁剪 + 动画的子树里 decode() 不 settle，用 load 事件兜底
      const show = (): void => img.classList.add('is-shown')
      if (img.complete) show()
      else img.addEventListener('load', show, { once: true })
    } else {
      face.append(el('div', 'frag-doc-box', fileGlyph(), el('div', 'frag-file', c.name)))
    }
    // 标签只留「编号 + 名字 + ×」：k 由位置决定（第几块就要几片），
    // 写成字反而是把一条能推出来的信息重复贴在图上
    tag.append(el('span', 'frag-name', baseName(c.name)), remove)
  }

  stage.addEventListener('click', (e) => {
    const x = (e.target as HTMLElement).closest<HTMLElement>('.frag-x')
    if (x) {
      e.stopPropagation()
      intent?.remove(Number(x.dataset.i) - 1)
      return
    }
    const hit = (e.target as HTMLElement).closest('.frag-slot')
    if (hit && !hit.classList.contains('is-empty')) return
    if (!canAdd()) return
    intent!.pick()
  })
  stage.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' && e.key !== ' ') return
    const hit = (e.target as HTMLElement).closest('.frag-slot')
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
      for (let i = 1; i <= SLOTS; i++) resetSlot(i)
      for (const c of cells) fillSlot(c)
      const used = Math.min(cells.length, SLOTS)
      note.textContent =
        used === 0
          ? `六块玻璃 = 六个文件。点一块放一张图，或直接拖进来。`
          : used < SLOTS
            ? `已放 ${used} / ${SLOTS} 块，还能再放 ${SLOTS - used} 张。第 1 块要 1 片、第 2 块要 2 片……每多一片就多解开一块。`
            : `六块排满了：1 片开第 1 块，2 片连第 2 块一起开……凑齐 ${SLOTS} 片才全开。`
    },
  }
}
