// 外观「碎片」：六张照片被剪碎，贴在同一片夜空上。
//
// 一块 = 一层。解锁一层点亮一块，凑不够的块一直暗着——碎的正是"还没凑齐"这件事。
// **形状共用、内容独立**：六块切线严丝合缝铺满舞台（--poly，在 fragment.css 里），
// 但每块装的是自己那份密文，谁也拼不出整体——像一趟旅行在六个地方拍的照片摆在一起，
// 内容有关联，却从来不是同一张。标签是舞台的孩子（碎片带 clip-path，标签挂在里面
// 会被切线切掉一半），位置写在 .frag-tag[data-i=n]。
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

/** 非图片格里的文件图标（内联 SVG，不依赖字体/emoji） */
function fileGlyph(): SVGSVGElement {
  const NS = 'http://www.w3.org/2000/svg'
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

/**
 * 六块舞台的骨架：星空层 + 六个碎片 + 六个标签。
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

  // 再铺一层"光晕"：每块背后一片同形状的模糊亮片。因为它在所有碎片之下，
  // 只会从缝里透出来——那就是碎玻璃边缘反光的样子。
  for (let i = 1; i <= SLOTS; i++) {
    const glow = el('div', 'frag-glow')
    glow.dataset.i = String(i)
    stage.append(glow)
  }
  for (let i = 1; i <= SLOTS; i++) {
    const slot = el('div', 'frag-slot is-empty')
    slot.dataset.i = String(i)
    slot.append(el('div', 'frag-face'))
    stage.append(slot)
    slots.set(i, slot)

    // 标签不能塞进碎片里：碎片带 clip-path，挂在里面会被切线切掉半个字。
    // 所以它是舞台的孩子，位置单独写在 .frag-tag[data-i=n]。
    // 初始文案是"空着"而不是"未解锁"：这套界面可以在没有密文的时候就摆出来，
    // 一上来就写"未解锁"会像"已经有东西、只是没凑够片"。
    const tag = el('div', 'frag-tag is-empty')
    tag.dataset.i = String(i)
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
    slot.className = `frag-slot ${kind}`
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
      slot.className = 'frag-slot is-locked'
      slot.title = `第 ${i} 格需要 ${k} 片，当前 ${have} 片 · 点一下补充分片`
      slot.tabIndex = 0
      slot.setAttribute('role', 'button')
      setTag(i, `需要 ${k} 片`, 'is-locked')
    },
    fake(i, k) {
      const slot = slots.get(i)
      if (!slot) return
      slot.className = 'frag-slot is-fake'
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
    slot.className = 'frag-slot is-empty'
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
      slot.className = 'frag-slot is-fake'
      slot.title = `第 ${i} 层是假文件层：凑够 ${c.k} 片也解不开`
      tag.className = 'frag-tag is-fake'
      face.append(el('div', 'frag-doc-box', fileGlyph(), el('div', 'frag-file', '假文件层')))
      tag.append(el('span', 'frag-name', '假文件层'), remove)
      return
    }

    const file = c.file
    const image = file !== null && isImageFileLike(file.name, file.type)
    slot.className = `frag-slot ${image ? 'is-image' : 'is-file'}`
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
