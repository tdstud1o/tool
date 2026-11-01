// 恢复端的通用小部件：一层文件卡、还差片的一行、假层的一行。
// 这几块和"外观"无关（默认外观直接用，碎片外观把它塞进折叠框），所以单列。

import { toHex } from '../core/b64.ts'
import { toDetachedOts } from '../core/ots.ts'
import { download, el, fmtSize, trackUrl } from '../ui/dom.ts'
import type { LayerInfo } from './types.ts'

/** 图片（按内层 MIME 或扩展名判断）恢复后直接在页面上预览 */
export function isImageName(name: string, mime: string): boolean {
  if (mime.startsWith('image/')) return true
  return /\.(png|jpe?g|gif|webp|bmp|svg|avif|ico)$/i.test(name)
}

/** 已解锁的一层 */
export function levelCard(r: LayerInfo, opts: { preview?: boolean; unit?: string } = {}): HTMLElement {
  const unit = opts.unit ?? '层'
  const box = el('div', 'rest-item')
  const head = el('div', 'rest-head')
  head.append(el('span', 'rest-lv', `第 ${r.index} ${unit}`), el('span', 'prod-name', r.name))
  box.append(head)
  box.append(
    el(
      'div',
      'prod-meta',
      `${fmtSize(r.data.length)}${r.createdAt ? ` · ${new Date(r.createdAt).toLocaleString()}` : ' · 时间未记录'}`,
    ),
  )
  if (opts.preview !== false && isImageName(r.name, r.mime)) {
    // 本地 blob URL 预览（CSP 的 img-src blob: 已放行）；img 上下文不执行脚本，SVG 也安全
    const url = trackUrl(URL.createObjectURL(new Blob([r.data], { type: r.mime || 'application/octet-stream' })))
    const img = document.createElement('img')
    img.className = 'rest-preview'
    img.src = url
    img.alt = r.name
    img.decoding = 'async'
    box.append(img)
  }
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

/**
 * 还没凑够片的那一层。
 * total 非 null = 密文自己声明了总片数（只有单层密文才有 N 字段），
 * 此时 k > total 是确凿的"永远凑不齐"；否则只能说"还差几片"。
 */
export function lockedRow(level: number, k: number, have: number, total: number | null): HTMLElement {
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
export function fakeRow(level: number, k: number): HTMLElement {
  const box = el('div', 'rest-item is-locked is-fake-layer')
  box.append(
    el('span', 'rest-lv', `第 ${level} 层`),
    el('span', 'mini-meta', `🔒 解密失败 · 假层（${k} 片插出来的密钥对不上）`),
  )
  return box
}

/** 层卡里预留的 OTS 回执容器（默认 hidden，由 OTS 渲染器点亮） */
export function otsHost(card: HTMLElement): HTMLElement {
  return card.querySelector('.ots-box') as HTMLElement
}
