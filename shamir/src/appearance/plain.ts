// 默认外观：一层一张文件卡，图片自动预览。
// 没有任何额外规矩——什么文件都收，层数不限。

import { el } from '../ui/dom.ts'
import { fakeRow, levelCard, lockedRow, otsHost } from './card.ts'
import type { RestoreView, SplitPolicy } from './types.ts'

export const PLAIN_SPLIT: SplitPolicy = {
  accept: '',
  acceptLabel: '任意文件',
  maxLayers: Number.POSITIVE_INFINITY,
  accepts: () => true,
  dropText: '拖文件到这里，或点击选择（可多选）',
}

export function createPlainView(): RestoreView {
  const root = el('div', 'view-plain')
  return {
    root,
    lock(index, k, have, total) {
      root.append(lockedRow(index, k, have, total))
    },
    fake(index, k) {
      root.append(fakeRow(index, k))
    },
    unlock(layer) {
      const card = levelCard(layer)
      root.append(card)
      return otsHost(card)
    },
  }
}
