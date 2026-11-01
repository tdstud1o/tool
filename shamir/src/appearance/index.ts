// 外观注册表：style 编号 → 模块。
//
// main.ts 只调这两个函数，不认识任何具体外观。新增外观的步骤固定为：
//   1) 在 src/appearance/ 里写一个 xxx.ts（导出 SplitPolicy + createXxxView）；
//   2) 在 core/styles.ts 的 STYLE 与 STYLE_LIST 里登记编号（编号发布后冻结）；
//   3) 在下面的 MODULES 里加一行。
// 没登记的编号（旧恢复端读到新外观）自动落到默认外观，分片照样能解开。

import { STYLE, type StyleId } from '../core/styles.ts'
import { createFragmentSplitView, createFragmentView, FRAGMENT_SPLIT } from './fragment.ts'
import { createPlainView, PLAIN_SPLIT } from './plain.ts'
import type { RestoreView, SplitPolicy, SplitView, StyleModule } from './types.ts'

const MODULES = new Map<StyleId, StyleModule>([
  [STYLE.PLAIN, { id: STYLE.PLAIN, split: PLAIN_SPLIT, view: createPlainView }],
  [
    STYLE.FRAGMENT,
    {
      id: STYLE.FRAGMENT,
      split: FRAGMENT_SPLIT,
      view: createFragmentView,
      splitView: createFragmentSplitView,
    },
  ],
])

function moduleOf(id: StyleId): StyleModule {
  return MODULES.get(id) ?? MODULES.get(STYLE.PLAIN)!
}

/** 拆分端规矩；占号未实现的外观按默认处理（不可选，走不到这里） */
export function splitPolicy(id: StyleId): SplitPolicy {
  return moduleOf(id).split ?? PLAIN_SPLIT
}

/** 恢复端渲染器（每次调用都拿到一份干净的状态） */
export function createRestoreView(id: StyleId): RestoreView {
  return moduleOf(id).view()
}

/** 拆分端主视觉；null = 这套外观没有自己的插入界面，用主流程那套层列表 */
export function createSplitView(id: StyleId): SplitView | null {
  return moduleOf(id).splitView?.() ?? null
}
