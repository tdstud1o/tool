// 外观（style）的契约：一个外观 = 一份拆分规矩 + 一个恢复端渲染器。
//
// main.ts 只认识这两个接口，不认识"碎片"/"星座"这些具体长什么样。
// 加新外观 = 在 src/appearance/ 里加一个文件 + 在 index.ts 里注册一行，
// 不需要动主流程里任何一处 if。

/** 解开一层后，交给外观的全部素材 */
export interface LayerInfo {
  /** 第几层（从 1 起） */
  index: number
  name: string
  data: Uint8Array
  mime: string
  createdAt: number | null
  /** SHA-256 是否与打包装进去时一致（null = 没有记录） */
  hashOk: boolean | null
  hash: Uint8Array
  ots: Uint8Array | null
}

/**
 * 「补充分片」的两个动作。外观自己决定怎么触发（碎片是点空格子 / 拖到拼图上），
 * 但开文件选择器和导入文件这两件事必须走主流程——那才认识密文与分片格式。
 */
export interface ShareIntent {
  /** 打开系统的分片文件选择器 */
  pick(): void
  /** 把拖进来的文件交给主流程（自动分辨密文 / 分片文本 / zip） */
  drop(files: File[]): void
  /** 此刻能不能收（恢复运行中为 false） */
  allowed(): boolean
}

/**
 * 恢复端的呈现契约。
 * main.ts 按顺序喂三类事件：还差片（lock）、假层（fake）、解开一层（unlock）。
 */
export interface RestoreView {
  /** 外观自己的主视觉，挂到恢复列表里 */
  readonly root: HTMLElement
  /**
   * 可选：这个外观想自己接管「补充分片」的入口。
   * 没实现 = 沿用主流程那套「② 导入分片」的列表与输入框。
   */
  attachShare?(intent: ShareIntent): void
  /** 这一层还差片。total 非 null = 密文自己声明了总片数 */
  lock(index: number, k: number, have: number, total: number | null): void
  /** 这一层是假层（密钥对不上密文） */
  fake(index: number, k: number): void
  /** 解开一层；返回"挂 OTS 回执"的容器 */
  unlock(layer: LayerInfo): HTMLElement
}

/** 拆分端的规矩：能收什么、能收几层、文案怎么说 */
export interface SplitPolicy {
  /** 文件选择框的 accept（'' = 不限） */
  accept: string
  /** 拒绝时文案里的名词：「只收图片」/「只收表格」… */
  acceptLabel: string
  /** 层数上限（假层也占一格）；Infinity = 不限 */
  maxLayers: number
  accepts(file: File): boolean
  /** 拖放区 / 分半按钮上的文案 */
  dropText: string
}

export interface StyleModule {
  id: number
  /** 拆分端规矩；null = 占号未实现，不给选 */
  split: SplitPolicy | null
  /** 恢复端渲染器（必须是纯工厂：每次恢复都要一份干净的状态） */
  view(): RestoreView
  /**
   * 可选：拆分端的主视觉。没实现 = 用主流程那套"每层一行"的列表。
   * 碎片把它做成了和恢复端同一块拼图：那边是往外取图，这边是往里塞图。
   */
  splitView?(): SplitView
}

// ===== 拆分端（"插入"这一侧）的契约 =====
//
// 和恢复端对称：外观只负责"长什么样、点哪儿"，文件的收与弃、k 与 n、加密
// 全在主流程。所以两边能共用一块拼图，差别只在喂给它的事件。

/** 拆分端的一格 = 一层 = 一份密文的其中一片 */
export interface SplitCell {
  /** 第几层，从 1 起 */
  index: number
  name: string
  size: number
  /** 这一层要几片才能解开（碎片外观下由主流程按层序自动给，不给改） */
  k: number
  /** 假层：占一格，但没有文件 */
  fake: boolean
  file: File | null
}

/** 拆分端补素材的三个动作 */
export interface SplitIntent {
  /** 打开系统的文件选择器 */
  pick(): void
  /** 把拖进来的文件交给主流程（那里才认识"只收图片 / 最多几层"） */
  drop(files: File[]): void
  /** 撤掉第几个（0 起，按 layers 的顺序） */
  remove(index: number): void
  /** 此刻能不能收（拆分运行中为 false） */
  allowed(): boolean
}

export interface SplitView {
  readonly root: HTMLElement
  /** 层数据变了就重画（主流程是唯一的数据源） */
  render(cells: readonly SplitCell[]): void
  attach(intent: SplitIntent): void
}
