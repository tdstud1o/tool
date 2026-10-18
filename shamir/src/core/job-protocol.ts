// 主线程 ↔ Worker 的消息协议。单独成文件，避免 worker 构造器被误引入。

/** 拆分：把 m 个槽位（密钥或诱饵）拆成 n 片，共用一套坐标 */
export interface SplitRequest {
  id: number
  type: 'split'
  /** null = 诱饵槽位：只写随机 y，没有对应密文层 */
  secrets: (Uint8Array | null)[]
  n: number
  /** 每个槽位的阈值，长度必须与 secrets 一致（诱饵位的值只作标签） */
  ks: number[]
}

/** 恢复：用 k 片还原一层密钥 */
export interface CombineRequest {
  id: number
  type: 'combine'
  shares: Uint8Array[]
  /** 与 shares 一一对应的坐标 */
  xs: number[]
}

export type JobRequest = SplitRequest | CombineRequest

export interface ProgressReply {
  id: number
  type: 'progress'
  phase: 'split' | 'combine'
  done: number
  total: number
}

/**
 * 拆分结果按人紧密排列，一次 transfer 回主线程：
 *   [y₀][y₁]…  每人 shareLen 字节，每组 32 字节连续切片
 * 坐标单独用 xs 回传，由主线程写进分片文本的前缀（一片只写一次）。
 */
export interface SplitDoneReply {
  id: number
  type: 'split-done'
  buffer: ArrayBuffer
  shareLen: number
  /** 组数 */
  m: number
  /** 每人一个坐标，顺序与 buffer 里的人员顺序一致 */
  xs: number[]
  /** 坐标是否按定宽 8 位写（组数 > 1 时为 true） */
  wide: boolean
}

export interface CombineDoneReply {
  id: number
  type: 'combine-done'
  secret: ArrayBuffer
}

export interface ErrorReply {
  id: number
  type: 'error'
  message: string
}

export type JobReply = ProgressReply | SplitDoneReply | CombineDoneReply | ErrorReply
