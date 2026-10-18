// 主线程 ↔ Worker 的消息协议。单独成文件，避免 worker 构造器被误引入。

/** 拆分：把 32 字节密钥拆成 n 片（任意 k 片可恢复） */
export interface SplitRequest {
  id: number
  type: 'split'
  secret: Uint8Array
  n: number
  k: number
}

/** 恢复：用 k 片还原密钥 */
export interface CombineRequest {
  id: number
  type: 'combine'
  shares: Uint8Array[]
}

export type JobRequest = SplitRequest | CombineRequest

export interface ProgressReply {
  id: number
  type: 'progress'
  phase: 'split' | 'combine'
  done: number
  total: number
}

/** 分片按定长紧密排列在一个 buffer 里，一次 transfer 回主线程 */
export interface SplitDoneReply {
  id: number
  type: 'split-done'
  buffer: ArrayBuffer
  shareLen: number
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
