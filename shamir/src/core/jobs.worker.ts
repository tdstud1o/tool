/// <reference lib="webworker" />
// Shamir 计算线程：拆分与恢复都在这里跑，避免主线程被几秒到几分钟的
// 同步 BigInt 运算冻结。这个文件只会被打包进 blob worker，不参与主 bundle。

import type { JobReply, JobRequest } from './job-protocol.ts'
import { shamirCombine, shamirSplitMulti } from './shamir.ts'

const ctx = self as unknown as DedicatedWorkerGlobalScope

function progress(id: number, phase: 'split' | 'combine', done: number, total: number): void {
  ctx.postMessage({ id, type: 'progress', phase, done, total } satisfies JobReply)
}

ctx.onmessage = async (e: MessageEvent<JobRequest>) => {
  const msg = e.data
  try {
    if (msg.type === 'split') {
      const { buffer, shareLen, m, xs } = await shamirSplitMulti(msg.secrets, msg.n, msg.ks, (done, total) =>
        progress(msg.id, 'split', done, total),
      )
      // 整个结果一次 transfer，避免十万次 postMessage
      const ab = buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength) as ArrayBuffer
      ctx.postMessage({ id: msg.id, type: 'split-done', buffer: ab, shareLen, m, xs } satisfies JobReply, [ab])
    } else {
      const secret = await shamirCombine(msg.shares, msg.xs, (done, total) =>
        progress(msg.id, 'combine', done, total),
      )
      const buffer = secret.buffer.slice(secret.byteOffset, secret.byteOffset + secret.byteLength) as ArrayBuffer
      ctx.postMessage({ id: msg.id, type: 'combine-done', secret: buffer } satisfies JobReply, [buffer])
    }
  } catch (err) {
    ctx.postMessage({
      id: msg.id,
      type: 'error',
      message: err instanceof Error ? err.message : String(err),
    } satisfies JobReply)
  }
}
