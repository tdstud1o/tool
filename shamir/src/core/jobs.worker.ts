/// <reference lib="webworker" />
// Shamir 计算线程：拆分与恢复都在这里跑，避免主线程被几秒到几分钟的
// 同步 BigInt 运算冻结。这个文件只会被打包进 blob worker，不参与主 bundle。

import type { JobReply, JobRequest } from './job-protocol.ts'
import { FIELD_LEN } from './gfp.ts'
import { coordWidth, shamirCombine, shamirSplit } from './shamir.ts'

const ctx = self as unknown as DedicatedWorkerGlobalScope

function progress(id: number, phase: 'split' | 'combine', done: number, total: number): void {
  ctx.postMessage({ id, type: 'progress', phase, done, total } satisfies JobReply)
}

ctx.onmessage = async (e: MessageEvent<JobRequest>) => {
  const msg = e.data
  try {
    if (msg.type === 'split') {
      const shares = await shamirSplit(msg.secret, msg.n, msg.k, (done, total) =>
        progress(msg.id, 'split', done, total),
      )
      // 定长紧密打包：n 片 → 一个 transferable buffer，避免十万次 postMessage
      const shareLen = FIELD_LEN + coordWidth(msg.n)
      const buffer = new ArrayBuffer(shareLen * shares.length)
      const view = new Uint8Array(buffer)
      for (let i = 0; i < shares.length; i++) view.set(shares[i]!, i * shareLen)
      ctx.postMessage({ id: msg.id, type: 'split-done', buffer, shareLen } satisfies JobReply, [buffer])
    } else {
      const secret = await shamirCombine(msg.shares, (done, total) =>
        progress(msg.id, 'combine', done, total),
      )
      const buffer = secret.buffer.slice(secret.byteOffset, secret.byteOffset + secret.byteLength)
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
