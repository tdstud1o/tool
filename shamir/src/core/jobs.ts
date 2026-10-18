// Shamir 计算的 Worker 封装：主线程只负责 UI，拆分/恢复全部丢进后台线程。
//
// 为什么必须这样：n=100000 / k=10000 时拆分要 5 分钟以上（n × (k−1) 次 256 位
// 模乘），恢复 k=10000 要 1 亿次模乘、约 1 分钟。同步跑在主线程等于页面假死。
//
// Worker 用 `?worker&inline` 打包：Vite 把它编译成 base64 blob，再由浏览器
// new Worker(blobURL) 起来。这样单 HTML 产物不会被拆成两个文件，离线可用性不变。

import JobWorker from './jobs.worker.ts?worker&inline'
import type { JobReply } from './job-protocol.ts'

export type JobProgress = (done: number, total: number) => void

interface Job {
  id: number
  resolve: (value: unknown) => void
  reject: (err: Error) => void
  onProgress?: JobProgress
}

let worker: Worker | null = null
let seq = 0
/** UI 一次只跑一个计算任务；同时发起第二个会被直接拒绝而不是排队 */
let current: Job | null = null

function getWorker(): Worker {
  if (worker) return worker
  const w = new JobWorker()
  w.onmessage = (e: MessageEvent<JobReply>) => {
    const msg = e.data
    const job = current
    if (!job || msg.id !== job.id) return
    if (msg.type === 'progress') {
      job.onProgress?.(msg.done, msg.total)
      return
    }
    current = null
    if (msg.type === 'error') job.reject(new Error(msg.message))
    else job.resolve(msg)
  }
  w.onerror = (e) => {
    const job = current
    current = null
    job?.reject(new Error(`后台线程出错：${e.message || '未知错误'}`))
  }
  worker = w
  return w
}

function run<T>(msg: object, onProgress?: JobProgress): Promise<T> {
  if (current) return Promise.reject(new Error('已有计算任务在进行，请等它结束'))
  const id = ++seq
  return new Promise<T>((resolve, reject) => {
    current = { id, resolve: resolve as (v: unknown) => void, reject, onProgress }
    getWorker().postMessage({ ...msg, id })
  })
}

/** 在后台线程多层拆分；返回按人排列的 buffer（每组 32 字节的 y 是连续切片） */
export async function splitInWorker(
  secrets: (Uint8Array | null)[],
  n: number,
  ks: number[],
  onProgress?: JobProgress,
): Promise<{
  buffer: ArrayBuffer
  shareLen: number
  count: number
  m: number
  xs: number[]
  wide: boolean
}> {
  const { buffer, shareLen, m, xs, wide } = await run<{
    buffer: ArrayBuffer
    shareLen: number
    m: number
    xs: number[]
    wide: boolean
  }>({ type: 'split', secrets, n, ks }, onProgress)
  return { buffer, shareLen, count: buffer.byteLength / shareLen, m, xs, wide }
}

/** 在后台线程恢复；xs 与 shares 一一对应 */
export async function combineInWorker(
  shares: Uint8Array[],
  xs: number[],
  onProgress?: JobProgress,
): Promise<Uint8Array> {
  const { secret } = await run<{ secret: ArrayBuffer }>({ type: 'combine', shares, xs }, onProgress)
  return new Uint8Array(secret)
}
