// OTS 回执的渲染：进度行 + 后台链上校对，原地更新。
//
// 外观模块只负责给出"回执该挂在哪个容器"，具体怎么画在这里；
// 这样换外观不用复制一遍 OTS 逻辑，OTS 逻辑也不用认识外观。

import {
  OtsNoCorsError,
  calendarHasCors,
  parseOts,
  upgradePending,
  verifyAnchorOnline,
} from '../core/ots.ts'
import { el } from './dom.ts'

type BitcoinAttestation = { kind: 'bitcoin'; height: number; digest: Uint8Array | null }
type PendingAttestation = { kind: 'pending'; uri: string; digest: Uint8Array | null }

export async function renderOtsInto(box: HTMLElement, otsBytes: Uint8Array, actualHash: Uint8Array): Promise<void> {
  box.hidden = false
  box.textContent = ''
  try {
    const ots = await parseOts(otsBytes, actualHash)
    const pending = ots.attestations.filter((a) => a.kind === 'pending') as PendingAttestation[]
    const anchors = ots.attestations.filter((a) => a.kind === 'bitcoin') as BitcoinAttestation[]

    const spinner = () => {
      const s = el('span', 'spinner')
      s.setAttribute('aria-hidden', 'true')
      return s
    }
    const status = el('div', 'ots-line')
    // 只有白名单里（实测带 CORS 头）的日历才值得发请求；否则请求发出去也读不到响应，
    // 纯粹白送一次外发。这类回执直接给"本地已校验、可交官方工具复核"的静态结论。
    const queryable = pending.filter((p) => calendarHasCors(p.uri))
    const hostOf = (uri: string) => {
      try {
        return new URL(uri).hostname
      } catch {
        return uri
      }
    }
    if (anchors.length > 0) {
      status.append(
        el('span', 'ots-status ok', `OTS 已锚定 Bitcoin 区块 #${anchors.map((a) => a.height).join(' / #')}`),
        spinner(),
        el('span', '', '正在比对区块链…'),
      )
    } else if (queryable.length > 0) {
      status.append(
        el('span', 'ots-status pending', 'OTS 待锚定'),
        spinner(),
        el('span', '', '拆分时已提交日历，正在后台查询最新状态…'),
      )
    } else if (pending.length > 0) {
      status.append(
        el('span', 'ots-status pending', 'OTS 待锚定'),
        el('span', '', `回执里的日历（${[...new Set(pending.map((p) => hostOf(p.uri)))].join('、')}）不允许浏览器跨域读取，因此没有做在线查询。回执本身已随密文一起存好，可用「下载 ots 文件」交给官方工具（ots verify）复核。`),
      )
    } else {
      status.append(el('span', 'ots-status pending', 'OTS 回执存在，但未识别出 attestation'))
    }
    box.append(status)

    // 没有可查的日历就直接收工，一次请求都不发
    if (pending.length > 0 && queryable.length === 0) {
      if (ots.degraded) box.append(el('div', 'hint', '回执里有暂不支持的 op/attestation，离线校验只走通了一部分。'))
      return
    }

    // 后台查询：完成后原地更新状态行（成功/失败都不打扰用户下载文件）
    void (async () => {
      try {
        let toVerify: BitcoinAttestation[] = anchors
        if (anchors.length === 0) {
          // 日历升级查询：只查白名单里的（外面已过滤掉不支持 CORS 的）
          const upgraded = await Promise.all(queryable.map((p) => upgradePending(p)))
          toVerify = upgraded.flatMap((u) =>
            u.attestations.filter((a) => a.kind === 'bitcoin'),
          ) as BitcoinAttestation[]
          if (toVerify.length === 0) {
            status.textContent = ''
            status.append(
              el('span', 'ots-status pending', 'OTS 待锚定'),
              el('span', '', `已查日历（${queryable.map((p) => p.uri).join('、')}）：尚未上链，比特币锚定通常需 1~3 小时，之后重新恢复本密文可自动再查。`),
            )
            return
          }
        }
        const results = await Promise.all(
          toVerify.map((a) => verifyAnchorOnline({ height: a.height, digest: a.digest })),
        )
        const ok = results.some((r) => r.ok)
        status.textContent = ''
        status.append(
          el('span', `ots-status ${ok ? 'ok' : 'pending'}`,
            ok ? '✓ OTS 存证有效（区块链验证通过）' : '⚠️ OTS 上链但验证未通过，请警惕文件来源'),
          ...results.map((r) =>
            el('span', '', `#${r.height} @ ${new Date(r.blockTime).toLocaleString()}：${r.detail}`),
          ),
        )
      } catch (e) {
        status.textContent = ''
        const noCors = e instanceof OtsNoCorsError
        status.append(
          el('span', 'ots-status pending', noCors
            ? 'OTS 待锚定（该日历不支持浏览器跨域读取，已跳过在线查询）'
            : `OTS 待锚定（后台查询失败：${e instanceof Error ? e.message : String(e)}）`),
          el('span', '', '可点「下载 ots 文件」交给官方工具（ots verify）复核，那条路径不受浏览器跨域限制。'),
        )
      }
    })()

    if (ots.degraded) {
      box.append(el('div', 'ots-line', el('span', 'ots-status pending', '回执含未识别结构，以上仅部分解析；建议用官方验证器复核。')))
    }
  } catch (e) {
    box.textContent = ''
    box.append(el('div', 'ots-line', el('span', 'ots-status pending', `OTS 回执解析失败：${e instanceof Error ? e.message : String(e)}`)))
  }
}
