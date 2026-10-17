import './style.css'
import { SMCF, SMPK, tlvBuild, tlvParse, u64beBytes, beBytesToU64 } from './core/tlv.ts'
import { IV_LEN, KEY_LEN, aesDecrypt, aesEncrypt, randomBytes, sha256 } from './core/crypto.ts'
import { shamirSplit, shamirCombine } from './core/shamir.ts'
import { checkConsistency, encodeShare, parseShares, type ShareEntry } from './core/format.ts'
import { otsStamp, parseOts, verifyAnchorOnline, type OtsParse } from './core/ots.ts'
import { toHex } from './core/b64.ts'

// ===== 工具 =====

const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T

function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`
  return `${(n / 1024 ** 3).toFixed(2)} GB`
}

function download(name: string, data: Uint8Array): void {
  const url = URL.createObjectURL(new Blob([data]))
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 3000)
}

async function copyText(text: string, btn: HTMLButtonElement): Promise<void> {
  try {
    await navigator.clipboard.writeText(text)
  } catch {
    const ta = document.createElement('textarea')
    ta.value = text
    document.body.appendChild(ta)
    ta.select()
    document.execCommand('copy')
    ta.remove()
  }
  const old = btn.textContent
  btn.textContent = '已复制'
  setTimeout(() => (btn.textContent = old), 1200)
}

function baseName(name: string): string {
  const i = name.lastIndexOf('.')
  return i > 0 ? name.slice(0, i) : name
}

// ===== 主题 =====

const root = document.documentElement
$<HTMLButtonElement>('themeToggle').addEventListener('click', () => {
  const cur = root.dataset.theme === 'dark' ? 'dark' : 'light'
  const next = cur === 'dark' ? 'light' : 'dark'
  root.dataset.theme = next
  try { localStorage.setItem('shamir-theme', next) } catch { /* ignore */ }
})

// ===== Tab 切换 =====

for (const tab of document.querySelectorAll<HTMLButtonElement>('.tab')) {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((t) => t.classList.remove('is-active'))
    tab.classList.add('is-active')
    const v = tab.dataset.view!
    $('view-split').hidden = v !== 'split'
    $('view-restore').hidden = v !== 'restore'
  })
}

// ===== 拆分 =====

let splitFile: File | null = null

function bindDrop(dropId: string, textId: string, onFile: (f: File) => void): HTMLInputElement {
  const drop = $(dropId)
  const text = $(textId)
  const input = document.createElement('input')
  input.type = 'file'
  input.hidden = true
  drop.addEventListener('click', () => input.click())
  drop.addEventListener('keydown', (e) => e.key === 'Enter' && input.click())
  input.addEventListener('change', () => input.files![0] && onFile(input.files![0]))
  for (const ev of ['dragover', 'dragenter'] as const)
    drop.addEventListener(ev, (e) => {
      e.preventDefault()
      drop.classList.add('is-drag')
    })
  for (const ev of ['dragleave', 'drop'] as const)
    drop.addEventListener(ev, () => drop.classList.remove('is-drag'))
  drop.addEventListener('drop', (e) => {
    e.preventDefault()
    const f = e.dataTransfer?.files?.[0]
    if (f) onFile(f)
  })
  text.textContent = text.textContent // noop，保持结构
  return input
}

function showSplitFile(f: File): void {
  splitFile = f
  const drop = $('dropSplit')
  drop.classList.add('has-file')
  $('dropSplitText').textContent = `📄 ${f.name} · ${fmtSize(f.size)}${f.type ? ` · ${f.type}` : ''}`
  refreshSplitBtn()
}

const fileSplitInput = bindDrop('dropSplit', 'dropSplitText', showSplitFile)
$('dropSplit').after(fileSplitInput)

const inK = $<HTMLInputElement>('inK')
const inN = $<HTMLInputElement>('inN')

function readKn(): { k: number; n: number } | null {
  const k = Math.round(Number(inK.value))
  const n = Math.round(Number(inN.value))
  if (!Number.isFinite(k) || !Number.isFinite(n) || k < 2 || n < 2 || n > 255 || k > n) return null
  return { k, n }
}

function refreshSplitBtn(): void {
  $<HTMLButtonElement>('btnSplit').disabled = !splitFile || !readKn()
}

for (const el of [inK, inN])
  el.addEventListener('input', () => {
    const v = readKn()
    if (v) {
      if (Number(inN.value) < Number(inK.value)) inK.value = inN.value
      if (Number(inK.value) < 2) inK.value = '2'
      if (Number(inN.value) > 255) inN.value = '255'
    }
    refreshSplitBtn()
  })

interface SplitResult {
  ctName: string
  ciphertext: Uint8Array
  shareTexts: string[]
}

let splitResult: SplitResult | null = null

$<HTMLButtonElement>('btnSplit').addEventListener('click', async () => {
  const err = $('splitError')
  const warn = $('splitWarn')
  err.hidden = warn.hidden = true
  const f = splitFile
  const kn = readKn()
  if (!f || !kn) return
  const { k, n } = kn
  try {
    const fileBytes = new Uint8Array(await f.arrayBuffer())
    const fileHash = await sha256(fileBytes)

    // OTS 存证（唯一可能联网的一步，失败不阻断主流程）
    let ots: Uint8Array | null = null
    if ($<HTMLInputElement>('otsCheck').checked) {
      try {
        ots = await otsStamp(fileHash)
      } catch (e) {
        warn.hidden = false
        warn.textContent = `OTS 存证失败（${e instanceof Error ? e.message : e}），已跳过，不影响分片。可稍后重试。`
      }
    }

    const key = randomBytes(KEY_LEN)
    const iv = randomBytes(IV_LEN)

    // 内层载荷包：原数据 + 元数据 + 存证，整体进密文
    const innerChunks = [
      { tag: SMPK.TAG.FILENAME, value: new TextEncoder().encode(f.name) },
      { tag: SMPK.TAG.CREATED_AT, value: u64beBytes(Date.now()) },
      { tag: SMPK.TAG.SHA256, value: fileHash },
      ...(f.type ? [{ tag: SMPK.TAG.MIME, value: new TextEncoder().encode(f.type) }] : []),
      ...(ots ? [{ tag: SMPK.TAG.OTS_RECEIPT, value: ots }] : []),
      { tag: SMPK.TAG.DATA, value: fileBytes },
    ]
    const inner = tlvBuild(SMPK.MAGIC, SMPK.VERSION, innerChunks, { lastTag: SMPK.TAG.DATA })
    const ciphertext = await aesEncrypt(key, iv, inner)

    const outer = tlvBuild(
      SMCF.MAGIC,
      SMCF.VERSION,
      [
        { tag: SMCF.TAG.FILENAME, value: new TextEncoder().encode(f.name) },
        { tag: SMCF.TAG.K, value: new Uint8Array([k]) },
        { tag: SMCF.TAG.N, value: new Uint8Array([n]) },
        { tag: SMCF.TAG.IV, value: iv },
        { tag: SMCF.TAG.CIPHERTEXT, value: ciphertext },
      ],
      { lastTag: SMCF.LAST_TAG },
    )

    const shares = await shamirSplit(key, n, k)
    const shareTexts = shares.map((s) => encodeShare(k, n, s))

    splitResult = { ctName: `${baseName(f.name)}.smcf`, ciphertext: outer, shareTexts }
    renderSplitResult(f, k, n, ots)
  } catch (e) {
    err.hidden = false
    err.textContent = `拆分失败：${e instanceof Error ? e.message : String(e)}`
  }
})

function renderSplitResult(f: File, k: number, n: number, ots: Uint8Array | null): void {
  const card = $('resultCard')
  card.hidden = false
  $('ctName').textContent = splitResult!.ctName
  $('ctMeta').textContent = `${fmtSize(f.size)} → ${fmtSize(splitResult!.ciphertext.length)} · k=${k}/n=${n}`

  const box = $('otsBox')
  if (ots) {
    box.hidden = false
    box.innerHTML = ''
    const line = document.createElement('div')
    line.className = 'ots-line'
    line.innerHTML = `<span class="ots-status pending">OTS 存证已提交</span><span>哈希已发送至公共日历，比特币锚定约需数小时；回执已藏进密文，恢复时自动显示。</span>`
    box.appendChild(line)
  } else {
    box.hidden = true
  }

  const list = $('shareList')
  list.innerHTML = ''
  splitResult!.shareTexts.forEach((text, i) => {
    const row = document.createElement('div')
    row.className = 'share-row'
    const idx = document.createElement('div')
    idx.className = 'share-idx'
    idx.textContent = String(i + 1)
    const span = document.createElement('div')
    span.className = 'share-text'
    span.textContent = text
    const bCopy = document.createElement('button')
    bCopy.className = 'btn share-btn'
    bCopy.type = 'button'
    bCopy.textContent = '复制'
    bCopy.addEventListener('click', () => copyText(text, bCopy))
    const bDl = document.createElement('button')
    bDl.className = 'btn share-btn'
    bDl.type = 'button'
    bDl.textContent = '下载'
    bDl.addEventListener('click', () => download(`${baseName(f.name)}_第${i + 1}片.txt`, new TextEncoder().encode(text + '\n')))
    row.append(idx, span, bCopy, bDl)
    list.appendChild(row)
  })

  $<HTMLButtonElement>('btnDlCt').onclick = () =>
    download(splitResult!.ctName, splitResult!.ciphertext)

  $<HTMLButtonElement>('btnDlAll').onclick = async () => {
    download(splitResult!.ctName, splitResult!.ciphertext)
    for (let i = 0; i < splitResult!.shareTexts.length; i++) {
      await new Promise((r) => setTimeout(r, 250))
      download(`${baseName(f.name)}_第${i + 1}片.txt`, new TextEncoder().encode(splitResult!.shareTexts[i]! + '\n'))
    }
  }

  card.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
}

// ===== 恢复 =====

let ctFile: File | null = null
let restoreOk: { name: string; data: Uint8Array } | null = null

function readRestoredShares(): ShareEntry[] {
  const shares = parseShares($<HTMLTextAreaElement>('shareText').value)
  const { k, n } = checkConsistency(shares)
  $('shareStatus').textContent = `已识别 ${shares.length} 片（k=${k}，n=${n}${shares.length >= k ? '，够用 ✓' : `，还差 ${k - shares.length} 片`}`
  return shares
}

$<HTMLTextAreaElement>('shareText').addEventListener('input', refreshRestoreBtn)

$<HTMLInputElement>('shareFiles').addEventListener('change', async (e) => {
  const files = (e.target as HTMLInputElement).files
  if (!files) return
  const parts: string[] = [$<HTMLTextAreaElement>('shareText').value]
  for (const f of files) parts.push(await f.text())
  $<HTMLTextAreaElement>('shareText').value = parts.join('\n')
  refreshRestoreBtn()
  ;(e.target as HTMLInputElement).value = ''
})

function showCtFile(f: File): void {
  ctFile = f
  const drop = $('dropCt')
  drop.classList.add('has-file')
  $('dropCtText').textContent = `🔐 ${f.name} · ${fmtSize(f.size)}`
  refreshRestoreBtn()
}

const fileCtInput = bindDrop('dropCt', 'dropCtText', showCtFile)
$('dropCt').after(fileCtInput)

function refreshRestoreBtn(): void {
  const hasShares = $<HTMLTextAreaElement>('shareText').value.includes('SHAMIR1:')
  $<HTMLButtonElement>('btnRestore').disabled = !(hasShares && ctFile)
  if (!hasShares) $('shareStatus').textContent = ''
}

$<HTMLButtonElement>('btnRestore').addEventListener('click', async () => {
  const err = $('restoreError')
  err.hidden = true
  try {
    const shares = parseShares($<HTMLTextAreaElement>('shareText').value)

    const ctBytes = new Uint8Array(await ctFile!.arrayBuffer())
    const outer = tlvParse(SMCF.MAGIC, ctBytes)
    if (outer.version !== SMCF.VERSION) throw new Error(`不支持的密文版本 v${outer.version}`)
    const iv = outer.chunks.get(SMCF.TAG.IV)
    const ct = outer.chunks.get(SMCF.TAG.CIPHERTEXT)
    if (!iv || iv.length !== IV_LEN) throw new Error('密文缺少 IV 或长度不对')
    if (!ct) throw new Error('密文缺少 CIPHERTEXT 块')
    const ctK = outer.chunks.get(SMCF.TAG.K)?.[0]
    const ctN = outer.chunks.get(SMCF.TAG.N)?.[0]
    checkConsistency(shares, ctK, ctN)

    // 交叉校验通过 → combine → 解密
    const key = await shamirCombine(shares.slice(0, shares[0]!.k).map((s) => s.payload))
    const inner = await aesDecrypt(key, iv, ct)
    const pack = tlvParse(SMPK.MAGIC, inner)
    if (pack.version !== SMPK.VERSION) throw new Error(`不支持的载荷包版本 v${pack.version}`)
    const data = pack.chunks.get(SMPK.TAG.DATA)
    if (!data) throw new Error('载荷包缺少 DATA 块')
    const nameBytes = pack.chunks.get(SMPK.TAG.FILENAME)
    const name = nameBytes ? new TextDecoder().decode(nameBytes) : 'restored.bin'

    // SHA-256 完整性
    const expect = pack.chunks.get(SMPK.TAG.SHA256)
    const actual = await sha256(data)
    const hashOk = expect ? toHex(expect) === toHex(actual) : null

    restoreOk = { name, data }
    await renderRestore(pack, data, name, hashOk, actual)
  } catch (e) {
    err.hidden = false
    err.textContent = `恢复失败：${e instanceof Error ? e.message : String(e)}`
  }
})

async function renderRestore(
  pack: { chunks: Map<number, Uint8Array> },
  data: Uint8Array,
  name: string,
  hashOk: boolean | null,
  actualHash: Uint8Array,
): Promise<void> {
  const card = $('restoreCard')
  card.hidden = false
  $('restName').textContent = name
  const createdAtBytes = pack.chunks.get(SMPK.TAG.CREATED_AT)
  const createdAt = createdAtBytes ? beBytesToU64(createdAtBytes) : null
  $('restMeta').textContent = `${fmtSize(data.length)}${createdAt ? ` · ${new Date(createdAt).toLocaleString()}` : ''}`
  $('hashLine').textContent = `SHA-256：${toHex(actualHash)}${hashOk === false ? '\n⚠️ 与打包时记录的哈希不一致，文件可能被篡改！' : ''}`

  // OTS：回执在内层，解密后才可见
  const otsBytes = pack.chunks.get(SMPK.TAG.OTS_RECEIPT)
  const box = $('otsRestBox')
  if (otsBytes) {
    box.hidden = false
    box.innerHTML = ''
    try {
      const ots = await parseOts(otsBytes)
      const hashMatch = toHex(ots.fileDigest) === toHex(actualHash)
      const anchored = ots.anchors.length > 0
      const status = document.createElement('div')
      status.className = 'ots-line'
      status.innerHTML =
        `<span class="ots-status ${anchored ? 'ok' : 'pending'}">` +
        (anchored ? `OTS 已锚定 Bitcoin 区块 #${ots.anchors.map((a) => a.height).join(' / #')}` : 'OTS 待锚定（已提交日历）') +
        '</span>' +
        `<span>${hashMatch ? '回执摘要与本文件一致 ✓' : '⚠️ 回执摘要与本文件不一致！'}</span>`
      box.appendChild(status)

      if (anchored) {
        const btn = document.createElement('button')
        btn.className = 'btn btn-ghost'
        btn.type = 'button'
        btn.textContent = '在线完整验证（需联网）'
        btn.addEventListener('click', async () => {
          btn.disabled = true
          btn.textContent = '验证中…'
          const line = document.createElement('div')
          line.className = 'ots-line'
          try {
            const results = await Promise.all(ots.anchors.map(verifyAnchorOnline))
            const ok = results.some((r) => r.ok)
            line.innerHTML =
              `<span class="ots-status ${ok ? 'ok' : 'pending'}">${ok ? '✓ 区块链验证通过' : '✗ 验证未通过'}</span>` +
              results.map((r) => `<span>#${r.height} @ ${new Date(r.blockTime).toLocaleString()}：${r.detail}</span>`).join('')
          } catch (e) {
            line.innerHTML = `<span class="ots-status pending">在线验证失败：${e instanceof Error ? e.message : e}</span>`
          }
          box.appendChild(line)
          btn.hidden = true
        })
        box.appendChild(btn)
      }
      if (!ots.complete) {
        const note = document.createElement('div')
        note.className = 'ots-line'
        note.innerHTML = `<span class="ots-status pending">回执含未识别结构，以上仅部分解析；建议用官方验证器复核。</span>`
        box.appendChild(note)
      }
    } catch (e) {
      box.innerHTML = `<div class="ots-line"><span class="ots-status pending">OTS 回执解析失败：${e instanceof Error ? e.message : e}</span></div>`
    }
  } else {
    box.hidden = true
  }

  $<HTMLButtonElement>('btnDlRest').onclick = () => restoreOk && download(restoreOk.name, restoreOk.data)
  card.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
}
