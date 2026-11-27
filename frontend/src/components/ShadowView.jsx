import { useCallback, useState } from 'react'
import { api } from '../api.js'
import NetworkMap from './NetworkMap.jsx'

const nameOf = (network, id) => network.assets.find((a) => a.id === id)?.label || id
const countAr = (n) => (n === 1 ? 'نقطة واحدة' : n === 2 ? 'نقطتين' : `${n} نقاط`)

export default function ShadowView({ network, analysis, onChange }) {
  const [selected, setSelected] = useState(0)
  const [busy, setBusy] = useState(false)
  const [edgeInfo, setEdgeInfo] = useState(null)
  const [toast, setToast] = useState(null)

  const showToast = (t) => {
    setToast(t)
    setTimeout(() => setToast(null), 4200)
  }

  const path = analysis.paths[selected] || null

  const applyFix = async (edgeId) => {
    setBusy(true)
    const before = { risk: analysis.risk_current, paths: analysis.paths_total }
    const res = await api.fix(edgeId)
    setSelected(0)
    setEdgeInfo(null)
    await onChange()
    setBusy(false)
    const after = res?.analysis || res || {}
    const risk = after.risk_current ?? before.risk
    const paths = after.paths_total ?? before.paths
    showToast({
      ok: true,
      title: `تم تطبيق الإصلاح ${edgeId}`,
      body: `قُطع ${Math.max(0, before.paths - paths)} مسار · الخطر من ${before.risk} إلى ${risk}`,
    })
  }

  const reset = async () => {
    setBusy(true)
    await api.reset()
    setSelected(0)
    await onChange()
    setBusy(false)
    showToast({ ok: false, title: 'رجعت الشبكة لحالتها الأصلية', body: 'كل الثغرات مفتوحة من جديد' })
  }

  const onSelectEdge = useCallback(
    (id) => setEdgeInfo(network.edges.find((e) => e.id === id) || null),
    [network],
  )

  return (
    <div className="shadow-grid">
      {toast && (
        <div className={`toast ${toast.ok ? 'ok' : 'warn'}`} role="status">
          <i className={toast.ok ? 'lamp ok' : 'lamp'} />
          <div>
            <b>{toast.title}</b>
            <p>{toast.body}</p>
          </div>
        </div>
      )}
      <section className={`panel map-panel ${busy ? 'scanning' : ''}`}>
        <div className="panel-head">
          <h2>خريطة الشبكة</h2>
          <span className="muted">{analysis.paths_total} مسار هجوم محتمل</span>
        </div>
        <NetworkMap network={network} analysis={analysis} selectedPath={path} onSelectEdge={onSelectEdge} />
        {edgeInfo && (
          <div className="edge-info">
            <b>
              {nameOf(network, edgeInfo.from)} ← {nameOf(network, edgeInfo.to)}
            </b>
            <p>{edgeInfo.label}</p>
            <p className="muted">
              {edgeInfo.mitre} · الصعوبة {edgeInfo.difficulty}
            </p>
            {!edgeInfo.fixed && !analysis.fixed_edges.includes(edgeInfo.id) && (
              <button disabled={busy} onClick={() => applyFix(edgeInfo.id)}>
                إصلاح: {edgeInfo.fix}
              </button>
            )}
          </div>
        )}
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>أخطر المسارات</h2>
        </div>
        {analysis.paths.length === 0 ? (
          <div className="empty good">ما فيه أي مسار يوصل للأصول الحرجة 🎉</div>
        ) : (
          <ol className="paths" key={analysis.paths_total}>
            {analysis.paths.map((p, i) => (
              <li key={i} className={i === selected ? 'active' : ''} onClick={() => setSelected(i)}>
                <div className="path-top">
                  <span className="prob">{Math.round(p.probability * 100)}٪</span>
                  <span>{p.entry_vector}</span>
                  <span className="muted">· {p.hops} خطوات</span>
                </div>
                <div className="chain">
                  {p.nodes.map((n, j) => (
                    <span key={n}>
                      {j > 0 && <em>←</em>}
                      {nameOf(network, n)}
                    </span>
                  ))}
                </div>
              </li>
            ))}
          </ol>
        )}
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>أهم الإصلاحات</h2>
          {analysis.fixed_edges.length > 0 && (
            <button className="ghost" disabled={busy} onClick={reset}>
              إرجاع الشبكة
            </button>
          )}
        </div>
        {analysis.min_cut_edges.length > 0 && (
          <p className="hint">
            إصلاح {countAr(analysis.min_cut_edges.length)} فقط يقطع <b>كل</b> المسارات: {analysis.min_cut_edges.join('، ')}
          </p>
        )}
        <ul className="recs" key={analysis.fixed_edges.join('-') || 'none'}>
          {analysis.recommendations.map((r) => (
            <li key={r.edge_id}>
              <div className="rec-head">
                <b>{r.fix}</b>
                {r.risk_reduction_pct > 0 ? (
                  <span className="cut">−{r.risk_reduction_pct}٪</span>
                ) : (
                  <span className="muted">يقطع مسار بديل</span>
                )}
              </div>
              <p className="muted">
                {nameOf(network, r.from)} ← {nameOf(network, r.to)}: {r.issue}
              </p>
              <div className="rec-foot">
                <span className="muted">يقطع {r.paths_blocked} مسار · {r.mitre}</span>
                <button disabled={busy} onClick={() => applyFix(r.edge_id)}>
                  طبّق الإصلاح
                </button>
              </div>
            </li>
          ))}
        </ul>
      </section>
    </div>
  )
}
