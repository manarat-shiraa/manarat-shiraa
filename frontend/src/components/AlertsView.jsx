import { useEffect, useMemo, useState } from 'react'
import { api, SEVERITY_AR, SOURCE_AR, timeAr } from '../api.js'

function Badge({ level }) {
  return <span className={`badge sev-${level}`}>{SEVERITY_AR[level]}</span>
}

export default function AlertsView({ alerts }) {
  const [selectedId, setSelectedId] = useState(alerts.find((a) => !a.duplicate_of)?.alert_id)
  const [detail, setDetail] = useState(null)
  const [hideFp, setHideFp] = useState(false)
  const [source, setSource] = useState('all')

  useEffect(() => {
    if (!selectedId) return
    setDetail(null)
    api.alert(selectedId).then(setDetail).catch(() => setDetail(null))
  }, [selectedId])

  // التكرارات ما تنعرض كصفوف، تظهر كعدد جنب التنبيه الأصلي
  const unique = alerts.filter((a) => !a.duplicate_of)
  const sources = useMemo(() => {
    const counts = {}
    unique.forEach((a) => (counts[a.source_type] = (counts[a.source_type] || 0) + 1))
    return counts
  }, [alerts])

  const rows = unique
    .filter((a) => (hideFp ? !a.likely_false_positive : true))
    .filter((a) => (source === 'all' ? true : a.source_type === source))

  const dupTotal = alerts.length - unique.length

  return (
    <div className="alerts-grid">
      <section className="panel">
        <div className="panel-head">
          <h2>التنبيهات مرتبة حسب الأولوية</h2>
          <label className="toggle">
            <input type="checkbox" checked={hideFp} onChange={(e) => setHideFp(e.target.checked)} />
            إخفاء الإنذارات الكاذبة
          </label>
        </div>

        <div className="filters">
          <button className={source === 'all' ? 'chip-btn active' : 'chip-btn'} onClick={() => setSource('all')}>
            الكل <span>{unique.length}</span>
          </button>
          {Object.entries(sources).map(([s, n]) => (
            <button key={s} className={source === s ? 'chip-btn active' : 'chip-btn'} onClick={() => setSource(s)}>
              {SOURCE_AR[s] || s} <span>{n}</span>
            </button>
          ))}
        </div>
        {dupTotal > 0 && (
          <p className="hint quiet">
            تم دمج {dupTotal === 1 ? 'تنبيه مكرر' : dupTotal === 2 ? 'تنبيهين مكررين' : `${dupTotal} تنبيهات مكررة`} مع أصلها، عشان ما تشتت المحلل.
          </p>
        )}

        <table className="alerts">
          <thead>
            <tr>
              <th>الخطورة</th>
              <th>التنبيه</th>
              <th>الجهاز</th>
              <th>الظل الرقمي</th>
              <th>الوقت</th>
            </tr>
          </thead>
          <tbody key={source + String(hideFp)}>
            {rows.map((a, i) => (
              <tr
                key={a.alert_id}
                style={{ '--i': Math.min(i, 14) }}
                className={`${a.alert_id === selectedId ? 'active' : ''} ${a.likely_false_positive ? 'fp' : ''}`}
                onClick={() => setSelectedId(a.alert_id)}
              >
                <td>
                  {a.escalated && (
                    <>
                      <span className="was">{SEVERITY_AR[a.base_severity]}</span>
                      <span className="arrow">←</span>
                    </>
                  )}
                  <Badge level={a.severity} />
                </td>
                <td>
                  <div>
                    {a.title_ar}
                    {a.duplicates > 0 && <span className="dup">×{a.duplicates + 1}</span>}
                  </div>
                  <small className="muted">
                    {SOURCE_AR[a.source_type] || a.source_type} · {a.category}
                    {a.exception_id && <span className="exc"> · استثناء {a.exception_id}</span>}
                  </small>
                </td>
                <td>{a.host_label}</td>
                <td>
                  {a.on_attack_path ? (
                    <span className="onpath">
                      {a.hops_to_crown_jewel === 0 ? 'أصل حرج' : `على مسار · ${a.hops_to_crown_jewel} خطوة`}
                    </span>
                  ) : (
                    <span className="muted">—</span>
                  )}
                </td>
                <td className="muted">{timeAr(a.timestamp)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="panel detail" key={detail?.alert_id || 'none'}>
        {!detail ? (
          <div className="empty">اختر تنبيه لعرض التحليل</div>
        ) : (
          <>
            <div className="panel-head">
              <h2>{detail.title_ar}</h2>
              <Badge level={detail.severity} />
            </div>
            <p className="muted">
              {detail.rule_name} · {detail.alert_id} · {detail.host_label} {detail.user && `· ${detail.user}`}
              {detail.incident_id && ` · ${detail.incident_id}`}
            </p>

            <h3>الشرح</h3>
            <p className="explain">{detail.explanation_ar}</p>
            <small className="muted">
              المصدر: {detail.explanation_source === 'template' ? 'قالب جاهز' : `نموذج ${detail.explanation_source}`}
            </small>

            {detail.reasons_ar.length > 0 && (
              <>
                <h3>ليش هذي الخطورة؟</h3>
                <ul className="reasons">
                  {detail.reasons_ar.map((r, i) => (
                    <li key={i}>{r}</li>
                  ))}
                </ul>
              </>
            )}

            {detail.mitre.length > 0 && (
              <>
                <h3>MITRE ATT&amp;CK</h3>
                <div className="chips">
                  {detail.mitre.map((t) => (
                    <span key={t.id} className="chip" title={t.name_en}>
                      {t.id} · {t.name_ar}
                    </span>
                  ))}
                </div>
              </>
            )}

            {detail.recommendations_ar.length > 0 && (
              <>
                <h3>التوصيات</h3>
                <ol className="todo">
                  {detail.recommendations_ar.map((r, i) => (
                    <li key={i}>{r}</li>
                  ))}
                </ol>
              </>
            )}

            <h3>الأدلة</h3>
            <pre className="raw">{detail.evidence.raw_log}</pre>
            {detail.intel.map((f) => (
              <p key={f.ip} className={f.malicious ? 'intel bad' : 'intel'}>
                {f.ip}: {f.note}
              </p>
            ))}
          </>
        )}
      </section>
    </div>
  )
}
