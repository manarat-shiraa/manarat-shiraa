import { useEffect, useState } from 'react'
import { api, SEVERITY_AR, SOURCE_AR, timeAr } from '../api.js'

// إعادة تشغيل الهجوم خطوة خطوة: يمشي على الخط الزمني ويضيء كل جهاز لحظة اختراقه
function useReplay(length, ms = 750) {
  const [step, setStep] = useState(-1)
  const [playing, setPlaying] = useState(false)
  useEffect(() => {
    if (!playing) return
    if (step >= length - 1) {
      setPlaying(false)
      return
    }
    const t = setTimeout(() => setStep((s) => s + 1), step < 0 ? 150 : ms)
    return () => clearTimeout(t)
  }, [playing, step, length, ms])
  const play = () => {
    setStep(-1)
    setPlaying(true)
  }
  const stop = () => {
    setPlaying(false)
    setStep(-1)
  }
  return { step, playing, play, stop, active: playing || step >= 0 }
}

// تقرير التحقيق على الأسئلة الخمسة (من مقابلة المحللين)
function FiveW({ w }) {
  return (
    <div className="five-w">
      <div className="w-card">
        <h4>من؟</h4>
        <p>
          <b>المستخدمين:</b> {w.who.users.join('، ') || '—'}
        </p>
        <p>
          <b>الأجهزة:</b> {w.who.hosts.join('، ')}
        </p>
        {w.who.suspicious_ips.length > 0 && (
          <p className="bad">
            <b>عناوين مشبوهة:</b> {w.who.suspicious_ips.join('، ')}
          </p>
        )}
      </div>
      <div className="w-card">
        <h4>متى؟</h4>
        <p>
          من <b>{timeAr(w.when.start)}</b> إلى <b>{timeAr(w.when.end)}</b>
        </p>
        <p className="muted">المدة: {w.when.duration_minutes} دقيقة</p>
      </div>
      <div className="w-card">
        <h4>كيف؟</h4>
        {w.how.entry_vector && (
          <p>
            <b>البداية:</b> {w.how.entry_vector}
          </p>
        )}
        <p className="phases">
          {w.how.phases.map((p, i) => (
            <span key={p}>
              {i > 0 && <em>←</em>}
              {p}
            </span>
          ))}
        </p>
      </div>
      <div className="w-card">
        <h4>لماذا هي خطيرة؟</h4>
        <ul>
          {w.why.map((r, i) => (
            <li key={i}>{r}</li>
          ))}
        </ul>
      </div>
      <div className="w-card wide">
        <h4>ماذا فعل المهاجم؟</h4>
        <ol>
          {w.what.map((s, i) => (
            <li key={i}>{s}</li>
          ))}
        </ol>
        {w.next_step && <p className="next">الخطوة المتوقعة الجاية: {w.next_step}</p>}
      </div>
    </div>
  )
}

export default function IncidentsView({ incidents, network }) {
  const label = (id) => network?.assets.find((a) => a.id === id)?.label || id

  if (!incidents.length) return <div className="empty">ما فيه حوادث</div>

  return (
    <div className="incidents">
      {incidents.map((inc) => {
        const m = inc.matched_attack_path
        return <Incident key={inc.id} inc={inc} m={m} label={label} />
      })}
    </div>
  )
}

// ملخص الحادثة: بدون الذكاء الاصطناعي (قالب من القواعد) أو معه (نموذج يكتب القصة بالعربي)
function AiSummary({ inc }) {
  const [ai, setAi] = useState(false)
  const [res, setRes] = useState(null)
  const [busy, setBusy] = useState(false)

  const pick = (useAi) => {
    setAi(useAi)
    setRes(null)
    setBusy(true)
    api.incidentSummary(inc.id, useAi).then(setRes).catch(() => setRes(null)).finally(() => setBusy(false))
  }
  const text = res ? res.summary_ar : inc.summary_ar
  const src = res ? res.summary_source : inc.summary_source
  const note = busy
    ? ai
      ? 'جارٍ الشرح بالنموذج المحلي… قد يستغرق نحو 20 ثانية.'
      : 'جارٍ تجهيز الشرح…'
    : ai && src === 'template'
      ? 'النموذج غير متاح الآن، فعُرض الشرح الجاهز من القواعد.'
      : ai
        ? `كتبه النموذج (${src}) من حقائق القواعد والظل الرقمي، والقرار يبقى للقواعد.`
        : 'قالب من القواعد بدون ذكاء اصطناعي.'

  return (
    <div className="ai-summary">
      <div className="ai-toggle" role="group" aria-label="الشرح بالذكاء الاصطناعي">
        <button className={`chip-btn ${!ai ? 'active' : ''}`} onClick={() => !ai || pick(false)} disabled={busy}>
          بدون الذكاء الاصطناعي
        </button>
        <button className={`chip-btn ${ai ? 'active' : ''}`} onClick={() => ai || pick(true)} disabled={busy}>
          مع الذكاء الاصطناعي
        </button>
      </div>
      <p className="summary">{busy ? (ai ? 'جارٍ الشرح بالنموذج…' : '…') : text}</p>
      <small className="muted">{note}</small>
    </div>
  )
}

function Incident({ inc, m, label }) {
  const replay = useReplay(inc.timeline.length)
  const seen = replay.active ? inc.timeline.slice(0, replay.step + 1) : inc.timeline
  const reachedHosts = new Set(seen.map((t) => t.host))
  const progress = replay.active ? ((replay.step + 1) / inc.timeline.length) * 100 : 100
  const current = replay.active && replay.step >= 0 ? inc.timeline[replay.step] : null
  {
        return (
          <section className={`panel incident sev-border-${inc.severity}`}>
            <div className="panel-head">
              <h2>
                {inc.id} · {inc.alert_count} تنبيه
              </h2>
              <div className="head-actions">
                {inc.alert_count > 2 && (
                  <button className={replay.playing ? 'ghost' : 'replay-btn'} onClick={replay.playing ? replay.stop : replay.play}>
                    {replay.playing ? '■ إيقاف' : '▶ إعادة تشغيل الهجوم'}
                  </button>
                )}
                <span className={`badge sev-${inc.severity}`}>{SEVERITY_AR[inc.severity]}</span>
              </div>
            </div>
            {replay.active && (
              <div className="replay">
                <div className="replay-bar"><div style={{ width: `${progress}%` }} /></div>
                {current && (
                  <p className="replay-now" key={current.alert_id}>
                    <span className="t">{timeAr(current.time)}</span> <b>{current.host_label}</b>: {current.title_ar}
                    <small className="muted"> · {current.phase_ar || current.category}</small>
                  </p>
                )}
              </div>
            )}
            <AiSummary inc={inc} />

            {inc.alert_count > 1 && <FiveW w={inc.five_w} />}

            {m && (
              <div className="story-path">
                <h3>مسار الهجوم اللي توقعه الظل الرقمي</h3>
                <div className="chain big">
                  {m.nodes.map((n, j) => {
                    const hit = m.compromised_hosts.includes(n) && (!replay.active || reachedHosts.has(n))
                    const next = n === m.next_expected_host && !replay.playing
                    const lit = replay.active && current?.host === n
                    return (
                      <span key={n} className={`${hit ? 'hit' : next ? 'next' : ''} ${lit ? 'lit' : ''}`}>
                        {j > 0 && <em>←</em>}
                        {label(n)}
                        {next && ' (الخطوة الجاية)'}
                      </span>
                    )
                  })}
                </div>
              </div>
            )}

            {inc.alert_count > 1 && (
              <ol className="timeline">
                {inc.timeline.map((t, i) => (
                  <li
                    key={t.alert_id}
                    className={replay.active ? (i === replay.step ? 'now' : i < replay.step ? 'done' : 'todo') : ''}
                  >
                    <span className="t">{timeAr(t.time)}</span>
                    <span className={`dot sev-${t.severity}`} />
                    <span>
                      <b>{t.host_label}</b>: {t.title_ar}
                      {t.repeats > 0 && <span className="dup">×{t.repeats + 1}</span>}{' '}
                      <small className="muted">
                        ({t.phase_ar || t.category} · {SOURCE_AR[t.source_type] || t.source_type})
                      </small>
                    </span>
                  </li>
                ))}
              </ol>
            )}
            {inc.mitre.length > 0 && <p className="muted">MITRE: {inc.mitre.join('، ')}</p>}
          </section>
        )
  }
}
