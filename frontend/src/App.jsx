import { useCallback, useEffect, useState } from 'react'
import { api } from './api.js'
import ShadowView from './components/ShadowView.jsx'
import AlertsView from './components/AlertsView.jsx'
import IncidentsView from './components/IncidentsView.jsx'
import RiskMeter from './components/RiskMeter.jsx'
import CountUp from './components/CountUp.jsx'

const TABS = [
  { id: 'shadow', label: 'الظل الرقمي' },
  { id: 'alerts', label: 'التنبيهات' },
  { id: 'incidents', label: 'الحوادث' },
]

export default function App() {
  const [tab, setTab] = useState('shadow')
  const [network, setNetwork] = useState(null)
  const [analysis, setAnalysis] = useState(null)
  const [alerts, setAlerts] = useState([])
  const [incidents, setIncidents] = useState([])
  const [error, setError] = useState('')

  // بعد أي إصلاح في الظل الرقمي، نعيد تحميل كل شي لأن أولويات التنبيهات تتغير
  const refresh = useCallback(async () => {
    try {
      const [n, a, al, inc] = await Promise.all([api.network(), api.analysis(), api.alerts(), api.incidents()])
      setNetwork(n)
      setAnalysis(a)
      setAlerts(al)
      setIncidents(inc)
      setError('')
    } catch (e) {
      setError('تعذّر الاتصال بالباك إند. تأكد إنه شغّال على المنفذ 8000.')
    }
  }, [])

  useEffect(() => {
    refresh()
  }, [refresh])

  const unique = alerts.filter((a) => !a.duplicate_of)
  const criticalInc = incidents.find((i) => i.severity === 'critical')
  const counts = {
    critical: unique.filter((a) => a.severity === 'critical').length,
    total: alerts.length,
    fp: unique.filter((a) => a.likely_false_positive).length,
  }

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <img className="team-logo" src="/logo-icon.png" alt="شعار منارة شراع" />
          <div>
            <h1>مرصاد + الظل الرقمي</h1>
            <p>نشوف الهجوم قبل ما يصير، ونكشفه لو صار</p>
          </div>
        </div>
        <div className="stats">
          <div className="stat">
            <b><CountUp value={counts.total} /></b>
            <span>تنبيه</span>
          </div>
          <div className="stat crit">
            <b><CountUp value={counts.critical} /></b>
            <span>حرج</span>
          </div>
          <div className="stat quiet">
            <b><CountUp value={counts.fp} /></b>
            <span>إنذار كاذب</span>
          </div>
          {analysis && <RiskMeter value={analysis.risk_current} baseline={analysis.risk_baseline} />}
        </div>
      </header>

      <nav className="tabs">
        {TABS.map((t) => (
          <button key={t.id} className={tab === t.id ? 'active' : ''} onClick={() => setTab(t.id)}>
            {t.label}
            {t.id === 'incidents' && incidents.length > 0 && <span className="pill">{incidents.length}</span>}
          </button>
        ))}
      </nav>

      {criticalInc ? (
        <div className="alarm-bar">
          <i className="lamp" />
          <span>
            <b>حادثة حرجة {criticalInc.id}</b> · {criticalInc.alert_count} تنبيه مترابط على مسار هجوم
          </span>
          {tab !== 'incidents' && <button onClick={() => setTab('incidents')}>افتح الحادثة</button>}
        </div>
      ) : (
        incidents.length > 0 && (
          <div className="alarm-bar ok">
            <i className="lamp ok" />
            <span><b>لا توجد حادثة حرجة</b> · الشبكة تحت المراقبة</span>
          </div>
        )
      )}

      {error && <div className="error">{error}</div>}

      <main key={tab} className="tab-body">
        {!network && !error && (
          <div className="skeleton-grid">
            <div className="skeleton" />
            <div className="skeleton" />
            <div className="skeleton" />
          </div>
        )}
        {tab === 'shadow' && network && analysis && (
          <ShadowView network={network} analysis={analysis} onChange={refresh} />
        )}
        {tab === 'alerts' && <AlertsView alerts={alerts} />}
        {tab === 'incidents' && <IncidentsView incidents={incidents} network={network} />}
      </main>
      <footer className="app-foot">فريق منارة شراع · هاكاثون شراع 2026 · بيانات المحاكاة للعرض فقط</footer>
    </div>
  )
}
