import { useCountTo } from './CountUp.jsx'

// مؤشر الخطر الكلي من الظل الرقمي (0-100) — الرقم يعدّ لين يوصل للقيمة الجديدة

export default function RiskMeter({ value, baseline }) {
  const shown = useCountTo(value)
  const level = value >= 30 ? 'high' : value >= 10 ? 'medium' : 'low'
  const reduced = baseline > 0 ? Math.round((100 * (baseline - value)) / baseline) : 0
  return (
    <div className={`risk risk-${level}`}>
      <div className="risk-head">
        <span>{level === 'low' ? <i className="lamp ok" /> : <i className="lamp" />}مؤشر الخطر</span>
        <b>{shown.toFixed(1)}</b>
      </div>
      <div className="risk-bar">
        <div style={{ width: `${Math.min(shown, 100)}%` }} />
      </div>
      {reduced > 0 && <small>انخفض {reduced}٪ بعد الإصلاحات</small>}
    </div>
  )
}
