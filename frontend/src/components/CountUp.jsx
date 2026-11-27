import { useEffect, useRef, useState } from 'react'

// رقم يعدّ بنعومة لين يوصل للقيمة الجديدة (يستخدم في الإحصائيات ومؤشر الخطر)
export function useCountTo(target, ms = 900) {
  const [shown, setShown] = useState(0)
  const from = useRef(0)
  useEffect(() => {
    const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
    if (reduce) { setShown(target); from.current = target; return }
    const start = performance.now()
    const a = from.current
    let raf
    const step = (now) => {
      const t = Math.min(1, (now - start) / ms)
      const v = a + (target - a) * (1 - Math.pow(1 - t, 3))
      setShown(v)
      if (t < 1) raf = requestAnimationFrame(step)
      else from.current = target
    }
    raf = requestAnimationFrame(step)
    return () => { cancelAnimationFrame(raf); from.current = target }
  }, [target, ms])
  return shown
}

export default function CountUp({ value, decimals = 0 }) {
  const v = useCountTo(value)
  return <>{v.toFixed(decimals)}</>
}
