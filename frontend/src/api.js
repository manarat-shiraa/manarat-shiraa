// كل الاتصال بالباك إند في مكان واحد
async function request(path, options = {}) {
  const res = await fetch(`/api${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`)
  return res.json()
}

export const api = {
  health: () => request('/health'),
  network: () => request('/network'),
  analysis: () => request('/shadow/analysis'),
  whatIf: (fixedEdges) => request('/shadow/whatif', { method: 'POST', body: JSON.stringify({ fixed_edges: fixedEdges }) }),
  fix: (edgeId) => request('/shadow/fix', { method: 'POST', body: JSON.stringify({ edge_id: edgeId }) }),
  reset: () => request('/shadow/reset', { method: 'POST' }),
  alerts: () => request('/alerts'),
  alert: (id) => request(`/alerts/${id}`),
  incidents: () => request('/incidents'),
  incidentSummary: (id, llm) => request(`/incidents/${id}/summary?llm=${llm}`),
}

export const SOURCE_AR = {
  endpoint: 'الأجهزة',
  firewall: 'الجدار الناري',
  network: 'الشبكة',
  server: 'الخوادم',
  identity: 'الهوية والدخول',
  email: 'البريد',
  ids: 'IDS/IPS',
  siem: 'SIEM',
}

export const SEVERITY_AR = { low: 'منخفضة', medium: 'متوسطة', high: 'عالية', critical: 'حرجة' }

export function timeAr(iso) {
  return new Date(iso).toLocaleTimeString('ar', { hour: '2-digit', minute: '2-digit', timeZone: 'UTC' })
}
