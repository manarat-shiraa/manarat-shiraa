import { useEffect, useRef } from 'react'
import cytoscape from 'cytoscape'

// خريطة الشبكة: المسارات بالأحمر، والمسار المحدد أعرض، والحواف المُصلحة خضراء متقطعة
export default function NetworkMap({ network, analysis, selectedPath, onSelectEdge }) {
  const ref = useRef(null)
  const cyRef = useRef(null)

  useEffect(() => {
    const entries = network.entry_points.map((e) => e.asset)
    const onPathNodes = new Set(analysis.nodes_on_paths)
    const onPathEdges = new Set(analysis.edges_on_paths)
    const fixed = new Set(analysis.fixed_edges)
    const selEdges = new Set(selectedPath?.edges || [])
    const selNodes = new Set(selectedPath?.nodes || [])

    const elements = [
      ...network.assets.map((a) => ({
        data: { id: a.id, label: a.label },
        classes: [
          a.crown_jewel ? 'crown' : '',
          entries.includes(a.id) ? 'entry' : '',
          onPathNodes.has(a.id) ? 'onpath' : '',
          selNodes.has(a.id) ? 'selected-node' : '',
        ].join(' '),
      })),
      ...network.edges.map((e) => ({
        data: { id: e.id, source: e.from, target: e.to, label: e.label },
        classes: [
          fixed.has(e.id) ? 'fixed' : onPathEdges.has(e.id) ? 'onpath' : '',
          selEdges.has(e.id) ? 'selected-edge' : '',
        ].join(' '),
      })),
    ]

    cyRef.current?.destroy()
    const cy = cytoscape({
      container: ref.current,
      elements,
      layout: { name: 'breadthfirst', directed: true, roots: entries, spacingFactor: 1.05, padding: 24 },
      wheelSensitivity: 0.2,
      style: [
        {
          selector: 'node',
          style: {
            label: 'data(label)',
            'font-size': 11,
            color: '#B8C4D6',
            'text-valign': 'bottom',
            'text-margin-y': 6,
            'text-wrap': 'wrap',
            'text-max-width': 90,
            'background-color': '#1D2C45',
            'border-width': 2,
            'border-color': '#3A5075',
            width: 30,
            height: 30,
          },
        },
        { selector: 'node.onpath', style: { 'background-color': '#43201F', 'border-color': '#E5574B' } },
        { selector: 'node.entry', style: { shape: 'diamond', width: 36, height: 36 } },
        { selector: 'node.crown', style: { shape: 'star', width: 42, height: 42, 'background-color': '#4A3D17', 'border-color': '#E9B949' } },
        { selector: 'node.selected-node', style: { 'border-width': 4 } },
        {
          selector: 'edge',
          style: {
            width: 1.5,
            'line-color': '#2B3D5C',
            'target-arrow-color': '#2B3D5C',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'arrow-scale': 0.9,
          },
        },
        { selector: 'edge.onpath', style: { 'line-color': '#E5574B', 'target-arrow-color': '#E5574B', width: 2.5, 'line-style': 'dashed', 'line-dash-pattern': [8, 5] } },
        { selector: 'edge.selected-edge', style: { 'line-color': '#FF8F84', 'target-arrow-color': '#FF8F84', width: 5 } },
        { selector: 'edge.fixed', style: { 'line-color': '#3FB37F', 'target-arrow-color': '#3FB37F', 'line-style': 'dashed', width: 2 } },
      ],
    })
    cy.on('tap', 'edge', (evt) => onSelectEdge?.(evt.target.id()))
    cyRef.current = cy

    // حركة: خطوط الهجوم تجري نحو الهدف، والأصول الحرجة على المسار تنبض
    const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
    let offset = 0
    let grow = false
    const flow = reduce ? null : setInterval(() => {
      offset = (offset - 1) % 130
      cy.edges('.onpath').style('line-dash-offset', offset)
    }, 40)
    const pulse = reduce ? null : setInterval(() => {
      grow = !grow
      cy.nodes('.crown.onpath').animate({ style: { width: grow ? 50 : 42, height: grow ? 50 : 42, 'border-width': grow ? 4 : 2 } }, { duration: 700 })
    }, 750)
    return () => {
      clearInterval(flow)
      clearInterval(pulse)
      cy.destroy()
    }
  }, [network, analysis, selectedPath, onSelectEdge])

  return (
    <div className="map-wrap">
      <div ref={ref} className="map" />
      <div className="legend">
        <span><i className="lg entry" />نقطة دخول</span>
        <span><i className="lg crown" />أصل حرج</span>
        <span><i className="lg path" />مسار هجوم</span>
        <span><i className="lg fixed" />تم إصلاحه</span>
      </div>
    </div>
  )
}
