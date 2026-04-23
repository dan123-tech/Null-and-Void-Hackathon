/* eslint-disable @typescript-eslint/no-explicit-any */
'use client'

import CytoscapeComponent from 'react-cytoscapejs'
import cytoscape, { type Core, type ElementDefinition, type EventObject } from 'cytoscape'
import coseBilkent from 'cytoscape-cose-bilkent'
import { useEffect, useMemo, useRef, useState } from 'react'

import type { Device } from '../lib/types'

cytoscape.use(coseBilkent)

function stateColor(state: Device['state']) {
  if (state === 'healthy') return '#1fe0d7'
  if (state === 'danger') return '#ff3b3b'
  return '#ffb020'
}

export function Topology({
  devices,
  selectedId,
  onSelect,
}: {
  devices: Device[]
  selectedId: string | null
  onSelect: (id: string | null) => void
}) {
  const cyRef = useRef<cytoscape.Core | null>(null)
  const lastIdsRef = useRef<string>('') // avoid visible refresh

  const buildElements = (current: Device[]) => {
    const guardian = current.find((d) => d.id === 'guardian')
    const peripheral = current.filter((d) => d.id !== 'guardian')

    const nodes: ElementDefinition[] = [
      {
        data: {
          id: guardian?.id ?? 'guardian',
          label: guardian?.hostname ?? 'The Guardian',
          state: guardian?.state ?? 'healthy',
          ip: guardian?.ip ?? '',
        },
        classes: 'guardian',
      },
      ...peripheral.map((d) => ({
        data: {
          id: d.id,
          label: d.hostname || d.ip,
          state: d.state,
          ip: d.ip,
        },
        classes: d.state === 'danger' ? 'danger' : d.state === 'unknown' ? 'unknown' : 'healthy',
      })),
    ]

    const edges: ElementDefinition[] = peripheral.map((d) => ({
      data: { id: `e-${d.id}`, source: 'guardian', target: d.id },
    }))

    return [...nodes, ...edges]
  }

  const [elements, setElements] = useState<ElementDefinition[]>(() => buildElements(devices))
  const idSignature = useMemo(() => devices.map((d) => d.id).sort().join('|'), [devices])

  useEffect(() => {
    if (idSignature === lastIdsRef.current) return
    lastIdsRef.current = idSignature
    setElements(buildElements(devices))
  }, [devices, idSignature])

  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return
    if (!idSignature) return

    const layout = cy.layout({
      name: 'cose-bilkent',
      animate: true,
      fit: true,
      padding: 30,
      idealEdgeLength: 130,
      nodeRepulsion: 8000,
      gravity: 0.35,
    } as any)
    layout.run()
  }, [idSignature])

  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return
    const byId = new Map(devices.map((d) => [d.id, d]))
    cy.nodes().forEach((n) => {
      const d = byId.get(n.id())
      if (!d) return
      n.data('label', d.hostname || d.ip)
      n.data('state', d.state)
      n.removeClass('healthy unknown danger')
      n.addClass(d.state === 'danger' ? 'danger' : d.state === 'unknown' ? 'unknown' : 'healthy')
    })
  }, [devices])

  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return
    let cancelled = false

    const loop = () => {
      if (cancelled) return
      cy.nodes('.danger').forEach((n) => {
        n.stop()
        ;(n as any)
          .animation({
            style: { 'border-width': 10, 'border-color': '#ff3b3b', 'border-opacity': 0.9 },
            duration: 500,
          })
          .play()
          .promise('completed')
          .then(() => {
            if (cancelled) return
            ;(n as any)
              .animation({
                style: { 'border-width': 2, 'border-opacity': 0.4 },
                duration: 600,
              })
              .play()
          })
          .catch(() => {})
      })
      setTimeout(loop, 1200)
    }

    loop()
    return () => {
      cancelled = true
    }
  }, [])

  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return
    cy.nodes().removeClass('selected')
    if (selectedId) cy.getElementById(selectedId).addClass('selected')
  }, [selectedId])

  const stylesheet = useMemo(
    () => [
      {
        selector: 'node',
        style: {
          'background-color': (ele: any) => stateColor(ele.data('state')),
          label: 'data(label)',
          color: '#cfe7ff',
          'font-size': 10,
          'text-outline-width': 2,
          'text-outline-color': '#0a0c14',
          'text-valign': 'bottom',
          'text-margin-y': 6,
          width: 26,
          height: 26,
          'border-width': 2,
          'border-color': '#3a4a6a',
          'border-opacity': 0.4,
        },
      },
      {
        selector: 'node.guardian',
        style: {
          width: 42,
          height: 42,
          'font-size': 12,
          'border-width': 3,
          'border-opacity': 0.7,
        },
      },
      {
        selector: 'node.selected',
        style: {
          'border-width': 3,
          'border-opacity': 1,
          'border-color': '#9dfcff',
        },
      },
      {
        selector: 'edge',
        style: {
          width: 1,
          'line-color': '#1e2b45',
          'curve-style': 'bezier',
          'target-arrow-shape': 'triangle',
          'target-arrow-color': '#1e2b45',
          'arrow-scale': 0.6,
          opacity: 0.9,
        },
      },
    ],
    [],
  )

  return (
    <div className="topology panel">
      <div className="panelHeader">
        <div className="panelTitle">DIGITAL TWIN</div>
        <div className="panelHint">Click a node to inspect and act.</div>
      </div>
      <div className="topologyCanvas">
        <CytoscapeComponent
          elements={elements}
          cy={(cy: Core) => {
            cyRef.current = cy
            cy.on('tap', 'node', (evt: EventObject) => {
              const id = evt.target.id()
              onSelect(id)
            })
            cy.on('tap', (evt: EventObject) => {
              if (evt.target === cy) onSelect(null)
            })
          }}
          stylesheet={stylesheet as any}
          style={{ width: '100%', height: '100%' }}
          userPanningEnabled
          userZoomingEnabled
        />
      </div>
    </div>
  )
}

