'use client'

import type { ServiceState } from '../lib/types'

function pillClass(state: ServiceState) {
  if (state === 'OK') return 'pill pill-healthy'
  if (state === 'WARNING') return 'pill pill-unknown'
  if (state === 'CRITICAL') return 'pill pill-danger'
  return 'pill'
}

export function StateBadge({ state }: { state: ServiceState }) {
  return <span className={pillClass(state)}>{state}</span>
}

