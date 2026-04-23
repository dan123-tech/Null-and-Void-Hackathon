export type DeviceState = 'healthy' | 'unknown' | 'danger'

export type VulnerabilityStatus = 'unknown' | 'patched' | 'vulnerable'

export type Device = {
  id: string
  ip: string
  mac: string
  hostname?: string | null
  state: DeviceState
  vulnerability_status: VulnerabilityStatus
  last_seen: string
}

export type Alert = {
  id: string
  ts: string
  level: 'info' | 'warning' | 'critical'
  message: string
  src_ip?: string | null
  device_id?: string | null
}

export type RiskScore = {
  score: number
  label: string
}

export type Snapshot = {
  ts: number
  devices: Device[]
  alerts: Alert[]
  risk: RiskScore
  blocked_ips: Record<string, string>
}

export type Packet = {
  id: string
  ts: string
  device_id: string
  src_ip: string
  dst_ip: string
  proto: string
  src_port?: number | null
  dst_port?: number | null
  flags?: string | null
  bytes: number
}

