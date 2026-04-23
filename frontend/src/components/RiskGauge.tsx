type Props = {
  score: number
  label: string
}

function clamp(n: number, min: number, max: number) {
  return Math.max(min, Math.min(max, n))
}

export function RiskGauge({ score, label }: Props) {
  const s = clamp(score, 0, 100)
  const angle = (s / 100) * 180
  const hue = s < 30 ? 175 : s < 60 ? 38 : 0 // cyan -> amber -> red
  const stroke = `hsl(${hue} 95% 60%)`

  return (
    <div className="gauge">
      <div className="gaugeTop">
        <div className="gaugeTitle">GLOBAL RISK</div>
        <div className="gaugeLabel">{label}</div>
      </div>
      <div className="gaugeWrap">
        <svg viewBox="0 0 220 120" className="gaugeSvg" aria-label={`Risk ${s}`}>
          <path className="gaugeTrack" d="M 20 110 A 90 90 0 0 1 200 110" fill="none" />
          <path
            className="gaugeArc"
            d="M 20 110 A 90 90 0 0 1 200 110"
            fill="none"
            stroke={stroke}
            strokeDasharray={`${(s / 100) * 283} 999`}
          />
          <g transform="translate(110 110)">
            <line
              x1="0"
              y1="0"
              x2="0"
              y2="-74"
              stroke={stroke}
              strokeWidth="3"
              transform={`rotate(${angle - 90})`}
            />
            <circle r="6" fill={stroke} />
          </g>
        </svg>
        <div className="gaugeValue">{s}</div>
        <div className="gaugeSub">Threat Index</div>
      </div>
    </div>
  )
}

