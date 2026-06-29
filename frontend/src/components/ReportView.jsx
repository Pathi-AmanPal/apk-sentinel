import { useState } from 'react'
import VerdictStamp from './VerdictStamp.jsx'
import { Panel, SectionHeader, Pill, Bar, KeyValueRow, severityColor, severitySoft } from './ui.jsx'
import { pdfReportUrl } from '../api.js'

export default function ReportView({ jobId, report, onReset }) {
  const { meta, verdict, narrative, staticAnalysis, dynamicAnalysis, genaiAnalysis, riskBreakdown } = report
  const pillar1 = genaiAnalysis?.identityGapAnalysis
  const pillar2 = genaiAnalysis?.codeDeobfuscation
  const pillar3 = genaiAnalysis?.attackClassification
  const pillar5 = genaiAnalysis?.spoofingAnalysis

  const [downloading, setDownloading] = useState(false)

  async function handleDownloadPdf() {
    setDownloading(true)
    try {
      const apiBase = import.meta.env.VITE_API_URL || '/api'
      const res = await fetch(`${apiBase}/report/pdf`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ jobId, report })
      })
      if (!res.ok) throw new Error('PDF generation failed on server.')
      const blob = await res.blob()
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `apk-sentinel-report-${meta.filename}.pdf`
      document.body.appendChild(a)
      a.click()
      a.remove()
      window.URL.revokeObjectURL(url)
    } catch (e) {
      alert(`Error downloading PDF: ${e.message}`)
    } finally {
      setDownloading(false)
    }
  }

  return (
    <div style={{ maxWidth: 920, margin: '0 auto', paddingBottom: 80 }}>
      {/* ── Letterhead ───────────────────────────────────── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 28, gap: 16, flexWrap: 'wrap' }}>
        <div>
          <div className="eyebrow">case file · {meta.jobId}</div>
          <h1 style={{ fontFamily: 'var(--font-display)', fontSize: 26, margin: '6px 0 0', fontWeight: 700 }}>
            {meta.filename}
          </h1>
          <div className="mono" style={{ fontSize: 12, color: 'var(--text-dim)', marginTop: 6 }}>
            generated {new Date(meta.generatedAt).toLocaleString()} · engine v{meta.analysisVersion}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button onClick={handleDownloadPdf} disabled={downloading} style={linkBtn}>
            {downloading ? 'Generating...' : '↓ download PDF'}
          </button>
          <button onClick={onReset} style={ghostBtn}>+ new scan</button>
        </div>
      </div>

      {/* ── Verdict ──────────────────────────────────────── */}
      <Panel style={{ marginBottom: 24 }}>
        <VerdictStamp score={verdict.riskScore} severity={verdict.severity} recommendation={verdict.recommendation} />
        {verdict.interpretation && (
          <p style={{ marginTop: 20, marginBottom: 0, color: 'var(--text-muted)', fontSize: 14, lineHeight: 1.6 }}>
            {verdict.interpretation}
          </p>
        )}
      </Panel>

      {/* ── 01 Executive Summary ────────────────────────── */}
      {narrative && (
        <Panel style={{ marginBottom: 24 }}>
          <SectionHeader index="01" title="Executive summary" />
          <p style={{ fontSize: 14.5, lineHeight: 1.7, color: 'var(--text)' }}>{narrative.executiveSummary}</p>
          <p style={{ fontSize: 13.5, lineHeight: 1.7, color: 'var(--text-muted)' }}>{narrative.threatNarrative}</p>

          {narrative.impactAssessment && (
            <div style={{ marginTop: 16, paddingTop: 16, borderTop: '1px solid var(--border-soft)' }}>
              <KeyValueRow label="Immediate impact" value={narrative.impactAssessment.immediateImpact} />
              <KeyValueRow label="Financial risk" value={narrative.impactAssessment.financialRisk} />
              <KeyValueRow label="Data compromised" value={(narrative.impactAssessment.dataCompromised || []).join(', ')} />
            </div>
          )}
        </Panel>
      )}

      {/* ── 02 Risk Breakdown ────────────────────────────── */}
      <Panel style={{ marginBottom: 24 }}>
        <SectionHeader index="02" title="Risk score breakdown" subtitle="composite, auditable scoring" />
        <BreakdownRow label="Static analysis" sub="permissions · certificate · strings" value={riskBreakdown.staticScore} max={30} color={severityColor(verdict.severity)} />
        <BreakdownRow label="Dynamic analysis" sub="C2 traffic · exfiltration" value={riskBreakdown.dynamicScore} max={25} color={severityColor(verdict.severity)} />
        <BreakdownRow label="Identity gap" sub="brand impersonation (pillar 1)" value={riskBreakdown.identityGapScore} max={25} color={severityColor(verdict.severity)} />
        <BreakdownRow label="Stealth rating" sub="anti-analysis (pillar 5)" value={riskBreakdown.stealthScore} max={10} color={severityColor(verdict.severity)} />
        <BreakdownRow label="Known malware match" sub="vector similarity" value={riskBreakdown.vectorMatchScore} max={10} color={severityColor(verdict.severity)} last />
      </Panel>

      {/* ── 03 Identity Gap ──────────────────────────────── */}
      {pillar1 && (
        <Panel style={{ marginBottom: 24 }}>
          <SectionHeader index="03" title="Identity gap analysis" subtitle="pillar 1" />
          <div style={{ display: 'flex', gap: 12, marginBottom: 14, flexWrap: 'wrap' }}>
            <Pill color="var(--accent)">verdict: {pillar1.verdict}</Pill>
            <Pill>confidence: {pillar1.confidence}</Pill>
            <Pill>gap score: {pillar1.identityGapScore}/100</Pill>
          </div>
          <p style={{ fontSize: 13.5, color: 'var(--text-muted)', lineHeight: 1.7 }}>{pillar1.reasoning}</p>
          <List title="Claimed vs. actual mismatches" items={pillar1.claimedVsActualMismatches} />
          <List title="Critical red flags" items={pillar1.criticalRedFlags} color="var(--critical)" />
        </Panel>
      )}

      {/* ── 04 Static Analysis ───────────────────────────── */}
      {staticAnalysis && (
        <Panel style={{ marginBottom: 24 }}>
          <SectionHeader index="04" title="Static analysis" subtitle="manifest · certificate · strings" />

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24, marginBottom: 20 }}>
            <div>
              <KeyValueRow label="Claims to be" value={staticAnalysis.claimedIdentity?.name} />
              <KeyValueRow label="Package" mono value={staticAnalysis.manifest?.packageName} />
              <KeyValueRow label="Real package (if known brand)" mono value={staticAnalysis.claimedIdentity?.realPackageName} />
            </div>
            <div>
              <KeyValueRow label="Certificate issuer" value={staticAnalysis.certificate?.issuer} />
              <KeyValueRow label="Debug certificate" value={staticAnalysis.certificate?.isDebugCert ? 'yes — red flag' : 'no'} />
              <KeyValueRow label="SHA-256" mono value={`${staticAnalysis.certificate?.sha256?.slice(0, 24)}…`} />
            </div>
          </div>

          <div className="eyebrow" style={{ marginBottom: 8 }}>permissions ({staticAnalysis.manifest?.permissions?.length || 0})</div>
          <div style={{ marginBottom: 20 }}>
            {(staticAnalysis.manifest?.permissions || []).map((p, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '6px 0', borderBottom: '1px solid var(--border-soft)' }}>
                <Pill color={severityColor(p.risk)} soft={severitySoft(p.risk)}>{p.risk}</Pill>
                <span className="mono" style={{ fontSize: 12, color: 'var(--text)' }}>{p.name}</span>
                <span style={{ fontSize: 12, color: 'var(--text-dim)', marginLeft: 'auto', textAlign: 'right' }}>{p.reason}</span>
              </div>
            ))}
          </div>

          <div className="eyebrow" style={{ marginBottom: 8 }}>suspicious strings ({staticAnalysis.suspiciousStrings?.length || 0})</div>
          <div>
            {(staticAnalysis.suspiciousStrings || []).map((s, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '6px 0', borderBottom: '1px solid var(--border-soft)' }}>
                <Pill color={severityColor(s.risk)} soft={severitySoft(s.risk)}>{s.risk}</Pill>
                <span className="mono" style={{ fontSize: 12, color: 'var(--text)', wordBreak: 'break-all' }}>{s.value}</span>
                <span style={{ fontSize: 11, color: 'var(--text-dim)', marginLeft: 'auto' }}>{s.type}</span>
              </div>
            ))}
          </div>
        </Panel>
      )}

      {/* ── 05 Behavioral Timeline ───────────────────────── */}
      {dynamicAnalysis && (
        <Panel style={{ marginBottom: 24 }}>
          <SectionHeader index="05" title="Temporal attack graph" subtitle={`${dynamicAnalysis.sandboxDurationSeconds}s sandbox run`} />
          <div style={{ position: 'relative', paddingLeft: 18 }}>
            <div style={{ position: 'absolute', left: 4, top: 6, bottom: 6, width: 2, background: 'var(--border)' }} />
            {(dynamicAnalysis.temporalAttackGraph || []).map((ev, i) => (
              <div key={i} style={{ position: 'relative', marginBottom: 16 }}>
                <div style={{
                  position: 'absolute', left: -18, top: 4, width: 9, height: 9, borderRadius: '50%',
                  background: severityColor(ev.risk), boxShadow: `0 0 0 3px var(--panel)`,
                }} />
                <div style={{ display: 'flex', gap: 10, alignItems: 'baseline', flexWrap: 'wrap' }}>
                  <span className="mono" style={{ fontSize: 11, color: 'var(--accent)' }}>T+{ev.T}s</span>
                  <span style={{ fontWeight: 600, fontSize: 13 }}>{ev.event.replace(/_/g, ' ')}</span>
                  <Pill color={severityColor(ev.risk)} soft={severitySoft(ev.risk)}>{ev.risk}</Pill>
                </div>
                <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 3 }}>{ev.description}</div>
                <div className="mono" style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 2 }}>{ev.apiCall}{ev.detail ? ` · ${ev.detail}` : ''}</div>
              </div>
            ))}
          </div>

          {!!dynamicAnalysis.networkActivity?.length && (
            <>
              <div className="eyebrow" style={{ margin: '20px 0 8px' }}>network activity</div>
              {dynamicAnalysis.networkActivity.map((n, i) => (
                <div key={i} style={{ display: 'flex', gap: 10, padding: '6px 0', borderBottom: '1px solid var(--border-soft)', fontSize: 12, flexWrap: 'wrap' }}>
                  <span className="mono" style={{ color: 'var(--text-dim)' }}>{n.timestamp}</span>
                  <span className="mono" style={{ color: 'var(--accent)' }}>{n.method}</span>
                  <span className="mono" style={{ color: 'var(--text)', wordBreak: 'break-all' }}>{n.url}</span>
                  <Pill>{n.classification}</Pill>
                </div>
              ))}
            </>
          )}

          {!!dynamicAnalysis.fridaHooks?.length && (
            <>
              <div className="eyebrow" style={{ margin: '20px 0 8px' }}>frida API hooks</div>
              {dynamicAnalysis.fridaHooks.map((h, i) => (
                <div key={i} style={{ display: 'flex', gap: 10, padding: '6px 0', borderBottom: '1px solid var(--border-soft)', fontSize: 12 }}>
                  <span style={{ color: h.called ? 'var(--critical)' : 'var(--text-dim)' }}>{h.called ? '●' : '○'}</span>
                  <span className="mono" style={{ color: 'var(--text)' }}>{h.api}</span>
                  <span style={{ color: 'var(--text-dim)', marginLeft: 'auto', textAlign: 'right' }}>{h.detail}</span>
                </div>
              ))}
            </>
          )}

          {dynamicAnalysis.intentSpoofingResults && (
            <div style={{ marginTop: 20, padding: 16, background: 'var(--panel-inset)', borderRadius: 'var(--radius-md)' }}>
              <div className="eyebrow" style={{ marginBottom: 8 }}>intent spoofing — environment evasion test</div>
              <KeyValueRow label="Scenario" value={dynamicAnalysis.intentSpoofingResults.scenario} />
              <KeyValueRow label="Baseline behavior" value={dynamicAnalysis.intentSpoofingResults.baselineBehavior} />
              <KeyValueRow label="Spoofed behavior" value={dynamicAnalysis.intentSpoofingResults.spoofedBehavior} />
              <KeyValueRow label="Behavioral delta" value={dynamicAnalysis.intentSpoofingResults.behavioralDelta} />
              <List title="Hidden payloads revealed" items={dynamicAnalysis.intentSpoofingResults.hiddenPayloadsRevealed} color="var(--critical)" />
            </div>
          )}
        </Panel>
      )}

      {/* ── 06 Code & Attack Classification ─────────────── */}
      {(pillar2 || pillar3) && (
        <Panel style={{ marginBottom: 24 }}>
          <SectionHeader index="06" title="Code deobfuscation & kill-chain mapping" subtitle="pillars 2 & 3" />
          {pillar2 && (
            <div style={{ marginBottom: 18 }}>
              <KeyValueRow label="Actual purpose" value={pillar2.actualPurpose} />
              <KeyValueRow label="Suspected family" value={pillar2.malwareFamilyGuess} />
              <p style={{ fontSize: 13.5, color: 'var(--text-muted)', lineHeight: 1.7, marginTop: 10 }}>{pillar2.attackChainSummary}</p>
              {(pillar2.patternAnalysis || []).map((p, i) => (
                <div key={i} style={{ display: 'flex', gap: 10, padding: '8px 0', borderBottom: '1px solid var(--border-soft)', fontSize: 12.5 }}>
                  <Pill color={severityColor(p.severity)} soft={severitySoft(p.severity)}>{p.severity}</Pill>
                  <span className="mono" style={{ color: 'var(--text)' }}>{p.pattern}</span>
                  <span style={{ color: 'var(--text-dim)' }}>— {p.plainEnglish}</span>
                </div>
              ))}
            </div>
          )}
          {pillar3 && (
            <div>
              <div style={{ display: 'flex', gap: 12, marginBottom: 12, flexWrap: 'wrap' }}>
                <Pill color="var(--accent)">{pillar3.attackCategory}</Pill>
                <Pill>sophistication: {pillar3.sophisticationLevel}</Pill>
                <Pill>first C2: T+{pillar3.timeToFirstC2Seconds}s</Pill>
                <Pill>exfil: T+{pillar3.timeToDataExfiltrationSeconds}s</Pill>
              </div>
              <KeyValueRow label="Attack pattern" value={pillar3.attackPattern} />
              <KeyValueRow label="Campaign similarity" value={pillar3.knownCampaignSimilarity} />
              <KeyValueRow label="Risk to victim" value={pillar3.immediateRiskToVictim} />
              {(pillar3.killChainPhases || []).map((k, i) => (
                <div key={i} style={{ display: 'flex', gap: 10, padding: '6px 0', fontSize: 12 }}>
                  <span className="mono" style={{ color: 'var(--accent)' }}>{k.mitreTechnique}</span>
                  <span style={{ color: 'var(--text)' }}>{k.phase}</span>
                  <span style={{ color: 'var(--text-dim)' }}>{(k.events || []).join(', ')}</span>
                </div>
              ))}
              {pillar3.analystNotes && (
                <p style={{ fontSize: 12.5, color: 'var(--text-dim)', marginTop: 8, fontStyle: 'italic' }}>{pillar3.analystNotes}</p>
              )}
            </div>
          )}
        </Panel>
      )}

      {/* ── 07 Stealth & Evasion ─────────────────────────── */}
      {pillar5 && (
        <Panel style={{ marginBottom: 24 }}>
          <SectionHeader index="07" title="Stealth & anti-analysis" subtitle="pillar 5" />
          <div style={{ display: 'flex', gap: 12, marginBottom: 14, flexWrap: 'wrap' }}>
            <Pill color="var(--accent)">stealth: {pillar5.stealthRating}</Pill>
            <Pill>discovery difficulty: {pillar5.discoveryDifficulty}</Pill>
          </div>
          <p style={{ fontSize: 13.5, color: 'var(--text-muted)', lineHeight: 1.7 }}>{pillar5.evasionAnalysis}</p>
          <List title="Trigger conditions" items={pillar5.triggerConditions} />
          <List title="Anti-analysis techniques" items={pillar5.antiAnalysisTechniques} />
          {(pillar5.hiddenCapabilities || []).map((h, i) => (
            <div key={i} style={{ display: 'flex', gap: 10, padding: '8px 0', borderBottom: '1px solid var(--border-soft)', fontSize: 12.5 }}>
              <Pill color={severityColor(h.severity)} soft={severitySoft(h.severity)}>{h.severity}</Pill>
              <span style={{ color: 'var(--text)' }}>{h.capability}</span>
              <span style={{ color: 'var(--text-dim)', marginLeft: 'auto', textAlign: 'right' }}>{h.activationTrigger}</span>
            </div>
          ))}
        </Panel>
      )}

      {/* ── 08 Investigator Checklist ────────────────────── */}
      {narrative && (
        <Panel>
          <SectionHeader index="08" title="Evidence & investigator checklist" />
          <List title="Evidence highlights" items={narrative.evidenceHighlights} color="var(--accent)" />
          <div style={{ marginTop: 16, padding: 16, background: 'var(--panel-inset)', borderRadius: 'var(--radius-md)' }}>
            <KeyValueRow label="Recommendation" value={narrative.recommendation?.replace(/_/g, ' ')} />
            <p style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 8 }}>{narrative.recommendationReasoning}</p>
          </div>
          {(narrative.investigatorChecklist || []).map((item, i) => (
            <div key={i} style={{ display: 'flex', gap: 10, padding: '8px 0', borderBottom: '1px solid var(--border-soft)', fontSize: 13 }}>
              <span className="mono" style={{ color: 'var(--accent)' }}>{String(i + 1).padStart(2, '0')}</span>
              <span style={{ color: 'var(--text)' }}>{item}</span>
            </div>
          ))}
        </Panel>
      )}
    </div>
  )
}

function BreakdownRow({ label, sub, value, max, color, last }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 16, padding: '12px 0', borderBottom: last ? 'none' : '1px solid var(--border-soft)' }}>
      <div style={{ width: 220, flexShrink: 0 }}>
        <div style={{ fontSize: 13, color: 'var(--text)' }}>{label}</div>
        <div className="mono" style={{ fontSize: 10.5, color: 'var(--text-dim)' }}>{sub}</div>
      </div>
      <Bar value={value} max={max} color={color} />
      <div className="mono" style={{ fontSize: 12, color: 'var(--text-muted)', width: 52, textAlign: 'right' }}>{value}/{max}</div>
    </div>
  )
}

function List({ title, items, color }) {
  if (!items?.length) return null
  return (
    <div style={{ marginTop: 14 }}>
      <div className="eyebrow" style={{ marginBottom: 6 }}>{title}</div>
      {items.map((it, i) => (
        <div key={i} style={{ display: 'flex', gap: 8, fontSize: 13, color: 'var(--text-muted)', padding: '4px 0', lineHeight: 1.5 }}>
          <span style={{ color: color || 'var(--text-dim)' }}>—</span>
          <span>{it}</span>
        </div>
      ))}
    </div>
  )
}

const linkBtn = {
  display: 'inline-flex', alignItems: 'center', textDecoration: 'none',
  fontFamily: 'var(--font-mono)', fontSize: 12, padding: '9px 14px',
  borderRadius: 'var(--radius-sm)', background: 'var(--accent)', color: '#1a1206', fontWeight: 600,
  border: 'none', cursor: 'pointer',
}
const ghostBtn = {
  fontFamily: 'var(--font-mono)', fontSize: 12, padding: '9px 14px',
  borderRadius: 'var(--radius-sm)', background: 'transparent', color: 'var(--text-muted)',
  border: '1px solid var(--border)', cursor: 'pointer',
}
