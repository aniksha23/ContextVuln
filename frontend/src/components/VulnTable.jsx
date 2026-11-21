import React, { useState } from 'react';
import { ChevronDown, ChevronRight, Flame, Wrench } from 'lucide-react';
import CallPathViewer from './CallPathViewer';

const TIER_STYLES = {
    CRITICAL_ACTION: { bg: '#fee2e2', text: '#991b1b', border: '#fca5a5', label: 'CRITICAL ACTION' },
    MONITOR: { bg: '#fef3c7', text: '#92400e', border: '#fcd34d', label: 'MONITOR' },
    LOW_RISK: { bg: '#e0f2fe', text: '#075985', border: '#7dd3fc', label: 'LOW RISK' },
    SUPPRESSED_NOISE: { bg: '#f1f5f9', text: '#475569', border: '#cbd5e1', label: 'SUPPRESSED NOISE' },
};

export default function VulnTable({ findings }) {
    const [filter, setFilter] = useState('ALL'); // ALL | REACHABLE | SUPPRESSED
    const [expandedCve, setExpandedCve] = useState(
        findings.length > 0 ? findings[0].cve_id : null
    );

    const filteredFindings = findings.filter((item) => {
        if (filter === 'REACHABLE') return item.is_reachable;
        if (filter === 'SUPPRESSED') return !item.is_reachable;
        return true;
    });

    const toggleExpand = (cveId) => {
        setExpandedCve((prev) => (prev === cveId ? null : cveId));
    };

    return (
        <div
            style={{
                background: '#ffffff',
                border: '1px solid #e2e8f0',
                borderRadius: '10px',
                overflow: 'hidden',
            }}
        >
            {/* Filter Toolbar */}
            <div
                style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: '0.9rem 1.25rem',
                    borderBottom: '1px solid #e2e8f0',
                    background: '#f8fafc',
                    flexWrap: 'wrap',
                    gap: '0.5rem',
                }}
            >
                <strong style={{ color: '#0f172a', fontSize: '0.95rem' }}>
                    Prioritized Vulnerability Findings ({filteredFindings.length})
                </strong>
                <div style={{ display: 'flex', gap: '0.4rem' }}>
                    {[
                        { id: 'ALL', label: `All (${findings.length})` },
                        { id: 'REACHABLE', label: `Actionable (${findings.filter((f) => f.is_reachable).length})` },
                        { id: 'SUPPRESSED', label: `Suppressed (${findings.filter((f) => !f.is_reachable).length})` },
                    ].map((tab) => (
                        <button
                            key={tab.id}
                            onClick={() => setFilter(tab.id)}
                            style={{
                                padding: '0.35rem 0.75rem',
                                borderRadius: '6px',
                                border: filter === tab.id ? '1px solid #0f172a' : '1px solid #cbd5e1',
                                background: filter === tab.id ? '#0f172a' : '#ffffff',
                                color: filter === tab.id ? '#ffffff' : '#334155',
                                fontSize: '0.8rem',
                                fontWeight: 600,
                                cursor: 'pointer',
                            }}
                        >
                            {tab.label}
                        </button>
                    ))}
                </div>
            </div>

            {/* Findings Table */}
            <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                    <thead>
                        <tr style={{ borderBottom: '1px solid #e2e8f0', fontSize: '0.78rem', color: '#64748b' }}>
                            <th style={{ padding: '0.75rem 1rem', width: '32px' }}></th>
                            <th style={{ padding: '0.75rem 1rem' }}>CVE & Package</th>
                            <th style={{ padding: '0.75rem 1rem' }}>AST Reachability</th>
                            <th style={{ padding: '0.75rem 1rem' }}>EPSS / CVSS</th>
                            <th style={{ padding: '0.75rem 1rem' }}>Utility Score</th>
                            <th style={{ padding: '0.75rem 1rem' }}>Priority Tier</th>
                        </tr>
                    </thead>
                    <tbody>
                        {filteredFindings.map((f) => {
                            const isExpanded = expandedCve === f.cve_id;
                            const tierStyle = TIER_STYLES[f.priority_tier] || TIER_STYLES.LOW_RISK;

                            return (
                                <React.Fragment key={f.cve_id}>
                                    <tr
                                        onClick={() => toggleExpand(f.cve_id)}
                                        style={{
                                            borderBottom: '1px solid #f1f5f9',
                                            cursor: 'pointer',
                                            background: isExpanded ? '#f8fafc' : '#ffffff',
                                            opacity: f.is_reachable ? 1 : 0.72,
                                        }}
                                    >
                                        <td style={{ padding: '0.85rem 1rem', color: '#64748b' }}>
                                            {isExpanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                                        </td>

                                        <td style={{ padding: '0.85rem 1rem' }}>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                                                <strong style={{ color: '#0f172a' }}>{f.cve_id}</strong>
                                                {f.is_in_kev && (
                                                    <span
                                                        title="CISA Known Exploited Vulnerability"
                                                        style={{
                                                            display: 'inline-flex',
                                                            alignItems: 'center',
                                                            gap: '0.2rem',
                                                            background: '#7f1d1d',
                                                            color: '#fff',
                                                            fontSize: '0.68rem',
                                                            fontWeight: 700,
                                                            padding: '0.12rem 0.4rem',
                                                            borderRadius: '4px',
                                                        }}
                                                    >
                                                        <Flame size={11} /> KEV
                                                    </span>
                                                )}
                                            </div>
                                            <div style={{ fontSize: '0.82rem', color: '#475569', marginTop: '0.15rem' }}>
                                                <code>{f.package_name}</code> @ <code>{f.installed_version}</code>
                                                {f.fixed_version && (
                                                    <span style={{ color: '#15803d' }}> → fix: {f.fixed_version}</span>
                                                )}
                                            </div>
                                        </td>

                                        <td style={{ padding: '0.85rem 1rem' }}>
                                            {f.is_reachable ? (
                                                <span
                                                    style={{
                                                        background: '#fef2f2',
                                                        color: '#b91c1c',
                                                        border: '1px solid #fecaca',
                                                        padding: '0.22rem 0.55rem',
                                                        borderRadius: '5px',
                                                        fontSize: '0.78rem',
                                                        fontWeight: 600,
                                                    }}
                                                >
                                                    Reachable ({Math.round(f.reachability_confidence * 100)}%)
                                                </span>
                                            ) : (
                                                <span
                                                    style={{
                                                        background: '#f1f5f9',
                                                        color: '#64748b',
                                                        padding: '0.22rem 0.55rem',
                                                        borderRadius: '5px',
                                                        fontSize: '0.78rem',
                                                        fontWeight: 600,
                                                    }}
                                                >
                                                    Unreachable (0%)
                                                </span>
                                            )}
                                        </td>

                                        <td style={{ padding: '0.85rem 1rem', fontSize: '0.85rem' }}>
                                            <div>
                                                <strong>EPSS:</strong> {(f.epss_score * 100).toFixed(1)}%
                                            </div>
                                            <div style={{ color: '#64748b' }}>
                                                <strong>CVSS:</strong> {f.cvss_score.toFixed(1)}
                                            </div>
                                        </td>

                                        <td style={{ padding: '0.85rem 1rem' }}>
                                            <span style={{ fontSize: '1.15rem', fontWeight: 700, color: '#0f172a' }}>
                                                {f.utility_score.toFixed(1)}
                                            </span>
                                            <span style={{ fontSize: '0.78rem', color: '#64748b' }}> / 100</span>
                                        </td>

                                        <td style={{ padding: '0.85rem 1rem' }}>
                                            <span
                                                style={{
                                                    background: tierStyle.bg,
                                                    color: tierStyle.text,
                                                    border: `1px solid ${tierStyle.border}`,
                                                    padding: '0.25rem 0.6rem',
                                                    borderRadius: '999px',
                                                    fontSize: '0.74rem',
                                                    fontWeight: 700,
                                                }}
                                            >
                                                {tierStyle.label}
                                            </span>
                                        </td>
                                    </tr>

                                    {/* Expandable Drawer: Call-Graph Trace + AI Reasoning + Remediation */}
                                    {isExpanded && (
                                        <tr style={{ background: '#f8fafc', borderBottom: '1px solid #e2e8f0' }}>
                                            <td colSpan={6} style={{ padding: '1rem 1.5rem 1.25rem 2.75rem' }}>
                                                <CallPathViewer
                                                    callPath={f.call_path}
                                                    isReachable={f.is_reachable}
                                                    vulnerableSymbols={f.vulnerable_symbols}
                                                />

                                                <div
                                                    style={{
                                                        display: 'grid',
                                                        gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
                                                        gap: '1rem',
                                                        marginTop: '0.85rem',
                                                    }}
                                                >
                                                    <div
                                                        style={{
                                                            background: '#ffffff',
                                                            border: '1px solid #e2e8f0',
                                                            borderRadius: '6px',
                                                            padding: '0.75rem',
                                                            fontSize: '0.85rem',
                                                        }}
                                                    >
                                                        <div style={{ fontWeight: 600, color: '#334155', marginBottom: '0.25rem' }}>
                                                            Agent Context & Exploit Reasoning
                                                        </div>
                                                        <div style={{ color: '#475569', lineHeight: 1.45 }}>{f.ai_reasoning}</div>
                                                    </div>

                                                    <div
                                                        style={{
                                                            background: '#eff6ff',
                                                            border: '1px solid #bfdbfe',
                                                            borderRadius: '6px',
                                                            padding: '0.75rem',
                                                            fontSize: '0.85rem',
                                                        }}
                                                    >
                                                        <div
                                                            style={{
                                                                display: 'flex',
                                                                alignItems: 'center',
                                                                gap: '0.35rem',
                                                                fontWeight: 600,
                                                                color: '#1e40af',
                                                                marginBottom: '0.25rem',
                                                            }}
                                                        >
                                                            <Wrench size={14} /> Recommended Remediation
                                                        </div>
                                                        <div style={{ color: '#1e3a8a', lineHeight: 1.45 }}>
                                                            {f.remediation_advice}
                                                        </div>
                                                    </div>
                                                </div>
                                            </td>
                                        </tr>
                                    )}
                                </React.Fragment>
                            );
                        })}
                    </tbody>
                </table>
            </div>
        </div>
    );
}