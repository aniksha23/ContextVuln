import React from 'react';
import { AlertTriangle, CheckCircle2, Layers, ShieldOff } from 'lucide-react';

export default function MetricsSummary({ report }) {
    const cards = [
        {
            label: 'Raw Scanner CVEs',
            value: report.total_cves_found,
            subtext: 'Total dependency alerts',
            color: '#0f172a',
            bg: '#f8fafc',
            border: '#e2e8f0',
            icon: <Layers size={20} color="#475569" />,
        },
        {
            label: 'Confirmed Reachable',
            value: report.reachable_cves,
            subtext: 'Verified AST call-path exists',
            color: '#b91c1c',
            bg: '#fef2f2',
            border: '#fecaca',
            icon: <AlertTriangle size={20} color="#dc2626" />,
        },
        {
            label: 'Suppressed Noise',
            value: report.suppressed_cves,
            subtext: 'Unreachable dead-code CVEs',
            color: '#334155',
            bg: '#f1f5f9',
            border: '#cbd5e1',
            icon: <ShieldOff size={20} color="#64748b" />,
        },
        {
            label: 'False-Positive Reduction',
            value: `${report.noise_reduction_pct}%`,
            subtext: 'Triage workload eliminated',
            color: '#15803d',
            bg: '#f0fdf4',
            border: '#bbf7d0',
            icon: <CheckCircle2 size={20} color="#16a34a" />,
        },
    ];

    return (
        <div
            style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
                gap: '1rem',
                marginBottom: '1.5rem',
            }}
        >
            {cards.map((card) => (
                <div
                    key={card.label}
                    style={{
                        background: card.bg,
                        border: `1px solid ${card.border}`,
                        borderRadius: '10px',
                        padding: '1.1rem 1.25rem',
                    }}
                >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ fontSize: '0.82rem', fontWeight: 600, color: '#475569' }}>
                            {card.label}
                        </span>
                        {card.icon}
                    </div>
                    <div style={{ fontSize: '1.9rem', fontWeight: 700, color: card.color, margin: '0.35rem 0' }}>
                        {card.value}
                    </div>
                    <div style={{ fontSize: '0.78rem', color: '#64748b' }}>{card.subtext}</div>
                </div>
            ))}
        </div>
    );
}