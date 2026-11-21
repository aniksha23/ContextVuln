import React from 'react';
import { ArrowRight, GitCommit, ShieldCheck } from 'lucide-react';

export default function CallPathViewer({ callPath, isReachable, vulnerableSymbols }) {
    if (!isReachable || !callPath || callPath.length === 0) {
        return (
            <div
                style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem',
                    padding: '0.6rem 0.85rem',
                    background: '#f8fafc',
                    border: '1px dashed #cbd5e1',
                    borderRadius: '6px',
                    fontSize: '0.82rem',
                    color: '#64748b',
                }}
            >
                <ShieldCheck size={16} color="#16a34a" />
                <span>
                    No AST execution path reaches{' '}
                    <code style={{ color: '#334155' }}>
                        {vulnerableSymbols?.join(', ') || 'vulnerable symbol'}
                    </code>
                    .
                </span>
            </div>
        );
    }

    return (
        <div
            style={{
                background: '#0f172a',
                color: '#f8fafc',
                padding: '0.75rem 1rem',
                borderRadius: '8px',
                fontSize: '0.82rem',
            }}
        >
            <div
                style={{
                    fontSize: '0.72rem',
                    textTransform: 'uppercase',
                    letterSpacing: '0.05em',
                    color: '#94a3b8',
                    marginBottom: '0.5rem',
                    fontWeight: 600,
                }}
            >
                Verified AST Call-Graph Execution Trace
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.45rem' }}>
                {callPath.map((node, index) => {
                    const isSink = index === callPath.length - 1;
                    return (
                        <React.Fragment key={`${node}-${index}`}>
                            <span
                                style={{
                                    display: 'inline-flex',
                                    alignItems: 'center',
                                    gap: '0.3rem',
                                    padding: '0.3rem 0.6rem',
                                    borderRadius: '5px',
                                    fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
                                    background: isSink ? '#7f1d1d' : '#1e293b',
                                    border: isSink ? '1px solid #ef4444' : '1px solid #334155',
                                    color: isSink ? '#fecaca' : '#e2e8f0',
                                    fontWeight: isSink ? 700 : 400,
                                }}
                            >
                                <GitCommit size={13} />
                                {node}
                            </span>
                            {!isSink && <ArrowRight size={14} color="#64748b" />}
                        </React.Fragment>
                    );
                })}
            </div>
        </div>
    );
}