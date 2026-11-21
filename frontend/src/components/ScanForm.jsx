import React, { useState } from 'react';
import { ShieldAlert, Play, GitBranch, FileArchive, UploadCloud } from 'lucide-react';

export default function ScanForm({ onScan, loading }) {
    const [mode, setMode] = useState('github'); // 'github' | 'upload'
    const [repoUrl, setRepoUrl] = useState('https://github.com/pallets/flask');
    const [zipFile, setZipFile] = useState(null);
    const [criticality, setCriticality] = useState('1.0');

    const handleSubmit = (e) => {
        e.preventDefault();
        if (mode === 'github') {
            if (!repoUrl.trim()) return;
            onScan({ mode: 'github', repoUrl: repoUrl.trim(), criticality });
        } else {
            if (!zipFile) return;
            onScan({ mode: 'upload', zipFile, criticality });
        }
    };

    return (
        <form
            onSubmit={handleSubmit}
            style={{
                background: '#ffffff',
                border: '1px solid #e2e8f0',
                borderRadius: '10px',
                padding: '1.25rem',
                marginBottom: '1.5rem',
                boxShadow: '0 1px 3px rgba(0,0,0,0.05)',
            }}
        >
            {/* Mode Switcher Tabs */}
            <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
                <button
                    type="button"
                    onClick={() => setMode('github')}
                    style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '0.4rem',
                        padding: '0.45rem 0.9rem',
                        borderRadius: '6px',
                        border: mode === 'github' ? '1px solid #0f172a' : '1px solid #cbd5e1',
                        background: mode === 'github' ? '#0f172a' : '#f8fafc',
                        color: mode === 'github' ? '#ffffff' : '#334155',
                        fontSize: '0.85rem',
                        fontWeight: 600,
                        cursor: 'pointer',
                    }}
                >
                    <GitBranch size={15} />
                    GitHub Repository URL
                </button>

                <button
                    type="button"
                    onClick={() => setMode('upload')}
                    style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '0.4rem',
                        padding: '0.45rem 0.9rem',
                        borderRadius: '6px',
                        border: mode === 'upload' ? '1px solid #0f172a' : '1px solid #cbd5e1',
                        background: mode === 'upload' ? '#0f172a' : '#f8fafc',
                        color: mode === 'upload' ? '#ffffff' : '#334155',
                        fontSize: '0.85rem',
                        fontWeight: 600,
                        cursor: 'pointer',
                    }}
                >
                    <FileArchive size={15} />
                    Upload Project (.zip)
                </button>
            </div>

            {/* Input Controls */}
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', alignItems: 'flex-end' }}>
                {mode === 'github' ? (
                    <div style={{ flex: '1 1 360px' }}>
                        <label
                            style={{
                                display: 'flex',
                                alignItems: 'center',
                                gap: '0.4rem',
                                fontSize: '0.85rem',
                                fontWeight: 600,
                                color: '#334155',
                                marginBottom: '0.4rem',
                            }}
                        >
                            <GitBranch size={16} />
                            Public GitHub Repository URL
                        </label>
                        <input
                            type="url"
                            value={repoUrl}
                            onChange={(e) => setRepoUrl(e.target.value)}
                            placeholder="https://github.com/owner/repository"
                            required
                            style={{
                                width: '100%',
                                padding: '0.65rem 0.85rem',
                                borderRadius: '6px',
                                border: '1px solid #cbd5e1',
                                fontSize: '0.95rem',
                                boxSizing: 'border-box',
                            }}
                        />
                    </div>
                ) : (
                    <div style={{ flex: '1 1 360px' }}>
                        <label
                            style={{
                                display: 'flex',
                                alignItems: 'center',
                                gap: '0.4rem',
                                fontSize: '0.85rem',
                                fontWeight: 600,
                                color: '#334155',
                                marginBottom: '0.4rem',
                            }}
                        >
                            <UploadCloud size={16} />
                            Project Folder Archive (.zip)
                        </label>
                        <input
                            type="file"
                            accept=".zip"
                            onChange={(e) => setZipFile(e.target.files?.[0] || null)}
                            required
                            style={{
                                width: '100%',
                                padding: '0.52rem 0.75rem',
                                borderRadius: '6px',
                                border: '1px solid #cbd5e1',
                                background: '#f8fafc',
                                fontSize: '0.9rem',
                                boxSizing: 'border-box',
                            }}
                        />
                    </div>
                )}

                <div style={{ flex: '0 1 240px' }}>
                    <label
                        style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '0.4rem',
                            fontSize: '0.85rem',
                            fontWeight: 600,
                            color: '#334155',
                            marginBottom: '0.4rem',
                        }}
                    >
                        <ShieldAlert size={16} />
                        Deployment Exposure (Criticality)
                    </label>
                    <select
                        value={criticality}
                        onChange={(e) => setCriticality(e.target.value)}
                        style={{
                            width: '100%',
                            padding: '0.65rem 0.85rem',
                            borderRadius: '6px',
                            border: '1px solid #cbd5e1',
                            fontSize: '0.95rem',
                            background: '#fff',
                        }}
                    >
                        <option value="0.7">Internal Tooling (0.7x)</option>
                        <option value="1.0">Standard Application (1.0x)</option>
                        <option value="1.4">Public-Facing Production (1.4x)</option>
                    </select>
                </div>

                <button
                    type="submit"
                    disabled={loading || (mode === 'upload' && !zipFile)}
                    style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '0.5rem',
                        padding: '0.68rem 1.4rem',
                        background: loading ? '#64748b' : '#0f172a',
                        color: '#ffffff',
                        border: 'none',
                        borderRadius: '6px',
                        fontWeight: 600,
                        fontSize: '0.95rem',
                        cursor: loading ? 'not-allowed' : 'pointer',
                    }}
                >
                    <Play size={16} />
                    {loading ? 'Analyzing Call Graph...' : 'Run ContextVuln Scan'}
                </button>
            </div>
        </form>
    );
}