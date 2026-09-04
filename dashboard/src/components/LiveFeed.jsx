import React, { useState, useEffect } from 'react';
import { AlertCircle, CheckCircle, Lock, Eye, XCircle, ArrowRight, Shield } from 'lucide-react';
import SlideOver from './common/SlideOver';
import { fetchAuditLogs } from '../api';

const StatusBadge = ({ status }) => {
    const styles = {
        PASS: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
        BLOCK: 'bg-red-500/10 text-red-400 border-red-500/20',
        SANITIZED: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
    };

    const icons = {
        PASS: CheckCircle,
        BLOCK: Lock,
        SANITIZED: AlertCircle,
    };

    const Icon = icons[status] || CheckCircle;

    return (
        <span className={`flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-medium border ${styles[status] || styles.PASS}`}>
            <Icon size={12} />
            <span>{status}</span>
        </span>
    );
};

const LiveFeed = () => {
    const [selectedReq, setSelectedReq] = useState(null);
    const [requests, setRequests] = useState([]);

    useEffect(() => {
        const load = async () => {
            try {
                const data = await fetchAuditLogs();
                // Transform Backend Data to UI Format
                if (Array.isArray(data)) {
                    const formatted = data.map(log => ({
                        id: (log.request_id || 'unknown').substring(0, 8) + '...', // Short ID
                        fullId: log.request_id,
                        time: new Date(log.timestamp).toLocaleTimeString(),
                        method: 'POST', // Assumed
                        provider: log.provider,
                        path: '/v1/chat/completions', // Placeholder
                        status: log.verdict === 'BLOCK' ? 'BLOCK' : (log.sanitized ? 'SANITIZED' : 'PASS'),
                        risk: log.risk_score,
                        prompt: "Prompt content not logged in cleartext (Hash: " + (log.prompt_hash || '').substring(0, 8) + ")",
                        sanitized_prompt: "Hash: " + (log.prompt_hash || 'none').substring(0, 8)
                    }));
                    setRequests(formatted);
                }
            } catch (e) {
                console.error("Failed to fetch logs", e);
            }
        };

        load();
        const interval = setInterval(load, 2000); // 2s polling
        return () => clearInterval(interval);
    }, []);

    return (
        <>
            <div className="bg-slate-900 rounded-xl border border-slate-800 overflow-hidden">
                <div className="px-6 py-4 border-b border-slate-800 flex justify-between items-center">
                    <h3 className="font-semibold text-slate-100">Live Traffic Feed</h3>
                    <span className="flex h-2 w-2 relative">
                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                        <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                    </span>
                </div>

                <div className="overflow-x-auto">
                    <table className="w-full text-left">
                        <thead className="bg-slate-950 text-slate-400 text-xs uppercase font-medium">
                            <tr>
                                <th className="px-6 py-3">Timestamp</th>
                                <th className="px-6 py-3">Req ID</th>
                                <th className="px-6 py-3">Provider</th>
                                <th className="px-6 py-3">Status</th>
                                <th className="px-6 py-3 text-right">Risk Score</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800">
                            {requests.map((req, i) => (
                                <tr
                                    key={i}
                                    className="hover:bg-slate-800/50 transition-colors cursor-pointer"
                                    onClick={() => setSelectedReq(req)}
                                >
                                    <td className="px-6 py-4 text-sm text-slate-400 font-mono">{req.time}</td>
                                    <td className="px-6 py-4 text-sm text-slate-300 font-mono">{req.id}</td>
                                    <td className="px-6 py-4 text-sm text-slate-300">{req.provider}</td>
                                    <td className="px-6 py-4">
                                        <StatusBadge status={req.status} />
                                    </td>
                                    <td className="px-6 py-4 text-right">
                                        <span className={`text-sm font-bold ${req.risk > 80 ? 'text-red-400' :
                                            req.risk > 50 ? 'text-amber-400' : 'text-emerald-400'
                                            }`}>
                                            {req.risk}
                                        </span>
                                    </td>
                                </tr>
                            ))}
                            {requests.length === 0 && (
                                <tr>
                                    <td colSpan="5" className="px-6 py-8 text-center text-slate-500">
                                        Waiting for traffic... (Send a request via curl)
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            <SlideOver
                isOpen={!!selectedReq}
                onClose={() => setSelectedReq(null)}
                title="Request Details"
            >
                {selectedReq && (
                    <div className="space-y-6">
                        {/* Detail content simplified as we don't store full prompt in DB yet */}
                        <div className="p-4 bg-slate-950 rounded-lg text-slate-400 text-sm">
                            Full Prompt viewing not available in Audit mode (Privacy).
                            <br />Risk Score: {selectedReq.risk}
                        </div>
                    </div>
                )}
            </SlideOver>
        </>
    );
};

export default LiveFeed;
