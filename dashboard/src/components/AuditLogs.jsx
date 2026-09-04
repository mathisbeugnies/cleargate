import React, { useState } from 'react';
import { Download, Search, Filter, AlertTriangle, Shield } from 'lucide-react';

import { fetchAuditLogs, submitFeedbackException, fetchIntegrity } from '../api';

const LogDetailsModal = ({ log, onClose }) => {
    const [decryptedData, setDecryptedData] = useState(null);
    const [, setPrivateKey] = useState(null);
    const [error, setError] = useState('');

    // Check if log contains encrypted RSA data
    let encryptedMap = null;
    try {
        if (log.details && log.details.startsWith('{')) {
            const parsed = JSON.parse(log.details);
            // Check if any value starts with RSA:
            if (Object.values(parsed).some(v => v.startsWith('RSA:'))) {
                encryptedMap = parsed;
            }
        }
    } catch { /* details isn't encrypted JSON */ }

    const importPrivateKey = async (pem) => {
        // pem to binary
        const pemHeader = "-----BEGIN PRIVATE KEY-----";
        const pemFooter = "-----END PRIVATE KEY-----";
        const pemContents = pem.substring(
            pem.indexOf(pemHeader) + pemHeader.length,
            pem.indexOf(pemFooter)
        ).replace(/\s/g, ''); // remove all whitespace

        const binaryDerString = window.atob(pemContents);
        const binaryDer = new Uint8Array(binaryDerString.length);
        for (let i = 0; i < binaryDerString.length; i++) {
            binaryDer[i] = binaryDerString.charCodeAt(i);
        }

        return await window.crypto.subtle.importKey(
            "pkcs8",
            binaryDer.buffer,
            {
                name: "RSA-OAEP",
                hash: "SHA-256",
            },
            true,
            ["decrypt"]
        );
    };

    const handleFileUpload = async (e) => {
        const file = e.target.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = async (evt) => {
            try {
                const pem = evt.target.result;
                const key = await importPrivateKey(pem);
                setPrivateKey(key);
                decryptAll(key);
            } catch (err) {
                console.error(err);
                setError('Invalid Private Key file. Ensure it is the correct PEM format.');
            }
        };
        reader.readAsText(file);
    };

    const decryptPrompt = async (key) => {
        if (!log.prompt_encrypted || !log.prompt_encrypted.startsWith('RSA:')) return;
        try {
            const ciphertext = log.prompt_encrypted.substring(4);
            const binary = new Uint8Array(window.atob(ciphertext).split("").map(c => c.charCodeAt(0)));
            const decryptedBuffer = await window.crypto.subtle.decrypt(
                { name: "RSA-OAEP" },
                key,
                binary
            );
            const dec = new TextDecoder().decode(decryptedBuffer);
            // setDecryptedData needs to handle prompt specifically or just use a new state?
            // Existing logic uses decryptedData for the DETAILS map.
            // Let's store prompt separately in a ref or new state, but for simplicity let's misuse decryptedData or add a field.
            setDecryptedData(prev => ({ ...prev, _FULL_PROMPT_: dec }));
        } catch (err) {
            console.error("Prompt Decryption failed", err);
        }
    };

    const decryptAll = async (key) => {
        await decryptPrompt(key);
        if (!encryptedMap) return;
        const decrypted = {};

        for (const [k, v] of Object.entries(encryptedMap)) {
            if (v.startsWith('RSA:')) {
                try {
                    const ciphertext = v.substring(4); // Remove RSA:
                    const binary = new Uint8Array(window.atob(ciphertext).split("").map(c => c.charCodeAt(0)));
                    const decryptedBuffer = await window.crypto.subtle.decrypt(
                        { name: "RSA-OAEP" },
                        key,
                        binary
                    );
                    const dec = new TextDecoder().decode(decryptedBuffer);
                    decrypted[k] = dec;
                } catch (err) {
                    console.error("Decryption failed for " + k, err);
                    decrypted[k] = "[Decryption Failed]";
                }
            } else {
                decrypted[k] = v;
            }
        }
        setDecryptedData(decrypted);
    };

    const handleAllow = async () => {
        if (!decryptedData || !decryptedData._FULL_PROMPT_) {
            alert("Please decrypt the prompt first using the Organization Private Key.");
            return;
        }

        try {
            await submitFeedbackException(decryptedData._FULL_PROMPT_);
            alert("Exception Added! Future similar requests will be allowed.");
            onClose();
        } catch (e) {
            console.error(e);
            alert("Network error.");
        }
    };

    return (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center p-4 z-50">
            <div className="bg-slate-900 border border-slate-700 rounded-xl w-full max-w-2xl max-h-[80vh] overflow-y-auto shadow-2xl">
                <div className="p-6 border-b border-slate-800 flex justify-between items-center">
                    <h3 className="text-xl font-bold text-slate-100">Log Details: {log.id}</h3>
                    <button onClick={onClose} className="text-slate-400 hover:text-white">✕</button>
                </div>
                <div className="p-6 space-y-4">
                    <div className="grid grid-cols-2 gap-4 text-sm">
                        <div><span className="text-slate-500">Timestamp:</span> <div className="text-slate-200">{log.timestamp}</div></div>
                        <div><span className="text-slate-500">User:</span> <div className="text-slate-200">{log.user}</div></div>
                        <div><span className="text-slate-500">Action:</span> <div className="text-slate-200">{log.actionShort}</div></div>
                        <div><span className="text-slate-500">Outcome:</span> <div className="text-slate-200">{log.outcome}</div></div>
                    </div>

                    <div className="bg-black/30 p-4 rounded-lg border border-slate-800 font-mono text-xs overflow-x-auto text-slate-400">
                        {/* Raw Details if not encrypted map or plain text */}
                        {!encryptedMap && log.details}
                        {encryptedMap && !decryptedData && (
                            <div className="space-y-2">
                                <div className="flex items-center gap-2 text-amber-400 font-bold">
                                    <AlertTriangle size={16} /> Encrypted Content Detected
                                </div>
                                <pre>{JSON.stringify(encryptedMap, null, 2)}</pre>
                                <div className="pt-4 border-t border-slate-700">
                                    <label htmlFor="private-key-upload" className="block text-sm text-slate-400 mb-2">Unlock with Organization Private Key (.pem)</label>
                                    <input
                                        id="private-key-upload"
                                        name="private-key-upload"
                                        type="file"
                                        accept=".pem"
                                        onChange={handleFileUpload}
                                        className="block w-full text-sm text-slate-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-blue-600 file:text-white hover:file:bg-blue-700"
                                    />
                                    {error && <p className="text-red-400 text-xs mt-2">{error}</p>}
                                </div>
                            </div>
                        )}
                        {decryptedData && (
                            <div className="space-y-2">
                                <div className="flex items-center gap-2 text-emerald-400 font-bold">
                                    <Download size={16} /> Content Decrypted Successfully
                                </div>
                                <pre className="text-emerald-300">{JSON.stringify(decryptedData, null, 2)}</pre>
                            </div>
                        )}
                    </div>
                </div>
                {/* Full Prompt Section */}
                <div className="px-6 pb-6">
                    <h4 className="text-sm font-bold text-slate-400 mb-2">Original Prompt (Encrypted)</h4>
                    <div className="bg-black/30 p-4 rounded-lg border border-slate-800 font-mono text-xs text-slate-400 whitespace-pre-wrap">
                        {decryptedData && decryptedData._FULL_PROMPT_ ? (
                            <span className="text-emerald-300">{decryptedData._FULL_PROMPT_}</span>
                        ) : log.prompt_encrypted ? (
                            <span className="text-purple-400">{log.prompt_encrypted.substring(0, 50)}... [LOCKED]</span>
                        ) : (
                            <span className="text-slate-600">Not recorded (or not encrypted)</span>
                        )}
                    </div>
                </div>

                <div className="p-6 border-t border-slate-800 flex justify-between">
                    {log.outcome === 'BLOCK' && (
                        <button
                            onClick={handleAllow}
                            className="px-4 py-2 bg-purple-600 text-white rounded hover:bg-purple-500 shadow-lg shadow-purple-900/20"
                        >
                            ✅ Autoriser (Exception)
                        </button>
                    )}
                    <button onClick={onClose} className="px-4 py-2 bg-slate-800 text-slate-300 rounded hover:bg-slate-700">Close</button>
                </div>
            </div>
        </div>
    );
};

const AuditLogs = () => {
    const [logs, setLogs] = useState([]);
    const [loading, setLoading] = useState(true);
    const [selectedLog, setSelectedLog] = useState(null);

    const [filters, setFilters] = useState({
        q: '',
        risk: '',
        verdict: '',
        limit: 100
    });
    const [debouncedSearch, setDebouncedSearch] = useState('');

    React.useEffect(() => {
        const timer = setTimeout(() => {
            setDebouncedSearch(filters.q);
        }, 500);
        return () => clearTimeout(timer);
    }, [filters.q]);

    React.useEffect(() => {
        const load = async () => {
            setLoading(true);
            try {
                const query = { ...filters, q: debouncedSearch };
                // Clean empty
                Object.keys(query).forEach(key => !query[key] && delete query[key]);

                const data = await fetchAuditLogs(query);

                if (!Array.isArray(data)) {
                    console.warn("AuditLogs received non-array data:", data);
                    setLogs([]);
                    return;
                }

                const mapped = data.map(l => ({
                    id: l.request_id,
                    timestamp: new Date(l.timestamp).toLocaleString(),
                    user: l.user_id,
                    actionShort: l.threat_details?.length > 50 ? "Content Redacted/Blocked" : (l.threat_details || (l.sanitized ? "Sanitization" : "Standard Query")),
                    details: l.threat_details, // Keep full details
                    risk: l.risk_score > 80 ? 'HIGH' : l.risk_score > 0 ? 'MEDIUM' : 'LOW',
                    outcome: l.verdict, // BLOCK, PASS, SANITIZED
                    prompt_encrypted: l.prompt_encrypted
                }));
                setLogs(mapped);
            } catch (e) {
                console.error("Failed to load audit logs", e);
            } finally {
                setLoading(false);
            }
        };
        load();

        // Optional: poll every 10s if no search active
        if (!debouncedSearch) {
            const interval = setInterval(load, 10000);
            return () => clearInterval(interval);
        }
    }, [debouncedSearch, filters.risk, filters.verdict]); // Trigger on debounce or filter change

    const handleExport = () => {
        const csvContent = "data:text/csv;charset=utf-8,"
            + "ID,Timestamp,User,Action,Risk,Outcome\n"
            + logs.map(e => `${e.id},${e.timestamp},${e.user},${e.actionShort},${e.risk},${e.outcome}`).join("\n");
        const encodedUri = encodeURI(csvContent);
        const link = document.createElement("a");
        link.setAttribute("href", encodedUri);
        link.setAttribute("download", "audit_logs.csv");
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    };

    return (
        <div className="space-y-6">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                    <h2 className="text-2xl font-bold text-slate-100">Audit Logs</h2>
                    <p className="text-slate-500">Immutable record of all security events and proxy traffic.</p>
                </div>
                <div className="flex gap-2">
                    <div className="flex items-center gap-2 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2">
                        <Filter size={16} className="text-slate-500" />
                        <label htmlFor="risk-filter" className="sr-only">Filter by Risk</label>
                        <select
                            id="risk-filter"
                            name="risk-filter"
                            className="bg-transparent text-slate-300 text-sm focus:outline-none"
                            value={filters.risk}
                            onChange={(e) => setFilters(prev => ({ ...prev, risk: e.target.value }))}
                        >
                            <option value="">All Risks</option>
                            <option value="HIGH">High Risk</option>
                            <option value="MEDIUM">Medium Risk</option>
                            <option value="LOW">Low Risk</option>
                        </select>
                    </div>
                    <div className="flex items-center gap-2 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2">
                        <Shield size={16} className="text-slate-500" />
                        <label htmlFor="verdict-filter" className="sr-only">Filter by Verdict</label>
                        <select
                            id="verdict-filter"
                            name="verdict-filter"
                            className="bg-transparent text-slate-300 text-sm focus:outline-none"
                            value={filters.verdict}
                            onChange={(e) => setFilters(prev => ({ ...prev, verdict: e.target.value }))}
                        >
                            <option value="">All Verdicts</option>
                            <option value="BLOCK">Blocked</option>
                            <option value="PASS">Allowed</option>
                        </select>
                    </div>

                    <button
                        onClick={async () => {
                            const btn = document.getElementById('integrity-btn');
                            btn.innerText = "Checking...";
                            btn.disabled = true;
                            try {
                                const data = await fetchIntegrity();
                                if (data.valid) {
                                    alert(`Integrity Verified! \n${data.total_checked} logs checked.\nHash Chain Intact.`);
                                } else {
                                    alert(`CRITICAL: Integrity Check Failed!\nError: ${data.error}\nBroken log ID: ${data.broken_at_id}`);
                                }
                            } catch {
                                alert("Failed to contact verification server.");
                            }
                            btn.innerText = "Values Validated";
                            btn.disabled = false;
                            setTimeout(() => btn.innerText = "Verify Integrity", 3000);
                        }}
                        id="integrity-btn"
                        className="flex items-center gap-2 px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-500 transition-colors shadow-lg shadow-purple-900/20"
                    >
                        🛡️ Verify Integrity
                    </button>
                    <button
                        onClick={handleExport}
                        className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-500 transition-colors shadow-lg shadow-blue-900/20"
                    >
                        <Download size={16} /> Export CSV
                    </button>
                </div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
                <div className="p-4 border-b border-slate-800 flex flex-col md:flex-row gap-4 justify-between items-center">
                    <div className="relative flex-1">
                        <label htmlFor="audit-search" className="sr-only">Search</label>
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" size={16} />
                        <input
                            id="audit-search"
                            name="audit-search"
                            type="text"
                            autoComplete="off"
                            placeholder="Search logs..."
                            className="w-full bg-black/20 border border-slate-700 rounded-lg py-2 pl-10 pr-4 text-slate-200 focus:outline-none focus:border-blue-500 transition-colors"
                            value={filters.q}
                            onChange={(e) => setFilters(prev => ({ ...prev, q: e.target.value }))}
                        />
                    </div>
                    <div className="text-slate-500 text-sm font-mono">
                        {loading ? 'Searching...' : `${logs.length} results found`}
                    </div>
                </div>

                <div className="overflow-x-auto">
                    <table className="w-full text-left text-sm">
                        <thead className="bg-slate-950 text-slate-400 text-xs uppercase font-medium">
                            <tr>
                                <th className="px-6 py-3">Timestamp</th>
                                <th className="px-6 py-3">User</th>
                                <th className="px-6 py-3">Event Action</th>
                                <th className="px-6 py-3">Risk Level</th>
                                <th className="px-6 py-3 text-right">Outcome</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800">
                            {logs.map((log) => (
                                <tr
                                    key={log.id}
                                    onClick={() => setSelectedLog(log)}
                                    className="hover:bg-slate-800/50 transition-colors cursor-pointer group"
                                >
                                    <td className="px-6 py-4 text-slate-400 font-mono text-xs">{log.timestamp}</td>
                                    <td className="px-6 py-4 text-slate-300">{log.user}</td>
                                    <td className="px-6 py-4 text-slate-200 font-medium">{log.actionShort}</td>
                                    <td className="px-6 py-4">
                                        <span className={`inline-flex items-center gap-1 font-bold ${log.risk === 'HIGH' ? 'text-red-400' :
                                            log.risk === 'MEDIUM' ? 'text-amber-400' : 'text-slate-500'
                                            }`}>
                                            {log.risk === 'HIGH' && <AlertTriangle size={12} />}
                                            {log.risk}
                                        </span>
                                    </td>
                                    <td className="px-6 py-4 text-right">
                                        <span className={`px-2 py-1 rounded text-xs font-bold ${log.outcome === 'BLOCK' ? 'bg-red-500/20 text-red-400' :
                                            log.outcome === 'SANITIZED' ? 'bg-amber-500/20 text-amber-400' :
                                                'bg-emerald-500/20 text-emerald-400'
                                            }`}>
                                            {log.outcome}
                                        </span>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>

            {selectedLog && <LogDetailsModal log={selectedLog} onClose={() => setSelectedLog(null)} />}
        </div>
    );
};

export default AuditLogs;
