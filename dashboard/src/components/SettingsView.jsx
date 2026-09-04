import React, { useState, useEffect } from 'react';
import { Server, ShieldAlert, Key, Lock, Download, Check, RefreshCw, Trash2, Activity, Cpu } from 'lucide-react';
import { flushAuditLogs, reloadProxy, fetchStats, uploadPublicKey } from '../api';

const SettingsView = () => {
    const [generating, setGenerating] = useState(false);
    const [status, setStatus] = useState('');

    // Maintenance State
    const [flushing, setFlushing] = useState(false);
    const [reloading, setReloading] = useState(false);
    const [maintenanceMsg, setMaintenanceMsg] = useState('');

    // Stats State
    const [stats, setStats] = useState(null);

    useEffect(() => {
        loadStats();
        // Poll stats every 10s
        const interval = setInterval(loadStats, 10000);
        return () => clearInterval(interval);
    }, []);

    const loadStats = async () => {
        try {
            const data = await fetchStats();
            setStats(data);
        } catch (err) {
            console.error(err);
        }
    };

    const handleFlush = async () => {
        if (!window.confirm("Are you sure? This will delete all logs older than 90 days.")) return;
        setFlushing(true);
        try {
            const res = await flushAuditLogs();
            setMaintenanceMsg(`Success: Deleted ${res.deleted} old logs.`);
            setTimeout(() => setMaintenanceMsg(''), 5000);
        } catch {
            setMaintenanceMsg('Error flushing logs.');
        } finally {
            setFlushing(false);
        }
    };

    const handleReload = async () => {
        setReloading(true);
        try {
            await reloadProxy();
            setMaintenanceMsg('Success: Proxy Reload Signal Sent.');
            setTimeout(() => setMaintenanceMsg(''), 5000);
        } catch {
            setMaintenanceMsg('Error sending reload signal.');
        } finally {
            setReloading(false);
        }
    };

    const arrayBufferToBase64 = (buffer) => {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    };

    const exportPEM = async (key, type) => {
        const exported = await window.crypto.subtle.exportKey('spki', key);
        const exportedAsBase64 = arrayBufferToBase64(exported);
        const pem = `-----BEGIN PUBLIC KEY-----\n${exportedAsBase64}\n-----END PUBLIC KEY-----`;
        return pem;
    };

    const exportPrivatePEM = async (key) => {
        const exported = await window.crypto.subtle.exportKey('pkcs8', key);
        const exportedAsBase64 = arrayBufferToBase64(exported);
        const pem = `-----BEGIN PRIVATE KEY-----\n${exportedAsBase64}\n-----END PRIVATE KEY-----`;
        return pem;
    };

    const generateKeys = async () => {
        setGenerating(true);
        setStatus('Generating RSA-OAEP Key Pair...');
        try {
            const keyPair = await window.crypto.subtle.generateKey(
                {
                    name: "RSA-OAEP",
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: "SHA-256",
                },
                true,
                ["encrypt", "decrypt"]
            );

            // 1. Prepare Public Key for Server
            const publicKeyPEM = await exportPEM(keyPair.publicKey);

            // 2. Prepare Private Key for User Download
            const privateKeyPEM = await exportPrivatePEM(keyPair.privateKey);

            // 3. Upload Public Key
            setStatus('Uploading Public Key to ClearGate...');
            await uploadPublicKey(publicKeyPEM);

            // 4. Trigger Download of Private Key
            const blob = new Blob([privateKeyPEM], { type: 'application/x-pem-file' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'cleargate_private_key.pem';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);

            setStatus('Success! Private Key downloaded. Keep it safe!');
        } catch (err) {
            console.error(err);
            setStatus('Error: ' + err.message);
        } finally {
            setGenerating(false);
        }
    };

    return (
        <div className="space-y-6">
            {/* System Status / Health Dashboard */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
                <h3 className="text-lg font-semibold text-slate-100 flex items-center mb-4">
                    <Activity className="mr-2 text-blue-400" size={20} /> System Health
                </h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                    <div className="p-4 bg-black/20 rounded-lg">
                        <span className="text-slate-500 block mb-1">Status</span>
                        <span className="text-emerald-400 font-mono font-bold flex items-center">
                            <div className="w-2 h-2 rounded-full bg-emerald-500 mr-2 animate-pulse"></div>
                            ONLINE
                        </span>
                    </div>
                    <div className="p-4 bg-black/20 rounded-lg">
                        <span className="text-slate-500 block mb-1">Memory Usage</span>
                        <span className="text-slate-200 font-mono text-lg">
                            {stats ? `${stats.mem_usage_mb} MB` : '...'}
                        </span>
                    </div>
                    <div className="p-4 bg-black/20 rounded-lg">
                        <span className="text-slate-500 block mb-1">Goroutines</span>
                        <span className="text-slate-200 font-mono text-lg">
                            {stats ? stats.num_goroutine : '...'}
                        </span>
                    </div>
                    <div className="p-4 bg-black/20 rounded-lg">
                        <span className="text-slate-500 block mb-1">Active Vectors</span>
                        <span className="text-indigo-400 font-mono text-lg">
                            {stats ? stats.vector_count : '...'}
                        </span>
                    </div>
                </div>
            </div>

            {/* Encryption */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
                <h3 className="text-lg font-semibold text-slate-100 flex items-center mb-4">
                    <Lock className="mr-2 text-emerald-400" size={20} /> Encryption & Privacy
                </h3>
                <div className="bg-black/20 p-4 rounded-lg border border-slate-800">
                    <div className="flex justify-between items-start">
                        <div>
                            <h4 className="text-slate-200 font-medium mb-1">Zero-Knowledge Encryption</h4>
                            <p className="text-sm text-slate-500 mb-4 max-w-xl">
                                Generate an RSA Key Pair to encrypt intercepted secrets (PII).
                                The <strong>Public Key</strong> is stored on the server to encrypt data.
                                The <strong>Private Key</strong> is downloaded to your device and is required to unlock data in Audit Logs.
                                The server <em>never</em> sees your Private Key.
                            </p>
                            {status && (
                                <div className={`text-sm mb-4 px-3 py-2 rounded ${status.includes('Error') ? 'bg-red-500/10 text-red-400' : 'bg-emerald-500/10 text-emerald-400'}`}>
                                    {status}
                                </div>
                            )}
                            <button
                                onClick={generateKeys}
                                disabled={generating}
                                className="px-4 py-2 bg-emerald-600 text-white rounded-lg hover:bg-emerald-500 transition-colors flex items-center shadow-lg shadow-emerald-900/20"
                            >
                                {generating ? <Server className="animate-pulse mr-2" size={18} /> : <Key className="mr-2" size={18} />}
                                {generating ? 'Processing...' : 'Generate New Key Pair'}
                            </button>
                        </div>
                        <div className="hidden md:block">
                            <ShieldAlert className="text-slate-700" size={64} />
                        </div>
                    </div>
                </div>
            </div>

            {/* Maintenance / Danger Zone */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
                <h3 className="text-lg font-semibold text-slate-100 flex items-center mb-4">
                    <ShieldAlert className="mr-2 text-red-400" size={20} /> Maintenance & Danger Zone
                </h3>
                <p className="text-slate-500 text-sm mb-4">
                    Administrative actions. These are executed immediately.
                </p>

                {maintenanceMsg && (
                    <div className="mb-4 p-3 rounded bg-blue-500/10 text-blue-400 text-sm border border-blue-500/20">
                        {maintenanceMsg}
                    </div>
                )}

                <div className="flex space-x-4">
                    <button
                        onClick={handleFlush}
                        disabled={flushing}
                        className="px-4 py-2 bg-red-500/10 text-red-400 border border-red-500/20 rounded-lg hover:bg-red-500/20 transition-colors flex items-center"
                    >
                        <Trash2 size={16} className="mr-2" />
                        {flushing ? 'Flushing...' : 'Flush Old Logs (>90d)'}
                    </button>

                    <button
                        onClick={handleReload}
                        disabled={reloading}
                        className="px-4 py-2 bg-slate-800 text-slate-300 border border-slate-700 rounded-lg hover:bg-slate-700 transition-colors flex items-center"
                    >
                        <RefreshCw size={16} className={`mr-2 ${reloading ? 'animate-spin' : ''}`} />
                        {reloading ? 'Reloading...' : 'Restart Proxy Service'}
                    </button>
                </div>
            </div>
        </div>
    );
};

export default SettingsView;
