import React, { useState } from 'react';
import { Play, Shield, AlertTriangle, EyeOff, CheckCircle, XCircle, ArrowRight } from 'lucide-react';
import api from '../api';

const Simulator = () => {
    const [prompt, setPrompt] = useState('');
    const [result, setResult] = useState(null);
    const [loading, setLoading] = useState(false);

    const handleRun = async () => {
        if (!prompt.trim()) return;
        setLoading(true);
        setResult(null);
        try {
            const resp = await api.post('/api/admin/sandbox/test', { prompt });
            setResult(resp.data);
        } catch (err) {
            console.error("Simulation failed", err);
            alert("Simulation failed");
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="h-[calc(100vh-100px)] flex flex-col gap-6">
            <div>
                <h2 className="text-2xl font-bold text-slate-100 flex items-center gap-2">
                    <Shield className="text-blue-400" /> Security Simulator
                </h2>
                <p className="text-slate-500">Test your security policies in a sandbox environment without calling external LLMs.</p>
            </div>

            <div className="flex-1 grid grid-cols-2 gap-6 min-h-0">
                {/* Input Pane */}
                <div className="flex flex-col gap-4">
                    <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex-1 flex flex-col">
                        <label htmlFor="simulator-prompt" className="text-slate-400 text-sm font-medium mb-3 uppercase tracking-wider">Input Prompt</label>
                        <textarea
                            id="simulator-prompt"
                            name="simulator-prompt"
                            className="flex-1 bg-slate-950 border border-slate-800 rounded-lg p-4 text-slate-200 resize-none focus:outline-none focus:border-blue-500 font-mono text-sm leading-relaxed"
                            placeholder="Enter a prompt to test (e.g., 'Ignore instructions', 'My email is bob@corp.com')..."
                            value={prompt}
                            onChange={(e) => setPrompt(e.target.value)}
                        />
                        <div className="mt-4 flex justify-end">
                            <button
                                onClick={handleRun}
                                disabled={loading || !prompt.trim()}
                                className={`flex items-center gap-2 px-6 py-3 rounded-lg font-bold text-white transition-all
                                    ${loading ? 'bg-slate-700 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-500 shadow-lg shadow-blue-900/20'}
                                `}
                            >
                                {loading ? 'Scanning...' : <><Play size={18} /> Run Simulation</>}
                            </button>
                        </div>
                    </div>
                </div>

                {/* Results Pane */}
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 overflow-y-auto">
                    <h3 className="text-slate-400 text-sm font-medium mb-4 block uppercase tracking-wider">Analysis Result</h3>

                    {!result && !loading && (
                        <div className="h-full flex flex-col items-center justify-center text-slate-600">
                            <Shield size={48} className="mb-4 opacity-50" />
                            <p>Run a simulation to see the security pipeline in action.</p>
                        </div>
                    )}

                    {loading && (
                        <div className="space-y-4 animate-pulse">
                            <div className="h-12 bg-slate-800 rounded-lg w-full"></div>
                            <div className="h-12 bg-slate-800 rounded-lg w-full"></div>
                            <div className="h-12 bg-slate-800 rounded-lg w-full"></div>
                        </div>
                    )}

                    {result && (
                        <div className="space-y-6">
                            {/* Verdict Badge */}
                            <div className={`p-4 rounded-lg border flex items-center gap-3 ${result.verdict === 'BLOCK' ? 'bg-red-500/10 border-red-500/20 text-red-400' : 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'}`}>
                                {result.verdict === 'BLOCK' ? <XCircle size={24} /> : <CheckCircle size={24} />}
                                <div>
                                    <h3 className="font-bold text-lg">{result.verdict === 'BLOCK' ? 'Request Blocked' : 'Request Safe'}</h3>
                                    <p className="text-sm opacity-80">{result.verdict === 'BLOCK' ? 'The prompt violated security policies.' : 'The prompt passed all checks.'}</p>
                                </div>
                            </div>

                            {/* Steps Timeline */}
                            <div className="space-y-3 relative before:absolute before:left-[19px] before:top-4 before:bottom-4 before:w-0.5 before:bg-slate-800">
                                {result.steps.map((step, idx) => (
                                    <div key={idx} className="relative flex gap-4 items-start bg-slate-950 p-4 rounded-lg border border-slate-800 z-10">
                                        <div className={`mt-1 w-10 h-10 rounded-full flex items-center justify-center shrink-0 border-4 border-slate-900 
                                            ${step.status === 'BLOCK' ? 'bg-red-500 text-white' :
                                                step.status === 'MODIFY' ? 'bg-amber-500 text-white' :
                                                    step.status === 'SKIP' ? 'bg-slate-700 text-slate-400' :
                                                        'bg-emerald-500 text-white'}`}>
                                            {step.status === 'BLOCK' && <XCircle size={18} />}
                                            {step.status === 'MODIFY' && <EyeOff size={18} />}
                                            {step.status === 'PASS' && <CheckCircle size={18} />}
                                            {step.status === 'SKIP' && <ArrowRight size={18} />}
                                        </div>
                                        <div className="flex-1">
                                            <div className="flex justify-between items-center mb-1">
                                                <h4 className="font-semibold text-slate-200">{step.name}</h4>
                                                <span className="text-xs font-mono uppercase opacity-50">{step.status}</span>
                                            </div>
                                            <p className="text-sm text-slate-400">{step.details}</p>
                                            {step.meta && step.meta.mapping && (
                                                <div className="mt-2 text-xs font-mono bg-slate-900 p-2 rounded text-amber-400">
                                                    Redacted: {Object.keys(step.meta.mapping).join(', ')}
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                ))}
                            </div>

                            {/* Final Output */}
                            {result.final_prompt && result.final_prompt !== prompt && (
                                <div>
                                    <label className="text-slate-400 text-xs uppercase font-bold mb-2 block">Sanitized Output</label>
                                    <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 font-mono text-sm text-slate-300 whitespace-pre-wrap">
                                        {result.final_prompt}
                                    </div>
                                </div>
                            )}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default Simulator;
