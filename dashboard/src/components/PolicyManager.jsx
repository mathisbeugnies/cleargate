import React, { useState, useEffect } from 'react';
import { Shield, Mail, Code, Key, Save, Database, Binary, Phone, Users, Stethoscope, Lock, Eye, Activity } from 'lucide-react';
import { fetchConfig, updateConfig } from '../api';

const PolicyToggle = ({ id, label, description, icon: Icon, enabled, onChange }) => (
    <div className="flex items-center justify-between p-4 bg-slate-900 border border-slate-800 rounded-lg hover:border-slate-700 transition-colors">
        <div className="flex items-center gap-4">
            <div className={`p-2 rounded-lg ${enabled ? 'bg-blue-500/10 text-blue-400' : 'bg-slate-800 text-slate-500'}`}>
                <Icon size={20} />
            </div>
            <div>
                <label htmlFor={id} className="font-medium text-slate-200 cursor-pointer">{label}</label>
                <p className="text-sm text-slate-500">{description}</p>
            </div>
        </div>

        <div className="relative inline-flex items-center cursor-pointer">
            <input
                id={id}
                name={id}
                type="checkbox"
                checked={enabled}
                onChange={onChange}
                className="sr-only peer"
            />
            <label htmlFor={id} className="w-11 h-6 bg-slate-700 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600 cursor-pointer"></label>
        </div>
    </div>
);

const PolicyManager = () => {
    const [policies, setPolicies] = useState({
        email_redaction: true,
        phone_redaction: true,
        api_key_detection: true,
        source_code_dlp: true,
        prompt_injection: true,
        vector_guard: true,
        entropy_scanner: false,
        ner_enabled: false,
        medical_check: false,
        prompt_leaking: true,
        output_control: true,
        anomaly_detection: true, // Default ON
    });
    const [, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);

    useEffect(() => {
        const load = async () => {
            try {
                const cfg = await fetchConfig();
                setPolicies(prev => ({ ...prev, ...cfg }));
            } catch (e) {
                console.error("Load config failed", e);
            } finally {
                setLoading(false);
            }
        };
        load();
    }, []);

    const handleToggle = async (key) => {
        const newState = { ...policies, [key]: !policies[key] };
        setPolicies(newState); // Optimistic UI update
        setSaving(true);
        try {
            await updateConfig(newState);
        } catch (e) {
            console.error("Save config failed", e);
            setPolicies(policies); // Revert on error
        } finally {
            setSaving(false);
        }
    };

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between mb-6">
                <div>
                    <h2 className="text-2xl font-bold text-slate-100">Policy Manager</h2>
                    <p className="text-slate-500">Configure global security rules and sanitization filters.</p>
                </div>
                {saving && (
                    <span className="flex items-center text-emerald-400 text-sm font-medium animate-pulse">
                        <Save size={16} className="mr-2" /> Saving changes...
                    </span>
                )}
            </div>

            <div className="grid gap-4">
                <h3 className="text-slate-400 text-sm font-semibold uppercase tracking-wider mt-2 mb-1">DLP & Sanitization</h3>
                <PolicyToggle
                    id="policy-email-redaction"
                    label="Email Redaction"
                    description="Detects and masks email addresses (e.g. [EMAIL_DETECTED])"
                    icon={Mail}
                    enabled={policies.email_redaction}
                    onChange={() => handleToggle('email_redaction')}
                />
                <PolicyToggle
                    id="policy-phone-redaction"
                    label="Phone Redaction"
                    description="Detects and masks phone numbers (e.g. [PHONE_DETECTED])"
                    icon={Phone}
                    enabled={policies.phone_redaction}
                    onChange={() => handleToggle('phone_redaction')}
                />
                <PolicyToggle
                    id="policy-api-key"
                    label="API Key Protection"
                    description="Blocks requests containing potential API keys (AWS, Stripe, etc.)"
                    icon={Key}
                    enabled={policies.api_key_detection}
                    onChange={() => handleToggle('api_key_detection')}
                />
                <PolicyToggle
                    id="policy-source-code"
                    label="Source Code DLP"
                    description="Detects leakage of source code chunks > 10 lines"
                    icon={Code}
                    enabled={policies.source_code_dlp}
                    onChange={() => handleToggle('source_code_dlp')}
                />
                <PolicyToggle
                    id="policy-entropy"
                    label="Shannon Entropy Scanner"
                    description="Detects high-entropy strings (passwords, tokens) > 12 chars"
                    icon={Binary}
                    enabled={policies.entropy_scanner}
                    onChange={() => handleToggle('entropy_scanner')}
                />
                <PolicyToggle
                    id="policy-ner"
                    label="Advanced NER Detection"
                    description="Detects Names, Locations, and Organizations using heuristics"
                    icon={Users}
                    enabled={policies.ner_enabled}
                    onChange={() => handleToggle('ner_enabled')}
                />
                <PolicyToggle
                    id="policy-medical"
                    label="Medical Context Risk"
                    description="Alerts when Medical Terms are found near Personal Names"
                    icon={Stethoscope}
                    enabled={policies.medical_check}
                    onChange={() => handleToggle('medical_check')}
                />

                <h3 className="text-slate-400 text-sm font-semibold uppercase tracking-wider mt-6 mb-1">Threat Protection</h3>
                <PolicyToggle
                    id="policy-injection"
                    label="Prompt Injection Firewall"
                    description="Heuristic detection of jailbreak attempts and DAN mode"
                    icon={Shield}
                    enabled={policies.prompt_injection}
                    onChange={() => handleToggle('prompt_injection')}
                />
                <PolicyToggle
                    id="policy-leak-protection"
                    label="System Prompt Leak Protection"
                    description="Blocks attempts to reveal system instructions (e.g. 'Repeat above')"
                    icon={Lock}
                    enabled={policies.prompt_leaking}
                    onChange={() => handleToggle('prompt_leaking')}
                />
                <PolicyToggle
                    id="policy-vector-guard"
                    label="Vector Semantic Guard"
                    description="Blocks prompts semantically similar to forbidden topics (RAG)"
                    icon={Database}
                    enabled={policies.vector_guard}
                    onChange={() => handleToggle('vector_guard')}
                />
                <PolicyToggle
                    id="policy-output-guard"
                    label="AI Output Guard (Mirror Pipeline)"
                    description="Deep scan of AI responses for leaks and forbidden topics (Adds latency)"
                    icon={Eye}
                    enabled={policies.output_control}
                    onChange={() => handleToggle('output_control')}
                />
                <PolicyToggle
                    id="policy-anomaly"
                    label="Anomaly & Risk Auto-Ban"
                    description="Blocks users with high failure rates (5/10min) or usage spikes (>300%)"
                    icon={Activity}
                    enabled={policies.anomaly_detection}
                    onChange={() => handleToggle('anomaly_detection')}
                />
            </div>
        </div>
    );
};

export default PolicyManager;
