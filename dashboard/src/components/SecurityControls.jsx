import React, { useState } from 'react';
import { ToggleRight, ToggleLeft, Shield, BrainCircuit, FileCode } from 'lucide-react';

const ToggleCard = ({ title, description, icon: Icon, active, onToggle }) => (
    <div className="bg-slate-900 p-4 rounded-xl border border-slate-800 flex justify-between items-center group hover:border-slate-700 transition-colors">
        <div className="flex items-center space-x-4">
            <div className={`p-2 rounded-lg ${active ? 'bg-blue-500/20 text-blue-400' : 'bg-slate-800 text-slate-500'}`}>
                <Icon size={20} />
            </div>
            <div>
                <h4 className="font-semibold text-slate-200">{title}</h4>
                <p className="text-xs text-slate-500">{description}</p>
            </div>
        </div>
        <button
            onClick={onToggle}
            className={`transition-colors ${active ? 'text-blue-500' : 'text-slate-600'}`}
        >
            {active ? <ToggleRight size={32} /> : <ToggleLeft size={32} />}
        </button>
    </div>
);

import { fetchConfig, updateConfig } from '../api';

const SecurityControls = () => {
    const [controls, setControls] = useState({
        regex: true,
        qdrant: true,
        injection: true,
    });

    // We map internal backend keys to component keys
    // backend: email_redaction (part of regex), vector_guard (qdrant), prompt_injection (injection)

    // Actually, SecurityControls simplifies the view. 
    // "Regex Sanitizer" usually implies email, phone, secrets.
    // Let's map "regex" -> toggle ALL regex fields? Or just check if ANY is on?
    // For simplicity: "regex" maps to "email_redaction" as a proxy for the group. 
    // "qdrant" -> "vector_guard"
    // "injection" -> "prompt_injection"

    const [fullConfig, setFullConfig] = useState({});

    React.useEffect(() => {
        const load = async () => {
            try {
                const cfg = await fetchConfig();
                setFullConfig(cfg);
                setControls({
                    regex: cfg.email_redaction,
                    qdrant: cfg.vector_guard,
                    injection: cfg.prompt_injection,
                });
            } catch { /* keep default toggles */ }
        };
        load();
    }, []);

    const toggle = async (key) => {
        let newConfig = { ...fullConfig };
        let newVal = !controls[key];

        // Specific mappings
        if (key === 'regex') {
            newConfig.email_redaction = newVal;
            newConfig.phone_redaction = newVal;
            newConfig.api_key_detection = newVal;
        } else if (key === 'qdrant') {
            newConfig.vector_guard = newVal;
        } else if (key === 'injection') {
            newConfig.prompt_injection = newVal;
        }

        setControls(prev => ({ ...prev, [key]: newVal }));
        setFullConfig(newConfig);
        await updateConfig(newConfig);
    };

    return (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
            <ToggleCard
                title="Regex Sanitizer"
                description="PII & Secrets Replacement"
                icon={FileCode}
                active={controls.regex}
                onToggle={() => toggle('regex')}
            />
            <ToggleCard
                title="Vector Guard"
                description="Semantic Blocking (Qdrant)"
                icon={BrainCircuit}
                active={controls.qdrant}
                onToggle={() => toggle('qdrant')}
            />
            <ToggleCard
                title="Injection Firewall"
                description="Heuristic Jailbreak Detection"
                icon={Shield}
                active={controls.injection}
                onToggle={() => toggle('injection')}
            />
        </div>
    );
};

export default SecurityControls;
