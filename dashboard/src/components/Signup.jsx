import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { Link, useNavigate } from 'react-router-dom';
import { Shield, Lock, Mail, Building2, CheckCircle, Copy } from 'lucide-react';

const Signup = () => {
    const { signup, error, loading } = useAuth();
    const navigate = useNavigate();
    const [orgName, setOrgName] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [confirm, setConfirm] = useState('');
    const [localError, setLocalError] = useState(null);
    const [apiKey, setApiKey] = useState(null);
    const [copied, setCopied] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLocalError(null);

        if (password !== confirm) {
            setLocalError('Passwords do not match');
            return;
        }
        if (password.length < 8) {
            setLocalError('Password must be at least 8 characters');
            return;
        }

        const result = await signup(orgName, email, password);
        if (result.success) {
            setApiKey(result.apiKey);
        }
    };

    const handleCopy = () => {
        navigator.clipboard.writeText(apiKey);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    if (apiKey) {
        return (
            <div className="min-h-screen bg-neutral-900 flex items-center justify-center p-4">
                <div className="bg-neutral-800 border border-neutral-700 rounded-xl p-8 w-full max-w-md shadow-2xl text-center">
                    <div className="bg-emerald-500/10 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
                        <CheckCircle className="w-8 h-8 text-emerald-500" />
                    </div>
                    <h1 className="text-2xl font-bold text-white mb-2">You're all set</h1>
                    <p className="text-neutral-400 text-sm mb-6">
                        Here is your API key. Copy it now, you won't see it here again.
                    </p>
                    <div className="bg-neutral-900 border border-neutral-700 rounded-lg p-3 flex items-center justify-between gap-2 mb-6">
                        <code className="text-emerald-400 text-sm break-all text-left">{apiKey}</code>
                        <button
                            onClick={handleCopy}
                            className="shrink-0 text-neutral-400 hover:text-white transition-colors"
                            title="Copy to clipboard"
                        >
                            <Copy className="w-4 h-4" />
                        </button>
                    </div>
                    {copied && <p className="text-emerald-500 text-xs mb-4">Copied!</p>}
                    <button
                        onClick={() => navigate('/')}
                        className="w-full bg-gradient-to-r from-emerald-500 to-teal-500 hover:from-emerald-600 hover:to-teal-600 text-white font-semibold py-2.5 rounded-lg transition-all shadow-lg shadow-emerald-500/20"
                    >
                        Go to Dashboard
                    </button>
                </div>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-neutral-900 flex items-center justify-center p-4">
            <div className="bg-neutral-800 border border-neutral-700 rounded-xl p-8 w-full max-w-md shadow-2xl">
                <div className="flex flex-col items-center mb-8">
                    <div className="bg-emerald-500/10 p-4 rounded-full mb-4">
                        <Shield className="w-10 h-10 text-emerald-500" />
                    </div>
                    <h1 className="text-2xl font-bold text-white">Create your account</h1>
                    <p className="text-neutral-400 text-sm mt-1">Get an API key and start proxying requests in seconds</p>
                </div>

                {(localError || error) && (
                    <div className="bg-red-500/10 text-red-500 p-3 rounded-lg mb-6 text-sm text-center">
                        {localError || error}
                    </div>
                )}

                <form onSubmit={handleSubmit} className="space-y-5">
                    <div>
                        <label htmlFor="orgName" className="block text-neutral-400 text-sm mb-2">Organization Name</label>
                        <div className="relative">
                            <Building2 className="w-5 h-5 absolute left-3 top-2.5 text-neutral-500" />
                            <input
                                id="orgName"
                                name="orgName"
                                type="text"
                                required
                                value={orgName}
                                onChange={(e) => setOrgName(e.target.value)}
                                className="w-full bg-neutral-900 border border-neutral-700 rounded-lg py-2 pl-10 pr-4 text-white focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition-colors"
                                placeholder="Acme Inc."
                            />
                        </div>
                    </div>

                    <div>
                        <label htmlFor="email" className="block text-neutral-400 text-sm mb-2">Email Address</label>
                        <div className="relative">
                            <Mail className="w-5 h-5 absolute left-3 top-2.5 text-neutral-500" />
                            <input
                                id="email"
                                name="email"
                                type="email"
                                autoComplete="username"
                                required
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
                                className="w-full bg-neutral-900 border border-neutral-700 rounded-lg py-2 pl-10 pr-4 text-white focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition-colors"
                                placeholder="name@company.com"
                            />
                        </div>
                    </div>

                    <div>
                        <label htmlFor="password" className="block text-neutral-400 text-sm mb-2">Password</label>
                        <div className="relative">
                            <Lock className="w-5 h-5 absolute left-3 top-2.5 text-neutral-500" />
                            <input
                                id="password"
                                name="password"
                                type="password"
                                autoComplete="new-password"
                                required
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                className="w-full bg-neutral-900 border border-neutral-700 rounded-lg py-2 pl-10 pr-4 text-white focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition-colors"
                                placeholder="At least 8 characters"
                            />
                        </div>
                    </div>

                    <div>
                        <label htmlFor="confirm" className="block text-neutral-400 text-sm mb-2">Confirm Password</label>
                        <div className="relative">
                            <Lock className="w-5 h-5 absolute left-3 top-2.5 text-neutral-500" />
                            <input
                                id="confirm"
                                name="confirm"
                                type="password"
                                autoComplete="new-password"
                                required
                                value={confirm}
                                onChange={(e) => setConfirm(e.target.value)}
                                className="w-full bg-neutral-900 border border-neutral-700 rounded-lg py-2 pl-10 pr-4 text-white focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition-colors"
                                placeholder="••••••••"
                            />
                        </div>
                    </div>

                    <button
                        type="submit"
                        disabled={loading}
                        className="w-full bg-gradient-to-r from-emerald-500 to-teal-500 hover:from-emerald-600 hover:to-teal-600 text-white font-semibold py-2.5 rounded-lg transition-all shadow-lg shadow-emerald-500/20 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                        {loading ? 'Creating account...' : 'Create Account'}
                    </button>

                    <div className="text-center text-sm text-neutral-500 mt-4">
                        Already have an account?{' '}
                        <Link to="/login" className="text-emerald-500 hover:text-emerald-400">Sign in</Link>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default Signup;
