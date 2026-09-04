import React, { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { getInvitation, completeInvitation } from '../api';
import { Shield, Key, CheckCircle } from 'lucide-react';

const SetupAccount = () => {
    const [searchParams] = useSearchParams();
    const navigate = useNavigate();
    const token = searchParams.get('token');

    const [loading, setLoading] = useState(!!token);
    const [valid, setValid] = useState(false);
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [confirm, setConfirm] = useState('');
    const [error, setError] = useState(null);

    useEffect(() => {
        if (!token) return;
        // Validate Token & Get Info
        getInvitation(token)
            .then(data => {
                setValid(true);
                setEmail(data.email);
            })
            .catch(() => {
                setValid(false);
                setError("Invitation invalid or expired.");
            })
            .finally(() => setLoading(false));
    }, [token]);

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (password !== confirm) {
            setError("Passwords do not match");
            return;
        }

        try {
            await completeInvitation(token, password);
            navigate('/login');
        } catch {
            setError("Failed to setup account. Please try again.");
        }
    };

    if (loading) return <div className="min-h-screen bg-slate-950 text-white flex items-center justify-center">Verifying invitation...</div>;

    if (!valid) return (
        <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4">
            <div className="bg-slate-900 border border-slate-800 p-8 rounded-xl max-w-md w-full text-center">
                <Shield className="w-12 h-12 text-slate-600 mx-auto mb-4" />
                <h2 className="text-xl text-white font-bold mb-2">Invalid Invitation</h2>
                <p className="text-slate-400 mb-6">{error || "This link is invalid or has expired."}</p>
                <button onClick={() => navigate('/login')} className="text-emerald-500 hover:text-emerald-400">Go to Login</button>
            </div>
        </div>
    );

    return (
        <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4">
            <div className="bg-slate-900 border border-slate-800 p-8 rounded-xl max-w-md w-full shadow-2xl">
                <div className="text-center mb-8">
                    <div className="bg-emerald-500/10 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
                        <Key className="w-8 h-8 text-emerald-500" />
                    </div>
                    <h1 className="text-2xl font-bold text-white">Welcome to ClearGate</h1>
                    <p className="text-slate-400 mt-2">Set up your account for <span className="text-white font-medium">{email}</span></p>
                </div>

                {error && (
                    <div className="bg-red-500/10 text-red-500 p-3 rounded-lg mb-6 text-sm text-center">
                        {error}
                    </div>
                )}

                <form onSubmit={handleSubmit} className="space-y-6">
                    <div>
                        <label htmlFor="create-password" className="block text-slate-400 text-sm mb-2">Create Password</label>
                        <input
                            id="create-password"
                            name="create-password"
                            type="password"
                            autoComplete="new-password"
                            required
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            className="w-full bg-slate-950 border border-slate-700 rounded-lg p-3 text-white focus:outline-none focus:border-emerald-500"
                            placeholder="••••••••"
                        />
                    </div>
                    <div>
                        <label htmlFor="confirm-password" className="block text-slate-400 text-sm mb-2">Confirm Password</label>
                        <input
                            id="confirm-password"
                            name="confirm-password"
                            type="password"
                            autoComplete="new-password"
                            required
                            value={confirm}
                            onChange={(e) => setConfirm(e.target.value)}
                            className="w-full bg-slate-950 border border-slate-700 rounded-lg p-3 text-white focus:outline-none focus:border-emerald-500"
                            placeholder="••••••••"
                        />
                    </div>

                    <button
                        type="submit"
                        className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-bold py-3 rounded-lg transition-colors flex items-center justify-center gap-2"
                    >
                        <CheckCircle className="w-5 h-5" />
                        Complete Setup
                    </button>
                </form>
            </div>
        </div>
    );
};

export default SetupAccount;
