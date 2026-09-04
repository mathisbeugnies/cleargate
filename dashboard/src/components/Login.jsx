import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useNavigate, Link } from 'react-router-dom';
import { Shield, Lock, Mail } from 'lucide-react';

const Login = () => {
    const { login, error, loading } = useAuth();
    const navigate = useNavigate();
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        const success = await login(email, password);
        if (success) {
            navigate('/');
        }
    };

    return (
        <div className="min-h-screen bg-neutral-900 flex items-center justify-center p-4">
            <div className="bg-neutral-800 border border-neutral-700 rounded-xl p-8 w-full max-w-md shadow-2xl">
                <div className="flex flex-col items-center mb-8">
                    <div className="bg-emerald-500/10 p-4 rounded-full mb-4">
                        <Shield className="w-10 h-10 text-emerald-500" />
                    </div>
                    <h1 className="text-2xl font-bold text-white">ClearGate Security</h1>
                    <p className="text-neutral-400 text-sm mt-1">Sign in to access your dashboard</p>
                </div>

                {error && (
                    <div className="bg-red-500/10 text-red-500 p-3 rounded-lg mb-6 text-sm text-center">
                        {error}
                    </div>
                )}

                <form onSubmit={handleSubmit} className="space-y-6">
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
                                autoComplete="current-password"
                                required
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
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
                        {loading ? 'Signing in...' : 'Sign In'}
                    </button>

                    <div className="text-center text-sm text-neutral-500 mt-4">
                        No account yet?{' '}
                        <Link to="/signup" className="text-emerald-500 hover:text-emerald-400">Create one</Link>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default Login;
