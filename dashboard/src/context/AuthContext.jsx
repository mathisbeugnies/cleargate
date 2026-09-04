import React, { createContext, useState, useContext, useEffect } from 'react';
import { login as apiLogin, signup as apiSignup, logout as apiLogout, getMe } from '../api';

const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
    const [user, setUser] = useState(null);
    const [authReady, setAuthReady] = useState(false);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    // On load, ask the server who we are (the session is an httpOnly cookie).
    useEffect(() => {
        getMe()
            .then((me) => setUser({ email: me.email, role: me.role }))
            .catch(() => setUser(null))
            .finally(() => setAuthReady(true));
    }, []);

    const login = async (email, password) => {
        setLoading(true);
        setError(null);
        try {
            const data = await apiLogin(email, password);
            setUser({ email: data.email, role: data.role });
            return true;
        } catch {
            setError('Login failed. Check credentials.');
            return false;
        } finally {
            setLoading(false);
        }
    };

    const signup = async (orgName, email, password) => {
        setLoading(true);
        setError(null);
        try {
            const data = await apiSignup(orgName, email, password);
            setUser({ email: data.email, role: data.role, apiKey: data.api_key });
            return { success: true, apiKey: data.api_key };
        } catch (err) {
            const message = err?.response?.data?.error || 'Signup failed. Please try again.';
            setError(typeof message === 'string' ? message : 'Signup failed. Please try again.');
            return { success: false };
        } finally {
            setLoading(false);
        }
    };

    const logout = async () => {
        try {
            await apiLogout();
        } catch { /* ignore */ }
        setUser(null);
    };

    return (
        <AuthContext.Provider value={{ user, authReady, login, signup, logout, loading, error }}>
            {children}
        </AuthContext.Provider>
    );
};

// eslint-disable-next-line react-refresh/only-export-components
export const useAuth = () => useContext(AuthContext);
