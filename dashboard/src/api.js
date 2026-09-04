import axios from 'axios';

// Configurable at build time via VITE_API_BASE. In production it defaults to a
// relative base so the dashboard talks to whatever origin served it (behind a
// reverse proxy that forwards /api and /auth). In `vite dev` it points at the
// local backend on :8080.
export const API_BASE =
    import.meta.env.VITE_API_BASE ?? (import.meta.env.DEV ? 'http://localhost:8080' : '');

// The session lives in an httpOnly cookie set by the server; send it with
// every request.
const api = axios.create({
    baseURL: API_BASE,
    withCredentials: true,
});

export const login = async (email, password) => {
    const res = await api.post('/auth/login', { email, password });
    return res.data;
};

export const logout = async () => {
    await api.post('/auth/logout');
};

export const getMe = async () => {
    const res = await api.get('/auth/me');
    return res.data;
};

export const signup = async (orgName, email, password) => {
    const res = await api.post('/api/signup', { org_name: orgName, email, password });
    return res.data;
};

export const fetchAuditLogs = async (params = {}) => {
    const query = new URLSearchParams(params).toString();
    const res = await api.get(`/api/admin/audit?${query}`);
    return res.data;
};

export const fetchConfig = async () => {
    const res = await api.get('/api/config');
    return res.data;
};

export const updateConfig = async (newConfig) => {
    const res = await api.post('/api/config', newConfig);
    return res.data;
};

// Maintenance
export const flushAuditLogs = async () => {
    const res = await api.delete('/api/admin/audit');
    return res.data;
};

export const reloadProxy = async () => {
    const res = await api.post('/api/admin/reload');
    return res.data;
};

export const fetchStats = async () => {
    const res = await api.get('/api/stats');
    return res.data;
};

// Vector / RAG API
export const fetchDocuments = async () => {
    const res = await api.get('/api/vector/documents');
    return res.data;
};

export const deleteDocument = async (id) => {
    const res = await api.delete(`/api/vector/delete?id=${id}`);
    return res.data;
};

export const testSimilarity = async (text) => {
    const res = await api.post('/api/vector/test', { text, top_k: 5 });
    return res.data;
};

// Encryption keys
export const uploadPublicKey = async (publicKeyPEM) => {
    const res = await api.post('/api/keys', { public_key: publicKeyPEM });
    return res.data;
};

// Audit review
export const submitFeedbackException = async (text) => {
    const res = await api.post('/api/admin/feedback', { text });
    return res.data;
};

export const fetchIntegrity = async () => {
    const res = await api.get('/api/admin/integrity');
    return res.data;
};

// Invitation / account setup
export const getInvitation = async (token) => {
    const res = await api.get(`/api/invite?token=${encodeURIComponent(token)}`);
    return res.data;
};

export const completeInvitation = async (token, password) => {
    const res = await api.post('/api/invite/complete', { token, password });
    return res.data;
};

export default api;
