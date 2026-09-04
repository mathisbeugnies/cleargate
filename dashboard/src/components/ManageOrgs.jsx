import React, { useState, useEffect } from 'react';
import api from '../api';
import { Building2, Plus, Mail, Copy, Check } from 'lucide-react';

const ManageOrgs = () => {
    const [orgs, setOrgs] = useState([]);
    const [, setLoading] = useState(true);
    const [showModal, setShowModal] = useState(false);

    // Form State
    const [name, setName] = useState('');
    const [adminEmail, setAdminEmail] = useState('');
    const [successData, setSuccessData] = useState(null);

    useEffect(() => {
        fetchOrgs();
    }, []);

    const fetchOrgs = async () => {
        try {
            const res = await api.get('/api/superadmin/organizations/list');
            setOrgs(res.data);
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    const handleCreate = async (e) => {
        e.preventDefault();
        try {
            const res = await api.post('/api/superadmin/organizations', { name, admin_email: adminEmail });
            setSuccessData(res.data);
            fetchOrgs();
            setName('');
            setAdminEmail('');
        } catch (err) {
            console.error(err);
            const msg = err.response?.data || err.message || "Failed to create org";
            alert(typeof msg === 'object' ? JSON.stringify(msg) : msg);
        }
    };

    const copyToClipboard = (text) => {
        navigator.clipboard.writeText(text);
    };

    return (
        <div className="p-1">
            <div className="flex justify-between items-center mb-6">
                <div>
                    <h3 className="text-xl font-semibold text-slate-200">Organization Management</h3>
                    <p className="text-slate-500 text-sm">Manage client instances and invitations</p>
                </div>
                <button
                    onClick={() => setShowModal(true)}
                    className="bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2 rounded-lg flex items-center gap-2 transition-colors"
                >
                    <Plus className="w-4 h-4" /> Add Organization
                </button>
            </div>

            {/* List */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {orgs.map(org => (
                    <div key={org.ID} className="bg-slate-900 border border-slate-800 rounded-xl p-6 hover:border-slate-700 transition-colors">
                        <div className="flex items-start justify-between mb-4">
                            <div className="bg-indigo-500/10 p-3 rounded-lg">
                                <Building2 className="w-6 h-6 text-indigo-400" />
                            </div>
                            <span className="text-xs font-mono text-slate-500">ID: {org.ID}</span>
                        </div>
                        <h4 className="text-lg font-bold text-white mb-1">{org.Name}</h4>
                        <div className="bg-slate-950 rounded p-2 mt-4 flex justify-between items-center group">
                            <code className="text-xs text-slate-400 font-mono truncate max-w-[200px]">{org.ApiKey}</code>
                            <button onClick={() => copyToClipboard(org.ApiKey)} className="text-slate-600 hover:text-white transition-colors">
                                <Copy className="w-3 h-3" />
                            </button>
                        </div>
                    </div>
                ))}
            </div>

            {/* Create Modal */}
            {showModal && (
                <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center p-4 z-[9999]">
                    <div className="bg-slate-900 border border-slate-800 p-6 rounded-xl w-full max-w-md shadow-2xl relative z-[10000]">
                        {!successData ? (
                            <>
                                <h3 className="text-xl font-bold text-white mb-4">Add New Organization</h3>
                                <form onSubmit={handleCreate} className="space-y-4">
                                    <div>
                                        <label htmlFor="org-name" className="text-sm text-slate-400 block mb-1">Company Name</label>
                                        <input
                                            id="org-name"
                                            name="org-name"
                                            autoFocus
                                            value={name} onChange={e => setName(e.target.value)}
                                            className="w-full bg-slate-950 border border-slate-700 rounded p-2 text-white focus:border-emerald-500 outline-none"
                                            placeholder="Acme Corp" required
                                        />
                                    </div>
                                    <div>
                                        <label htmlFor="admin-email" className="text-sm text-slate-400 block mb-1">Admin Email (Invite)</label>
                                        <input
                                            id="admin-email"
                                            name="admin-email"
                                            value={adminEmail} onChange={e => setAdminEmail(e.target.value)} type="email"
                                            className="w-full bg-slate-950 border border-slate-700 rounded p-2 text-white focus:border-emerald-500 outline-none"
                                            placeholder="admin@acme.com" required
                                        />
                                    </div>
                                    <div className="flex gap-3 mt-6">
                                        <button type="button" onClick={() => setShowModal(false)} className="flex-1 bg-slate-800 text-slate-300 py-2 rounded hover:bg-slate-700">Cancel</button>
                                        <button type="submit" className="flex-1 bg-emerald-600 text-white py-2 rounded hover:bg-emerald-500">Create & Invite</button>
                                    </div>
                                </form>
                            </>
                        ) : (
                            <div className="text-center">
                                <div className="bg-emerald-500/10 w-12 h-12 rounded-full flex items-center justify-center mx-auto mb-4">
                                    <Check className="w-6 h-6 text-emerald-500" />
                                </div>
                                <h3 className="text-xl font-bold text-white mb-2">Success!</h3>
                                <p className="text-slate-400 text-sm mb-6">Organization created and invitation sent.</p>

                                <div className="bg-slate-950 p-4 rounded-lg text-left mb-6">
                                    <p className="text-xs text-slate-500 mb-1">Invitation Link (Dev Mode)</p>
                                    <div className="flex gap-2 items-center">
                                        <code className="text-emerald-400 text-xs break-all">{successData.invite_link}</code>
                                        <button onClick={() => copyToClipboard(successData.invite_link)}><Copy className="w-4 h-4 text-slate-500 hover:text-white" /></button>
                                    </div>
                                </div>

                                <button onClick={() => { setShowModal(false); setSuccessData(null); }} className="w-full bg-slate-800 text-white py-2 rounded hover:bg-slate-700">Close</button>
                            </div>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
};

export default ManageOrgs;
