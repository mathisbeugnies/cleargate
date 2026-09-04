import React, { useState, useCallback, useEffect } from 'react';
import { Upload, Trash2, FileText, Database, Check, AlertCircle, Loader, Search, Zap } from 'lucide-react';
import { useDropzone } from 'react-dropzone';
import api, { fetchDocuments, deleteDocument, testSimilarity } from '../api';

const KnowledgeBase = () => {
    const [files, setFiles] = useState([]);
    const [uploading, setUploading] = useState(false);
    const [uploadError, setUploadError] = useState(null);
    const [testQuery, setTestQuery] = useState('');
    const [testResults, setTestResults] = useState(null);
    const [testing, setTesting] = useState(false);

    const loadFiles = async () => {
        try {
            const data = await fetchDocuments();
            if (Array.isArray(data)) {
                setFiles(data.map(d => ({
                    id: d.id,
                    name: d.filename,
                    size: (d.size_bytes / 1024).toFixed(1) + ' KB',
                    status: 'Indexed',
                    date: new Date(d.uploaded_at).toLocaleDateString(),
                    chunks: d.chunks_count
                })));
            }
        } catch (e) {
            console.error("Failed to load documents", e);
        }
    };

    useEffect(() => {
        // eslint-disable-next-line react-hooks/set-state-in-effect
        loadFiles();
    }, []);

    const onDrop = useCallback(async (acceptedFiles) => {
        setUploading(true);
        setUploadError(null);

        for (const file of acceptedFiles) {
            const formData = new FormData();
            formData.append('file', file);

            try {
                // Optimistic UI update (placeholder)
                const tempId = Date.now();
                setFiles(prev => [{
                    id: tempId,
                    name: file.name,
                    size: (file.size / 1024).toFixed(1) + ' KB',
                    status: 'Processing',
                    date: 'Scanning...'
                }, ...prev]);

                await api.post('/api/vector/upload', formData, {
                    headers: { 'Content-Type': 'multipart/form-data' }
                });

                // Reload real list from DB
                await loadFiles();

            } catch (err) {
                console.error("Upload failed", err);
                const msg = err.response?.data || "Upload failed";
                setUploadError(typeof msg === 'object' ? JSON.stringify(msg) : msg);
                // Remove failed file from list
                await loadFiles();
            }
        }
        setUploading(false);
    }, []);

    const { getRootProps, getInputProps, isDragActive } = useDropzone({
        onDrop,
        accept: {
            'application/pdf': ['.pdf'],
            'text/plain': ['.txt', '.md']
        }
    });

    const handleDelete = async (id) => {
        if (!window.confirm("Delete this document and its vectors?")) return;
        try {
            // Optimistic
            setFiles(files.filter(f => f.id !== id));
            await deleteDocument(id);
        } catch (e) {
            console.error("Delete failed", e);
            loadFiles(); // Revert
        }
    };

    const handleTest = async () => {
        if (!testQuery.trim()) return;
        setTesting(true);
        try {
            const results = await testSimilarity(testQuery);
            setTestResults(results);
        } catch {
            alert("Test failed");
        }
        setTesting(false);
    };

    return (
        <div className="space-y-8">
            <div>
                <h2 className="text-2xl font-bold text-slate-100">Knowledge Base</h2>
                <p className="text-slate-500">Manage documents indexed in Qdrant for RAG context.</p>
            </div>

            {/* ERROR ALERT */}
            {uploadError && (
                <div className="bg-red-500/10 border border-red-500/20 text-red-400 p-4 rounded-lg flex items-center gap-2">
                    <AlertCircle size={20} />
                    <span>{uploadError}</span>
                    <button onClick={() => setUploadError(null)} className="ml-auto hover:text-white"><Check size={16} /></button>
                </div>
            )}

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                {/* LEFT COLUMN: UPLOAD & LIST */}
                <div className="lg:col-span-2 space-y-6">
                    {/* Dropzone */}
                    <div
                        {...getRootProps()}
                        className={`border-2 border-dashed rounded-xl p-8 text-center transition-all cursor-pointer group
                        ${isDragActive ? 'border-blue-500 bg-blue-500/10' : 'border-slate-700 bg-slate-900/50 hover:border-blue-500/50 hover:bg-slate-900'}
                        ${uploading ? 'opacity-50 pointer-events-none' : ''}`}
                    >
                        <label htmlFor="dropzone-file" className="sr-only">Upload documents</label>
                        <input
                            {...getInputProps({
                                id: 'dropzone-file',
                                name: 'dropzone-file'
                            })}
                        />
                        <div className="bg-slate-800 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4 group-hover:bg-blue-500/20 transition-colors">
                            {uploading ? <Loader className="animate-spin text-blue-400" /> : <Upload className="text-slate-400 group-hover:text-blue-400" size={32} />}
                        </div>
                        <h3 className="text-lg font-medium text-slate-200">
                            {isDragActive ? "Drop documents here..." : "Drop files to index"}
                        </h3>
                        <p className="text-slate-500 mt-2 text-sm max-w-sm mx-auto">
                            Support for PDF and TXT/MD. Files will be chunked and embedded instantly.
                        </p>
                    </div>

                    {/* File List */}
                    <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
                        <div className="px-6 py-4 border-b border-slate-800 flex justify-between items-center bg-slate-900">
                            <h3 className="font-semibold text-slate-200 flex items-center gap-2">
                                <Database size={16} className="text-blue-400" /> Indexed Documents ({files.length})
                            </h3>
                        </div>
                        <div className="overflow-x-auto">
                            <table className="w-full text-left font-sm">
                                <thead className="bg-slate-950 text-slate-400 text-xs uppercase">
                                    <tr>
                                        <th className="px-6 py-3">Filename</th>
                                        <th className="px-6 py-3">Size</th>
                                        <th className="px-6 py-3">Date</th>
                                        <th className="px-6 py-3">Status</th>
                                        <th className="px-6 py-3 text-right">Action</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-slate-800">
                                    {files.map(file => (
                                        <tr key={file.id} className="hover:bg-slate-800/50 transition-colors">
                                            <td className="px-6 py-4 font-medium text-slate-200 flex items-center gap-3">
                                                <FileText size={16} className="text-slate-500" />
                                                {file.name}
                                            </td>
                                            <td className="px-6 py-4 text-slate-400 text-sm">{file.size}</td>
                                            <td className="px-6 py-4 text-slate-400 text-sm">{file.date}</td>
                                            <td className="px-6 py-4 text-sm">
                                                <span className={`px-2 py-1 rounded-full text-xs font-medium flex items-center gap-1 w-fit ${file.status === 'Indexed'
                                                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                                                    : 'bg-blue-500/10 text-blue-400 border border-blue-500/20 animate-pulse'
                                                    }`}>
                                                    {file.status === 'Indexed' && <Check size={10} />}
                                                    {file.status}
                                                    {file.chunks > 0 && <span className="opacity-70 ml-1">({file.chunks} chunks)</span>}
                                                </span>
                                            </td>
                                            <td className="px-6 py-4 text-right">
                                                <button
                                                    onClick={(e) => { e.stopPropagation(); handleDelete(file.id); }}
                                                    className="p-2 hover:bg-red-500/10 hover:text-red-400 text-slate-500 rounded-lg transition-colors"
                                                    title="Delete index"
                                                >
                                                    <Trash2 size={16} />
                                                </button>
                                            </td>
                                        </tr>
                                    ))}
                                    {files.length === 0 && (
                                        <tr>
                                            <td colSpan="5" className="px-6 py-8 text-center text-slate-500">
                                                No documents indexed yet. Upload a PDF or TXT file to start.
                                            </td>
                                        </tr>
                                    )}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                {/* RIGHT COLUMN: TEST */}
                <div className="space-y-6">
                    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 h-full flex flex-col">
                        <div className="flex items-center gap-2 mb-4">
                            <Zap className="text-amber-400" size={20} />
                            <h3 className="text-lg font-bold text-slate-200">Similarity Test</h3>
                        </div>
                        <p className="text-slate-400 text-sm mb-4">
                            Check which documents are retrieved (RAG) for a given query to verify index quality.
                        </p>

                        <div className="relative mb-4">
                            <label htmlFor="similarity-search" className="sr-only">Search Query</label>
                            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" size={16} />
                            <input
                                id="similarity-search"
                                name="similarity-search"
                                type="text"
                                className="w-full bg-slate-950 border border-slate-700 rounded-lg py-2 pl-9 pr-4 text-slate-200 text-sm focus:outline-none focus:border-blue-500 transition-colors"
                                placeholder="Enter query (e.g. 'Project Alpha')..."
                                value={testQuery}
                                onChange={(e) => setTestQuery(e.target.value)}
                                onKeyDown={(e) => e.key === 'Enter' && handleTest()}
                            />
                        </div>
                        <button
                            onClick={handleTest}
                            disabled={testing || !testQuery}
                            className="w-full py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed mb-6"
                        >
                            {testing ? 'Searching...' : 'Find Matches'}
                        </button>

                        <div className="flex-1 overflow-y-auto space-y-3 min-h-[200px]">
                            {testResults && testResults.length === 0 && (
                                <div className="text-center text-slate-500 py-4 italic">No matches found with &gt; 50% similarity.</div>
                            )}
                            {testResults && testResults.map((res, i) => (
                                <div key={i} className="bg-slate-950 p-3 rounded border border-slate-800 text-sm">
                                    <div className="flex justify-between items-start mb-1">
                                        <span className="font-semibold text-slate-300 text-xs truncate max-w-[150px]" title={res.filename}>{res.filename}</span>
                                        <span className={`text-xs font-mono px-1.5 py-0.5 rounded ${res.score > 0.7 ? 'bg-emerald-500/20 text-emerald-400' : 'bg-blue-500/20 text-blue-400'}`}>
                                            {(res.score * 100).toFixed(0)}%
                                        </span>
                                    </div>
                                    <p className="text-slate-400 line-clamp-3 text-xs leading-relaxed">
                                        "{res.text}"
                                    </p>
                                </div>
                            ))}
                            {!testResults && (
                                <div className="text-center text-slate-600 py-10 flex flex-col items-center">
                                    <Database size={32} className="mb-2 opacity-50" />
                                    Results will appear here
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default KnowledgeBase;
