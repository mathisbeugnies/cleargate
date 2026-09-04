import React, { useEffect } from 'react';
import { X } from 'lucide-react';

const SlideOver = ({ isOpen, onClose, title, children }) => {
    useEffect(() => {
        const handleEsc = (e) => {
            if (e.key === 'Escape') onClose();
        };
        window.addEventListener('keydown', handleEsc);
        return () => window.removeEventListener('keydown', handleEsc);
    }, [onClose]);

    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 z-50 overflow-hidden">
            <div className="absolute inset-0 bg-slate-950/80 backdrop-blur-sm transition-opacity" onClick={onClose} />

            <div className="fixed inset-y-0 right-0 pl-10 max-w-full flex">
                <div className="w-screen max-w-md transform transition-transform bg-slate-900 border-l border-slate-800 shadow-2xl h-full flex flex-col">
                    <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
                        <h2 className="text-lg font-semibold text-slate-100">{title}</h2>
                        <button
                            onClick={onClose}
                            className="text-slate-400 hover:text-white transition-colors p-1 rounded-md hover:bg-slate-800"
                        >
                            <X size={20} />
                        </button>
                    </div>

                    <div className="relative flex-1 px-6 py-6 overflow-y-auto">
                        {children}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default SlideOver;
