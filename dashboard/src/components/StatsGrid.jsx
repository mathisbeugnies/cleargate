import React, { useEffect, useState } from 'react';
import { Shield, AlertTriangle, Activity, Eye, Key } from 'lucide-react';
import { fetchStats } from '../api';
import Skeleton from './common/Skeleton';

const StatCard = ({ title, value, icon: Icon, color, trend, inverseTrend, loading }) => {
    const isPositive = trend > 0;
    const isGood = inverseTrend ? !isPositive : isPositive;

    return (
        <div className="bg-slate-900 p-6 rounded-xl border border-slate-800 hover:border-slate-700 transition-all">
            <div className="flex justify-between items-start mb-4">
                <div className={`p-3 rounded-lg bg-${color}-500/10 text-${color}-400`}>
                    <Icon size={24} />
                </div>
                {trend !== undefined && trend !== null && (
                    <span className={`text-xs font-medium px-2 py-1 rounded bg-${isGood ? 'emerald' : 'red'}-500/10 text-${isGood ? 'emerald' : 'red'}-400`}>
                        {trend > 0 ? '+' : ''}{trend}%
                    </span>
                )}
            </div>
            <h3 className="text-slate-400 text-sm font-medium">{title}</h3>
            {loading ? (
                <Skeleton className="h-8 w-24 mt-1" />
            ) : (
                <p className="text-3xl font-bold text-slate-100 mt-1">{value}</p>
            )}
        </div>
    );
};

const StatsGrid = () => {
    const [stats, setStats] = useState({ TotalRequests: 0, BlockedCount: 0, SanitizedCount: 0 });
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const load = async () => {
            try {
                const data = await fetchStats();
                setStats(data);
            } catch (e) {
                console.error("Failed to load stats", e);
            } finally {
                setLoading(false);
            }
        };
        load();
        // Poll every 5 seconds
        const interval = setInterval(load, 5000);
        return () => clearInterval(interval);
    }, []);

    return (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <StatCard
                title="Total Requests"
                value={stats && stats.storage_stats ? new Intl.NumberFormat().format(stats.storage_stats.TotalRequests) : "0"}
                icon={Activity}
                color="blue"
                trend={stats && stats.storage_stats ? stats.storage_stats.TotalRequestsTrend : 0}
                loading={loading}
            />
            <StatCard
                title="Threats Blocked"
                value={stats && stats.storage_stats ? stats.storage_stats.BlockedCount : "0"}
                icon={Shield}
                color="red"
                trend={stats && stats.storage_stats ? stats.storage_stats.BlockedCountTrend : 0}
                loading={loading}
            />
            <StatCard
                title="PII Redacted"
                value={stats && stats.storage_stats ? stats.storage_stats.SanitizedCount : "0"}
                icon={Eye}
                color="amber"
                trend={stats && stats.storage_stats ? stats.storage_stats.SanitizedCountTrend : 0}
                loading={loading}
            />
            <StatCard
                title="Avg. Latency"
                value={stats && stats.storage_stats && stats.storage_stats.AvgLatency ? stats.storage_stats.AvgLatency : "0ms"}
                icon={Key}
                color="emerald"
                trend={stats && stats.storage_stats ? stats.storage_stats.AvgLatencyTrend : 0}
                inverseTrend={true}
                loading={false}
            />
        </div>
    );
};

export default StatsGrid;
