"use client";

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

type EvalReport = {
    run_id: string;
    total_tests: number;
    passed: number;
    failed: number;
    errors: number;
    plugins: Record<string, any>;
    raw_results: any[];
};

export default function EvalDashboard() {
    const [status, setStatus] = useState<"idle" | "running" | "completed" | "failed">("idle");
    const [runId, setRunId] = useState<string | null>(null);
    const [progress, setProgress] = useState(0);
    const [report, setReport] = useState<EvalReport | null>(null);
    const [errorMsg, setErrorMsg] = useState("");

    const startEval = async () => {
        setStatus("running");
        setProgress(0);
        setReport(null);
        setErrorMsg("");
        try {
            const res = await fetch("http://localhost:8000/eval/run", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    num_tests: 3,
                    plugins: ["shell-injection", "system-prompt-override", "data-exfil", "pliny", "excessive-agency"],
                    strategies: ["jailbreak"]
                })
            });
            if (!res.ok) throw new Error("Failed to start eval");
            const data = await res.json();
            setRunId(data.run_id);
        } catch (e: any) {
            setErrorMsg(e.message);
            setStatus("failed");
        }
    };

    useEffect(() => {
        let interval: NodeJS.Timeout;
        if (status === "running" && runId) {
            interval = setInterval(async () => {
                try {
                    const res = await fetch(`http://localhost:8000/eval/status/${runId}`);
                    if (res.ok) {
                        const data = await res.json();
                        setProgress(data.progress * 100);
                        if (data.status === "completed") {
                            setStatus("completed");
                            fetchReport(runId);
                        } else if (data.status === "failed") {
                            setStatus("failed");
                        }
                    }
                } catch (e) {
                    console.error("Status check failed", e);
                }
            }, 3000);
        }
        return () => clearInterval(interval);
    }, [status, runId]);

    const fetchReport = async (id: string) => {
        try {
            const res = await fetch(`http://localhost:8000/eval/report/${id}`);
            if (res.ok) {
                const data = await res.json();
                setReport(data);
            } else {
                setErrorMsg("Failed to load report data.");
            }
        } catch (e) {
            setErrorMsg("Failed to load report data.");
        }
    };

    return (
        <div className="p-8 max-w-7xl mx-auto space-y-8">
            {/* Header */}
            <div className="flex items-center justify-between border-b border-white/10 pb-6 mb-8">
                <div>
                    <h1 className="text-3xl font-black text-white tracking-tight flex items-center gap-3">
                        <span className="text-purple-500">⚡</span> Promptfoo Red Team Eval
                    </h1>
                    <p className="text-slate-400 mt-2 text-sm leading-relaxed max-w-2xl">
                        Execute advanced adversarial attacks against the Aegis Target Agent using dynamic AI generators. This will launch a sandboxed container and sweep multiple vulnerability categories automatically.
                    </p>
                </div>
                <button
                    onClick={startEval}
                    disabled={status === "running"}
                    className={`px-6 py-3 rounded-xl font-bold flex items-center gap-2 transition-all ${status === "running"
                        ? "bg-slate-800 text-slate-500 cursor-not-allowed"
                        : "bg-purple-500 hover:bg-purple-400 text-white shadow-[0_0_20px_rgba(168,85,247,0.4)]"
                        }`}
                >
                    {status === "running" ? (
                        <><div className="w-5 h-5 border-2 border-white/20 border-t-white rounded-full animate-spin" /> Scanning...</>
                    ) : (
                        <><span className="text-lg">🔥</span> Launch Eval</>
                    )}
                </button>
            </div>

            {errorMsg && (
                <div className="p-4 bg-red-500/10 border border-red-500/20 text-red-400 rounded-xl text-sm font-medium">
                    Error: {errorMsg}
                </div>
            )}

            {/* Progress Bar */}
            <AnimatePresence>
                {status === "running" && (
                    <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        exit={{ opacity: 0, height: 0 }}
                        className="bg-slate-900/50 border border-white/5 p-6 rounded-2xl"
                    >
                        <div className="flex justify-between items-end mb-3">
                            <div>
                                <h3 className="text-white font-bold text-lg">Initializing Red Team Matrix...</h3>
                                <p className="text-slate-400 text-sm mt-1">Generating and executing payloads via Ollama locally.</p>
                            </div>
                            <span className="text-purple-400 font-mono text-sm">{Math.round(progress)}%</span>
                        </div>
                        <div className="h-2 w-full bg-slate-950 rounded-full overflow-hidden border border-white/5">
                            <motion.div
                                className="h-full bg-gradient-to-r from-purple-600 to-indigo-500 relative"
                                initial={{ width: "0%" }}
                                animate={{ width: `${progress}%` }}
                                transition={{ duration: 0.5 }}
                            >
                                <div className="absolute inset-0 bg-white/20 animate-pulse"></div>
                            </motion.div>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>

            {/* Results Dashboard */}
            {report && (
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="space-y-8"
                >
                    {/* Top Level Stats */}
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                        <StatCard label="Total Tests" value={report.total_tests} icon="🧪" />
                        <StatCard label="Defended (Passed)" value={report.passed} valueColor="text-emerald-400" icon="🛡️" />
                        <StatCard label="Exploited (Failed)" value={report.failed} valueColor="text-red-400" icon="☠️" />
                        <StatCard label="Errors" value={report.errors} valueColor="text-amber-400" icon="⚠️" />
                    </div>

                    {/* Plugin Matrix */}
                    <div className="bg-slate-900/50 border border-white/5 rounded-2xl overflow-hidden">
                        <div className="p-5 border-b border-white/5 bg-slate-950/20">
                            <h3 className="text-white font-bold flex items-center gap-2"><span className="text-indigo-400">📊</span> Vulnerability Matrix</h3>
                        </div>
                        <div className="p-6">
                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                                {Object.entries(report.plugins).map(([plugin, stats]: [string, any]) => (
                                    <div key={plugin} className="bg-slate-950 rounded-xl p-5 border border-white/5">
                                        <div className="flex justify-between items-center mb-4">
                                            <span className="text-slate-200 font-mono text-sm">{plugin}</span>
                                            <span className={`px-2 py-1 rounded text-[10px] uppercase font-black tracking-wider ${stats.failed === 0 ? 'bg-emerald-500/20 text-emerald-400' : 'bg-red-500/20 text-red-400'}`}>
                                                {stats.failed === 0 ? 'SECURE' : 'VULNERABLE'}
                                            </span>
                                        </div>
                                        <div className="flex gap-4 text-sm mt-4 pt-4 border-t border-white/5">
                                            <div className="flex-1">
                                                <div className="text-slate-500 text-[10px] uppercase font-bold tracking-wider mb-1">Passed</div>
                                                <div className="text-emerald-400 font-mono">{stats.passed}</div>
                                            </div>
                                            <div className="flex-1">
                                                <div className="text-slate-500 text-[10px] uppercase font-bold tracking-wider mb-1">Failed</div>
                                                <div className="text-red-400 font-mono">{stats.failed}</div>
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>
                </motion.div>
            )}
        </div>
    );
}

function StatCard({ label, value, valueColor = "text-white", icon }: { label: string, value: number, valueColor?: string, icon: string }) {
    return (
        <div className="bg-slate-900/50 border border-white/5 p-6 rounded-2xl relative overflow-hidden group">
            <div className="absolute -right-4 -top-4 text-6xl opacity-10 group-hover:scale-110 transition-transform duration-500 filter grayscale">{icon}</div>
            <p className="text-slate-400 text-xs font-bold uppercase tracking-widest mb-2 relative z-10">{label}</p>
            <p className={`text-4xl font-black ${valueColor} font-mono relative z-10`}>{value}</p>
        </div>
    );
}
