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

type EvalPluginCatalog = {
    official_plugins: string[];
    supported_plugins: string[];
    unsupported_plugins: Record<string, string>;
};

export default function EvalDashboard() {
    const [status, setStatus] = useState<"idle" | "running" | "completed" | "failed">("idle");
    const [runId, setRunId] = useState<string | null>(null);
    const [progress, setProgress] = useState(0);
    const [completedTests, setCompletedTests] = useState(0);
    const [totalTests, setTotalTests] = useState(0);
    const [phase, setPhase] = useState("Idle");
    const [etaSeconds, setEtaSeconds] = useState<number | null>(null);
    const [lastOutputLine, setLastOutputLine] = useState("");
    const [report, setReport] = useState<EvalReport | null>(null);
    const [availablePlugins, setAvailablePlugins] = useState<string[]>([]);
    const [pluginCatalog, setPluginCatalog] = useState<EvalPluginCatalog | null>(null);
    const [selectedPlugins, setSelectedPlugins] = useState<string[]>(["pliny", "rbac"]);
    const [numTests, setNumTests] = useState(5);
    const [promptfooProtectionEnabled, setPromptfooProtectionEnabled] = useState(true);
    const [errorMsg, setErrorMsg] = useState("");

    useEffect(() => {
        const loadPlugins = async () => {
            try {
                const res = await fetch("http://localhost:8000/eval/plugins");
                if (!res.ok) {
                    throw new Error("Failed to load Promptfoo vectors");
                }
                const data: EvalPluginCatalog = await res.json();
                const supported = Array.isArray(data.supported_plugins) ? data.supported_plugins : [];
                setPluginCatalog(data);
                setAvailablePlugins(supported);
                setSelectedPlugins((prev) => {
                    const filtered = prev.filter((p) => supported.includes(p));
                    if (filtered.length > 0) {
                        return filtered;
                    }
                    return supported.slice(0, Math.min(2, supported.length));
                });
            } catch (e) {
                console.error("Failed to load Promptfoo vectors", e);
                setErrorMsg("Failed to load official Promptfoo vectors.");
            }
        };
        loadPlugins();
    }, []);

    const startEval = async () => {
        if (selectedPlugins.length === 0) {
            setErrorMsg("Select at least one attack vector before launching.");
            return;
        }
        setStatus("running");
        setProgress(0);
        setCompletedTests(0);
        setTotalTests(0);
        setPhase("Preparing attack chain");
        setEtaSeconds(null);
        setLastOutputLine("");
        setReport(null);
        setErrorMsg("");
        try {
            const res = await fetch("http://localhost:8000/eval/run", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    num_tests: numTests,
                    plugins: selectedPlugins,
                    strategies: [],
                    session_hardened: promptfooProtectionEnabled,
                    proxy_enabled: promptfooProtectionEnabled,
                })
            });
            if (!res.ok) throw new Error("Failed to start eval");
            const data = await res.json();
            setRunId(data.run_id);
            if (data.phase) setPhase(data.phase);
            if (data.eta_seconds !== undefined) setEtaSeconds(data.eta_seconds);
            if (data.last_output_line) setLastOutputLine(data.last_output_line);
        } catch (e: any) {
            setErrorMsg(e.message);
            setStatus("failed");
        }
    };

    const stopEval = async () => {
        try {
            // Nuclear stop - kills ALL promptfoo processes regardless of runId
            await fetch("http://localhost:8000/eval/kill-all", { method: "POST" });
        } catch (e) {
            // Best-effort - even if it fails, reset UI state
        } finally {
            setStatus("idle");
            setRunId(null);
            setProgress(0);
            setCompletedTests(0);
            setTotalTests(0);
            setPhase("Idle");
            setEtaSeconds(null);
            setLastOutputLine("");
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
                        setProgress((prev) => Math.max(prev, data.progress * 100));
                        if (data.completed_tests !== undefined) setCompletedTests(data.completed_tests);
                        if (data.total_tests !== undefined) setTotalTests(data.total_tests);
                        if (data.phase) setPhase(data.phase);
                        if (data.eta_seconds !== undefined) setEtaSeconds(data.eta_seconds);
                        if (data.last_output_line !== undefined) setLastOutputLine(data.last_output_line);
                        if (data.status === "completed") {
                            setProgress(100);
                            setPhase("Completed");
                            setEtaSeconds(0);
                            setLastOutputLine("");
                            setStatus("completed");
                            fetchReport(runId);
                        } else if (data.status === "failed") {
                            setStatus("failed");
                            setEtaSeconds(null);
                            setErrorMsg("Evaluation process exited with an error. Check backend logs. You can retry with Launch Eval.");
                            // Do NOT hide progress bar on failure - let user see state and retry
                        } else if (data.status === "stopped") {
                            setStatus("idle");
                            setRunId(null);
                            setProgress(0);
                            setPhase("Stopped");
                            setEtaSeconds(null);
                            setLastOutputLine("");
                        }
                    }
                } catch (e) {
                    console.error("Status check failed", e);
                }
            }, 500);
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
                        Promptfoo Red Team Eval
                    </h1>
                    <p className="text-slate-400 mt-2 text-sm leading-relaxed max-w-2xl">
                        Execute advanced adversarial attacks against the Aegis Target Agent using dynamic AI generators. This will launch a sandboxed container and sweep multiple vulnerability categories automatically.
                    </p>
                </div>
                <div className="flex items-center gap-3">
                    {/* STOP - always visible, always works */}
                    <button
                        onClick={stopEval}
                        className="px-6 py-3 rounded-xl font-bold flex items-center gap-2 transition-all bg-red-600 hover:bg-red-500 text-white shadow-[0_0_20px_rgba(239,68,68,0.4)] active:scale-95"
                        title="Stop any running evaluation immediately"
                    >
                        Stop Eval
                    </button>

                    {/* LAUNCH - disabled while running */}
                    <button
                        onClick={startEval}
                        disabled={status === "running"}
                        className={`px-6 py-3 rounded-xl font-bold flex items-center gap-2 transition-all ${status === "running"
                            ? "bg-slate-800 text-slate-500 cursor-not-allowed"
                            : "bg-purple-500 hover:bg-purple-400 text-white shadow-[0_0_20px_rgba(168,85,247,0.4)] active:scale-95"
                            }`}
                    >
                        {status === "running" ? (
                            <><div className="w-5 h-5 border-2 border-white/20 border-t-white rounded-full animate-spin" /> Scanning...</>
                        ) : (
                            <>Launch Eval</>
                        )}
                    </button>
                </div>
            </div>

            {/* Compliance Quick Links */}
            <div className="flex gap-4 mb-8">
                <button
                    onClick={() => window.open('http://localhost:15500', '_blank')}
                    className="flex-1 bg-slate-800/80 hover:bg-slate-700 border border-white/10 p-4 rounded-xl flex items-center justify-between group transition-all"
                >
                    <div className="flex items-center gap-4">
                        <div className="w-10 h-10 bg-indigo-500/20 rounded-lg flex items-center justify-center text-xl" />
                        <div className="text-left">
                            <div className="text-white font-bold">OWASP / NIST Compliance</div>
                            <div className="text-slate-400 text-xs">View full regulatory mapping and ready-to-share reports</div>
                        </div>
                    </div>
                    <span className="text-slate-500 group-hover:text-white transition-colors">-&gt;</span>
                </button>
            </div>

            {/* Attack Vector Selection */}
            <div className="bg-slate-900/50 border border-white/5 p-6 rounded-2xl mb-8">
                <div className="flex items-center justify-between mb-6">
                    <h3 className="text-white font-bold flex items-center gap-2">
                        Attack Vectors & Scaling
                    </h3>

                    <div className="flex items-center gap-4 bg-slate-950/50 p-2 px-4 rounded-xl border border-white/5">
                        <label className="text-slate-400 text-xs font-bold uppercase tracking-wider text-[10px]">Tests Per Plugin:</label>
                        <input
                            type="number"
                            min="1"
                            max="100"
                            value={numTests}
                            onChange={(e) => setNumTests(parseInt(e.target.value) || 1)}
                            className="bg-slate-900 border border-white/10 rounded-lg px-3 py-1 text-white font-mono w-20 focus:outline-none focus:border-purple-500/50 transition-all"
                        />
                    </div>
                    <button
                        type="button"
                        onClick={() => setPromptfooProtectionEnabled((prev) => !prev)}
                        className={`px-4 py-2 rounded-xl text-[10px] font-black uppercase tracking-[0.18em] border transition-all ${
                            promptfooProtectionEnabled
                                ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-300"
                                : "bg-slate-950/50 border-white/5 text-slate-400"
                        }`}
                        title="When on, Promptfoo uses proxy and hardening together."
                    >
                        Protection {promptfooProtectionEnabled ? "On" : "Off"}
                    </button>
                </div>
                <p className="text-slate-500 text-xs mb-4">
                    Showing {availablePlugins.length}
                    {pluginCatalog ? ` locally supported vectors out of ${pluginCatalog.official_plugins.length} official Promptfoo vectors.` : " vectors."}
                </p>
                <div className="flex flex-wrap gap-3">

                    {availablePlugins.map(plugin => {
                        const isSelected = selectedPlugins.includes(plugin);
                        return (
                            <button
                                key={plugin}
                                onClick={() => {
                                    if (isSelected) {
                                        if (selectedPlugins.length > 1) {
                                            setSelectedPlugins(selectedPlugins.filter(p => p !== plugin));
                                        }
                                    } else {
                                        setSelectedPlugins([...selectedPlugins, plugin]);
                                    }
                                }}
                                className={`px-4 py-2 rounded-lg text-sm font-medium transition-all border ${isSelected
                                    ? "bg-purple-500/20 border-purple-500/50 text-purple-300"
                                    : "bg-slate-800/50 border-white/5 text-slate-400 hover:bg-slate-800 hover:text-slate-300"
                                    }`}
                            >
                                {plugin}
                            </button>
                        );
                    })}
                </div>
            </div>

            {errorMsg && (
                <div className="p-4 bg-red-500/10 border border-red-500/20 text-red-400 rounded-xl text-sm font-medium">
                    Error: {errorMsg}
                </div>
            )}

            {/* Progress Bar & Stop Control */}
            <AnimatePresence>
                {status === "running" && (
                    <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        exit={{ opacity: 0, height: 0 }}
                        className="bg-slate-900/50 border border-purple-500/30 p-6 rounded-2xl relative overflow-hidden"
                    >
                        <div className="flex justify-between items-start mb-6">
                            <div className="flex-1">
                                <div className="flex items-center gap-3">
                                    <div className="w-2 h-2 rounded-full bg-purple-500 animate-ping" />
                                    <h3 className="text-white font-black text-xl tracking-tight">Active Evaluation Chain</h3>
                                </div>
                                <p className="text-slate-400 text-sm mt-1 max-w-xl">
                                    Aegis is currently stress-testing the target agent with {selectedPlugins.length} attack vectors.
                                    Do not close this window until the report is synthesized.
                                </p>
                                <p className="text-slate-500 text-[11px] mt-2 font-bold uppercase tracking-[0.14em]">
                                    Protection {promptfooProtectionEnabled ? "On" : "Off"}
                                </p>
                                <p className="text-cyan-400/80 text-xs mt-2 font-bold">
                                    {phase}{etaSeconds !== null && status === "running" ? ` | ~${etaSeconds}s remaining` : ""}
                                </p>
                                {lastOutputLine && (
                                    <p className="text-slate-500 text-xs mt-2 font-mono truncate">
                                        {lastOutputLine}
                                    </p>
                                )}
                            </div>

                            <button
                                onClick={stopEval}
                                className="px-4 py-2 bg-rose-500/10 hover:bg-rose-500 border border-rose-500/30 text-rose-500 hover:text-white rounded-xl text-[10px] font-black uppercase tracking-widest transition-all active:scale-95 flex items-center gap-2"
                            >
                                <span className="text-sm">[X]</span> Stop Sequence
                            </button>
                        </div>

                        <div className="space-y-2">
                            <div className="flex justify-between items-end">
                                <span className="text-[10px] font-black text-purple-400 uppercase tracking-widest">Orchestration Progress</span>
                                <span className="text-purple-400 font-mono text-sm font-bold">
                                    {totalTests > 0
                                        ? `Test ${completedTests} / ${totalTests}`
                                        : etaSeconds !== null && status === "running"
                                            ? `${Math.round(progress)}% | ~${etaSeconds}s`
                                            : `${Math.round(progress)}%`
                                    }
                                </span>
                            </div>
                            <div className="h-3 w-full bg-slate-950 rounded-full overflow-hidden border border-white/5 p-0.5">
                                <motion.div
                                    className="h-full bg-gradient-to-r from-purple-600 via-indigo-500 to-cyan-400 rounded-full relative"
                                    initial={{ width: "0%" }}
                                    animate={{ width: `${progress}%` }}
                                    transition={{ duration: 0.5 }}
                                >
                                    <div className="absolute inset-0 bg-white/20 animate-[shimmer_2s_infinite]" />
                                </motion.div>
                            </div>
                        </div>

                        {/* Current Task HUD */}
                        <div className="mt-6 pt-6 border-t border-white/5 flex gap-8 items-center">
                            <div className="flex flex-col">
                                <span className="text-[9px] font-black text-slate-500 uppercase tracking-[0.2em] mb-1">Target Engine</span>
                                <span className="text-xs font-bold text-slate-300">Ollama (Llama 3.1 8B)</span>
                            </div>
                            <div className="flex flex-col">
                                <span className="text-[9px] font-black text-slate-500 uppercase tracking-[0.2em] mb-1">Active Plugins</span>
                                <span className="text-xs font-bold text-indigo-400">{selectedPlugins.length} / {availablePlugins.length}</span>
                            </div>
                            <div className="flex flex-col">
                                <span className="text-[9px] font-black text-slate-500 uppercase tracking-[0.2em] mb-1">Status</span>
                                <span className="text-xs font-bold text-emerald-400 animate-pulse">{phase.toUpperCase()}</span>
                            </div>
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
                        <StatCard label="Total Tests" value={report.total_tests} icon="T" />
                        <StatCard label="Defended (Passed)" value={report.passed} valueColor="text-emerald-400" icon="OK" />
                        <StatCard label="Exploited (Failed)" value={report.failed} valueColor="text-red-400" icon="X" />
                        <StatCard label="Errors" value={report.errors} valueColor="text-amber-400" icon="!" />
                    </div>

                    {/* Plugin Matrix */}
                    <div className="bg-slate-900/50 border border-white/5 rounded-2xl overflow-hidden">
                        <div className="p-5 border-b border-white/5 bg-slate-950/20">
                            <h3 className="text-white font-bold flex items-center gap-2"><span className="text-indigo-400">[M]</span> Vulnerability Matrix</h3>
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

