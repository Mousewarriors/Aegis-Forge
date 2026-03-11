"use client";

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

type EvalReport = {
    run_id: string;
    evaluator?: string;
    total_tests: number;
    passed: number;
    failed: number;
    errors: number;
    plugins: Record<string, any>;
    raw_results: any[];
    report_state?: "provisional" | "official";
    generated_at?: number;
    timeline?: EvalActivity[];
    recent_attempts?: EvalAttempt[];
};

type EvalActivity = {
    id?: string;
    timestamp?: number;
    run_id?: string;
    evaluator?: string;
    event_type?: string;
    summary?: string;
    phase?: string;
    status?: string;
    severity?: string;
    success?: boolean;
    provisional?: boolean;
    probe_id?: string;
    probe_label?: string;
    probe_description?: string;
    plugin_id?: string;
    progress_completed?: number;
    progress_total?: number;
    prompt?: string;
    response?: string;
    attack_type?: string;
    converter_chain?: string[];
    objective_index?: number;
    preview_mode?: string;
    transformed_preview?: string;
    transformed_preview_escaped?: string;
    transformation_note?: string;
    transformation_summary?: string;
    status_text?: string;
};

type EvalAttempt = {
    seq?: number;
    probe_id?: string;
    probe_label?: string;
    probe_description?: string;
    category?: string;
    prompt?: string;
    response?: string;
    detector_results?: Record<string, any>;
    status?: number;
};

type PyritObjectivePreviewSample = {
    raw_objective?: string;
    transformed_preview?: string;
    transformed_preview_escaped?: string;
    preview_mode?: string;
    transformation_note?: string;
    transformation_summary?: string;
    attack_type?: string;
    converter_chain?: string[];
};

type EvalStatusPayload = {
    run_id: string;
    evaluator: Evaluator;
    status: "idle" | "running" | "completed" | "failed" | "stopped";
    progress: number;
    completed_tests: number;
    total_tests: number;
    phase: string;
    eta_seconds?: number | null;
    last_output_line?: string;
    last_stderr?: string[];
    warnings?: string[];
    requested_mode?: string;
    effective_mode?: string;
    remote_readiness?: EvalRemoteReadiness;
    current_probe?: string | null;
    current_probe_label?: string | null;
    current_probe_description?: string | null;
    probe_progress?: Record<string, any>;
    live_events?: EvalActivity[];
    recent_attempts?: EvalAttempt[];
    preview_report?: EvalReport | Record<string, any>;
    report_ready?: boolean;
};

type EvalLogPayload = {
    run_id: string;
    evaluator?: Evaluator;
    live_events?: EvalActivity[];
    attempts?: EvalAttempt[];
    failed_results?: any[];
    report_state?: "provisional" | "official" | string;
};

type EvalPluginDetail = {
    id: string;
    label?: string;
    description?: string;
    category?: string;
    aliases?: string[];
    recommended?: boolean;
    selection_kind?: "family" | "probe";
    parent_plugin?: string;
    estimated_prompts?: number;
    concrete_probe_ids?: string[];
    concrete_probe_count?: number;
    attack_type?: string;
    converter_chain?: string[];
    objective_templates?: string[];
    objective_preview_samples?: PyritObjectivePreviewSample[];
    scorer?: string;
};

type EvalPluginCatalog = {
    official_plugins: string[];
    supported_plugins: string[];
    unsupported_plugins: Record<string, string>;
    plugin_details?: Record<string, EvalPluginDetail>;
    plugin_groups?: EvalPluginDetail[];
    recommended_plugins?: string[];
    plugin_modes?: Record<string, string[]>;
    default_mode?: string;
    remote_generation_enabled?: boolean;
    remote_readiness?: EvalRemoteReadiness;
};

type EvalRemoteReadiness = {
    ready: boolean;
    policy_enabled?: boolean;
    auth_ready?: boolean;
    source?: string;
    reason?: string;
    checked_at?: number;
};

type EvalMode = "local" | "hybrid" | "remote";
type Evaluator = "promptfoo" | "garak" | "pyrit";

const normalizeEvaluatorParam = (value?: string | null): Evaluator => {
    const normalized = String(value || "").trim().toLowerCase();
    if (normalized === "garak") return "garak";
    if (normalized === "pyrit") return "pyrit";
    return "promptfoo";
};

const getRequestedEvaluatorFromLocation = (): Evaluator => {
    if (typeof window === "undefined") {
        return "promptfoo";
    }
    const params = new URLSearchParams(window.location.search);
    return normalizeEvaluatorParam(params.get("evaluator") || params.get("engine"));
};

const normalizeEvalMode = (mode?: string): EvalMode => {
    const value = String(mode || "local").toLowerCase();
    if (value === "hybrid" || value === "remote") return value;
    return "local";
};

const pluginsForMode = (catalog: EvalPluginCatalog, mode: EvalMode): string[] => {
    if (!catalog) return [];
    const official = Array.isArray(catalog.official_plugins) ? catalog.official_plugins : [];
    const unsupportedSet = new Set(Object.keys(catalog.unsupported_plugins || {}));
    if (mode === "local") {
        if (Array.isArray(catalog.supported_plugins) && catalog.supported_plugins.length > 0) {
            return catalog.supported_plugins.filter((plugin) => !unsupportedSet.has(plugin));
        }
        return official.filter((plugin) => !unsupportedSet.has(plugin));
    }
    const pluginModes = catalog.plugin_modes || {};
    return official.filter((plugin) => {
        const modes = pluginModes[plugin];
        return !Array.isArray(modes) || modes.length === 0 || modes.includes(mode);
    });
};

const pluginMeta = (catalog: EvalPluginCatalog | null, plugin: string) => {
    return catalog?.plugin_details?.[plugin] || null;
};

const getGroupedPluginFamilies = (catalog: EvalPluginCatalog | null): EvalPluginDetail[] => {
    return Array.isArray(catalog?.plugin_groups) ? (catalog.plugin_groups as EvalPluginDetail[]) : [];
};

const getEffectiveCount = (estimatedCount?: number, cap?: number) => {
    const prompts = Math.max(Number(estimatedCount) || 0, 0);
    const normalizedCap = Math.max(Number(cap) || 0, 0);
    return normalizedCap > 0 ? Math.min(prompts, normalizedCap) : prompts;
};

const formatAuditTime = (timestamp?: number) => {
    if (!timestamp) return "--:--:--";
    return new Date(timestamp * 1000).toLocaleTimeString();
};

const formatPreviewMode = (value?: string) => {
    const normalized = String(value || "direct").trim().toLowerCase();
    if (normalized === "exact") return "Exact preview";
    if (normalized === "approximate") return "Approximate preview";
    if (normalized === "partial") return "Partial preview";
    if (normalized === "runtime_only") return "Runtime only";
    return "Direct objective";
};

const eventTone = (event: EvalActivity) => {
    if (event.severity === "error") {
        return "border-red-500/30 bg-red-500/5 text-red-200";
    }
    if (event.success) {
        return "border-red-500/30 bg-red-500/5 text-red-200";
    }
    if (event.provisional) {
        return "border-amber-500/30 bg-amber-500/5 text-amber-200";
    }
    if (event.event_type === "completion") {
        return "border-emerald-500/30 bg-emerald-500/5 text-emerald-200";
    }
    return "border-cyan-500/20 bg-cyan-500/5 text-cyan-100";
};

export default function EvalDashboard() {
    const [evaluator, setEvaluator] = useState<Evaluator>(() => getRequestedEvaluatorFromLocation());
    const [status, setStatus] = useState<"idle" | "running" | "completed" | "failed" | "stopped">("idle");
    const [runId, setRunId] = useState<string | null>(null);
    const [progress, setProgress] = useState(0);
    const [completedTests, setCompletedTests] = useState(0);
    const [totalTests, setTotalTests] = useState(0);
    const [phase, setPhase] = useState("Idle");
    const [etaSeconds, setEtaSeconds] = useState<number | null>(null);
    const [lastOutputLine, setLastOutputLine] = useState("");
    const [lastStderr, setLastStderr] = useState<string[]>([]);
    const [report, setReport] = useState<EvalReport | null>(null);
    const [previewReport, setPreviewReport] = useState<EvalReport | null>(null);
    const [liveEvents, setLiveEvents] = useState<EvalActivity[]>([]);
    const [recentAttempts, setRecentAttempts] = useState<EvalAttempt[]>([]);
    const [failedResults, setFailedResults] = useState<any[]>([]);
    const [currentProbe, setCurrentProbe] = useState<string | null>(null);
    const [currentProbeLabel, setCurrentProbeLabel] = useState<string>("");
    const [currentProbeDescription, setCurrentProbeDescription] = useState<string>("");
    const [probeProgress, setProbeProgress] = useState<Record<string, any>>({});
    const [availablePlugins, setAvailablePlugins] = useState<string[]>([]);
    const [pluginCatalog, setPluginCatalog] = useState<EvalPluginCatalog | null>(null);
    const [selectedPlugins, setSelectedPlugins] = useState<string[]>(["pliny", "rbac"]);
    const [evalMode, setEvalMode] = useState<EvalMode>("local");
    const [requestedMode, setRequestedMode] = useState<EvalMode>("local");
    const [effectiveMode, setEffectiveMode] = useState<EvalMode>("local");
    const [runWarnings, setRunWarnings] = useState<string[]>([]);
    const [remoteReadiness, setRemoteReadiness] = useState<EvalRemoteReadiness | null>(null);
    const [numTests, setNumTests] = useState(5);
    const [garakPromptCap, setGarakPromptCap] = useState(8);
    const [promptfooProtectionEnabled, setPromptfooProtectionEnabled] = useState(true);
    const [errorMsg, setErrorMsg] = useState("");

    useEffect(() => {
        const nextEvaluator = getRequestedEvaluatorFromLocation();
        setEvaluator((current) => (current === nextEvaluator ? current : nextEvaluator));
    }, []);

    useEffect(() => {
        const loadPlugins = async () => {
            try {
                const res = await fetch(`http://localhost:8000/eval/plugins?evaluator=${evaluator}`);
                if (!res.ok) {
                    throw new Error(`Failed to load ${evaluator} vectors`);
                }
                const data: EvalPluginCatalog = await res.json();
                setPluginCatalog(data);
                const defaultMode = normalizeEvalMode(data.default_mode);
                setEvalMode(defaultMode);
                setRequestedMode(defaultMode);
                setEffectiveMode(defaultMode);
                if (data.remote_readiness) {
                    setRemoteReadiness(data.remote_readiness);
                }
                if (Array.isArray(data.recommended_plugins) && data.recommended_plugins.length > 0) {
                    setSelectedPlugins(data.recommended_plugins.slice(0, Math.min(3, data.recommended_plugins.length)));
                }
                const readinessRes = await fetch(`http://localhost:8000/eval/readiness?evaluator=${evaluator}`);
                if (readinessRes.ok) {
                    const readiness = await readinessRes.json();
                    setRemoteReadiness(readiness);
                }
            } catch (e) {
                console.error(`Failed to load ${evaluator} vectors`, e);
                setErrorMsg(`Failed to load official ${evaluator} vectors.`);
            }
        };
        loadPlugins();
    }, [evaluator]);

    useEffect(() => {
        if (!pluginCatalog) return;
        const plugins = pluginsForMode(pluginCatalog, evalMode);
        setAvailablePlugins(plugins);
        setSelectedPlugins((prev) => {
            const filtered = prev.filter((p) => plugins.includes(p));
            if (filtered.length > 0) {
                return filtered;
            }
            return plugins.slice(0, Math.min(2, plugins.length));
        });
    }, [pluginCatalog, evalMode, evaluator]);

    const syncStatusData = (data: Partial<EvalStatusPayload>) => {
        if (data.progress !== undefined) {
            setProgress((prev) => Math.max(prev, Number(data.progress) * 100));
        }
        if (data.completed_tests !== undefined) setCompletedTests(Number(data.completed_tests) || 0);
        if (data.total_tests !== undefined) setTotalTests(Number(data.total_tests) || 0);
        if (data.phase) setPhase(data.phase);
        if (data.eta_seconds !== undefined) setEtaSeconds(data.eta_seconds ?? null);
        if (data.last_output_line !== undefined) setLastOutputLine(data.last_output_line || "");
        if (Array.isArray(data.last_stderr)) setLastStderr(data.last_stderr);
        if (data.requested_mode) setRequestedMode(normalizeEvalMode(data.requested_mode));
        if (data.effective_mode) setEffectiveMode(normalizeEvalMode(data.effective_mode));
        if (Array.isArray(data.warnings)) setRunWarnings(data.warnings);
        if (data.remote_readiness) setRemoteReadiness(data.remote_readiness);
        if (Array.isArray(data.live_events)) setLiveEvents(data.live_events);
        if (Array.isArray(data.recent_attempts)) setRecentAttempts(data.recent_attempts);
        if (data.current_probe !== undefined) setCurrentProbe(data.current_probe || null);
        if (data.current_probe_label !== undefined) setCurrentProbeLabel(data.current_probe_label || "");
        if (data.current_probe_description !== undefined) setCurrentProbeDescription(data.current_probe_description || "");
        if (data.probe_progress && typeof data.probe_progress === "object") setProbeProgress(data.probe_progress);
        if (data.preview_report && typeof data.preview_report === "object" && Object.keys(data.preview_report).length > 0) {
            setPreviewReport(data.preview_report as EvalReport);
        }
    };

    const fetchReport = async (id: string, retries = 8): Promise<void> => {
        try {
            const res = await fetch(`http://localhost:8000/eval/report/${id}`);
            if (res.ok) {
                const data: EvalReport = await res.json();
                setReport(data);
                setPreviewReport(data);
                setErrorMsg("");
                return;
            }
            const detail = await res.text();
            if ((res.status === 400 || res.status === 404 || res.status === 500) && retries > 0) {
                await new Promise((resolve) => setTimeout(resolve, 750));
                return fetchReport(id, retries - 1);
            }
            setErrorMsg(`Failed to load report data. ${detail}`.trim());
        } catch (e) {
            if (retries > 0) {
                await new Promise((resolve) => setTimeout(resolve, 750));
                return fetchReport(id, retries - 1);
            }
            setErrorMsg("Failed to load report data.");
        }
    };

    const fetchLogs = async (id: string): Promise<void> => {
        try {
            const res = await fetch(`http://localhost:8000/eval/logs/${id}`);
            if (!res.ok) return;
            const data: EvalLogPayload = await res.json();
            if (Array.isArray(data.live_events)) setLiveEvents(data.live_events);
            if (Array.isArray(data.attempts)) setRecentAttempts(data.attempts);
            if (Array.isArray(data.failed_results)) setFailedResults(data.failed_results);
        } catch (e) {
            console.error("Failed to load full eval logs", e);
        }
    };

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
        setLastStderr([]);
        setReport(null);
        setPreviewReport(null);
        setLiveEvents([]);
        setRecentAttempts([]);
        setFailedResults([]);
        setCurrentProbe(null);
        setCurrentProbeLabel("");
        setCurrentProbeDescription("");
        setProbeProgress({});
        setRunWarnings([]);
        setErrorMsg("");
        try {
            const basePayload = {
                evaluator,
                num_tests: numTests,
                plugins: selectedPlugins,
                strategies: [],
                garak_prompt_cap: evaluator === "garak" ? garakPromptCap : null,
                session_hardened: promptfooProtectionEnabled,
                proxy_enabled: promptfooProtectionEnabled,
                eval_mode: evalMode,
            };

            const preflightRes = await fetch("http://localhost:8000/eval/preflight", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(basePayload),
            });
            if (!preflightRes.ok) throw new Error("Failed to preflight eval settings");
            const preflight = await preflightRes.json();
            const preflightPlugins = Array.isArray(preflight.selected_plugins) ? preflight.selected_plugins : selectedPlugins;
            const resolvedRequested = normalizeEvalMode(preflight.requested_mode);
            const resolvedEffective = normalizeEvalMode(preflight.effective_mode);
            setRequestedMode(resolvedRequested);
            setEffectiveMode(resolvedEffective);
            setRunWarnings(Array.isArray(preflight.warnings) ? preflight.warnings : []);
            if (preflight.remote_readiness) setRemoteReadiness(preflight.remote_readiness);

            if (preflightPlugins.length === 0) {
                throw new Error("No runnable vectors remain after preflight filtering.");
            }

            const res = await fetch("http://localhost:8000/eval/run", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    ...basePayload,
                    plugins: preflightPlugins,
                })
            });
            if (!res.ok) throw new Error("Failed to start eval");
            const data: EvalStatusPayload = await res.json();
            setRunId(data.run_id);
            syncStatusData(data);
            await fetchLogs(data.run_id);
        } catch (e: any) {
            setErrorMsg(e.message);
            setStatus("failed");
        }
    };

    const stopEval = async () => {
        try {
            if (runId) {
                await fetch(`http://localhost:8000/eval/stop/${runId}`, { method: "POST" });
                const res = await fetch(`http://localhost:8000/eval/status/${runId}`);
                if (res.ok) {
                    const data: EvalStatusPayload = await res.json();
                    syncStatusData(data);
                    await fetchLogs(runId);
                    await fetchReport(runId);
                }
            } else {
                await fetch("http://localhost:8000/eval/kill-all", { method: "POST" });
            }
        } catch (e) {
            console.error("Failed to stop evaluation cleanly", e);
        } finally {
            setStatus("stopped");
            setPhase("Stopped");
            setEtaSeconds(null);
            setLastOutputLine((prev) => prev || "Evaluation stopped by user.");
        }
    };

    const resetEvalDashboard = async () => {
        try {
            await fetch("http://localhost:8000/eval/reset", { method: "POST" });
        } catch (e) {
            console.error("Failed to reset evaluation dashboard", e);
        } finally {
            setStatus("idle");
            setRunId(null);
            setProgress(0);
            setCompletedTests(0);
            setTotalTests(0);
            setPhase("Idle");
            setEtaSeconds(null);
            setLastOutputLine("");
            setLastStderr([]);
            setReport(null);
            setPreviewReport(null);
            setLiveEvents([]);
            setRecentAttempts([]);
            setFailedResults([]);
            setCurrentProbe(null);
            setCurrentProbeLabel("");
            setCurrentProbeDescription("");
            setProbeProgress({});
            setRunWarnings([]);
            setErrorMsg("");
        }
    };

    const togglePluginSelection = (plugin: string) => {
        setSelectedPlugins((prev) => (
            prev.includes(plugin)
                ? prev.filter((current) => current !== plugin)
                : [...prev, plugin]
        ));
    };

    const setGarakFamilySelection = (probeIds: string[], selected: boolean) => {
        setSelectedPlugins((prev) => {
            const next = new Set(prev);
            for (const probeId of probeIds) {
                if (selected) {
                    next.add(probeId);
                } else {
                    next.delete(probeId);
                }
            }
            return Array.from(next);
        });
    };


    useEffect(() => {
        let interval: NodeJS.Timeout;
        if (status === "running" && runId) {
            interval = setInterval(async () => {
                try {
                    const res = await fetch(`http://localhost:8000/eval/status/${runId}`);
                    if (res.ok) {
                        const data: EvalStatusPayload = await res.json();
                        syncStatusData(data);
                        await fetchLogs(runId);
                        if (data.status === "completed") {
                            setProgress(100);
                            setStatus("completed");
                            if (data.phase) setPhase(data.phase);
                            setEtaSeconds(0);
                            await fetchReport(runId);
                        } else if (data.status === "failed") {
                            setStatus("failed");
                            setEtaSeconds(null);
                            await fetchReport(runId);
                            setErrorMsg(
                                data.last_stderr && data.last_stderr.length > 0
                                    ? `Evaluation process exited with an error. ${data.last_stderr[0]}`
                                    : "Evaluation process exited with an error. Check backend logs. You can retry with Launch Eval."
                            );
                        } else if (data.status === "stopped") {
                            setStatus("stopped");
                            setPhase("Stopped");
                            setEtaSeconds(null);
                            await fetchReport(runId);
                        }
                    }
                } catch (e) {
                    console.error("Status check failed", e);
                }
            }, 750);
        }
        return () => clearInterval(interval);
    }, [status, runId]);

    const displayedReport = report || previewReport;
    const reportState = displayedReport?.report_state || (report ? "official" : "provisional");
    const runningOrStopped = status === "running" || status === "stopped" || status === "failed";
    const displayedFailedResults = Array.isArray(report?.raw_results) && report.raw_results.length > 0
        ? report.raw_results.filter((result: any) => !result?.passed)
        : failedResults;
    const groupedFamilies = getGroupedPluginFamilies(pluginCatalog);
    const selectedGarakProbeDetails = evaluator === "garak"
        ? selectedPlugins
            .map((plugin) => pluginMeta(pluginCatalog, plugin))
            .filter((detail): detail is EvalPluginDetail => Boolean(detail))
        : [];
    const selectedGarakFamilies = Array.from(
        new Set(selectedGarakProbeDetails.map((detail) => detail.parent_plugin).filter((value): value is string => Boolean(value)))
    );
    const estimatedGarakPromptCases = selectedGarakProbeDetails.reduce(
        (total, detail) => total + getEffectiveCount(detail.estimated_prompts, garakPromptCap),
        0,
    );
    const estimatedGarakAttempts = estimatedGarakPromptCases * Math.max(numTests, 1);
    const selectedPyritScenarioDetails = evaluator === "pyrit"
        ? selectedPlugins
            .map((plugin) => pluginMeta(pluginCatalog, plugin))
            .filter((detail): detail is EvalPluginDetail => Boolean(detail))
        : [];
    const selectedPyritFamilies = Array.from(
        new Set(selectedPyritScenarioDetails.map((detail) => detail.parent_plugin).filter((value): value is string => Boolean(value)))
    );
    const estimatedPyritAttempts = selectedPyritScenarioDetails.reduce(
        (total, detail) => total + getEffectiveCount(detail.estimated_prompts, numTests),
        0,
    );
    const pyritObjectivePreview = selectedPyritScenarioDetails.map((detail) => ({
        id: detail.id,
        label: detail.label || detail.id,
        attackType: detail.attack_type || "prompt_sending",
        converterChain: Array.isArray(detail.converter_chain) ? detail.converter_chain : [],
        previewSamples: Array.isArray(detail.objective_preview_samples) && detail.objective_preview_samples.length > 0
            ? detail.objective_preview_samples.slice(0, Math.max(numTests, 1))
            : Array.isArray(detail.objective_templates)
                ? detail.objective_templates.slice(0, Math.max(numTests, 1)).map((objective) => ({
                    raw_objective: objective,
                    preview_mode: "direct",
                    transformed_preview: "",
                    transformed_preview_escaped: "",
                    transformation_note: "",
                    transformation_summary: "Direct objective",
                }))
                : [],
    }));

    return (
        <div className="p-8 max-w-7xl mx-auto space-y-8">
            {/* Header */}
            <div className="flex items-center justify-between border-b border-white/10 pb-6 mb-8">
                <div>
                    <h1 className="text-3xl font-black text-white tracking-tight flex items-center gap-3">
                        {evaluator === "promptfoo"
                            ? "Promptfoo Red Team Eval"
                            : evaluator === "garak"
                                ? "Garak Red Team Eval"
                                : "PyRIT Red Team Eval"}
                    </h1>
                    <p className="text-slate-400 mt-2 text-sm leading-relaxed max-w-2xl">
                        Execute advanced adversarial attacks against the Aegis Target Agent using the selected evaluator. This will launch a sandboxed sweep and stream results into the shared audit feed.
                    </p>
                </div>
                <div className="flex items-center gap-3">
                    <button
                        onClick={resetEvalDashboard}
                        className="px-6 py-3 rounded-xl font-bold flex items-center gap-2 transition-all bg-slate-800 hover:bg-slate-700 text-white border border-white/10 active:scale-95"
                        title="Clear the dashboard state, audit feed, and test counters"
                    >
                        Reset Dashboard
                    </button>
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
                    <div className="flex items-center gap-3">
                        <div className="flex items-center gap-1 bg-slate-950/50 p-1 rounded-xl border border-white/5">
                            {(["promptfoo", "garak", "pyrit"] as Evaluator[]).map((engineOption) => (
                                <button
                                    key={engineOption}
                                    type="button"
                                    onClick={() => setEvaluator(engineOption)}
                                    className={`px-3 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-[0.16em] border transition-all ${
                                        evaluator === engineOption
                                            ? "bg-cyan-500/20 border-cyan-500/40 text-cyan-300"
                                            : "bg-slate-950/50 border-white/5 text-slate-400"
                                    }`}
                                >
                                    {engineOption}
                                </button>
                            ))}
                        </div>
                        <div className="flex items-center gap-1 bg-slate-950/50 p-1 rounded-xl border border-white/5">
                            {(["local", "hybrid", "remote"] as EvalMode[]).map((modeOption) => (
                                <button
                                    key={modeOption}
                                    type="button"
                                    onClick={() => evaluator === "promptfoo" && setEvalMode(modeOption)}
                                    disabled={evaluator !== "promptfoo"}
                                    className={`px-3 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-[0.16em] border transition-all ${
                                        evalMode === modeOption
                                            ? "bg-indigo-500/20 border-indigo-500/40 text-indigo-300"
                                            : "bg-slate-950/50 border-white/5 text-slate-400"
                                    }`}
                                    title={modeOption === "local"
                                        ? "Use only vectors runnable in local mode."
                                        : modeOption === "hybrid"
                                            ? "Allow vectors that require remote generation when enabled."
                                            : "Run remote-required vectors only (requires remote enable)."}
                                >
                                    {modeOption}
                                </button>
                            ))}
                        </div>
                        <div className="flex items-center gap-4 bg-slate-950/50 p-2 px-4 rounded-xl border border-white/5">
                            <label className="text-slate-400 text-xs font-bold uppercase tracking-wider text-[10px]">
                                {evaluator === "garak"
                                    ? "Generations Per Prompt:"
                                    : evaluator === "pyrit"
                                        ? "Objectives Per Scenario:"
                                        : "Tests Per Plugin:"}
                            </label>
                            <input
                                type="number"
                                min="1"
                                max="100"
                                value={numTests}
                                onChange={(e) => setNumTests(parseInt(e.target.value) || 1)}
                                className="bg-slate-900 border border-white/10 rounded-lg px-3 py-1 text-white font-mono w-20 focus:outline-none focus:border-purple-500/50 transition-all"
                            />
                        </div>
                        {evaluator === "garak" && (
                            <div className="flex items-center gap-4 bg-slate-950/50 p-2 px-4 rounded-xl border border-white/5">
                                <label className="text-slate-400 text-xs font-bold uppercase tracking-wider text-[10px]">Prompts Per Probe:</label>
                                <input
                                    type="number"
                                    min="0"
                                    max="200"
                                    value={garakPromptCap}
                                    onChange={(e) => setGarakPromptCap(Math.max(parseInt(e.target.value) || 0, 0))}
                                    className="bg-slate-900 border border-white/10 rounded-lg px-3 py-1 text-white font-mono w-20 focus:outline-none focus:border-purple-500/50 transition-all"
                                />
                                <span className="text-[10px] font-mono uppercase tracking-[0.18em] text-slate-500">0 = Full Probe</span>
                            </div>
                        )}
                        <button
                            type="button"
                            onClick={() => setPromptfooProtectionEnabled((prev) => !prev)}
                            className={`px-4 py-2 rounded-xl text-[10px] font-black uppercase tracking-[0.18em] border transition-all ${
                                promptfooProtectionEnabled
                                    ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-300"
                                    : "bg-slate-950/50 border-white/5 text-slate-400"
                            }`}
                            title={`When on, ${evaluator === "promptfoo" ? "Promptfoo" : evaluator === "garak" ? "Garak" : "PyRIT"} uses proxy and hardening together.`}
                        >
                            Protection {promptfooProtectionEnabled ? "On" : "Off"}
                        </button>
                    </div>
                </div>
                <p className="text-slate-500 text-xs mb-4">
                    {evaluator === "garak"
                        ? `Showing ${availablePlugins.length} concrete Garak probe(s) across ${groupedFamilies.length} family group(s).`
                        : evaluator === "pyrit"
                            ? `Showing ${availablePlugins.length} concrete PyRIT scenario(s) across ${groupedFamilies.length} family group(s).`
                            : `Showing ${availablePlugins.length}${pluginCatalog ? ` vectors in ${evalMode.toUpperCase()} mode out of ${pluginCatalog.official_plugins.length} official Promptfoo vectors.` : " vectors."}`}
                </p>
                {remoteReadiness && evaluator === "promptfoo" && evalMode !== "local" && (
                    <p className={`text-xs mb-2 ${remoteReadiness.ready ? "text-emerald-300" : "text-amber-300"}`}>
                        Remote readiness: {remoteReadiness.ready ? "READY" : "NOT READY"}
                        {remoteReadiness.reason ? ` | ${remoteReadiness.reason}` : ""}
                    </p>
                )}
                {pluginCatalog && evaluator === "promptfoo" && !pluginCatalog.remote_generation_enabled && evalMode !== "local" && (
                    <p className="text-amber-300 text-xs mb-4">
                        Remote generation is disabled on this machine. Hybrid/remote mode will be downgraded to local at launch.
                    </p>
                )}
                {evaluator === "garak" || evaluator === "pyrit" ? (
                    <div className="space-y-4">
                        <div className="rounded-2xl border border-cyan-500/20 bg-slate-950/60 p-5">
                            <div className="flex items-start justify-between gap-4 flex-wrap">
                                <div>
                                    <div className="text-[10px] font-black uppercase tracking-[0.18em] text-cyan-300">Scan Plan</div>
                                    <div className="mt-2 text-sm font-bold text-slate-200">
                                        {evaluator === "garak"
                                            ? `${selectedPlugins.length} concrete probe(s) selected across ${selectedGarakFamilies.length} family group(s)`
                                            : `${selectedPlugins.length} concrete scenario(s) selected across ${selectedPyritFamilies.length} family group(s)`}
                                    </div>
                                    <div className="mt-2 text-sm text-slate-400">
                                        {evaluator === "garak"
                                            ? (
                                                <>
                                                    Estimated runtime volume: about {estimatedGarakAttempts} attempt(s) from {estimatedGarakPromptCases} prompt case(s)
                                                    {garakPromptCap > 0 ? ` with a cap of ${garakPromptCap} prompt(s) per concrete probe.` : " using each probe's full built-in prompt set."}
                                                </>
                                            )
                                            : (
                                                <>
                                                    Estimated runtime volume: about {estimatedPyritAttempts} scored attempt(s) from the first {Math.max(numTests, 1)} objective(s) in each selected scenario.
                                                </>
                                            )}
                                    </div>
                                </div>
                                <div className="text-[11px] font-mono text-slate-500">
                                    {evaluator === "garak"
                                        ? `${numTests} generation${numTests === 1 ? "" : "s"} per prompt`
                                        : `${Math.max(numTests, 1)} objective${Math.max(numTests, 1) === 1 ? "" : "s"} per scenario`}
                                </div>
                            </div>
                        </div>

                        {evaluator === "pyrit" && pyritObjectivePreview.length > 0 && (
                            <div className="rounded-2xl border border-indigo-500/20 bg-slate-950/60 p-5 space-y-4">
                                <div>
                                    <div className="text-[10px] font-black uppercase tracking-[0.18em] text-indigo-300">Objective Preview</div>
                                    <div className="mt-2 text-sm text-slate-400">
                                        These are the objective prompts PyRIT will execute first for the currently selected scenarios.
                                    </div>
                                </div>
                                <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                                    {pyritObjectivePreview.map((scenario) => (
                                        <div key={scenario.id} className="rounded-xl border border-white/5 bg-slate-900/50 p-4 space-y-3">
                                            <div>
                                                <div className="text-sm font-bold text-slate-100">{scenario.label}</div>
                                                <div className="mt-1 text-[10px] font-mono uppercase tracking-[0.18em] text-slate-500">
                                                    {scenario.attackType}
                                                    {scenario.converterChain.length > 0 ? ` | ${scenario.converterChain.join(" -> ")}` : " | direct"}
                                                </div>
                                            </div>
                                            <div className="space-y-2">
                                                {scenario.previewSamples.map((sample, idx) => (
                                                    <div key={`${scenario.id}-${idx}`} className="rounded-lg border border-white/5 bg-slate-950/70 p-3 space-y-3">
                                                        <div className="flex items-center justify-between gap-4">
                                                            <div className="text-[10px] font-black uppercase tracking-[0.18em] text-slate-500">
                                                                Objective {idx + 1}
                                                            </div>
                                                            <div className="text-[10px] font-mono uppercase tracking-[0.18em] text-indigo-300">
                                                                {formatPreviewMode(sample.preview_mode)}
                                                            </div>
                                                        </div>
                                                        <div>
                                                            <div className="text-[10px] font-black uppercase tracking-[0.18em] text-slate-500 mb-1">Raw Objective</div>
                                                            <div className="text-sm text-slate-200 whitespace-pre-wrap break-words">{sample.raw_objective || "No objective captured."}</div>
                                                        </div>
                                                        {(sample.transformed_preview || sample.transformed_preview_escaped) && (
                                                            <div>
                                                                <div className="text-[10px] font-black uppercase tracking-[0.18em] text-slate-500 mb-1">PyRIT Preview</div>
                                                                <div className="text-sm text-cyan-100 whitespace-pre-wrap break-words font-mono">
                                                                    {sample.transformed_preview_escaped || sample.transformed_preview}
                                                                </div>
                                                            </div>
                                                        )}
                                                        {sample.transformation_note && (
                                                            <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 px-3 py-2 text-xs text-amber-200">
                                                                {sample.transformation_note}
                                                            </div>
                                                        )}
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {groupedFamilies.map((group) => {
                            const probeIds = (group.concrete_probe_ids || []).filter((probeId) => availablePlugins.includes(probeId));
                            const selectedCount = probeIds.filter((probeId) => selectedPlugins.includes(probeId)).length;
                            const allSelected = probeIds.length > 0 && selectedCount === probeIds.length;
                            const someSelected = selectedCount > 0 && !allSelected;
                            const estimatedFamilyPrompts = probeIds.reduce((total, probeId) => {
                                const meta = pluginMeta(pluginCatalog, probeId);
                                return total + getEffectiveCount(meta?.estimated_prompts, evaluator === "garak" ? garakPromptCap : numTests);
                            }, 0);

                            return (
                                <div key={group.id} className="rounded-2xl border border-white/5 bg-slate-950/50 p-5">
                                    <div className="flex items-start justify-between gap-4 flex-wrap">
                                        <div>
                                            <div className="flex items-center gap-2 flex-wrap">
                                                <div className="text-lg font-bold text-slate-100">{group.label || group.id}</div>
                                                {group.category && (
                                                    <span className="px-2 py-0.5 rounded-full border border-white/10 text-[9px] font-black uppercase tracking-[0.18em] text-cyan-300">
                                                        {group.category}
                                                    </span>
                                                )}
                                                {group.recommended && (
                                                    <span className="px-2 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-[9px] font-black uppercase tracking-[0.18em] text-emerald-300">
                                                        Recommended
                                                    </span>
                                                )}
                                                {someSelected && (
                                                    <span className="px-2 py-0.5 rounded-full bg-amber-500/10 border border-amber-500/30 text-[9px] font-black uppercase tracking-[0.18em] text-amber-300">
                                                        Partial
                                                    </span>
                                                )}
                                            </div>
                                            <div className="mt-2 text-sm text-slate-400 max-w-3xl">
                                                {group.description || `No description available for this ${evaluator === "garak" ? "Garak" : "PyRIT"} family.`}
                                            </div>
                                            <div className="mt-3 text-[11px] font-mono text-slate-500">
                                                {evaluator === "garak"
                                                    ? `${probeIds.length} concrete probe(s) | ~${estimatedFamilyPrompts} prompt case(s) at current cap`
                                                    : `${probeIds.length} concrete scenario(s) | ~${estimatedFamilyPrompts} scored objective(s) at current selection`}
                                            </div>
                                        </div>
                                        <div className="flex items-center gap-2">
                                            <button
                                                type="button"
                                                onClick={() => setGarakFamilySelection(probeIds, true)}
                                                className={`px-3 py-2 rounded-xl text-[10px] font-black uppercase tracking-[0.18em] border transition-all ${
                                                    allSelected
                                                        ? "bg-cyan-500/10 border-cyan-500/30 text-cyan-300"
                                                        : "bg-slate-900 border-white/10 text-slate-300 hover:border-cyan-500/30 hover:text-cyan-200"
                                                }`}
                                            >
                                                Select Family
                                            </button>
                                            <button
                                                type="button"
                                                onClick={() => setGarakFamilySelection(probeIds, false)}
                                                className="px-3 py-2 rounded-xl text-[10px] font-black uppercase tracking-[0.18em] border bg-slate-900 border-white/10 text-slate-400 hover:border-rose-500/30 hover:text-rose-300 transition-all"
                                            >
                                                Clear
                                            </button>
                                        </div>
                                    </div>

                                    <div className="mt-5 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                                        {probeIds.map((probeId) => {
                                            const meta = pluginMeta(pluginCatalog, probeId);
                                            const isSelected = selectedPlugins.includes(probeId);
                                            const estimatedPrompts = Number(meta?.estimated_prompts) || 0;
                                            const effectivePrompts = getEffectiveCount(estimatedPrompts, evaluator === "garak" ? garakPromptCap : numTests);
                                            return (
                                                <button
                                                    key={probeId}
                                                    type="button"
                                                    onClick={() => togglePluginSelection(probeId)}
                                                    className={`text-left rounded-2xl p-4 border transition-all ${
                                                        isSelected
                                                            ? "bg-purple-500/10 border-purple-500/40 shadow-[0_0_20px_rgba(168,85,247,0.15)]"
                                                            : "bg-slate-900/60 border-white/5 hover:border-cyan-500/30 hover:bg-slate-900/90"
                                                    }`}
                                                >
                                                    <div className="flex items-start justify-between gap-3">
                                                        <div>
                                                            <div className={`text-sm font-bold ${isSelected ? "text-purple-200" : "text-slate-200"}`}>
                                                                {meta?.label || probeId}
                                                            </div>
                                                            <div className="text-[10px] font-mono tracking-[0.18em] text-slate-500 mt-1">
                                                                {probeId}
                                                            </div>
                                                        </div>
                                                        <div className="text-[10px] font-black uppercase tracking-[0.18em] text-indigo-300">
                                                            {effectivePrompts}
                                                            <div className="mt-1 text-slate-500 normal-case tracking-normal">
                                                                {evaluator === "garak"
                                                                    ? (garakPromptCap > 0 && estimatedPrompts > effectivePrompts ? `of ${estimatedPrompts}` : "prompt(s)")
                                                                    : `${estimatedPrompts} objective(s)`}
                                                            </div>
                                                        </div>
                                                    </div>
                                                    <p className="mt-3 text-sm leading-relaxed text-slate-400">
                                                        {meta?.description || "No description available for this concrete probe."}
                                                    </p>
                                                    {evaluator === "pyrit" && (
                                                        <div className="mt-3 flex flex-wrap gap-2 text-[10px] font-black uppercase tracking-[0.18em] text-slate-500">
                                                            <span>{meta?.attack_type || "prompt_sending"}</span>
                                                            {Array.isArray(meta?.converter_chain) && meta.converter_chain.map((converter) => (
                                                                <span key={`${probeId}-${converter}`} className="px-2 py-0.5 rounded-full border border-white/10 text-cyan-300">
                                                                    {converter}
                                                                </span>
                                                            ))}
                                                        </div>
                                                    )}
                                                </button>
                                            );
                                        })}
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                        {availablePlugins.map(plugin => {
                            const isSelected = selectedPlugins.includes(plugin);
                            const meta = pluginMeta(pluginCatalog, plugin);
                            return (
                                <button
                                    key={plugin}
                                    onClick={() => togglePluginSelection(plugin)}
                                    className={`text-left rounded-2xl p-4 border transition-all ${isSelected
                                        ? "bg-purple-500/10 border-purple-500/40 shadow-[0_0_20px_rgba(168,85,247,0.15)]"
                                        : "bg-slate-950/50 border-white/5 hover:border-cyan-500/30 hover:bg-slate-900/70"
                                        }`}
                                >
                                    <div className="flex items-start justify-between gap-3">
                                        <div>
                                            <div className={`text-sm font-bold ${isSelected ? "text-purple-200" : "text-slate-200"}`}>
                                                {meta?.label || plugin}
                                            </div>
                                            <div className="text-[10px] font-mono uppercase tracking-[0.18em] text-slate-500 mt-1">
                                                {plugin}
                                            </div>
                                        </div>
                                        <div className="flex flex-col items-end gap-2">
                                            {meta?.category && (
                                                <span className="px-2 py-0.5 rounded-full border border-white/10 text-[9px] font-black uppercase tracking-[0.18em] text-cyan-300">
                                                    {meta.category}
                                                </span>
                                            )}
                                            {meta?.recommended && (
                                                <span className="px-2 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-[9px] font-black uppercase tracking-[0.18em] text-emerald-300">
                                                    Recommended
                                                </span>
                                            )}
                                        </div>
                                    </div>
                                    <p className="mt-3 text-sm leading-relaxed text-slate-400">
                                        {meta?.description || "No description available for this attack vector."}
                                    </p>
                                </button>
                            );
                        })}
                    </div>
                )}
            </div>

            {errorMsg && (
                <div className="p-4 bg-red-500/10 border border-red-500/20 text-red-400 rounded-xl text-sm font-medium">
                    Error: {errorMsg}
                </div>
            )}
            {runWarnings.length > 0 && (
                <div className="p-4 bg-amber-500/10 border border-amber-500/30 text-amber-200 rounded-xl text-sm font-medium space-y-1">
                    {runWarnings.map((warning, idx) => (
                        <p key={`${warning}-${idx}`}>{warning}</p>
                    ))}
                </div>
            )}

            {/* Active Evaluation View */}
            <AnimatePresence>
                {runningOrStopped && runId && (
                    <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        exit={{ opacity: 0, height: 0 }}
                        className="space-y-6"
                    >
                        <div className="bg-slate-900/50 border border-purple-500/30 p-6 rounded-2xl relative overflow-hidden">
                            <div className="flex justify-between items-start gap-6 mb-6">
                                <div className="flex-1">
                                    <div className="flex items-center gap-3">
                                        <div className={`w-2 h-2 rounded-full ${status === "running" ? "bg-purple-500 animate-ping" : status === "failed" ? "bg-red-500" : "bg-amber-400"}`} />
                                        <h3 className="text-white font-black text-xl tracking-tight">
                                            {status === "running" ? "Active Evaluation Chain" : "Last Evaluation Snapshot"}
                                        </h3>
                                    </div>
                                    <p className="text-slate-400 text-sm mt-1 max-w-2xl">
                                        {status === "running"
                                            ? `Aegis is actively exercising ${selectedPlugins.length} attack vector(s) through ${evaluator}. The panels below now show the live audit stream, current probe, and attack artifacts.`
                                            : "The latest run state is preserved here so you can inspect what happened instead of losing context when the run stops or fails."}
                                    </p>
                                    <p className="text-slate-500 text-[11px] mt-2 font-bold uppercase tracking-[0.14em]">
                                        Run {runId} | Protection {promptfooProtectionEnabled ? "On" : "Off"} | Mode {(evaluator === "promptfoo" ? requestedMode : "local").toUpperCase()} {evaluator === "promptfoo" && requestedMode !== effectiveMode ? `-> ${effectiveMode.toUpperCase()}` : ""}{evaluator === "garak" ? ` | Cap ${garakPromptCap > 0 ? `${garakPromptCap}/probe` : "full"}` : evaluator === "pyrit" ? ` | Objectives ${Math.max(numTests, 1)}/scenario` : ""}
                                    </p>
                                    <p className="text-cyan-300 text-xs mt-2 font-bold">
                                        {phase}{etaSeconds !== null && status === "running" ? ` | ~${etaSeconds}s remaining` : ""}
                                    </p>
                                    {lastOutputLine && (
                                        <p className="text-slate-500 text-xs mt-2 font-mono break-words">
                                            {lastOutputLine}
                                        </p>
                                    )}
                                </div>

                                <button
                                    onClick={stopEval}
                                    disabled={status !== "running"}
                                    className={`px-4 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all flex items-center gap-2 ${
                                        status === "running"
                                            ? "bg-rose-500/10 hover:bg-rose-500 border border-rose-500/30 text-rose-500 hover:text-white active:scale-95"
                                            : "bg-slate-950/60 border border-white/5 text-slate-500 cursor-not-allowed"
                                    }`}
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

                            <div className="mt-6 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
                                <div className="rounded-xl border border-white/5 bg-slate-950/60 p-4">
                                    <div className="text-[10px] font-black uppercase tracking-[0.18em] text-slate-500">Target Engine</div>
                                    <div className="mt-2 text-sm font-bold text-slate-200">Ollama via {evaluator}</div>
                                </div>
                                <div className="rounded-xl border border-white/5 bg-slate-950/60 p-4">
                                    <div className="text-[10px] font-black uppercase tracking-[0.18em] text-slate-500">Current Probe</div>
                                    <div className="mt-2 text-sm font-bold text-cyan-300">{currentProbeLabel || currentProbe || "Waiting for first attack event"}</div>
                                    {currentProbeDescription && (
                                        <div className="mt-2 text-xs text-slate-500">{currentProbeDescription}</div>
                                    )}
                                </div>
                                <div className="rounded-xl border border-white/5 bg-slate-950/60 p-4">
                                    <div className="text-[10px] font-black uppercase tracking-[0.18em] text-slate-500">Probe Progress</div>
                                    <div className="mt-2 text-sm font-bold text-indigo-300">
                                        {probeProgress.completed !== undefined && probeProgress.total !== undefined
                                            ? `${probeProgress.completed} / ${probeProgress.total}`
                                            : totalTests > 0
                                                ? `${completedTests} / ${totalTests}`
                                                : "Pending"}
                                    </div>
                                    {probeProgress.summary && (
                                        <div className="mt-2 text-xs text-slate-500 break-words">{probeProgress.summary}</div>
                                    )}
                                </div>
                                <div className="rounded-xl border border-white/5 bg-slate-950/60 p-4">
                                    <div className="text-[10px] font-black uppercase tracking-[0.18em] text-slate-500">Live Events</div>
                                    <div className="mt-2 text-sm font-bold text-emerald-300">{liveEvents.length}</div>
                                    <div className="mt-2 text-xs text-slate-500">
                                        {status === "running" ? "Streaming provisional runtime telemetry." : "Runtime telemetry retained from the latest run."}
                                    </div>
                                </div>
                            </div>

                            {lastStderr.length > 0 && (
                                <div className="mt-6 rounded-xl border border-red-500/20 bg-red-500/5 p-4">
                                    <div className="text-[10px] font-black uppercase tracking-[0.18em] text-red-300">Latest STDERR</div>
                                    <div className="mt-2 space-y-1 text-xs font-mono text-red-200">
                                        {lastStderr.slice(-3).map((line, idx) => (
                                            <p key={`${line}-${idx}`} className="break-words">{line}</p>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>

                        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
                            <div className="bg-slate-900/50 border border-white/5 rounded-2xl overflow-hidden">
                                <div className="p-5 border-b border-white/5 bg-slate-950/30 flex items-center justify-between">
                                    <h3 className="text-white font-bold flex items-center gap-2"><span className="text-cyan-400">[A]</span> Live Audit Stream</h3>
                                    <span className="text-[10px] font-black uppercase tracking-[0.18em] text-slate-500">Eval-local feed</span>
                                </div>
                                <div className="p-5 space-y-3 max-h-[420px] overflow-y-auto">
                                    {liveEvents.length === 0 && (
                                        <p className="text-slate-500 text-sm">Waiting for runtime events from the evaluator.</p>
                                    )}
                                    {[...liveEvents].reverse().map((event, idx) => (
                                        <div key={event.id || `${event.summary}-${idx}`} className={`rounded-xl border p-4 ${eventTone(event)}`}>
                                            <div className="flex items-center justify-between gap-4">
                                                <div className="text-[10px] font-black uppercase tracking-[0.18em]">
                                                    {event.event_type || "event"}
                                                </div>
                                                <div className="text-[10px] font-mono text-slate-400">
                                                    {formatAuditTime(event.timestamp)}
                                                </div>
                                            </div>
                                            <p className="mt-2 text-sm font-medium break-words">{event.summary || "No summary provided."}</p>
                                            {(event.probe_label || event.plugin_id || event.probe_id) && (
                                                <p className="mt-2 text-[11px] text-slate-400 uppercase tracking-[0.16em]">
                                                    {(event.probe_label || event.plugin_id || event.probe_id)}
                                                </p>
                                            )}
                                            {(event.progress_completed !== undefined && event.progress_total !== undefined) && (
                                                <p className="mt-1 text-[11px] text-slate-500 font-mono">
                                                    Progress {event.progress_completed}/{event.progress_total}
                                                </p>
                                            )}
                                            {(event.attack_type || (Array.isArray(event.converter_chain) && event.converter_chain.length > 0)) && (
                                                <p className="mt-2 text-[11px] text-slate-500 font-mono uppercase tracking-[0.16em] break-words">
                                                    {event.attack_type || "prompt_sending"}
                                                    {Array.isArray(event.converter_chain) && event.converter_chain.length > 0 ? ` | ${event.converter_chain.join(" -> ")}` : ""}
                                                </p>
                                            )}
                                            {event.prompt && (
                                                <div className="mt-3 rounded-lg border border-white/5 bg-slate-950/40 p-3">
                                                    <div className="text-[10px] font-black uppercase tracking-[0.18em] text-slate-500 mb-1">Objective</div>
                                                    <div className="text-sm text-slate-200 whitespace-pre-wrap break-words">{event.prompt}</div>
                                                </div>
                                            )}
                                            {(event.transformed_preview || event.transformed_preview_escaped) && (
                                                <div className="mt-3 rounded-lg border border-cyan-500/20 bg-cyan-500/5 p-3">
                                                    <div className="text-[10px] font-black uppercase tracking-[0.18em] text-cyan-200 mb-1">
                                                        {event.transformation_summary || "PyRIT Preview"}
                                                    </div>
                                                    <div className="text-sm text-cyan-100 whitespace-pre-wrap break-words font-mono">
                                                        {event.transformed_preview_escaped || event.transformed_preview}
                                                    </div>
                                                </div>
                                            )}
                                            {event.transformation_note && (
                                                <p className="mt-2 text-xs text-amber-200 break-words">{event.transformation_note}</p>
                                            )}
                                            {event.response && (
                                                <div className="mt-3 rounded-lg border border-white/5 bg-slate-950/40 p-3">
                                                    <div className="text-[10px] font-black uppercase tracking-[0.18em] text-slate-500 mb-1">Response</div>
                                                    <div className="text-sm text-slate-300 whitespace-pre-wrap break-words">{event.response}</div>
                                                </div>
                                            )}
                                        </div>
                                    ))}
                                </div>
                            </div>

                            <div className="bg-slate-900/50 border border-white/5 rounded-2xl overflow-hidden">
                                <div className="p-5 border-b border-white/5 bg-slate-950/30 flex items-center justify-between">
                                    <h3 className="text-white font-bold flex items-center gap-2"><span className="text-indigo-400">[L]</span> Live Attack Preview</h3>
                                    <span className="text-[10px] font-black uppercase tracking-[0.18em] text-slate-500">
                                        {recentAttempts.length} captured attempt{recentAttempts.length === 1 ? "" : "s"}
                                    </span>
                                </div>
                                <div className="p-5 space-y-4 max-h-[420px] overflow-y-auto">
                                    {recentAttempts.length === 0 && (
                                        <p className="text-slate-500 text-sm">Attack prompts and responses will appear here as the evaluator produces them.</p>
                                    )}
                                    {[...recentAttempts].reverse().map((attempt, idx) => (
                                        <div key={`${attempt.probe_id}-${attempt.seq}-${idx}`} className="rounded-xl border border-white/5 bg-slate-950/60 p-4">
                                            <div className="flex items-start justify-between gap-4">
                                                <div>
                                                    <div className="text-sm font-bold text-slate-200">{attempt.probe_label || attempt.probe_id || "Attack attempt"}</div>
                                                    {attempt.probe_description && (
                                                        <div className="mt-1 text-xs text-slate-500">{attempt.probe_description}</div>
                                                    )}
                                                </div>
                                                <span className="text-[10px] font-black uppercase tracking-[0.18em] text-cyan-300">Attempt {attempt.seq ?? idx + 1}</span>
                                            </div>
                                            <div className="mt-4 space-y-3 text-sm">
                                                <div>
                                                    <div className="text-[10px] font-black uppercase tracking-[0.18em] text-slate-500 mb-1">Prompt</div>
                                                    <div className="text-slate-200 whitespace-pre-wrap break-words">{attempt.prompt || "No prompt captured yet."}</div>
                                                </div>
                                                <div>
                                                    <div className="text-[10px] font-black uppercase tracking-[0.18em] text-slate-500 mb-1">Response</div>
                                                    <div className="text-slate-300 whitespace-pre-wrap break-words">{attempt.response || "No response captured yet."}</div>
                                                </div>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>

            {/* Results Dashboard */}
            {displayedReport && (
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="space-y-8"
                >
                    <div className={`rounded-2xl border p-5 ${reportState === "official" ? "border-emerald-500/30 bg-emerald-500/5" : "border-amber-500/30 bg-amber-500/5"}`}>
                        <div className="flex items-center justify-between gap-4 flex-wrap">
                            <div>
                                <h3 className="text-white font-bold">
                                    {reportState === "official" ? "Official Evaluation Report" : "Provisional Evaluation Preview"}
                                </h3>
                                <p className="text-sm text-slate-400 mt-1">
                                    {reportState === "official"
                                        ? "This is the finalized evaluator report."
                                        : "These results are live and may change until the official evaluator summary is finalized."}
                                </p>
                            </div>
                            <span className={`px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-[0.18em] ${
                                reportState === "official" ? "bg-emerald-500/10 text-emerald-300 border border-emerald-500/30" : "bg-amber-500/10 text-amber-300 border border-amber-500/30"
                            }`}>
                                {reportState === "official" ? "Official" : "Provisional"}
                            </span>
                        </div>
                    </div>

                    {/* Top Level Stats */}
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                        <StatCard label="Total Tests" value={displayedReport.total_tests} icon="T" />
                        <StatCard label="Defended (Passed)" value={displayedReport.passed} valueColor="text-emerald-400" icon="OK" />
                        <StatCard label="Exploited (Failed)" value={displayedReport.failed} valueColor="text-red-400" icon="X" />
                        <StatCard label="Errors" value={displayedReport.errors} valueColor="text-amber-400" icon="!" />
                    </div>

                    {/* Plugin Matrix */}
                    <div className="bg-slate-900/50 border border-white/5 rounded-2xl overflow-hidden">
                        <div className="p-5 border-b border-white/5 bg-slate-950/20">
                            <h3 className="text-white font-bold flex items-center gap-2"><span className="text-indigo-400">[M]</span> Vulnerability Matrix</h3>
                        </div>
                        <div className="p-6">
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                        {Object.entries(displayedReport.plugins).map(([plugin, stats]: [string, any]) => (
                            <div key={plugin} className="bg-slate-950 rounded-xl p-5 border border-white/5">
                                <div className="flex justify-between items-center mb-4">
                                    <div>
                                        <div className="text-slate-200 font-mono text-sm">{stats.label || plugin}</div>
                                        <div className="text-slate-500 text-[10px] uppercase tracking-[0.16em] mt-1">{plugin}</div>
                                        {(stats.description || pluginMeta(pluginCatalog, plugin.split(":")[0])?.description) && (
                                            <div className="text-slate-500 text-xs mt-1 max-w-xs">
                                                {stats.description || pluginMeta(pluginCatalog, plugin.split(":")[0])?.description}
                                            </div>
                                        )}
                                    </div>
                                    <span className={`px-2 py-1 rounded text-[10px] uppercase font-black tracking-wider ${stats.failed === 0 ? 'bg-emerald-500/20 text-emerald-400' : 'bg-red-500/20 text-red-400'}`}>
                                        {stats.failed === 0 ? (reportState === "official" ? 'SECURE' : 'CLEAR SO FAR') : 'FLAGGED'}
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

                    <div className="bg-slate-900/50 border border-white/5 rounded-2xl overflow-hidden">
                        <div className="p-5 border-b border-white/5 bg-slate-950/20 flex items-center justify-between">
                            <h3 className="text-white font-bold flex items-center gap-2"><span className="text-rose-400">[F]</span> Flagged Findings</h3>
                            <span className="text-[10px] font-black uppercase tracking-[0.18em] text-slate-500">
                                {displayedFailedResults.length} failed prompt{displayedFailedResults.length === 1 ? "" : "s"}
                            </span>
                        </div>
                        <div className="p-6 space-y-4 max-h-[520px] overflow-y-auto">
                            {displayedFailedResults.length === 0 && (
                                <p className="text-slate-500 text-sm">No failed prompts captured for the current report state.</p>
                            )}
                            {displayedFailedResults.map((result: any, idx: number) => {
                                const probeId = String(result.plugin || "");
                                const probeKey = probeId.split(":")[0];
                                const meta = pluginMeta(pluginCatalog, probeKey);
                                const sampleAttempts = Array.isArray(result?.grading?.sample_attempts) ? result.grading.sample_attempts : [];
                                const promptText = String(result.prompt || sampleAttempts[0]?.prompt || "");
                                const responseText = String(result.response || sampleAttempts[0]?.response || "");
                                return (
                                    <div key={`failed-${probeId}-${idx}`} className="bg-slate-950 rounded-xl p-5 border border-rose-500/20 space-y-4">
                                        <div className="flex items-start justify-between gap-4">
                                            <div>
                                                <div className="text-white font-bold">{result.label || meta?.label || probeId}</div>
                                                <div className="text-slate-400 text-xs font-mono mt-1">{probeId}</div>
                                            </div>
                                            <span className="px-2 py-1 rounded text-[10px] uppercase font-black tracking-wider bg-red-500/20 text-red-400">
                                                Flagged
                                            </span>
                                        </div>
                                        <div className="text-sm text-slate-300">{result.reason || "No failure reason captured."}</div>
                                        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4 text-sm">
                                            <div className="border border-white/5 rounded-lg p-4 bg-slate-900/40">
                                                <div className="text-slate-500 text-[10px] uppercase font-bold mb-2">Prompt</div>
                                                <div className="text-slate-200 whitespace-pre-wrap break-words">{promptText || "No prompt captured."}</div>
                                            </div>
                                            <div className="border border-white/5 rounded-lg p-4 bg-slate-900/40">
                                                <div className="text-slate-500 text-[10px] uppercase font-bold mb-2">Response</div>
                                                <div className="text-slate-300 whitespace-pre-wrap break-words">{responseText || "No response captured."}</div>
                                            </div>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    </div>

                    <div className="bg-slate-900/50 border border-white/5 rounded-2xl overflow-hidden">
                        <div className="p-5 border-b border-white/5 bg-slate-950/20">
                            <h3 className="text-white font-bold flex items-center gap-2"><span className="text-cyan-400">[D]</span> Attack Details</h3>
                        </div>
                        <div className="p-6 space-y-4">
                            {displayedReport.raw_results.length === 0 && (
                                <p className="text-slate-500 text-sm">No detailed attack records were returned for this run.</p>
                            )}
                            {displayedReport.raw_results.map((result, idx) => {
                                const probeId = String(result.plugin || "");
                                const probeKey = probeId.split(":")[0];
                                const meta = pluginMeta(pluginCatalog, probeKey);
                                const grading = result.grading || {};
                                const sampleAttempts = Array.isArray(grading.sample_attempts) ? grading.sample_attempts : [];
                                return (
                                    <div key={`${probeId}-${idx}`} className="bg-slate-950 rounded-xl p-5 border border-white/5 space-y-4">
                                        <div className="flex items-start justify-between gap-4">
                                            <div>
                                                <div className="text-white font-bold">{result.label || meta?.label || probeId}</div>
                                                <div className="text-slate-400 text-xs font-mono mt-1">{probeId}</div>
                                                {(result.description || meta?.description) && <div className="text-slate-500 text-sm mt-2 max-w-3xl">{result.description || meta?.description}</div>}
                                            </div>
                                            <span className={`px-2 py-1 rounded text-[10px] uppercase font-black tracking-wider ${result.passed ? 'bg-emerald-500/20 text-emerald-400' : 'bg-red-500/20 text-red-400'}`}>
                                                {result.passed ? (reportState === "official" ? 'Defended' : 'Clear so far') : 'Flagged'}
                                            </span>
                                        </div>
                                        <div className="text-sm text-slate-300">{result.reason}</div>
                                        {sampleAttempts.length > 0 && (
                                            <div className="space-y-3">
                                                {sampleAttempts.map((sample: any, sampleIdx: number) => (
                                                    <div key={`${probeId}-sample-${sampleIdx}`} className="border border-white/5 rounded-lg p-4 bg-slate-900/40">
                                                        <div className="text-[10px] uppercase tracking-[0.18em] text-slate-500 font-bold mb-2">
                                                            Sample {sampleIdx + 1}
                                                        </div>
                                                        <div className="space-y-2 text-sm">
                                                            <div>
                                                                <div className="text-slate-500 text-[10px] uppercase font-bold mb-1">Prompt</div>
                                                                <div className="text-slate-200 whitespace-pre-wrap break-words">{sample.prompt || "No prompt captured."}</div>
                                                            </div>
                                                            {(sample.transformed_preview || sample.transformed_preview_escaped) && (
                                                                <div>
                                                                    <div className="text-slate-500 text-[10px] uppercase font-bold mb-1">PyRIT Preview</div>
                                                                    <div className="text-cyan-100 whitespace-pre-wrap break-words font-mono">
                                                                        {sample.transformed_preview_escaped || sample.transformed_preview}
                                                                    </div>
                                                                </div>
                                                            )}
                                                            {sample.transformation_note && (
                                                                <div className="text-amber-200 text-xs whitespace-pre-wrap break-words">
                                                                    {sample.transformation_note}
                                                                </div>
                                                            )}
                                                            <div>
                                                                <div className="text-slate-500 text-[10px] uppercase font-bold mb-1">Response</div>
                                                                <div className="text-slate-300 whitespace-pre-wrap break-words">{sample.response || "No response captured."}</div>
                                                            </div>
                                                        </div>
                                                    </div>
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                );
                            })}
                        </div>
                    </div>

                    {Array.isArray(displayedReport.timeline) && displayedReport.timeline.length > 0 && (
                        <div className="bg-slate-900/50 border border-white/5 rounded-2xl overflow-hidden">
                            <div className="p-5 border-b border-white/5 bg-slate-950/20">
                                <h3 className="text-white font-bold flex items-center gap-2"><span className="text-amber-400">[T]</span> Evaluation Timeline</h3>
                            </div>
                            <div className="p-6 space-y-3 max-h-[420px] overflow-y-auto">
                                {[...displayedReport.timeline].reverse().map((event, idx) => (
                                    <div key={event.id || `${event.summary}-${idx}`} className={`rounded-xl border p-4 ${eventTone(event)}`}>
                                        <div className="flex items-center justify-between gap-4">
                                            <div className="text-[10px] font-black uppercase tracking-[0.18em]">
                                                {event.event_type || "event"}
                                            </div>
                                            <div className="text-[10px] font-mono text-slate-400">
                                                {formatAuditTime(event.timestamp)}
                                            </div>
                                        </div>
                                        <p className="mt-2 text-sm font-medium break-words">{event.summary || "No summary provided."}</p>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
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

