'use client';

import React, { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import { Terminal, Shield, AlertTriangle, Play, BarChart3, List, Activity, Cpu, Zap, Eye, Info, Radio, Layers, Download, FlaskConical, HelpCircle, Lock, Unlock, Globe, Box, Target } from 'lucide-react';

const TOOLTIPS = {
  MODE_SIM: "Direct Simulation: Bypasses the LLM and runs a pre-defined shell command directly in the sandbox. Primarily used to test Firewall rules and SysWatch monitoring.",
  MODE_AGENT: "Single-Shot Test: Sends the attack prompt to the real Ollama model. Tests if the model's base training is sufficient to refuse malicious tool calls.",
  MODE_INQUISITOR: "Adversarial Hunt: Uses a secondary Red-Team agent to dynamically probe the target over multiple turns. Finds complex bypasses that single prompts miss.",
  HARDENING: "System Prompt Injection: Applies a strict 'Security-First' set of constraints to the target agent. Tests if the model can be protected via persona enforcement.",
  CATEGORY: "The specific threat vector being simulated. Each category contains a library of unique adversarial payloads.",
  AUDIT: "Deep Scanning: Automated execution of multiple threat vectors to provide a comprehensive Risk Score for the target configuration.",
  HARDENING_SCAN: "Strategy Probing: Specifically tests the target against common psychological bypass techniques like Piggybacking or Hypothetical Framing.",
  INTELLIGENCE: "Predictive Analytics: Our AI analyzes your current configuration to forecast the attack vector, sandbox isolation status, and active defense layers."
};

const InfoTooltip = ({ text, side = 'top', align = 'right' }: { text: string; side?: 'top' | 'bottom'; align?: 'left' | 'right' }) => {
  const [isVisible, setIsVisible] = useState(false);

  return (
    <div
      className="relative inline-block ml-1"
      onMouseEnter={() => setIsVisible(true)}
      onMouseLeave={() => setIsVisible(false)}
    >
      <HelpCircle className="w-4 h-4 text-slate-500 hover:text-cyan-400 cursor-help transition-all duration-300" />
      {isVisible && (
        <div className={`absolute ${side === 'top' ? 'bottom-full mb-3' : 'top-full mt-3'} ${align === 'right' ? 'right-0 origin-bottom-right' : 'left-0 origin-bottom-left'} w-72 p-4 bg-slate-950 border border-cyan-500/40 rounded-2xl shadow-[0_10px_40px_rgba(0,0,0,0.9)] backdrop-blur-xl z-[999] animate-in fade-in zoom-in-95 duration-200`}>
          <div className="text-[11px] font-bold leading-relaxed text-slate-200 tracking-tight">
            {text}
          </div>
          {/* Arrow */}
          <div className={`absolute ${side === 'top' ? 'top-full border-t-cyan-500/40' : 'bottom-full border-b-cyan-500/40'} ${align === 'right' ? 'right-3' : 'left-3'} border-8 border-transparent`} />
          <div className={`absolute ${side === 'top' ? 'top-full -mt-[1px] border-t-slate-950' : 'bottom-full -mb-[1px] border-b-slate-950'} ${align === 'right' ? 'right-[13px] border-[7px]' : 'left-[13px] border-[7px]'} border-transparent`} />
        </div>
      )}
    </div>
  );
};

export default function Dashboard() {
  const [stats, setStats] = useState({
    total_attacks: 0,
    successful_exploits: 0,
    failed_attempts: 0,
    campaign_history: []
  });
  const [campaignName, setCampaignName] = useState('Security Audit');
  const [category, setCategory] = useState('prompt_injection');
  const [mode, setMode] = useState('SIMULATED');
  const [categories, setCategories] = useState<string[]>(['code_injection', 'prompt_injection', 'data_exfiltration']);
  const [loading, setLoading] = useState(false);
  const [lastResult, setLastResult] = useState<any>(null);
  const [inquisitorResult, setInquisitorResult] = useState<any>(null);
  const [preview, setPreview] = useState<any>(null);
  const [availableScans, setAvailableScans] = useState<any[]>([]);
  const [selectedScan, setSelectedScan] = useState<string>('');
  const [scanResult, setScanResult] = useState<any>(null);
  const [scanning, setScanning] = useState(false);
  const [strategyStats, setStrategyStats] = useState<any>({});
  const [hardenResult, setHardenResult] = useState<any>(null);
  const [hardening, setHardening] = useState(false);
  const [showHeatmap, setShowHeatmap] = useState(false);
  const [agentHardened, setAgentHardened] = useState(false);
  const [intelligenceFeed, setIntelligenceFeed] = useState<any>(null);

  // Semantic Guardrail State
  const [guardrailMode, setGuardrailMode] = useState('warn');
  const [guardrailModel, setGuardrailModel] = useState('llama3.1:8b');
  const [contextTurns, setContextTurns] = useState(10);

  const fetchStats = async () => {
    try {
      const res = await fetch('http://localhost:8000/stats');
      const data = await res.json();
      setStats(data);
    } catch (err) {
      console.error("Failed to fetch stats", err);
    }
  };

  const fetchPreview = useCallback(async (cat: string) => {
    try {
      const res = await fetch(`http://localhost:8000/payloads/preview/${cat}`);
      const data = await res.json();
      setPreview(data);
    } catch (err) {
      console.error("Failed to fetch preview", err);
    }
  }, []);

  const fetchCategories = async () => {
    try {
      const res = await fetch('http://localhost:8000/categories');
      const data = await res.json();
      setCategories(data);
      if (data.length > 0) {
        setCategory(data[0]);
        fetchPreview(data[0]);
      }
    } catch (err) {
      console.error("Failed to fetch categories", err);
    }
  };

  const fetchAvailableScans = async () => {
    try {
      const res = await fetch('http://localhost:8000/scans/available');
      const data = await res.json();
      setAvailableScans(data);
      if (data.length > 0) setSelectedScan(data[0].id);
    } catch (err) {
      console.error("Failed to fetch scans", err);
    }
  };

  useEffect(() => {
    fetchStats();
    fetchCategories();
    fetchAvailableScans();
    fetchStrategyStats();
    fetchAgentStatus();
    const interval = setInterval(() => { fetchStats(); fetchStrategyStats(); }, 5000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (category) fetchPreview(category);
  }, [category, fetchPreview]);

  // Dynamic Information & Predictive Intelligence
  useEffect(() => {
    const formattedCat = category.replace(/_/g, ' ').toUpperCase();
    const hardeningLabel = agentHardened ? ' (HARDENED)' : '';
    const newName = `${mode}: ${formattedCat}${hardeningLabel}`;
    setCampaignName(newName);

    // Predictive Intelligence Logic
    const feed = {
      vector: mode === 'INQUISITOR' ? 'Adversarial Escalation Loop' : mode === 'REAL_AGENT' ? 'Single-Shot Model Probe' : 'Direct Sandbox Simulation',
      isolation: '100% Isolated Docker Environment',
      defense: agentHardened ? 'Policy Engine + System Hardening' : 'Policy Engine Standard'
    };
    setIntelligenceFeed(feed);
  }, [mode, category, agentHardened]);

  const runCampaign = async () => {
    setLoading(true);
    try {
      const res = await fetch('http://localhost:8000/campaigns/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: campaignName,
          target_agent_type: mode === 'REAL_AGENT' ? 'mistral:latest' : 'Sandbox Container',
          attack_category: category,
          mode: mode,
          guardrail_mode: guardrailMode,
          guardrail_model: guardrailModel,
          guardrail_context_turns: contextTurns
        })
      });
      const data = await res.json();
      setLastResult(data);
      fetchStats();
    } catch (err) {
      console.error("Failed to run campaign", err);
    } finally {
      setLoading(false);
    }
  };

  const runInquisitor = async () => {
    setLoading(true);
    setInquisitorResult(null);
    setLastResult(null);
    try {
      const res = await fetch('http://localhost:8000/campaigns/inquisitor', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: campaignName,
          attack_category: category,
          mode: 'INQUISITOR',
          max_turns: 5,
          guardrail_mode: guardrailMode,
          guardrail_model: guardrailModel,
          guardrail_context_turns: contextTurns
        })
      });
      const data = await res.json();
      setInquisitorResult(data);
      fetchStats();
    } catch (err) {
      console.error("Failed to run inquisitor", err);
    } finally {
      setLoading(false);
    }
  };

  const handleExecute = () => {
    if (mode === 'INQUISITOR') {
      runInquisitor();
    } else {
      runCampaign();
    }
  };

  const fetchStrategyStats = async () => {
    try {
      const res = await fetch('http://localhost:8000/stats/strategies');
      const data = await res.json();
      setStrategyStats(data.strategy_stats || {});
    } catch { /* silent */ }
  };

  const runHardeningScan = async () => {
    setHardening(true);
    setHardenResult(null);
    try {
      const res = await fetch('http://localhost:8000/campaigns/harden', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'Hardening Scan', attack_category: category, mode: 'INQUISITOR', max_turns: 1 })
      });
      setHardenResult(await res.json());
    } catch (err) { console.error('Hardening scan failed', err); }
    finally { setHardening(false); }
  };

  const exportReport = () => {
    window.open('http://localhost:8000/reports/export', '_blank');
  };

  const fetchAgentStatus = async () => {
    try {
      const res = await fetch('http://localhost:8000/agent/status');
      const data = await res.json();
      setAgentHardened(data.hardened);
    } catch { /* silent */ }
  };

  const toggleAgentHardening = async () => {
    const newState = !agentHardened;
    setAgentHardened(newState);
    try {
      await fetch('http://localhost:8000/agent/configure', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hardened: newState })
      });
    } catch (err) {
      console.error("Failed to toggle hardening", err);
      setAgentHardened(!newState);
    }
  };

  const runAutomatedScan = async () => {
    setScanning(true);
    setScanResult(null);
    try {
      const res = await fetch('http://localhost:8000/scans/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scan_type: selectedScan })
      });
      const data = await res.json();
      setScanResult(data);
    } catch (err) {
      console.error("Failed to run scan", err);
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-8 font-sans selection:bg-cyan-500/30">
      {/* Header */}
      <header className="flex justify-between items-center mb-12 border-b border-white/10 pb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-cyan-500/20 rounded-lg">
            <Shield className="w-8 h-8 text-cyan-400" />
          </div>
          <div>
            <h1 className="text-3xl font-bold tracking-tight bg-gradient-to-r from-white to-cyan-400 bg-clip-text text-transparent">
              AEGIS FORGE
            </h1>
            <p className="text-slate-500 text-sm font-medium tracking-widest uppercase">AI-Agent Red Teaming Harness</p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex flex-col items-end">
            <span className="text-[10px] text-slate-500 uppercase font-black tracking-widest leading-none">Intelligence Feed</span>
            <div className={`mt-1 h-1 w-24 rounded-full bg-slate-800 overflow-hidden relative`}>
              <div className={`absolute inset-0 bg-cyan-500 animate-[shimmer_2s_infinite] ${loading ? 'opacity-100' : 'opacity-0'}`} />
            </div>
          </div>
          <button
            onClick={exportReport}
            className="flex items-center gap-2 bg-slate-800/50 hover:bg-slate-700 border border-white/10 text-slate-300 text-xs font-semibold px-4 py-2.5 rounded-xl transition-all hover:scale-105 active:scale-95"
          >
            <Download className="w-4 h-4" />
            Report
          </button>
          <Link
            href="/eval"
            className="flex items-center gap-2 bg-purple-500/10 hover:bg-purple-500/20 border border-purple-500/20 hover:border-purple-500/50 text-purple-400 text-xs font-semibold px-4 py-2.5 rounded-xl transition-all shadow-[0_0_15px_rgba(168,85,247,0.1)] hover:shadow-[0_0_25px_rgba(168,85,247,0.3)]"
          >
            <FlaskConical className="w-4 h-4" />
            Eval Matrix
          </Link>
          <div className="flex items-center gap-2 bg-slate-900/50 px-4 py-2 rounded-full border border-white/5">
            <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span className="text-xs font-mono text-slate-400 tracking-wider">HARNESS ONLINE</span>
          </div>
        </div>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left Column: Controls & Defense */}
        <div className="lg:col-span-4 space-y-8 relative z-20">
          {/* Launch Sequence Section */}
          <section className="bg-slate-900/60 border border-white/10 rounded-3xl p-7 backdrop-blur-xl shadow-[0_0_50px_-12px_rgba(0,0,0,0.5)] relative group animate-in slide-in-from-left duration-700">
            <div className="absolute top-0 right-0 p-4 opacity-0 group-hover:opacity-100 transition-opacity">
              <InfoTooltip text="This panel configures the primary attack sequence. The 'Go' button will trigger a fresh Docker sandbox." side="bottom" align="left" />
            </div>
            <h2 className="text-lg font-black mb-8 flex items-center gap-3 text-white uppercase tracking-tighter">
              <div className="p-1.5 bg-cyan-500 rounded-lg shadow-[0_0_15px_rgba(6,182,212,0.4)]">
                <Play className="w-4 h-4 text-slate-950 fill-current" />
              </div>
              Launch Sequence
            </h2>

            <div className="space-y-7">
              <div>
                <label className="text-[10px] font-bold text-slate-500 uppercase mb-2 block tracking-widest">Campaign Label</label>
                <input
                  type="text"
                  value={campaignName}
                  onChange={(e) => setCampaignName(e.target.value)}
                  className="w-full bg-slate-950 border border-white/10 rounded-xl px-4 py-3 focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-all font-mono text-sm"
                />
              </div>

              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest flex items-center gap-1">Evaluation Mode <InfoTooltip text={TOOLTIPS.MODE_SIM} align="left" /></label>
                </div>
                <div className="grid grid-cols-3 gap-2">
                  <button
                    onClick={() => setMode('SIMULATED')}
                    className={`group relative overflow-hidden flex flex-col items-center justify-center gap-1 py-4 rounded-2xl border-2 transition-all hover:scale-[1.02] active:scale-[0.98] ${mode === 'SIMULATED' ? 'bg-cyan-500/10 border-cyan-500 shadow-[0_0_20px_rgba(6,182,212,0.2)]' : 'bg-slate-950 border-white/5 text-slate-500 hover:border-white/10'}`}
                  >
                    <Zap className={`w-4 h-4 ${mode === 'SIMULATED' ? 'text-cyan-400' : 'text-slate-600'}`} />
                    <span className={`text-[9px] font-black tracking-widest ${mode === 'SIMULATED' ? 'text-cyan-400' : 'text-slate-600'}`}>SIM</span>
                    {mode === 'SIMULATED' && <div className="absolute inset-0 bg-gradient-to-t from-cyan-500/10 to-transparent pointer-events-none" />}
                  </button>
                  <button
                    onClick={() => setMode('REAL_AGENT')}
                    className={`group relative overflow-hidden flex flex-col items-center justify-center gap-1 py-4 rounded-2xl border-2 transition-all hover:scale-[1.02] active:scale-[0.98] ${mode === 'REAL_AGENT' ? 'bg-purple-500/10 border-purple-500 shadow-[0_0_20px_rgba(168,85,247,0.2)]' : 'bg-slate-950 border-white/5 text-slate-500 hover:border-white/10'}`}
                  >
                    <Cpu className={`w-4 h-4 ${mode === 'REAL_AGENT' ? 'text-purple-400' : 'text-slate-600'}`} />
                    <span className={`text-[9px] font-black tracking-widest ${mode === 'REAL_AGENT' ? 'text-purple-400' : 'text-slate-600'}`}>AGENT</span>
                    {mode === 'REAL_AGENT' && <div className="absolute inset-0 bg-gradient-to-t from-purple-500/10 to-transparent pointer-events-none" />}
                  </button>
                  <button
                    onClick={() => setMode('INQUISITOR')}
                    className={`group relative overflow-hidden flex flex-col items-center justify-center gap-1 py-4 rounded-2xl border-2 transition-all hover:scale-[1.02] active:scale-[0.98] ${mode === 'INQUISITOR' ? 'bg-amber-500/10 border-amber-500 shadow-[0_0_20px_rgba(245,158,11,0.2)]' : 'bg-slate-950 border-white/5 text-slate-500 hover:border-white/10'}`}
                  >
                    <Radio className={`w-4 h-4 ${mode === 'INQUISITOR' ? 'text-amber-400' : 'text-slate-600'}`} />
                    <span className={`text-[9px] font-black tracking-widest ${mode === 'INQUISITOR' ? 'text-amber-400' : 'text-slate-600'}`}>INQ</span>
                    {mode === 'INQUISITOR' && <div className="absolute inset-0 bg-gradient-to-t from-amber-500/10 to-transparent pointer-events-none" />}
                  </button>
                </div>
              </div>

              {/* Agent Hardening Toggle */}
              <div className={`rounded-2xl p-5 flex items-center justify-between group transition-all duration-500 ${agentHardened ? 'bg-amber-500/10 border-2 border-amber-500/50 shadow-[0_0_20px_rgba(245,158,11,0.1)]' : 'bg-slate-950/50 border-2 border-white/5 shadow-none'}`}>
                <div className="flex items-center gap-4">
                  <div className={`p-3 rounded-xl transition-all duration-500 ${agentHardened ? 'bg-amber-500 shadow-[0_0_15px_rgba(245,158,11,0.4)]' : 'bg-slate-800'}`}>
                    <Shield className={`w-5 h-5 ${agentHardened ? 'text-slate-950' : 'text-slate-500'}`} />
                  </div>
                  <div>
                    <div className="flex items-center gap-1">
                      <label className="text-xs font-black text-slate-100 uppercase tracking-widest block">Agent Hardening</label>
                      <InfoTooltip text={TOOLTIPS.HARDENING} align="left" />
                    </div>
                    <p className={`text-[10px] font-medium ${agentHardened ? 'text-amber-400' : 'text-slate-500'}`}>{agentHardened ? 'STRICT PERSONA ACTIVE' : 'NO GUARDRAILS APPLIED'}</p>
                  </div>
                </div>
                <button
                  onClick={toggleAgentHardening}
                  className={`w-12 h-6 rounded-full relative transition-all duration-300 ${agentHardened ? 'bg-amber-500' : 'bg-slate-700'}`}
                >
                  <div className={`absolute top-1 w-4 h-4 rounded-full bg-white shadow-lg transition-all transform ${agentHardened ? 'translate-x-7' : 'translate-x-1'}`} />
                </button>
              </div>

              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest flex items-center gap-1">Target Vector <InfoTooltip text={TOOLTIPS.CATEGORY} align="left" /></label>
                </div>
                <select
                  value={category}
                  onChange={(e) => setCategory(e.target.value)}
                  className="w-full bg-slate-950 border-2 border-white/10 rounded-2xl px-5 py-4 focus:outline-none focus:border-cyan-500 transition-all appearance-none cursor-pointer font-black text-xs tracking-wider uppercase text-slate-300"
                >
                  {categories.map(cat => (
                    <option key={cat} value={cat}>{cat.replace(/_/g, ' ')}</option>
                  ))}
                </select>
              </div>

              {/* Predictive Intelligence Feed */}
              {intelligenceFeed && (
                <div className="bg-slate-950 border-2 border-cyan-500/20 rounded-2xl p-6 relative animate-in fade-in zoom-in duration-500 shadow-xl">
                  <div className="absolute top-0 right-0 p-3">
                    <InfoTooltip text={TOOLTIPS.INTELLIGENCE} side="bottom" align="left" />
                  </div>
                  <div className="flex items-center gap-3 mb-5">
                    <div className="flex items-center justify-center p-2 bg-cyan-500 rounded-lg">
                      <Radio className="w-3.5 h-3.5 text-slate-950 fill-current animate-pulse" />
                    </div>
                    <span className="text-xs font-black text-cyan-400 uppercase tracking-[0.2em]">Intelligence Feed</span>
                  </div>

                  <div className="grid grid-cols-1 gap-4">
                    <div className="flex items-center gap-4 group/item">
                      <div className="h-10 w-1 p-0.5 bg-cyan-500/20 group-hover/item:bg-cyan-500 transition-all rounded-full" />
                      <div className="flex-1">
                        <p className="text-[10px] font-black text-slate-600 uppercase tracking-tighter mb-0.5">Execution Pathway</p>
                        <p className="text-xs font-bold text-white flex items-center gap-2">
                          <Target className="w-3 h-3 text-cyan-500" /> {intelligenceFeed.vector}
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center gap-4 group/item">
                      <div className="h-10 w-1 p-0.5 bg-emerald-500/20 group-hover/item:bg-emerald-500 transition-all rounded-full" />
                      <div className="flex-1">
                        <p className="text-[10px] font-black text-slate-600 uppercase tracking-tighter mb-0.5">Sandbox Status</p>
                        <p className="text-xs font-bold text-white flex items-center gap-2">
                          <Box className="w-3 h-3 text-emerald-500" /> {intelligenceFeed.isolation}
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center gap-4 group/item">
                      <div className="h-10 w-1 p-0.5 bg-purple-500/20 group-hover/item:bg-purple-500 transition-all rounded-full" />
                      <div className="flex-1">
                        <p className="text-[10px] font-black text-slate-600 uppercase tracking-tighter mb-0.5">Defense Overlay</p>
                        <p className="text-xs font-bold text-white flex items-center gap-2">
                          {agentHardened ? <Lock className="w-3 h-3 text-purple-500" /> : <Unlock className="w-3 h-3 text-purple-500" />} {intelligenceFeed.defense}
                        </p>
                      </div>
                    </div>
                  </div>

                  <div className="mt-6 pt-5 border-t border-white/5">
                    <div className="bg-slate-900/50 p-3 rounded-xl border border-white/5">
                      <p className="text-[9px] font-black text-slate-600 uppercase tracking-widest mb-1.5 flex items-center gap-1.5"><Globe className="w-3 h-3" /> Live Pattern Detection</p>
                      <p className="text-[10px] text-slate-400 font-medium leading-relaxed italic">"Our models predict a high probability of {mode === 'SIMULATED' ? 'policy-driven mitigation' : 'behavioral bypass attempt'}."</p>
                    </div>
                  </div>
                </div>
              )}

              <div className="space-y-4">
                <div className="bg-black/40 p-4 rounded-2xl border border-white/5">
                  <p className="text-[10px] font-black text-slate-600 uppercase mb-2 tracking-widest">Target Context</p>
                  <p className="text-xs text-slate-400 leading-relaxed italic">"{preview?.description || 'Loading context...'}"</p>
                </div>
                <div className="bg-black/40 p-4 rounded-2xl border border-white/5 overflow-hidden">
                  <p className="text-[10px] font-black text-slate-600 uppercase mb-2 tracking-widest">Raw Directives</p>
                  <p className="text-[10px] text-cyan-500/80 font-mono break-all line-clamp-3">{preview?.payload || 'Scanning...'}</p>
                </div>
              </div>

              <div className="flex justify-between items-center py-2">
                <span className={`text-[10px] font-black px-3 py-1 rounded-full uppercase tracking-widest ${preview?.risk_level === 'Critical' || preview?.risk_level === 'High' ? 'bg-rose-500/20 text-rose-500 border border-rose-500/30' : 'bg-cyan-500/10 text-cyan-500 border border-cyan-500/30'}`}>
                  RISK: {preview?.risk_level || 'N/A'}
                </span>
                <div className="flex items-center gap-2 text-[10px] font-black text-slate-600 uppercase tracking-widest">
                  <Activity className="w-3.5 h-3.5 animate-pulse" />
                  <span>Ready</span>
                </div>
              </div>
            </div>

            <button
              onClick={handleExecute}
              disabled={loading}
              className={`w-full mt-8 py-5 rounded-2xl font-black tracking-[0.3em] uppercase transition-all shadow-[0_20px_40px_-15px_rgba(0,0,0,0.5)] active:scale-95 disabled:opacity-50 flex flex-col items-center justify-center relative overflow-hidden group/btn ${mode === 'INQUISITOR'
                ? 'bg-amber-400 text-slate-950 hover:shadow-[0_10px_30px_rgba(245,158,11,0.3)]'
                : 'bg-white text-slate-950 hover:bg-cyan-400 hover:shadow-[0_10px_30px_rgba(34,211,238,0.3)]'
                }`}
            >
              <div className="absolute inset-0 bg-white/20 translate-x-[-100%] group-hover/btn:translate-x-[100%] transition-transform duration-1000 skew-x-12" />
              {loading ? (
                <Activity className="animate-spin w-5 h-5 text-slate-950" />
              ) : (
                <>
                  <span className="text-xs">{mode === 'INQUISITOR' ? '⚡ Unleash Inquisitor' : 'Execute Sequence'}</span>
                  <span className="text-[9px] opacity-60 tracking-widest font-black mt-1">Initiating Sandbox Orchestration</span>
                </>
              )}
            </button>
          </section>

          {/* Semantic Guard Configuration */}
          <section className="bg-slate-900/60 border border-white/10 rounded-3xl p-7 backdrop-blur-xl shadow-xl relative group">
            <h2 className="text-lg font-black mb-8 flex items-center gap-3 text-cyan-400 uppercase tracking-tighter">
              <div className="p-1.5 bg-cyan-500 rounded-lg shadow-[0_0_15px_rgba(34,211,238,0.4)]">
                <Shield className="w-4 h-4 text-slate-950 fill-current" />
              </div>
              Semantic Guard
            </h2>
            <div className="space-y-6">
              <div>
                <label className="text-[10px] font-black text-slate-500 uppercase mb-3 block tracking-widest">Enforcement Mode</label>
                <div className="grid grid-cols-3 gap-2">
                  {['observe', 'warn', 'block'].map((m) => (
                    <button
                      key={m}
                      onClick={() => setGuardrailMode(m)}
                      className={`py-3 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all border-2 ${guardrailMode === m ? 'bg-cyan-500 text-slate-950 border-cyan-400 shadow-[0_0_15px_rgba(34,211,238,0.3)]' : 'bg-slate-950 text-slate-500 border-white/10 hover:border-white/20'}`}
                    >
                      {m}
                    </button>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-[10px] font-black text-slate-500 uppercase mb-2 block tracking-widest">Guard Model</label>
                  <select
                    value={guardrailModel}
                    onChange={(e) => setGuardrailModel(e.target.value)}
                    className="w-full bg-slate-950 border-2 border-white/10 rounded-2xl px-4 py-3 focus:outline-none focus:border-cyan-500 transition-all appearance-none cursor-pointer font-black text-[10px] tracking-wider uppercase text-slate-300"
                  >
                    <option value="llama3.1:8b">Llama 3.1 8B</option>
                    <option value="qwen2.5:14b">Qwen 2.5 14B</option>
                  </select>
                </div>
                <div>
                  <label className="text-[10px] font-black text-slate-500 uppercase mb-2 block tracking-widest">Context History</label>
                  <input
                    type="number"
                    value={contextTurns}
                    onChange={(e) => setContextTurns(parseInt(e.target.value))}
                    className="w-full bg-slate-950 border-2 border-white/10 rounded-2xl px-4 py-3 focus:outline-none focus:border-cyan-500 transition-all font-black text-[10px] tracking-wider text-slate-300"
                  />
                </div>
              </div>

              <div className="p-4 bg-cyan-500/5 border border-cyan-500/20 rounded-2xl">
                <p className="text-[9px] text-cyan-400 leading-relaxed font-bold italic">
                  {guardrailMode === 'observe' && "OBSERVE: The guard will analyze intent but will NOT interfere with the campaign flow."}
                  {guardrailMode === 'warn' && "WARN: The guard will inject warnings into the evidence stream if adversarial intent is detected."}
                  {guardrailMode === 'block' && "BLOCK: The guard will actively terminate any turn that exceeds risk thresholds."}
                </p>
              </div>
            </div>
          </section>

          {/* Defense Metrics - Wrapped in a div for spacing */}
          <div className="bg-slate-900/60 border border-white/10 rounded-3xl p-7 shadow-xl">
            <div className="flex justify-between items-center mb-6">
              <h2 className="text-lg font-black flex items-center gap-3 text-emerald-400 uppercase tracking-tighter">
                <Shield className="w-5 h-5 text-emerald-500" /> System Stats
              </h2>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="bg-slate-950 p-4 rounded-2xl border border-white/5">
                <p className="text-[10px] font-black text-slate-500 uppercase mb-1 tracking-widest">Exploits</p>
                <p className="text-2xl font-black text-rose-500 tabular-nums">{stats.successful_exploits}</p>
              </div>
              <div className="bg-slate-950 p-4 rounded-2xl border border-white/5">
                <p className="text-[10px] font-black text-slate-500 uppercase mb-1 tracking-widest">Neutralized</p>
                <p className="text-2xl font-black text-emerald-400 tabular-nums">{stats.failed_attempts}</p>
              </div>
            </div>
          </div>

          {/* Automated Audit Section */}
          <section className="bg-slate-900/60 border border-white/10 rounded-3xl p-7 backdrop-blur-xl shadow-xl relative group">
            <div className="absolute top-0 right-0 p-4 opacity-0 group-hover:opacity-100 transition-opacity">
              <InfoTooltip text={TOOLTIPS.AUDIT} side="bottom" align="left" />
            </div>
            <h2 className="text-lg font-black mb-8 flex items-center gap-3 text-purple-400 uppercase tracking-tighter">
              <div className="p-1.5 bg-purple-500 rounded-lg shadow-[0_0_15px_rgba(168,85,247,0.4)]">
                <Shield className="w-4 h-4 text-slate-950 fill-current" />
              </div>
              Defense Metrics
            </h2>
            <div className="space-y-4">
              <div>
                <label className="text-[10px] font-black text-slate-500 uppercase mb-2 block tracking-widest">Library Selection</label>
                <select
                  value={selectedScan}
                  onChange={(e) => setSelectedScan(e.target.value)}
                  className="w-full bg-slate-950 border-2 border-white/10 rounded-2xl px-5 py-4 focus:outline-none focus:border-purple-500 transition-all appearance-none cursor-pointer font-black text-xs tracking-wider uppercase text-slate-300"
                >
                  {availableScans.map(scan => (
                    <option key={scan.id} value={scan.id}>{scan.name}</option>
                  ))}
                </select>
              </div>
              <button
                onClick={runAutomatedScan}
                disabled={scanning || availableScans.length === 0}
                className="w-full py-4 bg-purple-600 hover:bg-purple-500 text-white rounded-2xl font-black tracking-widest uppercase transition-all shadow-lg shadow-purple-900/20 disabled:opacity-50 flex items-center justify-center gap-2 text-[10px]"
              >
                {scanning ? <Activity className="animate-spin w-4 h-4" /> : <><Zap className="w-4 h-4" /> Run Deep Scan</>}
              </button>

              {scanResult && (
                <div className="mt-4 p-5 bg-slate-950 border-2 border-purple-500/20 rounded-2xl animate-in fade-in zoom-in duration-300">
                  <div className="flex justify-between items-center mb-4">
                    <span className="text-[10px] font-black text-purple-400 uppercase tracking-widest">Global Scan Pulse</span>
                    <span className="text-[10px] bg-rose-500/10 text-rose-500 border border-rose-500/20 px-2 py-0.5 rounded font-black">
                      {scanResult.results_summary.risk_score} RISK
                    </span>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <p className="text-[9px] text-slate-600 uppercase font-black tracking-widest">Total Prompts</p>
                      <p className="text-xl font-black text-white">{scanResult.results_summary.total_prompts}</p>
                    </div>
                    <div>
                      <p className="text-[9px] text-slate-600 uppercase font-black tracking-widest">Confirmed Bypasses</p>
                      <p className="text-xl font-black text-rose-500">{scanResult.results_summary.vulnerabilities_found}</p>
                    </div>
                  </div>
                </div>
              )}

              <div className="border-t border-white/5 pt-6 mt-6">
                <button
                  onClick={runHardeningScan}
                  disabled={hardening}
                  className="w-full py-4 bg-slate-950 border-2 border-cyan-500/30 hover:border-cyan-400 text-cyan-400 rounded-2xl font-black tracking-widest uppercase transition-all disabled:opacity-50 flex items-center justify-center gap-2 text-[10px]"
                >
                  {hardening ? <Activity className="animate-spin w-4 h-4" /> : <><FlaskConical className="w-4 h-4" /> 🛡 Strategy Probe</>}
                </button>
                {hardenResult && (
                  <div className="mt-5 space-y-2 animate-in fade-in duration-300">
                    <p className="text-[10px] font-black text-cyan-400 uppercase tracking-widest mb-3">
                      {hardenResult.refused_count}/{hardenResult.total_strategies} REFUSED
                    </p>
                    {Object.entries(hardenResult.results as Record<string, any>).map(([strat, r]: [string, any]) => (
                      <div key={strat} className="flex items-center justify-between py-2 border-b border-white/5">
                        <span className="text-[10px] font-bold text-slate-500 truncate max-w-[60%] lowercase">{strat}</span>
                        <span className={`text-[9px] font-black px-2 py-0.5 rounded ${r.severity === 'CRITICAL' ? 'bg-rose-500 text-white' :
                          r.severity === 'HIGH' ? 'bg-orange-500 text-white' :
                            r.status === 'REFUSED' ? 'bg-emerald-500 text-slate-950' :
                              'bg-amber-500 text-slate-950'
                          }`}>{r.status}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </section>
        </div>

        {/* Right Column: Feed & Logs */}
        <div className="lg:col-span-8 space-y-8 relative z-10">
          {/* Audit Stream Section */}
          <section className="bg-slate-900/40 border border-white/10 rounded-3xl p-6 h-[400px] flex flex-col backdrop-blur-sm shadow-xl relative overflow-hidden">
            <div className="flex justify-between items-center mb-6">
              <h2 className="text-lg font-black flex items-center gap-2 text-slate-300 uppercase tracking-tighter">
                <Terminal className="w-5 h-5 text-cyan-400" /> Audit Stream
              </h2>
              <div className="px-4 py-1.5 bg-slate-950 border border-white/5 rounded-full flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full bg-cyan-500 animate-pulse" />
                <span className="text-[10px] font-black text-slate-500 uppercase tracking-[0.2em]">Live Telemetry</span>
              </div>
            </div>

            <div className="flex-1 overflow-y-auto font-mono text-[11px] space-y-3 pr-2 custom-scrollbar">
              {stats.campaign_history.length === 0 && (
                <p className="text-slate-700 italic font-medium tracking-tight">Listening for security flux events...</p>
              )}
              {[...stats.campaign_history].reverse().map((entry: any, i) => (
                <div
                  key={i}
                  onClick={() => {
                    if (entry.type === 'inquisitor') {
                      setInquisitorResult(entry.full_run);
                      setLastResult(null);
                    } else {
                      setLastResult(entry.full_run || {
                        outcome: entry.success ? 'FAIL' : 'PASS',
                        payload_id: entry.campaign?.split(' - ')[1],
                        mode: entry.campaign?.split(' - ')[0],
                        evidence: { input_prompt: 'Adversarial Test', stdout: entry.output_snippet, sensitive_events: entry.success ? [] : [entry.output_snippet] }
                      });
                    }
                  }}
                  className="group border-l-2 border-white/5 hover:border-cyan-500/50 pl-5 py-2 transition-all cursor-pointer hover:bg-white/5 rounded-r-xl"
                >
                  <div className="flex items-center gap-3 mb-1.5 flex-wrap">
                    <span className="text-slate-600 tabular-nums font-bold">
                      {new Date(entry.timestamp * 1000).toLocaleTimeString()}
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[9px] font-black tracking-widest shadow-sm ${entry.success ? 'bg-rose-500/10 text-rose-500 border border-rose-500/20' : 'bg-emerald-500/10 text-emerald-500 border border-emerald-500/20'
                      }`}>
                      {entry.success ? 'EXPLOIT FOUND' : 'NEUTRALIZED'}
                    </span>
                    {entry.type === 'inquisitor' && (
                      <span className="px-2 py-0.5 rounded text-[9px] font-black bg-amber-500/10 text-amber-300 border border-amber-500/20 tracking-widest">⚡ INQUISITOR</span>
                    )}
                    {entry.exploit_severity && (
                      <span className={`px-2 py-0.5 rounded text-[9px] font-black tracking-widest ${entry.exploit_severity === 'CRITICAL' ? 'bg-rose-700/20 text-rose-300 border border-rose-700/30' :
                        entry.exploit_severity === 'HIGH' ? 'bg-orange-500/10 text-orange-300 border border-orange-500/20' :
                          'bg-yellow-500/10 text-yellow-300 border border-yellow-500/20'
                        }`}>{entry.exploit_severity} SEVERITY</span>
                    )}
                    <span className="text-slate-500 text-[10px] font-bold uppercase tracking-tighter">{entry.category?.replace(/_/g, ' ')}</span>
                  </div>
                  <p className="text-slate-400 truncate italic font-medium">"{entry.output_snippet}"</p>
                </div>
              ))}
            </div>
          </section>

          {/* Strategy Heatmap Section */}
          {Object.keys(strategyStats).length > 0 && (
            <section className="bg-slate-900/40 border border-white/10 rounded-3xl p-7 backdrop-blur-sm shadow-xl">
              <button
                onClick={() => setShowHeatmap(h => !h)}
                className="w-full flex justify-between items-center text-left group"
              >
                <h2 className="text-lg font-black flex items-center gap-3 text-amber-400 uppercase tracking-tighter">
                  <BarChart3 className="w-5 h-5" /> Intelligence Map
                </h2>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-black text-slate-600 uppercase tracking-widest">{showHeatmap ? 'Collapse Matrix' : 'Expand Matrix'}</span>
                  <div className={`transition-transform duration-300 ${showHeatmap ? 'rotate-180' : ''}`}>
                    <BarChart3 className="w-4 h-4 text-slate-700" />
                  </div>
                </div>
              </button>
              {showHeatmap && (
                <div className="mt-8 space-y-6 animate-in fade-in slide-in-from-top-4 duration-500">
                  {Object.entries(strategyStats).map(([cat, strategies]: [string, any]) => (
                    <div key={cat} className="space-y-3">
                      <p className="text-[10px] font-black text-slate-600 uppercase tracking-[0.2em]">{cat.replace(/_/g, ' ')} Vector</p>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        {Object.entries(strategies).map(([strat, data]: [string, any]) => {
                          const rate = data.attempts > 0 ? (data.successes / data.attempts) * 100 : 0;
                          return (
                            <div key={strat} className="bg-slate-950/40 border border-white/5 rounded-2xl p-4 flex items-center gap-4 hover:border-white/10 transition-colors">
                              <div className="relative">
                                <div className={`w-3 h-3 rounded-full shadow-[0_0_10px_rgba(0,0,0,0.5)]`} style={{ backgroundColor: rate > 50 ? '#ef4444' : rate > 0 ? '#f97316' : '#22d3ee' }} />
                                {rate > 50 && <div className="absolute inset-0 bg-red-500 animate-ping rounded-full opacity-20" />}
                              </div>
                              <div className="flex-1 min-w-0">
                                <p className="text-[10px] font-bold text-slate-300 truncate lowercase">{strat}</p>
                                <div className="w-full h-1 bg-slate-900 rounded-full mt-2 overflow-hidden">
                                  <div className="h-full transition-all duration-1000" style={{ width: `${rate}%`, backgroundColor: rate > 50 ? '#ef4444' : rate > 0 ? '#f97316' : '#22d3ee' }} />
                                </div>
                              </div>
                              <span className="text-[10px] font-mono font-black text-slate-500 uppercase">{data.successes}/{data.attempts}</span>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </section>
          )}

          {/* Inquisitor Session Breakdown */}
          {inquisitorResult && (
            <section className="bg-slate-900/40 border-2 border-cyan-500/20 rounded-3xl p-8 mb-8 animate-in fade-in slide-in-from-bottom-8 duration-700 shadow-2xl relative overflow-hidden backdrop-blur-xl">
              <div className="absolute top-0 right-0 p-8 opacity-5">
                <Target className="w-32 h-32 text-cyan-400" />
              </div>

              <div className="relative z-10">
                <div className="flex justify-between items-center mb-10">
                  <div>
                    <div className="flex items-center gap-3 mb-4">
                      <div className={`text-[10px] font-black px-3 py-1.5 rounded-lg tracking-[0.2em] shadow-lg ${inquisitorResult.exploit_confirmed ? 'bg-rose-500 text-white' : 'bg-emerald-500 text-slate-950'}`}>
                        {inquisitorResult.exploit_confirmed ? 'EXPLOIT CONFIRMED' : 'ACCESS DENIED'}
                      </div>
                      <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">
                        Adversarial Session: {inquisitorResult.id.substring(0, 8)}
                      </span>
                    </div>
                    <h2 className="text-3xl font-black text-white tracking-tighter uppercase">
                      Inquisitor Report: {inquisitorResult.category}
                    </h2>
                  </div>
                  <div className="text-right">
                    <p className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-1">Total Turns</p>
                    <p className="text-2xl font-black text-cyan-400">{inquisitorResult.turns.length}</p>
                  </div>
                </div>

                <div className="space-y-6">
                  {inquisitorResult.turns.map((turn: any, idx: number) => (
                    <div key={idx} className="bg-slate-950/50 border border-white/5 rounded-2xl p-6 hover:border-cyan-500/20 transition-all duration-300 group">
                      <div className="flex justify-between items-center mb-6">
                        <span className="text-[11px] font-black text-cyan-500/70 uppercase tracking-widest bg-cyan-500/5 px-3 py-1 rounded-full">
                          Turn {turn.turn}
                        </span>
                        <div className={`text-[10px] font-black px-2 py-1 rounded lowercase ${turn.exploit_severity === 'CRITICAL' ? 'bg-rose-500 text-white' :
                          turn.exploit_severity === 'HIGH' ? 'bg-orange-500 text-white' :
                            'bg-slate-800 text-slate-400'
                          }`}>
                          {turn.escalation_decision}
                        </div>
                      </div>

                      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                        <div className="space-y-4">
                          <div>
                            <p className="text-[9px] font-black text-slate-500 uppercase tracking-widest mb-3">Attacker Prompt</p>
                            <div className="bg-slate-900/40 p-4 rounded-xl border border-white/5 text-[11px] text-rose-300/80 italic leading-relaxed font-mono">
                              "{turn.attacker_prompt}"
                            </div>
                          </div>
                          <div>
                            <p className="text-[9px] font-black text-slate-500 uppercase tracking-widest mb-3">Target Response</p>
                            <div className="bg-slate-900/40 p-4 rounded-xl border border-white/5 text-[11px] text-slate-300 leading-relaxed font-mono">
                              {turn.target_response}
                            </div>
                          </div>
                        </div>

                        <div className="space-y-4">
                          {turn.tool_call_attempted && (
                            <div>
                              <p className="text-[9px] font-black text-slate-500 uppercase tracking-widest mb-3">Tool Strategy</p>
                              <div className="bg-black/60 p-4 rounded-xl border border-white/5 font-mono text-[10px] text-cyan-400">
                                <span className="text-purple-400">call</span> {turn.tool_call_attempted.tool}({
                                  Object.entries(turn.tool_call_attempted.args || {}).map(([k, v]) => `${k}="${v}"`).join(', ')
                                })
                              </div>
                            </div>
                          )}
                          <div>
                            <p className="text-[9px] font-black text-slate-500 uppercase tracking-widest mb-3">Policy Decision</p>
                            <div className={`text-[10px] font-bold p-3 rounded-xl border ${turn.policy_decision?.includes('ALLOWED') ? 'bg-emerald-500/5 border-emerald-500/20 text-emerald-400' :
                              turn.policy_decision?.includes('BLOCKED') ? 'bg-rose-500/5 border-rose-500/20 text-rose-400' :
                                'bg-slate-800/40 border-white/5 text-slate-500'
                              }`}>
                              {turn.policy_decision || "N/A"}
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>

                <div className="mt-8 pt-8 border-t border-white/5 flex justify-between items-center">
                  <div className="max-w-2xl">
                    <p className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-2">Inquisitor Summary</p>
                    <p className="text-xs text-slate-400 leading-relaxed font-medium capitalize">{inquisitorResult.summary || "No summary generated."}</p>
                  </div>
                  <button
                    onClick={() => window.open(`/attack-graph/${inquisitorResult.id}`, '_blank')}
                    className="flex items-center gap-3 px-6 py-3 bg-cyan-500 text-slate-950 rounded-xl font-black text-[11px] uppercase tracking-widest hover:bg-cyan-400 hover:scale-105 active:scale-95 transition-all shadow-[0_0_20px_rgba(34,211,238,0.3)]"
                  >
                    <Activity className="w-4 h-4" /> Analyze Graph
                  </button>
                </div>
              </div>
            </section>
          )}

          {/* Campaign Result Display */}
          {lastResult && lastResult.evidence && (
            <section className={`border-2 rounded-3xl p-8 animate-in fade-in slide-in-from-bottom-8 duration-700 shadow-2xl relative overflow-hidden ${lastResult.outcome === 'FAIL' ? 'bg-rose-500/5 border-rose-500/30' : 'bg-cyan-500/5 border-cyan-500/30'}`}>
              <div className="absolute top-0 right-0 p-8 opacity-10">
                {lastResult.outcome === 'PASS' ? <Shield className="w-32 h-32 text-cyan-400" /> : <AlertTriangle className="w-32 h-32 text-rose-500" />}
              </div>

              <div className="relative z-10">
                <div className="flex justify-between items-start mb-8">
                  <div>
                    <div className={`text-[10px] font-black px-3 py-1.5 rounded-lg mb-4 inline-block tracking-[0.2em] shadow-lg ${lastResult.outcome === 'FAIL' ? 'bg-rose-500 text-white' : 'bg-cyan-500 text-slate-950'}`}>
                      CAMPAIGN STATUS: {lastResult.outcome === 'FAIL' ? 'COMPROMISED' : 'SECURE'}
                    </div>
                    <h3 className="text-3xl font-black text-white tracking-tighter uppercase mb-2">{lastResult.payload_id}</h3>
                    <p className="text-slate-400 text-xs font-bold tracking-widest uppercase opacity-70">Target Harness: {lastResult.mode}</p>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                  <div className="space-y-6 font-mono">
                    <div>
                      <p className="text-[10px] font-black text-slate-500 mb-3 uppercase tracking-widest">Input Payload</p>
                      <div className="bg-slate-950/80 p-5 rounded-2xl border border-white/5 text-slate-300 text-[11px] leading-relaxed break-words shadow-inner">
                        {lastResult.evidence.input_prompt}
                      </div>
                    </div>
                    {lastResult.evidence.sensitive_events?.length > 0 && (
                      <div>
                        <p className="text-[10px] font-black text-rose-400 mb-3 uppercase tracking-widest flex items-center gap-2">
                          <AlertTriangle className="w-3.5 h-3.5" /> Security Violations Detected
                        </p>
                        <div className="bg-rose-500/10 p-5 rounded-2xl border border-rose-500/20 text-rose-300 text-[11px] font-bold italic">
                          {lastResult.evidence.sensitive_events.map((ev: string, idx: number) => (
                            <div key={idx} className="mb-2 last:mb-0">! {ev}</div>
                          ))}
                        </div>
                        {lastResult.outcome === 'PASS' && (
                          <div className="mt-4 p-5 bg-emerald-500/10 border border-emerald-500/20 rounded-2xl text-[11px] font-bold text-emerald-400/90 shadow-[0_0_20px_rgba(16,185,129,0.1)] animate-in fade-in slide-in-from-top-2 duration-500">
                            <div className="flex items-center gap-3 mb-2">
                              <Shield className="w-4 h-4 text-emerald-500" />
                              <span className="uppercase tracking-widest text-[10px]">Defense Layer Activated</span>
                            </div>
                            The LLM attempted a prohibited command, but the Aegis Policy Engine successfully neutralized the execution.
                          </div>
                        )}
                      </div>
                    )}
                  </div>

                  <div className="space-y-6 font-mono">
                    {lastResult.evidence.tool_calls_attempted?.length > 0 && (
                      <div className="animate-in fade-in slide-in-from-right-4 duration-500">
                        <p className="text-[10px] font-black text-cyan-400 mb-3 uppercase tracking-widest flex items-center gap-2">
                          <Terminal className="w-4 h-4" /> Attempted Execution Trace
                        </p>
                        <div className="bg-slate-950/80 p-5 rounded-2xl border border-white/5 space-y-3 shadow-inner">
                          {lastResult.evidence.tool_calls_attempted.map((tc: any, idx: number) => (
                            <div key={idx} className="font-mono text-[10px] text-cyan-300/90 bg-black/40 p-3 rounded-lg border border-white/5 break-all">
                              <span className="text-purple-400">call</span> {tc.tool}({
                                Object.entries(tc.args || {}).map(([k, v]) => `${k}="${v}"`).join(', ')
                              })
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    <div>
                      <p className="text-[10px] font-black text-slate-500 mb-3 uppercase tracking-widest">Execution Output (Final)</p>
                      <div className="bg-slate-950/80 p-5 rounded-2xl border border-white/5 h-40 overflow-y-auto text-emerald-500 text-[11px] custom-scrollbar shadow-inner leading-relaxed">
                        {lastResult.evidence.stdout || 'No system output intercepted.'}
                      </div>
                    </div>

                    {/* SysWatch Kernel Monitor Integrations */}
                    {(lastResult.evidence.kernel_alerts?.length > 0 || lastResult.evidence.kernel_events?.length > 0) && (
                      <div className="animate-in fade-in zoom-in duration-500">
                        <p className="text-[10px] font-black text-amber-400 mb-3 uppercase tracking-widest flex items-center gap-2">
                          <Layers className="w-4 h-4" /> SysWatch Kernel Telemetry
                        </p>
                        <div className="bg-amber-500/5 p-5 rounded-2xl border border-amber-500/20 space-y-3">
                          {lastResult.evidence.kernel_alerts?.map((alert: string, idx: number) => (
                            <div key={idx} className="text-amber-300 text-[11px] font-bold border-l-2 border-amber-500/50 pl-3">{alert}</div>
                          ))}
                          {lastResult.evidence.kernel_events?.filter((e: any) => e.is_suspicious).map((ev: any, idx: number) => (
                            <div key={idx} className="flex items-center gap-3 bg-amber-500/10 px-3 py-2 rounded-xl text-amber-200 border border-amber-500/20">
                              <span className="text-[9px] bg-amber-500/30 px-1.5 py-0.5 rounded font-black tracking-widest uppercase">{ev.event_type}</span>
                              <span className="font-bold text-[10px] truncate flex-1">{ev.process} → {ev.target}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </section>
          )}

          {/* Inquisitor Session Breakdown */}
          {inquisitorResult && (
            <section className={`border-2 rounded-3xl p-8 animate-in fade-in slide-in-from-bottom-8 duration-700 shadow-2xl relative overflow-hidden ${inquisitorResult.exploit_confirmed ? 'bg-rose-500/5 border-rose-500/30' : 'bg-cyan-500/5 border-cyan-500/30'}`}>
              <div className="absolute top-0 right-0 p-8 opacity-10">
                <Radio className={`w-32 h-32 ${inquisitorResult.exploit_confirmed ? 'text-rose-500' : 'text-cyan-400'}`} />
              </div>

              <div className="relative z-10">
                <div className="flex justify-between items-start mb-6">
                  <div>
                    <div className={`text-[10px] font-black px-3 py-1.5 rounded-lg mb-4 inline-block tracking-[0.2em] shadow-lg ${inquisitorResult.exploit_confirmed ? 'bg-rose-500 text-white' : 'bg-cyan-500 text-slate-950'}`}>
                      ⚡ INQUISITOR STATUS: {inquisitorResult.exploit_confirmed ? 'SUCCESS' : 'FAILED'}
                    </div>
                    {inquisitorResult.exploit_severity && (
                      <span className={`ml-3 text-[10px] font-black px-3 py-1.5 rounded-lg tracking-[0.2em] shadow-lg inline-block uppercase ${inquisitorResult.exploit_severity === 'CRITICAL' ? 'bg-rose-700 text-white' : inquisitorResult.exploit_severity === 'HIGH' ? 'bg-orange-500 text-white' : 'bg-yellow-500 text-slate-950'}`}>
                        {inquisitorResult.exploit_severity} SEVERITY
                      </span>
                    )}
                    <h3 className="text-2xl font-black text-white tracking-tighter uppercase mb-2">{inquisitorResult.category?.replace(/_/g, ' ')} Hunt</h3>
                    <div className="flex items-center gap-4">
                      <p className="text-slate-400 text-xs font-bold tracking-widest uppercase opacity-70">{inquisitorResult.total_turns_used} Turns Executed · {inquisitorResult.summary}</p>
                      <button
                        onClick={() => window.open(`/attack-graph/${inquisitorResult.id}`, '_blank')}
                        className="flex items-center gap-1.5 text-[10px] font-black text-cyan-400 hover:text-cyan-300 transition-colors bg-cyan-400/10 px-3 py-1 rounded-full border border-cyan-400/20"
                      >
                        <Activity className="w-3.5 h-3.5" /> Analyze Graph
                      </button>
                    </div>
                  </div>
                </div>

                <div className="space-y-4 font-mono">
                  <p className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-4">Adversarial Turn Log</p>
                  <div className="space-y-3">
                    {inquisitorResult.turns?.map((turn: any, idx: number) => (
                      <div key={idx} className="bg-slate-950/80 border border-white/5 rounded-2xl p-5 space-y-3 shadow-inner hover:border-white/10 transition-colors">
                        <div className="flex items-center gap-3">
                          <span className="text-[10px] font-black text-slate-600 uppercase tracking-widest">Turn {turn.turn}</span>
                          <span className={`px-2 py-0.5 rounded text-[9px] font-black tracking-widest border ${turn.escalation_decision === 'EXPLOIT_FOUND' ? 'bg-rose-500/20 text-rose-400 border-rose-500/30' : turn.escalation_decision === 'FAILED' ? 'bg-slate-800 text-slate-500 border-white/10' : 'bg-amber-500/20 text-amber-400 border-amber-500/30'}`}>
                            {turn.escalation_decision}
                          </span>
                          {turn.policy_decision && (
                            <span className={`px-2 py-0.5 rounded text-[9px] font-black tracking-widest border ${turn.policy_decision === 'ALLOWED' ? 'bg-rose-500/10 text-rose-400 border-rose-500/20' : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'}`}>
                              {turn.policy_decision}
                            </span>
                          )}
                        </div>
                        <div className="space-y-2">
                          <p className="text-[11px] leading-relaxed"><span className="text-cyan-500 font-black uppercase tracking-tighter">ATTACKER › </span><span className="text-slate-300">{turn.attacker_prompt}</span></p>
                          <p className="text-[11px] leading-relaxed"><span className="text-purple-500 font-black uppercase tracking-tighter">TARGET   › </span><span className="text-slate-400 italic font-medium">"{turn.target_response?.slice(0, 300)}{turn.target_response?.length > 300 ? '...' : ''}"</span></p>

                          {turn.tool_call_attempted ? (
                            <div className="mt-3 p-4 bg-slate-900/80 border border-cyan-500/20 rounded-xl shadow-inner group/tool overflow-hidden relative">
                              <div className="absolute top-0 right-0 p-2 opacity-20 group-hover/tool:opacity-100 transition-opacity">
                                <Terminal className="w-3 h-3 text-cyan-400" />
                              </div>
                              <p className="text-[9px] font-black text-cyan-500/60 uppercase tracking-widest mb-2 flex items-center gap-2">
                                <Activity className="w-3 h-3" /> Attempted Execution Trace
                              </p>
                              <div className="font-mono text-[10px] text-cyan-300/90 bg-black/40 p-3 rounded-lg border border-white/5 break-all">
                                <span className="text-purple-400">call</span> {turn.tool_call_attempted.tool}({
                                  Object.entries(turn.tool_call_attempted.args || {}).map(([k, v]) => `${k}="${v}"`).join(', ')
                                })
                              </div>
                            </div>
                          ) : (
                            turn.escalation_decision === 'EXPLOIT_FOUND' && (
                              <div className={`mt-3 p-3 border rounded-xl text-[10px] font-bold italic flex items-center gap-2 ${turn.target_response?.toLowerCase().includes('permission denied') || turn.target_response?.toLowerCase().includes('i cannot') ? 'bg-cyan-500/10 border-cyan-500/20 text-cyan-400/70' : 'bg-amber-500/10 border-amber-500/20 text-amber-400/80'}`}>
                                <Shield className="w-3.5 h-3.5" />
                                {turn.target_response?.toLowerCase().includes('permission denied') || turn.target_response?.toLowerCase().includes('i cannot')
                                  ? '🟢 MODEL REFUSAL: Target correctly denied access at the thinking level. No execution attempted.'
                                  : '⚠️ SLOPPY COMPLIANCE: Target agreed to the attack but failed to trigger a structural tool call.'}
                              </div>
                            )
                          )}

                          {turn.escalation_decision === 'EXPLOIT_FOUND' && turn.tool_call_attempted && turn.policy_decision?.includes('BLOCKED') && (
                            <div className="mt-3 p-3 bg-emerald-500/10 border border-emerald-500/20 rounded-xl text-[10px] font-bold text-emerald-400/80 italic flex items-center gap-2">
                              <Shield className="w-3.5 h-3.5" />
                              🛡️ VULNERABILITY NEUTRALIZED: LLM bypass detected, but execution was killed by firewall.
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </section>
          )}
          <style jsx global>{`
        @keyframes shimmer {
          0% { transform: translateX(-100%); }
          100% { transform: translateX(100%); }
        }
        .custom-scrollbar::-webkit-scrollbar {
          width: 4px;
        }
        .custom-scrollbar::-webkit-scrollbar-track {
          background: rgba(255, 255, 255, 0.05);
        }
        .custom-scrollbar::-webkit-scrollbar-thumb {
          background: rgba(34, 211, 238, 0.2);
          border-radius: 10px;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover {
          background: rgba(34, 211, 238, 0.5);
        }
      `}</style>
        </div>
      </div>
    </div>
  );
}
