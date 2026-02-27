'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { Terminal, Shield, AlertTriangle, Play, BarChart3, List, Activity, Cpu, Zap, Eye, Info } from 'lucide-react';

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
  const [preview, setPreview] = useState<any>(null);
  const [availableScans, setAvailableScans] = useState<any[]>([]);
  const [selectedScan, setSelectedScan] = useState<string>('');
  const [scanResult, setScanResult] = useState<any>(null);
  const [scanning, setScanning] = useState(false);

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
    const interval = setInterval(fetchStats, 5000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (category) fetchPreview(category);
  }, [category, fetchPreview]);

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
          mode: mode
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
          <div className="flex items-center gap-2 bg-slate-900/50 px-4 py-2 rounded-full border border-white/5">
            <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span className="text-xs font-mono text-slate-400 tracking-wider">HARNESS ONLINE</span>
          </div>
        </div>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left Column: Controls */}
        <div className="lg:col-span-4 space-y-8">
          <section className="bg-slate-900/40 border border-white/10 rounded-2xl p-6 backdrop-blur-sm shadow-xl">
            <h2 className="text-lg font-semibold mb-6 flex items-center gap-2 text-cyan-400 uppercase tracking-tighter">
              <Play className="w-5 h-5" /> Launch Campaign
            </h2>
            <div className="space-y-6">
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
                <label className="text-[10px] font-bold text-slate-500 uppercase mb-2 block tracking-widest">Evaluation Mode</label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    onClick={() => setMode('SIMULATED')}
                    className={`flex items-center justify-center gap-2 py-3 rounded-xl border transition-all text-xs font-bold ${mode === 'SIMULATED' ? 'bg-cyan-500/20 border-cyan-500 text-cyan-300' : 'bg-slate-950 border-white/5 text-slate-500 hover:border-white/10'}`}
                  >
                    <Zap className="w-3 h-3" /> SIMULATED
                  </button>
                  <button
                    onClick={() => setMode('REAL_AGENT')}
                    className={`flex items-center justify-center gap-2 py-3 rounded-xl border transition-all text-xs font-bold ${mode === 'REAL_AGENT' ? 'bg-purple-500/20 border-purple-500 text-purple-300' : 'bg-slate-950 border-white/5 text-slate-500 hover:border-white/10'}`}
                  >
                    <Cpu className="w-3 h-3" /> REAL AGENT
                  </button>
                </div>
              </div>

              <div>
                <label className="text-[10px] font-bold text-slate-500 uppercase mb-2 block tracking-widest">Attack Category</label>
                <select
                  value={category}
                  onChange={(e) => setCategory(e.target.value)}
                  className="w-full bg-slate-950 border border-white/10 rounded-xl px-4 py-3 focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-all appearance-none cursor-pointer font-mono text-sm"
                >
                  {categories.map(cat => (
                    <option key={cat} value={cat}>{cat.replace(/_/g, ' ').toUpperCase()}</option>
                  ))}
                </select>
              </div>

              {/* NEW PREVIEW SECTION */}
              {preview && (
                <div className="bg-slate-950/80 border border-cyan-500/20 rounded-xl p-4 animate-in fade-in zoom-in duration-300">
                  <div className="flex items-center gap-2 mb-2">
                    <Eye className="w-3 h-3 text-cyan-400" />
                    <span className="text-[10px] font-black text-cyan-400 uppercase tracking-widest">Pre-Execution Preview</span>
                  </div>
                  <p className="text-xs font-bold text-white mb-1">{preview.name}</p>
                  <p className="text-[10px] text-slate-500 leading-tight mb-3 italic">"{preview.description}"</p>

                  <div className="space-y-2">
                    <div className="bg-black/40 p-3 rounded-lg border border-white/5">
                      <p className="text-[9px] font-bold text-slate-600 uppercase mb-1 tracking-tighter">Intent</p>
                      <p className="text-[10px] text-slate-400">{preview.intent}</p>
                    </div>
                    <div className="bg-black/40 p-3 rounded-lg border border-white/5">
                      <p className="text-[9px] font-bold text-slate-600 uppercase mb-1 tracking-tighter">Raw Payload</p>
                      <p className="text-[9px] text-cyan-500/80 font-mono break-all line-clamp-2">{preview.payload}</p>
                    </div>
                  </div>

                  <div className="mt-3 flex justify-between items-center">
                    <span className={`text-[9px] font-bold px-2 py-0.5 rounded uppercase ${preview.risk_level === 'Critical' || preview.risk_level === 'High' ? 'bg-rose-500/10 text-rose-500' : 'bg-cyan-500/10 text-cyan-500'}`}>
                      Risk: {preview.risk_level}
                    </span>
                    <div className="flex items-center gap-1 text-[9px] text-slate-600">
                      <Info className="w-3 h-3" />
                      <span>Ready for dispatch</span>
                    </div>
                  </div>
                </div>
              )}

              <button
                onClick={runCampaign}
                disabled={loading}
                className="w-full py-4 mt-2 bg-white text-slate-950 hover:bg-cyan-400 rounded-xl font-black tracking-widest uppercase transition-all shadow-lg disabled:opacity-50 flex items-center justify-center gap-2"
              >
                {loading ? <Activity className="animate-spin w-5 h-5 text-slate-950" /> : 'Execute Sequence'}
              </button>
            </div>
          </section>

          {/* Stats Summary */}
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-slate-900/40 border border-white/10 rounded-2xl p-5">
              <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block mb-1">Exploits Found</span>
              <span className="text-3xl font-mono text-rose-500 font-bold">{stats.successful_exploits}</span>
            </div>
            <div className="bg-slate-900/40 border border-white/10 rounded-2xl p-5">
              <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block mb-1">Successfully Blocked</span>
              <span className="text-3xl font-mono text-emerald-400 font-bold">{stats.failed_attempts}</span>
            </div>
          </div>

          <section className="bg-slate-900/40 border border-white/10 rounded-2xl p-6 backdrop-blur-sm shadow-xl">
            <h2 className="text-lg font-semibold mb-6 flex items-center gap-2 text-purple-400 uppercase tracking-tighter">
              <Shield className="w-5 h-5" /> Automated Security Audit
            </h2>
            <div className="space-y-4">
              <div>
                <label className="text-[10px] font-bold text-slate-500 uppercase mb-2 block tracking-widest">Available Frameworks</label>
                <select
                  value={selectedScan}
                  onChange={(e) => setSelectedScan(e.target.value)}
                  className="w-full bg-slate-950 border border-white/10 rounded-xl px-4 py-3 focus:outline-none focus:ring-1 focus:ring-purple-500 transition-all appearance-none cursor-pointer font-mono text-sm"
                >
                  {availableScans.map(scan => (
                    <option key={scan.id} value={scan.id}>{scan.name}</option>
                  ))}
                </select>
              </div>
              <button
                onClick={runAutomatedScan}
                disabled={scanning || availableScans.length === 0}
                className="w-full py-3 bg-purple-600 hover:bg-purple-500 text-white rounded-xl font-bold tracking-widest uppercase transition-all shadow-lg disabled:opacity-50 flex items-center justify-center gap-2 text-xs"
              >
                {scanning ? <Activity className="animate-spin w-4 h-4" /> : <><Zap className="w-4 h-4" /> Run Deep Scan</>}
              </button>

              {scanResult && (
                <div className="mt-4 p-4 bg-slate-950 rounded-xl border border-purple-500/30 animate-in fade-in zoom-in duration-300">
                  <div className="flex justify-between items-center mb-3">
                    <span className="text-[10px] font-black text-purple-400 uppercase tracking-widest">Audit Complete</span>
                    <span className="text-[10px] bg-rose-500/10 text-rose-500 border border-rose-500/20 px-2 py-0.5 rounded font-bold">
                      {scanResult.results_summary.risk_score} RISK
                    </span>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <p className="text-[9px] text-slate-500 uppercase font-bold">Total Prompts</p>
                      <p className="text-xl font-mono font-bold text-white">{scanResult.results_summary.total_prompts}</p>
                    </div>
                    <div>
                      <p className="text-[9px] text-slate-500 uppercase font-bold">Vulnerabilities</p>
                      <p className="text-xl font-mono font-bold text-rose-500">{scanResult.results_summary.vulnerabilities_found}</p>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </section>
        </div>

        {/* Right Column: Feed & Logs */}
        <div className="lg:col-span-8 space-y-8">
          {/* Live Feed */}
          <section className="bg-slate-900/40 border border-white/10 rounded-2xl p-6 h-[350px] flex flex-col backdrop-blur-sm shadow-xl relative overflow-hidden">
            <div className="flex justify-between items-center mb-6">
              <h2 className="text-lg font-semibold flex items-center gap-2 text-slate-300 uppercase tracking-tighter">
                <Terminal className="w-5 h-5 text-cyan-400" /> Audit Stream
              </h2>
              <div className="px-3 py-1 bg-slate-950 border border-white/5 rounded-full">
                <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest">Live Logs</span>
              </div>
            </div>

            <div className="flex-1 overflow-y-auto font-mono text-[11px] space-y-3 pr-2 custom-scrollbar">
              {stats.campaign_history.length === 0 && (
                <p className="text-slate-700 italic">Listening for flux events...</p>
              )}
              {[...stats.campaign_history].reverse().map((entry: any, i) => (
                <div
                  key={i}
                  onClick={() => setLastResult(entry.full_run || {
                    outcome: entry.success ? 'FAIL' : 'PASS',
                    payload_id: entry.campaign.split(' - ')[1],
                    mode: entry.campaign.split(' - ')[0],
                    evidence: {
                      input_prompt: "Adversarial Test",
                      stdout: entry.output_snippet,
                      sensitive_events: entry.success ? [] : [entry.output_snippet]
                    }
                  })}
                  className="group border-l border-white/5 hover:border-cyan-500/50 pl-4 py-1 transition-all cursor-pointer hover:bg-white/5"
                >
                  <div className="flex items-center gap-3 mb-1">
                    <span className="text-slate-600 tabular-nums">
                      {new Date(entry.timestamp * 1000).toLocaleTimeString()}
                    </span>
                    <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold tracking-widest ${entry.success ? 'bg-rose-500/10 text-rose-500 border border-rose-500/20' : 'bg-emerald-500/10 text-emerald-500 border border-emerald-500/20'}`}>
                      {entry.success ? 'FAIL' : 'PASS'}
                    </span>
                    <span className="text-slate-400 text-[10px]">{entry.campaign}</span>
                  </div>
                  <p className="text-slate-500 truncate italic">
                    {entry.output_snippet}
                  </p>
                </div>
              ))}
            </div>
          </section>

          {/* Last Result Details */}
          {lastResult && (
            <section className={`border rounded-2xl p-6 animate-in fade-in slide-in-from-bottom-5 duration-500 shadow-2xl ${lastResult.outcome === 'FAIL' ? 'bg-rose-500/5 border-rose-500/30' : 'bg-cyan-500/5 border-cyan-500/30'}`}>
              <div className="flex justify-between items-start mb-6">
                <div>
                  <div className={`text-[10px] font-bold px-2 py-1 rounded-md mb-2 inline-block tracking-widest ${lastResult.outcome === 'FAIL' ? 'bg-rose-500 text-white' : 'bg-cyan-500 text-slate-950'}`}>
                    CAMPAIGN OUTCOME: {lastResult.outcome}
                  </div>
                  <h3 className="text-2xl font-black text-white tracking-tighter uppercase">{lastResult.payload_id}</h3>
                  <p className="text-slate-400 text-sm mt-1">Target Identity: {lastResult.mode}</p>
                </div>
                {lastResult.outcome === 'PASS' ? <Shield className="w-12 h-12 text-cyan-400 opacity-20" /> : <AlertTriangle className="w-12 h-12 text-rose-500 opacity-20" />}
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-4 font-mono text-[10px]">
                  <div>
                    <p className="text-slate-500 mb-2 font-bold uppercase tracking-widest">Input Payload</p>
                    <div className="bg-slate-950 p-4 rounded-xl border border-white/5 text-slate-300 break-words">
                      {lastResult.evidence.input_prompt}
                    </div>
                  </div>
                  {lastResult.evidence.sensitive_events.length > 0 && (
                    <div>
                      <p className="text-rose-400 mb-2 font-bold uppercase tracking-widest italic">Security Events</p>
                      <div className="bg-rose-500/10 p-4 rounded-xl border border-rose-500/20 text-rose-300">
                        {lastResult.evidence.sensitive_events.map((ev: string, idx: number) => (
                          <div key={idx} className="mb-1">! {ev}</div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
                <div className="space-y-4 font-mono text-[10px]">
                  <div>
                    <p className="text-slate-500 mb-2 font-bold uppercase tracking-widest">Sandbox execution Output</p>
                    <div className="bg-slate-950 p-4 rounded-xl border border-white/5 h-32 overflow-y-auto text-emerald-500 custom-scrollbar">
                      {lastResult.evidence.stdout || 'No shell output.'}
                    </div>
                  </div>
                </div>
              </div>
            </section>
          )}
        </div>
      </div>

      <style jsx global>{`
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
  );
}
