'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { 
  ReactFlow, 
  Background, 
  Controls, 
  MiniMap, 
  useNodesState, 
  useEdgesState, 
  addEdge,
  Handle,
  Position,
  NodeProps,
  Edge,
  Node
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { ArrowLeft, Target, Shield, AlertTriangle, Activity, Zap, Info, ChevronRight } from 'lucide-react';

// ─────────────────────────────────────────────────────────────────────────────
// Custom Node Components
// ─────────────────────────────────────────────────────────────────────────────

const AttackerNode = ({ data }: NodeProps) => (
  <div className={`px-4 py-3 rounded-xl border transition-all duration-300 shadow-lg ${data.is_ponr ? 'bg-red-950/40 border-red-500 shadow-red-500/20' : 'bg-slate-900/90 border-slate-700 hover:border-red-500/60'}`}>
    <Handle type="target" position={Position.Top} className="!bg-slate-600" />
    <div className="flex items-center gap-2 mb-1">
      <Target className={`w-4 h-4 ${data.is_ponr ? 'text-red-500 animate-pulse' : 'text-slate-400'}`} />
      <span className="text-[10px] uppercase tracking-widest font-bold text-slate-500">{data.label}</span>
      {data.is_ponr && <span className="text-[10px] bg-red-600 text-white px-1.5 py-0.5 rounded-full font-bold">PONR</span>}
    </div>
    <div className="text-xs text-slate-300 font-mono line-clamp-3 leading-relaxed max-w-[200px]">
      {data.content}
    </div>
    <Handle type="source" position={Position.Bottom} className="!bg-slate-600" />
  </div>
);

const TargetResponseNode = ({ data }: NodeProps) => {
  const isIntentShift = data.is_intent_shift;
  const isBlocked = data.is_blocked;

  return (
    <div className={`px-4 py-3 rounded-xl border transition-all duration-300 shadow-lg ${isIntentShift ? 'bg-amber-950/40 border-amber-500 shadow-amber-500/20' : 'bg-slate-900/90 border-slate-700 hover:border-cyan-500/60'}`}>
      <Handle type="target" position={Position.Top} className="!bg-slate-600" />
      <div className="flex items-center gap-2 mb-1">
        <Shield className={`w-4 h-4 ${isBlocked ? 'text-cyan-400' : isIntentShift ? 'text-amber-500' : 'text-slate-400'}`} />
        <span className="text-[10px] uppercase tracking-widest font-bold text-slate-500">{data.label}</span>
        {isIntentShift && <span className="text-[10px] bg-amber-600 text-white px-1.5 py-0.5 rounded-full font-bold">INTENT SHIFT</span>}
      </div>
      <div className="text-xs text-slate-300 font-mono line-clamp-3 leading-relaxed max-w-[200px]">
        {data.content}
      </div>
      
      {data.verdicts && data.verdicts.length > 0 && (
        <div className="mt-2 pt-2 border-t border-slate-800 space-y-1">
          {data.verdicts.map((v: any, idx: number) => (
            <div key={idx} className="flex items-center gap-1.5 text-[9px]">
              <div className={`w-1.5 h-1.5 rounded-full ${v.risk_level === 'ALLOW' ? 'bg-green-500' : v.risk_level === 'BLOCK' ? 'bg-cyan-500' : 'bg-red-500'}`} />
              <span className="text-slate-500 uppercase font-bold">{v.risk_level}</span>
              <span className="text-slate-400 truncate">{v.reason}</span>
            </div>
          ))}
        </div>
      )}
      <Handle type="source" position={Position.Bottom} className="!bg-slate-600" />
    </div>
  );
};

const nodeTypes = {
  'Attacker Prompt': AttackerNode,
  'Target Response': TargetResponseNode,
  'Outcome': TargetResponseNode, // Re-use styling
};

// ─────────────────────────────────────────────────────────────────────────────
// Page Component
// ─────────────────────────────────────────────────────────────────────────────

export default function AttackGraphPage() {
  const { run_id } = useParams();
  const router = useRouter();
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [summary, setSummary] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchGraph = useCallback(async () => {
    try {
      setLoading(true);
      const res = await fetch(`http://localhost:8000/campaigns/${run_id}/graph`);
      if (!res.ok) throw new Error('Graph data not found');
      const data = await res.json();
      
      // Transform nodes to include nodeType and ReactFlow types
      const mappedNodes = data.nodes.map((n: any) => ({
        ...n,
        type: n.data.node_type === 'Attacker Prompt' ? 'Attacker Prompt' : 'Target Response',
        style: { width: 240 }
      }));

      setNodes(mappedNodes);
      setEdges(data.edges);
      setSummary(data.summary);
      setError(null);
    } catch (err: any) {
      console.error(err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [run_id, setNodes, setEdges]);

  useEffect(() => {
    fetchGraph();
  }, [fetchGraph]);

  const jumpToPONR = () => {
    const ponrNode = nodes.find(n => n.data.is_ponr);
    if (ponrNode) {
      // Basic jump logic - in a real app would use reactflow.setCenter
      const el = document.querySelector(`[data-id="${ponrNode.id}"]`);
      el?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  };

  const jumpToIntentShift = () => {
    const shiftNode = nodes.find(n => n.data.is_intent_shift);
    if (shiftNode) {
      const el = document.querySelector(`[data-id="${shiftNode.id}"]`);
      el?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  };

  return (
    <div className="flex flex-col h-screen bg-slate-950 font-sans text-slate-200 overflow-hidden">
      {/* Header */}
      <header className="flex items-center justify-between px-8 py-4 bg-slate-900/50 border-b border-slate-800 backdrop-blur-md z-10">
        <div className="flex items-center gap-6">
          <button 
            onClick={() => router.push('/')}
            className="p-2 hover:bg-slate-800 rounded-lg transition-colors group"
          >
            <ArrowLeft className="w-5 h-5 text-slate-400 group-hover:text-cyan-400" />
          </button>
          <div>
            <h1 className="text-lg font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent flex items-center gap-2">
              <Activity className="w-5 h-5 text-cyan-500" />
              Attack Graph — {run_id?.slice(0, 8)}
            </h1>
            <p className="text-[10px] text-slate-500 uppercase tracking-[0.2em] font-bold">Visualizing Multi-Turn Adversarial Chain</p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          {summary?.has_intent_shift && (
              <button 
                onClick={jumpToIntentShift}
                className="flex items-center gap-2 px-4 py-2 bg-amber-500/10 border border-amber-500/30 rounded-xl text-amber-500 text-xs font-bold hover:bg-amber-500/20 transition-all"
              >
                <Zap className="w-4 h-4" /> Jump to Intent Shift
              </button>
          )}
          {summary?.has_ponr && (
             <button 
                onClick={jumpToPONR}
                className="flex items-center gap-2 px-4 py-2 bg-red-500/10 border border-red-500/30 rounded-xl text-red-500 text-xs font-bold hover:bg-red-500/20 transition-all"
              >
                <Target className="w-4 h-4" /> Jump to PONR
              </button>
          )}
          <button 
            onClick={fetchGraph}
            className="p-2 bg-slate-800 hover:bg-slate-700 rounded-lg transition-all"
            title="Refresh Graph"
          >
            <Activity className="w-4 h-4 text-cyan-400" />
          </button>
        </div>
      </header>

      {/* Main Graph Area */}
      <main className="flex-grow relative">
        {loading && (
          <div className="absolute inset-0 flex flex-col items-center justify-center bg-slate-950/80 z-20 backdrop-blur-sm">
            <div className="w-12 h-12 border-4 border-cyan-500/20 border-t-cyan-500 rounded-full animate-spin mb-4" />
            <p className="text-xs font-bold text-slate-400 uppercase tracking-widest">Reconstructing Attack Chain...</p>
          </div>
        )}

        {error && (
           <div className="absolute inset-0 flex flex-col items-center justify-center z-20">
              <AlertTriangle className="w-12 h-12 text-red-500 mb-4" />
              <p className="text-lg font-bold text-slate-200">Failed to Load Graph</p>
              <p className="text-sm text-slate-500 mt-2">{error}</p>
              <button 
                onClick={() => router.push('/')}
                className="mt-6 px-6 py-2 bg-slate-800 hover:bg-slate-700 rounded-xl text-xs font-bold transition-all"
              >
                Return to Dashboard
              </button>
           </div>
        )}

        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          nodeTypes={nodeTypes}
          colorMode="dark"
          fitView
          fitViewOptions={{ padding: 0.2 }}
        >
          <Background color="#1e293b" gap={20} />
          <Controls className="!bg-slate-900 !border-slate-800 !fill-slate-400" />
          <MiniMap 
            nodeColor={(node: any) => {
              if (node.data.is_ponr) return '#ef4444';
              if (node.data.is_intent_shift) return '#f59e0b';
              if (node.type === 'Attacker Prompt') return '#334155';
              return '#0e7490';
            }}
            maskColor="rgba(2, 6, 23, 0.7)"
            style={{ backgroundColor: '#0f172a', borderRadius: '12px', border: '1px solid #1e293b' }}
          />
        </ReactFlow>

        {/* Legend */}
        <div className="absolute bottom-6 right-6 p-4 bg-slate-900/80 border border-slate-800 rounded-2xl backdrop-blur-md z-10 space-y-3 shadow-2xl">
          <h3 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-2">Legend</h3>
          <div className="flex items-center gap-3">
             <div className="w-3 h-3 rounded bg-slate-700 border border-slate-600" />
             <span className="text-[10px] font-bold text-slate-400 uppercase">Attacker Payload</span>
          </div>
          <div className="flex items-center gap-3">
             <div className="w-3 h-3 rounded bg-cyan-900/40 border border-cyan-500/40" />
             <span className="text-[10px] font-bold text-slate-400 uppercase">Target Response</span>
          </div>
          <div className="flex items-center gap-3">
             <div className="w-3 h-3 rounded bg-amber-500 border border-amber-400" />
             <span className="text-[10px] font-bold text-slate-400 uppercase">Intent Shift</span>
          </div>
          <div className="flex items-center gap-3">
             <div className="w-3 h-3 rounded bg-red-600 border border-red-500" />
             <span className="text-[10px] font-bold text-slate-400 uppercase">Point of No Return</span>
          </div>
        </div>

        {/* Info Box */}
        <div className="absolute bottom-6 left-6 p-4 bg-slate-900/80 border border-slate-800 rounded-2xl backdrop-blur-md z-10 w-64 shadow-2xl">
           <div className="flex items-center gap-2 mb-2 text-cyan-400">
              <Info className="w-4 h-4" />
              <span className="text-[11px] font-bold uppercase tracking-wider">Attack Analysis</span>
           </div>
           <p className="text-[10px] leading-relaxed text-slate-400">
              The graph visualizes the multi-hop progression from initial greeting to system compromise. 
              <span className="text-amber-500 font-bold ml-1">Intent Shift</span> marks the pivot into adversarial behavior.
              <span className="text-red-500 font-bold ml-1">PONR</span> marks the first successful bypass.
           </p>
        </div>
      </main>
    </div>
  );
}
