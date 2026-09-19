// The hunt's step graph, drawn with the same library the Huntbase app uses
// (React Flow), with a node card that mirrors the app's HuntNodeCard: a
// coloured rail per step type, a hollow in-dot and a filled out-dot, grey
// sequence edges and stepped merge edges on a dotted canvas.
//
// No build step: pinned ES modules resolved by the page's import map.
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  Background, BackgroundVariant, Controls, Handle, MarkerType, MiniMap, Position, ReactFlow,
} from '@xyflow/react';
import dagre from '@dagrejs/dagre';
import htm from 'htm';

const html = htm.bind(React.createElement);
const NODE_WIDTH = 270;

// Hex values are the app's HUNT_NODE_TYPE_META.
const META = {
  hypothesis: { label: 'Hypothesis', color: '#7a5af8' },
  query: { label: 'Query', color: '#3b82f6' },
  analytic: { label: 'Agent triage', color: '#6366f1' },
  checkpoint: { label: 'Decision', color: '#fabb3d' },
  action: { label: 'Response action', color: '#ea580c' },
  task: { label: 'Analyst task', color: '#02df84' },
};
const BRANCH_LABEL = {
  on_supports: 'supports', on_refutes: 'refutes', default: 'unclear', on_unavailable: 'no data',
};
const metaFor = (type) => META[type] || META.query;
const heightFor = (n) => (n.type === 'hypothesis' ? 58 : 84 + (n.description ? 34 : 0) + (n.query ? 40 : 0));

function layout(steps) {
  const g = new dagre.graphlib.Graph();
  g.setGraph({ rankdir: 'TB', nodesep: 36, ranksep: 64, marginx: 16, marginy: 16 });
  g.setDefaultEdgeLabel(() => ({}));
  steps.forEach((s) => g.setNode(s.id, { width: NODE_WIDTH, height: heightFor(s) }));
  steps.forEach((s) => (s.parents || []).forEach((p) => g.hasNode(p.id) && g.setEdge(p.id, s.id)));
  dagre.layout(g);
  return Object.fromEntries(steps.map((s) => {
    const { x, y } = g.node(s.id);
    return [s.id, { x: x - NODE_WIDTH / 2, y: y - heightFor(s) / 2 }];
  }));
}

function StepNode({ data }) {
  const { step, selected, dimmed } = data;
  const meta = metaFor(step.type);
  return html`
    <div className=${`rf-step${selected ? ' is-selected' : ''}${dimmed ? ' is-dimmed' : ''}`}
         style=${{ width: NODE_WIDTH, '--rail': meta.color }}>
      <${Handle} type="target" position=${Position.Top} className="rf-dot rf-dot-in" isConnectable=${false} />
      <div className="rf-step-head">
        <span className="rf-type" style=${{ color: meta.color }}>${meta.label}</span>
        ${step.role && html`<span className="rf-role">${step.role.replace(/-/g, ' ')}</span>`}
      </div>
      <div className="rf-label">${step.label}</div>
      ${step.description && step.type !== 'hypothesis' && html`<div className="rf-desc">${step.description}</div>`}
      ${step.query && html`<div className="rf-query">${step.query}</div>`}
      <${Handle} type="source" position=${Position.Bottom} className="rf-dot rf-dot-out" isConnectable=${false} />
    </div>`;
}
const nodeTypes = { step: StepNode };

// The ordered index on the left. The same three panes as the app's full-page
// playbook view: list, graph, inspector, one shared selection.
function StepList({ steps, selectedId, onSelect }) {
  return html`<ol className="rf-list">
    ${steps.map((s, i) => html`<li key=${s.id}>
      <button type="button" aria-current=${s.id === selectedId ? 'true' : undefined} onClick=${() => onSelect(s.id)}>
        <span className="num">${i + 1}</span>
        <span className="t">${s.label}</span>
        <span className="k"><i style=${{ background: metaFor(s.type).color }}></i>${metaFor(s.type).label}</span>
      </button>
    </li>`)}
  </ol>`;
}

function Inspector({ step, index, total, byId, children, onSelect, onStep }) {
  if (!step) return html`<aside className="rf-inspector is-empty"><p>Select a step.</p></aside>`;
  const meta = metaFor(step.type);
  const link = (id) => html`<button type="button" className="rf-link" key=${id} onClick=${() => onSelect(id)}>${byId[id]?.label || id}</button>`;
  return html`<aside className="rf-inspector">
    <div className="rf-inspector-head">
      <span className="rf-type" style=${{ color: meta.color }}>${meta.label}${step.role ? ` · ${step.role.replace(/-/g, ' ')}` : ''}</span>
    </div>
    <h3 className="heading-sm">${step.label}</h3>
    ${step.description && html`<p>${step.description}</p>`}
    ${step.query && html`<div className="code"><div className="code-head"><span>reads ${step.source || 'source'}</span><span>sql</span></div><pre><code>${step.query}</code></pre></div>`}
    ${step.expected && html`<p className="expected"><strong>What a hit looks like. </strong>${step.expected}</p>`}
    ${(step.parents || []).length > 0 && html`<div className="rf-rel"><span>Runs after</span>${step.parents.map((p) => link(p.id))}</div>`}
    ${children.length > 0 && html`<div className="rf-rel"><span>Leads to</span>${children.map(link)}</div>`}
    <div className="rf-pager">
      <button type="button" className="btn btn-ghost" disabled=${index <= 0} onClick=${() => onStep(-1)}>Previous</button>
      <span>Step ${index + 1} of ${total}</span>
      <button type="button" className="btn btn-ghost" disabled=${index >= total - 1} onClick=${() => onStep(1)}>Next</button>
    </div>
  </aside>`;
}

function HuntGraph({ steps }) {
  // A step is always selected: the one in the URL (#step-<id>), else the first.
  const fromHash = () => {
    const id = decodeURIComponent(location.hash.slice(1)).replace(/^step-/, '');
    return steps.some((s) => s.id === id) ? id : null;
  };
  const [selectedId, setSelectedId] = useState(() => fromHash() || steps[0]?.id || null);
  const [full, setFull] = useState(false);
  const [flow, setFlow] = useState(null);
  const dark = useMemo(() => matchMedia('(prefers-color-scheme: dark)').matches, []);
  const byId = useMemo(() => Object.fromEntries(steps.map((s) => [s.id, s])), [steps]);
  const positions = useMemo(() => layout(steps), [steps]);
  const childrenOf = useMemo(() => {
    const out = {};
    steps.forEach((s) => (s.parents || []).forEach((p) => (out[p.id] = out[p.id] || []).push(s.id)));
    return out;
  }, [steps]);

  const related = useMemo(() => {
    if (!selectedId) return null;
    const set = new Set([selectedId, ...(childrenOf[selectedId] || [])]);
    (byId[selectedId]?.parents || []).forEach((p) => set.add(p.id));
    return set;
  }, [selectedId, byId, childrenOf]);

  const nodes = useMemo(() => steps.map((s) => ({
    id: s.id, type: 'step', position: positions[s.id], draggable: false, selectable: false,
    initialWidth: NODE_WIDTH, initialHeight: heightFor(s),
    data: { step: s, selected: s.id === selectedId, dimmed: related ? !related.has(s.id) : false },
  })), [steps, positions, selectedId, related]);

  const edges = useMemo(() => steps.flatMap((s) => (s.parents || []).filter((p) => byId[p.id]).map((p, i) => {
    const active = selectedId && (p.id === selectedId || s.id === selectedId);
    const stroke = active ? '#7f34fa' : (dark ? '#6b6880' : '#89857f');
    return {
      id: `${p.id}->${s.id}-${i}`, source: p.id, target: s.id,
      type: p.kind === 'merge' ? 'smoothstep' : 'default',
      label: BRANCH_LABEL[p.branch], labelBgPadding: [6, 3], labelBgBorderRadius: 6,
      labelStyle: { fontFamily: 'Geist Mono, ui-monospace, monospace', fontSize: 10, fill: dark ? '#b4aecb' : '#4a4560' },
      labelBgStyle: { fill: dark ? '#181433' : '#ffffff', stroke: dark ? '#2b2650' : '#e6e2f0' },
      markerEnd: { type: MarkerType.ArrowClosed, color: stroke, width: 16, height: 16 },
      style: { stroke, strokeWidth: active ? 2 : 1.2, opacity: selectedId && !active ? 0.3 : 0.9 },
      animated: Boolean(active),
    };
  })), [steps, byId, selectedId, dark]);

  const select = useCallback((id) => {
    setSelectedId(id);
    history.replaceState(null, '', `#step-${encodeURIComponent(id)}`);
    const pos = positions[id];
    if (flow && pos) flow.setCenter(pos.x + NODE_WIDTH / 2, pos.y + 60, { zoom: Math.max(flow.getZoom(), 0.9), duration: 300 });
  }, [flow, positions]);

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && full) setFull(false); };
    addEventListener('keydown', onKey);
    return () => removeEventListener('keydown', onKey);
  }, [full]);
  useEffect(() => {
    document.documentElement.classList.toggle('rf-noscroll', full);
    // Full screen has room for the whole hunt; the inline canvas opens on the first steps.
    if (flow && full) setTimeout(() => flow.fitView({ padding: 0.12, duration: 200 }), 60);
  }, [full, flow]);

  // The canvas is sized while its tab is hidden; fit it when Steps opens, and
  // follow #step-<id> links from the other tabs.
  useEffect(() => {
    const onTab = (e) => {
      if (e.detail !== 'steps' || !flow) return;
      const id = fromHash();
      if (id) setSelectedId(id);
      requestAnimationFrame(() => flow.fitView({ nodes: [{ id: id || selectedId }], padding: 0.6, minZoom: 0.6, maxZoom: 1 }));
    };
    document.addEventListener('hunt:tab', onTab);
    return () => document.removeEventListener('hunt:tab', onTab);
  }, [flow, selectedId]);

  const index = steps.findIndex((s) => s.id === selectedId);
  const onStep = (delta) => { const next = steps[index + delta]; if (next) select(next.id); };

  return html`<div className=${`rf-shell${full ? ' is-full' : ''}`}>
    <${StepList} steps=${steps} selectedId=${selectedId} onSelect=${select} />
    <div className="rf-canvas">
      <${ReactFlow} nodes=${nodes} edges=${edges} nodeTypes=${nodeTypes} onInit=${setFlow}
        colorMode=${dark ? 'dark' : 'light'} fitView
        fitViewOptions=${{ nodes: steps.slice(0, 3).map((s) => ({ id: s.id })), padding: 0.25, minZoom: 0.85, maxZoom: 1 }}
        minZoom=${0.25} maxZoom=${1.75} nodesConnectable=${false} elementsSelectable=${false}
        panOnScroll zoomOnScroll=${false} zoomOnPinch
        onNodeClick=${(_, n) => select(n.id)}
        proOptions=${{ hideAttribution: false }}>
        <${Background} variant=${BackgroundVariant.Dots} gap=${16} size=${1} />
        <${Controls} showInteractive=${false} />
        <${MiniMap} pannable zoomable nodeStrokeWidth=${0} nodeBorderRadius=${6}
          nodeColor=${(n) => metaFor(n.data.step.type).color}
          bgColor=${dark ? '#181433' : '#ffffff'} maskColor=${dark ? 'rgba(16,13,34,0.7)' : 'rgba(230,226,240,0.65)'} />
      <//>
      <button type="button" className="rf-expand" onClick=${() => setFull(!full)}>${full ? 'Close full screen' : 'Full screen'}</button>
      <div className="rf-legend">
        ${Object.entries(META).map(([k, m]) => html`<span key=${k}><i style=${{ background: m.color }}></i>${m.label}</span>`)}
      </div>
    </div>
    <${Inspector} step=${byId[selectedId]} index=${index} total=${steps.length} byId=${byId}
      children=${childrenOf[selectedId] || []} onSelect=${select} onStep=${onStep} />
  </div>`;
}

const mount = document.getElementById('hunt-graph');
const data = document.getElementById('hunt-graph-data');
if (mount && data) {
  createRoot(mount).render(html`<${HuntGraph} steps=${JSON.parse(data.textContent)} />`);
  // Hides the server-rendered step list, which is only the no-JS fallback.
  mount.classList.add('is-mounted');
}
