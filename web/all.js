// The combined view: one packet across all the layers that saw it. The hooks
// are laid out in the order the packet crossed them, each in the lane of its
// layer: the device hooks at the bottom, the bridge hooks in the middle, and
// the IP hooks at the top. A hook that calls the hooks of another layer while
// the packet is in it (as a bridge hook does with br_netfilter) is drawn as a
// wide box, with the called hooks above it.

import { el, setWidth, store, clock, micros, stackName, peerName, ifaceByName, tracer, pickable } from './core.js';

let ctx = null;
let T = null;
let shown = null;  // the journey on view
let leaf = 0;      // the copy of it that the diagram follows

const LANES = [
  { layer: 'l3', label: 'IP hooks', short: 'L3' },
  { layer: 'l2', label: 'Bridge hooks', short: 'L2' },
  { layer: 'l1', label: 'Device hooks', short: 'L1' },
];
const COL = 172, BOX_W = 144, BOX_H = 46, LANE_H = 104, LEFT = 150, TOP = 26, END = 96;

// leaves are the copies that no bridge copied further: the ends of the paths.
function leaves(j) {
  const copies = j.copies || [];
  const parents = new Set(copies.map((c) => c.parent || 0));
  return copies.filter((c) => !parents.has(c.id));
}

// defaultLeaf follows the copy that went up to the network stack, else the first one.
function defaultLeaf(j) {
  const all = leaves(j);
  if (!all.length) return 0;
  return (all.find((c) => c.host) || all[0]).id;
}

// lineage is a copy with all the copies it descends from, and the original.
function lineage(j, id) {
  const line = new Set([0]);
  while (id && !line.has(id)) {
    line.add(id);
    id = j.copies[id - 1].parent || 0;
  }
  return line;
}

const copyName = (c) => (c.host ? `up to the stack (${c.bridge})` : `to ${c.to}`);

// plan turns the hops of one path into boxes. A box is one pass through a hook.
// It spans several columns when hooks of another layer ran in between.
function plan(j, leafId, on) {
  const line = lineage(j, leafId);
  const boxes = [];
  const open = new Map();
  const seq = []; // the path: a box and the column where the path touches it
  let col = -1;
  j.hops.forEach((h, index) => {
    if (!line.has(h.copy || 0) || !on.has(h.layer)) return;
    const key = h.layer === 'l3' ? `l3|${h.hook}|${h.pin || ''}|${h.pout || ''}`
      : h.layer === 'l2' ? `l2|${h.hook}|${h.bridge}|${h.hook === 'PREROUTING' || h.hook === 'INPUT' ? '' : h.out || ''}`
        : `l1|${h.hook}|${h.in || h.out}`;
    let box = open.get(key);
    const last = seq.length ? seq[seq.length - 1].box : null;
    if (!box) {
      col++;
      box = { layer: h.layer, hook: h.hook, c0: col, c1: col, hops: [], exited: false, first: h };
      open.set(key, box);
      boxes.push(box);
      seq.push({ box, col });
    } else if (box !== last) {
      col++;
      box.c1 = col;
      seq.push({ box, col });
    }
    box.hops.push({ h, index });
    if (h.exit) box.exited = true;
  });
  return { boxes, seq, cols: col + 1 };
}

function boxSub(box) {
  const h = box.first;
  if (box.layer === 'l1') return h.in || h.out;
  if (box.layer === 'l2') {
    if (box.hook === 'PREROUTING') return `${h.bridge} · from ${h.in}`;
    if (box.hook === 'INPUT') return `${h.bridge} · up`;
    return `${h.bridge} · to ${h.out}`;
  }
  const last = box.hops[box.hops.length - 1].h;
  return [h.pin || h.in, last.pout || last.out].filter(Boolean).join(' → ');
}

// boxPick tells what a click on a box traces: the device the packet was on when
// it crossed the hook.
function boxPick(box) {
  const h = box.first;
  const last = box.hops[box.hops.length - 1].h;
  const arriving = (dev) => (dev ? [{ ifaces: [`in:${dev}`] }, `what arrives on ${dev}`] : null);
  const leaving = (dev) => (dev ? [{ ifaces: [`out:${dev}`] }, `what leaves through ${dev}`] : null);
  if (box.layer === 'l1') return box.hook === 'INGRESS' ? arriving(h.in) : leaving(h.out);
  if (box.layer === 'l2') return box.hook === 'PREROUTING' || box.hook === 'INPUT' ? arriving(h.in) : leaving(h.out);
  const dev = { in: h.pin || h.in, out: last.pout || last.out };
  if (dev.in && box.hook !== 'OUTPUT' && box.hook !== 'POSTROUTING') return arriving(dev.in);
  return leaving(dev.out);
}

// ending tells how the path ended.
function ending(j, p) {
  if (!p.seq.length) return { kind: 'done', head: 'Nothing to show', text: 'None of the layers that are on saw this packet.' };
  const box = p.seq[p.seq.length - 1].box;
  const h = box.hops[box.hops.length - 1].h;
  const name = box.layer === 'l1' ? `the ${box.hook.toLowerCase()} hook of ${h.in || h.out}` : box.layer === 'l2' ? `${box.hook} of the bridge ${h.bridge}` : box.hook;
  if (!box.exited) {
    return { kind: 'stopped', head: `Dropped in ${name}`, text: `The packet entered ${name} and did not leave it: a rule there dropped, rejected, or queued it.`, box };
  }
  const l3 = j.l3;
  switch (`${box.layer}/${box.hook}`) {
    case 'l3/INPUT':
      return l3 && l3.to
        ? { kind: 'done', head: `Delivered to ${l3.to.name}`, text: `The packet passed INPUT and reached the ${l3.to.proto.toUpperCase()} socket on port ${l3.to.port} of ${l3.to.name} (pid ${l3.to.pid}).`, end: l3.to.name }
        : { kind: 'done', head: 'Delivered locally', text: `The packet passed INPUT and went up to the transport layer of ${stackName()}.`, end: 'local socket' };
    case 'l3/POSTROUTING': {
      const dev = h.pout || h.out;
      return { kind: 'done', head: `Sent via ${dev}`, text: `The packet passed POSTROUTING and was handed to ${dev}.${store.egress ? '' : ' This kernel has no egress hook for devices, so the path ends here.'}`, end: dev };
    }
    case 'l1/EGRESS':
      return { kind: 'done', head: `Sent through ${h.out}`, text: `The frame passed the egress hook of ${h.out} and was handed to the device.`, end: peerName(ifaceByName(h.out)) || 'the network' };
    case 'l2/POSTROUTING':
      return { kind: 'done', head: `Sent to port ${h.out}`, text: `The frame passed POSTROUTING of the bridge ${h.bridge} and was handed to its port ${h.out}.`, end: peerName(ifaceByName(h.out)) || h.out };
    case 'l2/INPUT':
      return { kind: 'done', head: `Delivered to ${stackName()}`, text: `The bridge ${h.bridge} passed the frame up to the network stack, and no hook above saw it. That is normal for a frame that is not an IP packet, like an ARP message.`, end: 'network stack' };
    case 'l1/INGRESS': {
      const dev = ifaceByName(h.in);
      return { kind: 'done', head: `Received on ${h.in}`, text: `The frame passed the ingress hook of ${h.in}, and no hook above saw it.${dev && dev.master ? ` ${h.in} is a port of ${dev.master}: the bridge may have dropped the frame before its own hooks.` : ' That is normal for a frame that is not an IP packet, like an ARP message.'}`, end: dev && dev.master ? dev.master : 'network stack' };
    }
    case 'l2/PREROUTING':
      return { kind: 'stopped', head: 'Dropped by the bridge', text: `The frame passed PREROUTING of ${h.bridge} and went nowhere: the bridge had no port to send it to.`, lost: true };
    default:
      return { kind: 'stopped', head: `Lost after ${name}`, text: `The packet left ${name} and was not seen again.${box.layer === 'l3' && box.hook === 'PREROUTING' ? ' The routing decision discarded it: no route, forwarding disabled, or a reverse path check.' : ''}`, lost: true };
  }
}

// origin tells where the path starts.
function origin(j, p) {
  const box = p.seq[0].box;
  const h = box.first;
  if (box.layer === 'l1' && box.hook === 'INGRESS') return peerName(ifaceByName(h.in)) || (h.in === 'lo' ? 'loopback' : 'the network');
  if (box.layer === 'l2' && box.hook === 'PREROUTING') return peerName(ifaceByName(h.in)) || `port ${h.in}`;
  if (box.layer === 'l3' && box.hook === 'PREROUTING' && h.stage === 'raw') return h.pin || h.in || 'a device';
  if (box.hook === 'OUTPUT' || box.hook === 'EGRESS') return j.l3 && j.l3.from ? j.l3.from.name : 'the network stack';
  return '';
}

// ---- Diagram ---------------------------------------------------------------

function onLayers() {
  const on = ctx.layers();
  return new Set(LANES.map((l) => l.layer).filter((l) => on.includes(l)));
}

function draw(j, animate) {
  const svg = ctx.svg;
  svg.replaceChildren();
  const on = onLayers();
  const lanes = LANES.filter((l) => on.has(l.layer));
  const p = j ? plan(j, leaf, on) : { boxes: [], seq: [], cols: 0 };
  const cols = Math.max(p.cols, 3);
  const W = LEFT + END + (cols - 1) * COL + BOX_W + END + 30;
  const height = TOP + lanes.length * LANE_H + 6;
  svg.setAttribute('viewBox', `0 0 ${W} ${height}`);
  setWidth(svg, W);
  const laneY = (layer) => TOP + lanes.findIndex((l) => l.layer === layer) * LANE_H + LANE_H / 2;
  const colX = (c) => LEFT + END + BOX_W / 2 + c * COL;

  lanes.forEach((lane, i) => {
    const y = TOP + i * LANE_H;
    svg.append(
      el('rect', { class: 'lane', x: 4, y: y + 4, width: W - 8, height: LANE_H - 8, rx: 10 }),
      el('text', { class: 'lane-name', x: 18, y: y + LANE_H / 2 - 2 }, lane.label),
      el('text', { class: 'label', x: 18, y: y + LANE_H / 2 + 14 }, lane.short),
    );
  });
  const trails = el('g'), marks = el('g');
  svg.append(trails);
  T = tracer(svg, trails, marks);
  T.reset(animate);
  if (!j || !p.seq.length) {
    svg.append(el('text', { class: 'label', x: W / 2, y: height / 2 + 4, 'text-anchor': 'middle' }, j ? 'None of the layers that are on saw this packet.' : 'Select a packet to see the hooks it crossed, layer by layer.'));
    svg.append(marks);
    return 0;
  }

  for (const box of p.boxes) {
    const x0 = colX(box.c0) - BOX_W / 2, x1 = colX(box.c1) + BOX_W / 2, y = laneY(box.layer);
    const g = el('g', { class: `hook ${box.c1 > box.c0 ? 'wide' : ''}` });
    const rewrote = box.hops.filter((x) => x.h.rewrote).map((x) => x.h.rewrote);
    const stages = box.layer === 'l3' ? box.hops.filter((x) => !x.h.exit).map((x) => x.h.stage).join(', ') : '';
    g.append(
      el('title', {}, [`${box.hook}${stages ? `: ${stages}` : ''}`, boxSub(box), ...rewrote.map((r) => `rewrote the ${r}`)].filter(Boolean).join('\n')),
      el('rect', { x: x0, y: y - BOX_H / 2, width: x1 - x0, height: BOX_H, rx: 10 }),
    );
    // A wide box is entered on its left and left on its right.
    for (const c of box.c1 > box.c0 ? [box.c0, box.c1] : [box.c0]) {
      g.append(
        el('text', { class: 'hookname', x: colX(c), y: y - 3, 'text-anchor': 'middle' }, box.hook),
        el('text', { class: 'hooksub', x: colX(c), y: y + 12, 'text-anchor': 'middle' }, c === box.c0 ? boxSub(box) : 'back in the hook'),
      );
    }
    const pick = boxPick(box);
    if (pick) pickable(g, ctx, ...pick);
    svg.append(g);
    box.el = g;
    box.rewrote = rewrote.length > 0;
  }

  const end = ending(j, p);
  const first = p.seq[0], last = p.seq[p.seq.length - 1];
  const startAt = [colX(first.col) - BOX_W / 2 - END + 30, laneY(first.box.layer)];
  const endAt = [colX(last.col) + BOX_W / 2 + END - 30, laneY(last.box.layer)];
  const from = origin(j, p);
  const startNode = el('circle', { class: `node ${from ? '' : 'unknown'}`, cx: startAt[0], cy: startAt[1], r: 8 });
  svg.append(startNode, el('text', { class: 'label', x: startAt[0], y: startAt[1] - 16, 'text-anchor': 'middle' }, from || 'first seen here'));
  let endNode = null;
  if (!end.box) {
    endNode = el('circle', { class: 'node', cx: endAt[0], cy: endAt[1], r: 8 });
    svg.append(endNode, el('text', { class: 'label', x: endAt[0], y: endAt[1] - 16, 'text-anchor': 'middle' }, end.lost ? 'not seen again' : end.end || ''));
  }
  svg.append(marks);

  // The trail: straight inside a lane, and through the gap between two columns
  // from lane to lane.
  const points = [startAt];
  const reach = [{ node: startNode, dist: 0 }];
  let dist = 0;
  const push = (pt) => {
    const prev = points[points.length - 1];
    dist += Math.abs(pt[0] - prev[0]) + Math.abs(pt[1] - prev[1]);
    points.push(pt);
  };
  p.seq.forEach((s, i) => {
    const at = [colX(s.col), laneY(s.box.layer)];
    const prev = points[points.length - 1];
    if (prev[1] !== at[1]) {
      const mid = at[0] - COL / 2;
      push([mid, prev[1]]);
      push([mid, at[1]]);
    }
    push(at);
    const stopHere = end.box === s.box && i === p.seq.length - 1;
    reach.push({ node: s.box.el, dist, cls: `lit${s.box.rewrote ? ' rewrote' : ''}${stopHere ? ' stopped' : ''}`, stop: stopHere ? [at[0] + BOX_W / 2 - 4, at[1] - BOX_H / 2 + 4] : null });
  });
  if (endNode) {
    push(endAt);
    reach.push({ node: endNode, dist, cls: end.lost ? 'stopped' : 'lit', stop: end.lost ? [endAt[0] + 16, endAt[1] - 16] : null });
  }
  const t = T.trail(points, '', 0);
  for (const r of reach) {
    const at = T.timeAt(0, r.dist);
    T.light(r.node, at, r.cls || 'lit');
    if (r.stop) T.stop(r.stop, at);
  }
  return t.done;
}

function show(item, animate) {
  const j = item ? item.j : null;
  if (j !== shown) {
    shown = j;
    leaf = j ? defaultLeaf(j) : 0;
  }
  return draw(j, animate);
}

// ---- Text ------------------------------------------------------------------

function verdict(item) {
  if (!item) return { text: 'Waiting for a packet that matches the filter.' };
  const j = item.j;
  const on = onLayers();
  const p = plan(j, shown === j ? leaf : defaultLeaf(j), on);
  const end = ending(j, p);
  let text = end.text;
  const hops = p.boxes.flatMap((b) => b.hops.map((x) => x.h));
  if (hops.some((h) => h.layer === 'l3' && (h.pin || h.pout)) && on.has('l2')) {
    text += ' The IP hooks ran inside the bridge hooks: br_netfilter is loaded, so iptables and nftables rules of the IP families see the bridged packets.';
  }
  const all = leaves(j);
  if (all.length > 1) {
    const mine = all.find((c) => c.id === leaf);
    text += ` A bridge made ${all.length} copies of this frame. This is the one that went ${mine ? copyName(mine) : 'on'}: pick another one above the diagram.`;
  }
  if (j.unreliable) text += ' Some probe events were lost around this packet, so the path may be incomplete.';
  return { head: `${end.head}.`, text, kind: end.kind };
}

const layersOf = (j) => LANES.map((l) => l.layer).filter((l) => j.hops.some((h) => h.layer === l)).reverse().map((l) => l.toUpperCase()).join(' ');

function cells(item) {
  const j = item.j;
  const f = j.frame;
  const end = ending(j, plan(j, defaultLeaf(j), new Set(['l1', 'l2', 'l3'])));
  const copies = leaves(j).length;
  return [
    [clock(j.time), 'mono'], [layersOf(j), 'mono'],
    [j.proto ? j.src : f ? f.src : '', 'mono'], [j.proto ? j.dst : f ? f.dst : '', 'mono'],
    [j.proto ? `${j.proto.toUpperCase()} ${j.info}` : f ? [f.type, f.info].filter(Boolean).join(' ') : '', 'details'],
    [end.head + (copies > 1 ? ` (1 of ${copies} copies)` : ''), end.kind === 'stopped' ? 'outcome-stopped' : 'outcome-done'],
  ];
}

// detail lists every probe that saw the packet on the path on view.
function detail(item) {
  const d = { title: 'Hooks of the selected packet', columns: ['Layer', 'Hook', 'In', 'Out', 'Source', 'Destination', 'Elapsed'], empty: 'Select a packet to see every probe that saw it.', summary: '', rows: [] };
  if (!item) return d;
  const j = item.j;
  d.summary = j.proto ? [j.proto.toUpperCase(), j.info, `${j.len} bytes`].filter(Boolean).join(', ') : j.frame ? [j.frame.type, j.frame.info].filter(Boolean).join(', ') : '';
  const on = onLayers();
  const line = lineage(j, shown === j ? leaf : defaultLeaf(j));
  const hops = j.hops.filter((h) => line.has(h.copy || 0) && on.has(h.layer));
  const end = ending(j, plan(j, shown === j ? leaf : defaultLeaf(j), on));
  hops.forEach((h, i) => {
    const name = h.layer === 'l3'
      ? (h.exit ? `left ${h.hook}` : `${h.stage}/${h.hook}`)
      : `${h.exit ? 'left' : 'entered'} ${h.hook}${h.layer === 'l2' ? ` of ${h.bridge}` : ''}`;
    const ip = h.layer === 'l3' || !h.smac;
    const row = {
      cells: [[h.layer.toUpperCase(), 'mono'], [name, 'mono wrap'], [h.pin || h.in || '', 'mono'], [h.pout || h.out || '', 'mono'], [(ip ? h.src : h.smac) || '', 'mono'], [(ip ? h.dst : h.dmac) || '', 'mono'], [micros(h.us), 'mono']],
      cls: h.exit ? 'exit' : '', notes: [],
    };
    if (h.rewrote) { row.cls += ' rewrote'; row.notes.push(`This stage rewrote the ${h.rewrote}.`); }
    if (i === hops.length - 1 && end.kind === 'stopped') {
      row.cls += ' stopped';
      row.notes.push(end.lost ? 'The packet was not seen after this point.' : 'The packet did not leave this hook.');
    }
    d.rows.push(row);
  });
  return d;
}

export default {
  id: 'all',
  label: 'Combined',
  title: 'Packets',
  noun: 'packet',
  layer: '',
  about: 'One packet across the device, bridge, and IP hooks, in the order it crossed them.',
  subs: [],
  // The layers of this view can be switched on and off one by one.
  layered: true,
  panels: [{ id: 'packets', label: 'Packets' }, { id: 'details', label: 'Hooks' }],
  aria: 'The hooks of all the layers and the path of the selected packet',
  init(context) { ctx = context; },
  items: (j) => [{ id: `${j.id}`, j, time: j.time }],
  columns: ['Time', 'Layers', 'Source', 'Destination', 'Details', 'Outcome'],
  cells,
  resize: () => false,
  build: () => { draw(shown, false); },
  show,
  verdict,
  detail,
  // tabs are the copies of the selected frame, when a bridge made several.
  tabs() {
    if (!shown) return [];
    const all = leaves(shown);
    return all.length < 2 ? [] : all.map((c) => ({ id: String(c.id), label: copyName(c), on: c.id === leaf }));
  },
  pickTab(id) { leaf = Number(id); },
  onTab: () => true,
  packetHops(item) {
    const on = onLayers();
    const line = lineage(item.j, shown === item.j ? leaf : defaultLeaf(item.j));
    return item.j.hops.map((h, i) => (line.has(h.copy || 0) && on.has(h.layer) ? i : -1)).filter((i) => i >= 0);
  },
};
