/* Minimal vanilla-SVG chart primitives: horizontal bar, donut, stacked timeline.
   No external dependencies. Follows: thin marks, 4px rounded bar ends, 2px
   surface gaps between segments, hover tooltips, legends for >=2 series. */

const Charts = (() => {
  const NS = "http://www.w3.org/2000/svg";

  function css(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  function el(tag, attrs) {
    const node = document.createElementNS(NS, tag);
    for (const k in attrs || {}) node.setAttribute(k, attrs[k]);
    return node;
  }

  function formatNum(n) {
    if (n >= 1000) return (n / 1000).toFixed(n >= 10000 ? 0 : 1).replace(/\.0$/, "") + "K";
    return String(n);
  }

  const tooltipEl = () => document.getElementById("chart-tooltip");

  function showTooltip(x, y, title, rows) {
    const tt = tooltipEl();
    tt.innerHTML = "";
    const t = document.createElement("div");
    t.className = "tt-title";
    t.textContent = title;
    tt.appendChild(t);
    rows.forEach((r) => {
      const row = document.createElement("div");
      row.className = "tt-row";
      if (r.color) {
        const key = document.createElement("span");
        key.className = "tt-key";
        key.style.background = r.color;
        row.appendChild(key);
      }
      const name = document.createElement("span");
      name.textContent = r.label;
      row.appendChild(name);
      const val = document.createElement("span");
      val.className = "tt-val";
      val.textContent = r.value;
      row.appendChild(val);
      tt.appendChild(row);
    });
    tt.style.display = "block";
    const pad = 14;
    let left = x + pad;
    let top = y + pad;
    const rect = tt.getBoundingClientRect();
    if (left + rect.width > window.innerWidth - 10) left = x - rect.width - pad;
    if (top + rect.height > window.innerHeight - 10) top = y - rect.height - pad;
    tt.style.left = left + "px";
    tt.style.top = top + "px";
  }

  function hideTooltip() {
    const tt = tooltipEl();
    tt.style.display = "none";
  }

  function buildLegend(container, items) {
    const legend = document.createElement("div");
    legend.className = "legend";
    items.forEach((it) => {
      const row = document.createElement("span");
      row.className = "legend-item";
      const sw = document.createElement("span");
      sw.className = "legend-swatch";
      sw.style.background = it.color;
      row.appendChild(sw);
      const label = document.createElement("span");
      label.textContent = it.label;
      row.appendChild(label);
      legend.appendChild(row);
    });
    container.appendChild(legend);
  }

  // ---- Horizontal bar chart: single measure across categories ----
  function horizontalBar(container, items, opts) {
    container.innerHTML = "";
    if (!items || !items.length) {
      const empty = document.createElement("div");
      empty.className = "empty-note";
      empty.textContent = "No data available.";
      container.appendChild(empty);
      return;
    }
    opts = opts || {};
    const color = opts.color || css("--series-1");
    const width = container.clientWidth || 400;
    const rowH = 26;
    const gap = 6;
    const labelW = Math.min(width * 0.42, 220);
    const chartW = width - labelW - 46;
    const height = items.length * (rowH + gap);
    const max = Math.max(...items.map((i) => i.value), 1);

    const svg = el("svg", { class: "chart-svg", width, height, viewBox: `0 0 ${width} ${height}` });

    items.forEach((item, i) => {
      const y = i * (rowH + gap);
      const barW = Math.max((item.value / max) * chartW, 2);

      const label = el("text", { x: labelW - 8, y: y + rowH / 2 + 4, "text-anchor": "end" });
      label.textContent = item.label.length > 34 ? item.label.slice(0, 33) + "…" : item.label;
      svg.appendChild(label);

      const track = el("rect", {
        x: labelW, y, width: chartW, height: rowH - 8,
        rx: 4, fill: "var(--surface-3)",
      });
      svg.appendChild(track);

      const bar = el("rect", {
        class: "bar-mark", x: labelW, y, width: barW, height: rowH - 8,
        rx: 4, fill: color,
      });
      svg.appendChild(bar);

      const showTitle = barW > 34;
      const valueLabel = el("text", {
        x: showTitle ? labelW + barW - 6 : labelW + barW + 6,
        y: y + rowH / 2 - 4 + 4,
        "text-anchor": showTitle ? "end" : "start",
        fill: showTitle ? "#fff" : "var(--text-secondary)",
      });
      valueLabel.textContent = formatNum(item.value);
      valueLabel.style.pointerEvents = "none";
      if (showTitle) valueLabel.style.fill = "#fff";
      svg.appendChild(valueLabel);

      const hit = el("rect", { x: 0, y, width, height: rowH - 8, fill: "transparent", class: "bar-mark" });
      hit.addEventListener("mousemove", (e) => {
        showTooltip(e.clientX, e.clientY, item.label, [{ value: item.value.toLocaleString() }]);
        bar.style.opacity = 0.82;
      });
      hit.addEventListener("mouseleave", () => {
        hideTooltip();
        bar.style.opacity = 1;
      });
      svg.appendChild(hit);
    });

    container.appendChild(svg);
  }

  // ---- Donut chart: severity part-to-whole ----
  function donut(container, segments, opts) {
    container.innerHTML = "";
    opts = opts || {};
    const total = segments.reduce((a, s) => a + s.value, 0);
    const width = container.clientWidth || 260;
    const size = Math.min(width, 220);
    const cx = size / 2;
    const cy = size / 2;
    const rOuter = size / 2 - 6;
    const rInner = rOuter * 0.62;

    const wrap = document.createElement("div");
    wrap.style.display = "flex";
    wrap.style.alignItems = "center";
    wrap.style.gap = "18px";
    wrap.style.flexWrap = "wrap";

    const svg = el("svg", { class: "chart-svg", width: size, height: size, viewBox: `0 0 ${size} ${size}`, style: `max-width:${size}px` });

    if (total === 0) {
      const empty = document.createElement("div");
      empty.className = "empty-note";
      empty.textContent = "No data available.";
      container.appendChild(empty);
      return;
    }

    let angle = -Math.PI / 2;
    const gapRad = total > 0 ? 0.02 : 0;

    segments.forEach((seg) => {
      if (seg.value <= 0) return;
      const frac = seg.value / total;
      const a0 = angle + gapRad / 2;
      const a1 = angle + frac * Math.PI * 2 - gapRad / 2;
      angle += frac * Math.PI * 2;

      const large = a1 - a0 > Math.PI ? 1 : 0;
      const x0o = cx + rOuter * Math.cos(a0), y0o = cy + rOuter * Math.sin(a0);
      const x1o = cx + rOuter * Math.cos(a1), y1o = cy + rOuter * Math.sin(a1);
      const x0i = cx + rInner * Math.cos(a1), y0i = cy + rInner * Math.sin(a1);
      const x1i = cx + rInner * Math.cos(a0), y1i = cy + rInner * Math.sin(a0);

      const d = `M ${x0o} ${y0o} A ${rOuter} ${rOuter} 0 ${large} 1 ${x1o} ${y1o} L ${x0i} ${y0i} A ${rInner} ${rInner} 0 ${large} 0 ${x1i} ${y1i} Z`;
      const path = el("path", { d, fill: seg.color, class: "bar-mark" });
      path.addEventListener("mousemove", (e) => {
        const pct = ((seg.value / total) * 100).toFixed(1);
        showTooltip(e.clientX, e.clientY, seg.label, [{ value: `${seg.value.toLocaleString()} (${pct}%)`, color: seg.color }]);
        path.style.opacity = 0.82;
      });
      path.addEventListener("mouseleave", () => { hideTooltip(); path.style.opacity = 1; });
      svg.appendChild(path);
    });

    const centerVal = el("text", { x: cx, y: cy - 2, "text-anchor": "middle", "font-size": "20", "font-weight": "600", fill: "var(--text-primary)" });
    centerVal.textContent = formatNum(total);
    const centerLbl = el("text", { x: cx, y: cy + 16, "text-anchor": "middle", "font-size": "10.5", fill: "var(--text-muted)" });
    centerLbl.textContent = "total events";
    svg.appendChild(centerVal);
    svg.appendChild(centerLbl);

    wrap.appendChild(svg);

    const list = document.createElement("div");
    list.style.flex = "1";
    list.style.minWidth = "140px";
    segments.forEach((seg) => {
      const row = document.createElement("div");
      row.style.display = "flex";
      row.style.alignItems = "center";
      row.style.gap = "8px";
      row.style.fontSize = "12.5px";
      row.style.padding = "5px 0";
      row.style.color = "var(--text-secondary)";
      const sw = document.createElement("span");
      sw.className = "legend-swatch";
      sw.style.background = seg.color;
      row.appendChild(sw);
      const label = document.createElement("span");
      label.textContent = seg.label;
      row.appendChild(label);
      const val = document.createElement("span");
      val.style.marginLeft = "auto";
      val.style.fontWeight = "600";
      val.style.color = "var(--text-primary)";
      val.style.fontVariantNumeric = "tabular-nums";
      val.textContent = seg.value.toLocaleString();
      row.appendChild(val);
      list.appendChild(row);
    });
    wrap.appendChild(list);

    container.appendChild(wrap);
  }

  // ---- Stacked bar timeline: events per day, segmented by severity ----
  function stackedTimeline(container, rows, seriesDefs) {
    container.innerHTML = "";
    if (!rows || !rows.length) {
      const empty = document.createElement("div");
      empty.className = "empty-note";
      empty.textContent = "No data available.";
      container.appendChild(empty);
      return;
    }
    const width = container.clientWidth || 600;
    const height = 220;
    const padL = 42, padB = 24, padT = 10, padR = 10;
    const chartW = width - padL - padR;
    const chartH = height - padT - padB;

    const totals = rows.map((r) => seriesDefs.reduce((a, s) => a + (r[s.key] || 0), 0));
    const max = Math.max(...totals, 1);
    const niceMax = Math.ceil(max / 5) * 5 || 1;

    const svg = el("svg", { class: "chart-svg", width, height, viewBox: `0 0 ${width} ${height}` });

    for (let i = 0; i <= 4; i++) {
      const gy = padT + chartH - (chartH * i) / 4;
      svg.appendChild(el("line", { class: "grid-line", x1: padL, x2: width - padR, y1: gy, y2: gy }));
      const t = el("text", { x: padL - 8, y: gy + 3, "text-anchor": "end" });
      t.textContent = formatNum(Math.round((niceMax * i) / 4));
      svg.appendChild(t);
    }
    svg.appendChild(el("line", { class: "axis-line", x1: padL, x2: width - padR, y1: padT + chartH, y2: padT + chartH }));

    const n = rows.length;
    const slot = chartW / n;
    const barW = Math.min(Math.max(slot - 4, 3), 26);

    const labelEvery = Math.max(1, Math.ceil(n / 8));

    rows.forEach((row, i) => {
      const x = padL + i * slot + (slot - barW) / 2;
      let yCursor = padT + chartH;
      const segRows = [];
      seriesDefs.forEach((s) => {
        const v = row[s.key] || 0;
        if (v <= 0) return;
        const h = (v / niceMax) * chartH;
        const y = yCursor - h;
        const rect = el("rect", {
          class: "bar-mark", x, y: y, width: barW, height: Math.max(h - 1, 0),
          fill: s.color,
        });
        svg.appendChild(rect);
        yCursor = y - 1;
        segRows.push({ label: s.label, value: v.toLocaleString(), color: s.color });
      });

      const hit = el("rect", { x: padL + i * slot, y: padT, width: slot, height: chartH, fill: "transparent", class: "bar-mark" });
      hit.addEventListener("mousemove", (e) => {
        if (segRows.length) showTooltip(e.clientX, e.clientY, row.date, segRows.slice().reverse());
      });
      hit.addEventListener("mouseleave", hideTooltip);
      svg.appendChild(hit);

      if (i % labelEvery === 0) {
        const t = el("text", { x: x + barW / 2, y: height - 6, "text-anchor": "middle" });
        t.textContent = row.date.slice(5);
        svg.appendChild(t);
      }
    });

    container.appendChild(svg);
  }

  // ---- Event timeline: discrete events plotted on a real time axis ----
  // ---- Event timeline: zoomable, with labels that never overlap ---------------
  // Events are drawn on a real time axis. Drag to zoom into a burst, shift+drag to
  // pan, ctrl/cmd+wheel to zoom about the cursor; the strip underneath shows the
  // whole range and the window you are looking at. Labels are packed into lanes by
  // their measured width, so two labels can never sit on top of each other - one
  // that does not fit is dropped (its dot stays, and hovering lists it).

  const TL_LANES = [1, -1, 2, -2, 3, -3, 4, -4];   // >0 above the axis, <0 below
  const TL_MIN_SPAN = 1;                            // seconds: deepest zoom
  const TL_STEPS = [1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200,
                    10800, 21600, 43200, 86400, 172800, 604800];

  let measureCtx = null;
  function textWidth(text) {
    if (!measureCtx) measureCtx = document.createElement("canvas").getContext("2d");
    measureCtx.font = "10.5px system-ui, sans-serif";
    return measureCtx.measureText(text).width;
  }

  function niceTicks(lo, hi, maxTicks) {
    const span = hi - lo;
    let step = TL_STEPS[TL_STEPS.length - 1];
    for (const s of TL_STEPS) { if (span / s <= maxTicks) { step = s; break; } }
    const ticks = [];
    if (step >= 86400) {
      const days = Math.round(step / 86400);
      const d = new Date(lo * 1000);
      d.setHours(0, 0, 0, 0);
      while (d.getTime() / 1000 < lo) d.setDate(d.getDate() + days);
      while (d.getTime() / 1000 <= hi) { ticks.push(d.getTime() / 1000); d.setDate(d.getDate() + days); }
    } else {
      const off = -new Date(lo * 1000).getTimezoneOffset() * 60;   // local seconds ahead of UTC
      for (let t = Math.ceil((lo + off) / step) * step - off; t <= hi; t += step) ticks.push(t);
    }
    return { ticks, step };
  }

  const TL_DAY = { month: "short", day: "numeric" };
  function tlTime(t, withSeconds) {
    return new Date(t * 1000).toLocaleTimeString(undefined, {
      hour: "2-digit", minute: "2-digit", ...(withSeconds ? { second: "2-digit" } : {}), hour12: false,
    });
  }

  function tickLabel(t, step, prevT) {
    const d = new Date(t * 1000);
    const day = d.toLocaleDateString(undefined, TL_DAY);
    if (step >= 86400) return { main: day, sub: "" };
    const newDay = prevT == null || new Date(prevT * 1000).toDateString() !== d.toDateString();
    return { main: tlTime(t, step < 60), sub: newDay ? day : "" };
  }

  function rangeText(lo, hi) {
    const a = new Date(lo * 1000), b = new Date(hi * 1000);
    const secs = hi - lo < 1800;
    if (a.toDateString() === b.toDateString()) {
      return `${a.toLocaleDateString(undefined, TL_DAY)}, ${tlTime(lo, secs)} – ${tlTime(hi, secs)}`;
    }
    return `${a.toLocaleDateString(undefined, TL_DAY)} ${tlTime(lo, secs)} – ${b.toLocaleDateString(undefined, TL_DAY)} ${tlTime(hi, secs)}`;
  }

  function eventTimeline(container, events, opts) {
    container.innerHTML = "";
    opts = opts || {};
    const dated = events
      .filter((e) => typeof e.timestamp === "number" && !isNaN(e.timestamp))
      .sort((a, b) => a.timestamp - b.timestamp);
    if (!dated.length) {
      const empty = document.createElement("div");
      empty.className = "empty-note";
      empty.textContent = "No dated events to plot yet.";
      container.appendChild(empty);
      return;
    }
    const undated = events.length - dated.length;

    const minT = dated[0].timestamp;
    const maxT = dated[dated.length - 1].timestamp;
    const pad = Math.max((maxT - minT) * 0.02, 30);
    const fullLo = minT - pad, fullHi = maxT + pad, fullSpan = fullHi - fullLo;

    const laneUnit = 32, maxLane = 4, padL = 18, padR = 18;
    const plotH = (maxLane * 2 + 1) * laneUnit + 8;
    const baselineY = plotH / 2;
    const height = plotH + 34;

    // ---- view state: null means the whole range ----
    let view = null;
    function clampView(lo, hi) {
      const span = Math.min(Math.max(hi - lo, TL_MIN_SPAN), fullSpan);
      if (span >= fullSpan * 0.995) return null;
      const centre = (lo + hi) / 2;
      lo = centre - span / 2;
      hi = lo + span;
      if (lo < fullLo) { lo = fullLo; hi = lo + span; }
      if (hi > fullHi) { hi = fullHi; lo = hi - span; }
      return { lo, hi };
    }
    if (opts.view && typeof opts.view.lo === "number" && typeof opts.view.hi === "number"
        && opts.view.hi > fullLo && opts.view.lo < fullHi) {
      view = clampView(opts.view.lo, opts.view.hi);
    }
    const cur = () => view || { lo: fullLo, hi: fullHi };

    let raf = 0;
    function setView(lo, hi) {
      view = clampView(lo, hi);
      if (opts.onViewChange) opts.onViewChange(view ? { lo: view.lo, hi: view.hi } : null);
      if (!raf) raf = requestAnimationFrame(() => { raf = 0; draw(); });
    }
    function zoomAt(frac, factor) {                 // factor < 1 zooms in
      const { lo, hi } = cur();
      const t = lo + frac * (hi - lo);
      const span = (hi - lo) * factor;
      setView(t - frac * span, t + (1 - frac) * span);
    }
    function panBy(fraction) {
      const { lo, hi } = cur();
      const d = (hi - lo) * fraction;
      setView(lo + d, hi + d);
    }

    // ---- DOM: toolbar, main chart, overview strip ----
    const toolbar = document.createElement("div");
    toolbar.className = "tl-toolbar";
    const mkBtn = (text, title, fn) => {
      const b = document.createElement("button");
      b.className = "ghost-btn tl-btn";
      b.type = "button";
      b.textContent = text;
      b.title = title;
      b.addEventListener("click", fn);
      toolbar.appendChild(b);
      return b;
    };
    const btnOut = mkBtn("−", "Zoom out", () => zoomAt(0.5, 2));
    const btnIn = mkBtn("+", "Zoom in", () => {
      // Zoom about the centre - unless that would show an empty stretch while events
      // exist elsewhere in view (typical when they cluster at the two ends), in which
      // case aim at the middle event instead so the button never lands on nothing.
      const { lo, hi } = cur();
      const half = (hi - lo) / 4;
      const centre = (lo + hi) / 2;
      let a = centre - half, b = centre + half;
      const inView = dated.filter((e) => e.timestamp >= lo && e.timestamp <= hi);
      if (inView.length && !dated.some((e) => e.timestamp >= a && e.timestamp <= b)) {
        const m = inView[Math.floor(inView.length / 2)].timestamp;
        a = m - half; b = m + half;
      }
      setView(a, b);
    });
    const btnLeft = mkBtn("◀", "Pan earlier", () => panBy(-0.5));
    const btnRight = mkBtn("▶", "Pan later", () => panBy(0.5));
    const btnReset = mkBtn("Reset", "Show the whole range", () => setView(fullLo, fullHi));
    const readout = document.createElement("span");
    readout.className = "tl-readout";
    toolbar.appendChild(readout);
    container.appendChild(toolbar);

    const mount = document.createElement("div");
    mount.className = "tl-main";
    container.appendChild(mount);

    const hint = document.createElement("div");
    hint.className = "tl-hint";
    hint.textContent = "Drag to zoom · Shift+drag to pan · Ctrl+wheel to zoom · double-click to zoom in (Shift to zoom out) · or use the strip below";
    container.appendChild(hint);

    const ovWrap = document.createElement("div");
    ovWrap.className = "tl-overview";
    container.appendChild(ovWrap);

    let geom = { width: 800, chartW: 764 };

    // ---- main chart ----
    function draw() {
      hideTooltip();
      const { lo, hi } = cur();
      const span = hi - lo;
      const width = Math.max(mount.clientWidth || container.clientWidth || 800, 320);
      const chartW = width - padL - padR;
      geom = { width, chartW };
      const xOf = (t) => padL + ((t - lo) / span) * chartW;

      const svg = el("svg", { class: "chart-svg", width, height, viewBox: `0 0 ${width} ${height}` });
      const { ticks, step } = niceTicks(lo, hi, Math.max(2, Math.floor(chartW / 96)));
      ticks.forEach((t, i) => {
        const x = xOf(t);
        svg.appendChild(el("line", { class: "grid-line", x1: x, x2: x, y1: 4, y2: plotH, opacity: 0.45 }));
        const lab = tickLabel(t, step, i === 0 ? null : ticks[i - 1]);
        const main = el("text", { class: "tl-tick", x, y: plotH + 14, "text-anchor": "middle" });
        main.textContent = lab.main;
        svg.appendChild(main);
        if (lab.sub) {
          const sub = el("text", { class: "tl-tick tl-tick-sub", x, y: plotH + 27, "text-anchor": "middle" });
          sub.textContent = lab.sub;
          svg.appendChild(sub);
        }
      });
      svg.appendChild(el("line", { class: "axis-line", x1: padL, x2: width - padR, y1: baselineY, y2: baselineY }));

      const visible = dated.filter((e) => e.timestamp >= lo && e.timestamp <= hi);
      if (!visible.length) {
        const none = el("text", { class: "tl-empty", x: width / 2, y: baselineY - 40, "text-anchor": "middle" });
        none.textContent = "No events in this window — use ◀ ▶, the strip below, or Reset";
        svg.appendChild(none);
      }

      // Pack labels into lanes left to right. Labels are centred on their dot but kept
      // inside the chart, and a lane is only reused once its last label has ended.
      const rightEdge = {};
      TL_LANES.forEach((l) => { rightEdge[l] = -Infinity; });
      const gap = 8;
      const clip = (s, n) => (s.length > n ? s.slice(0, n - 1) + "…" : s);
      const placed = [];
      let hidden = 0;
      visible.forEach((ev) => {
        const x = xOf(ev.timestamp);
        const label = ev.label || "";
        let pick = null;
        for (const text of [clip(label, 44), clip(label, 22)]) {
          const w = textWidth(text);
          const x0 = Math.min(Math.max(x - w / 2, 4), width - 4 - w);
          const lane = TL_LANES.find((l) => rightEdge[l] + gap <= x0);
          if (lane !== undefined) { pick = { lane, text, x0, w }; break; }
        }
        if (pick) rightEdge[pick.lane] = pick.x0 + pick.w; else hidden++;
        placed.push({ ev, x, pick });
      });

      placed.forEach(({ ev, x, pick }) => {
        if (!pick) return;
        const color = ev.color || css("--series-1");
        const labelY = baselineY - pick.lane * laneUnit;
        svg.appendChild(el("line", {
          x1: x, y1: baselineY, x2: x, y2: labelY + (pick.lane > 0 ? 9 : -9),
          stroke: color, "stroke-width": 1, opacity: 0.55,
        }));
        const text = el("text", { class: "tl-label", x: pick.x0, y: labelY + (pick.lane > 0 ? 4 : -4), "text-anchor": "start" });
        text.textContent = pick.text;
        svg.appendChild(text);
      });

      const dots = [];
      placed.forEach(({ ev, x }) => {
        const color = ev.color || css("--series-1");
        const dot = el("circle", { class: "tl-dot", cx: x, cy: baselineY, r: 5, fill: color });
        svg.appendChild(dot);
        dots.push(dot);
      });
      placed.forEach(({ ev, x }, i) => {
        const color = ev.color || css("--series-1");
        const hit = el("circle", { class: "tl-hit", cx: x, cy: baselineY, r: 12, fill: "transparent" });
        if (ev.onClick) hit.style.cursor = "pointer";
        hit.addEventListener("mousemove", (e) => {
          // Several events can share a pixel; list them all rather than only the top one.
          const near = placed.filter((p) => Math.abs(p.x - x) <= 6);
          if (near.length > 1) {
            showTooltip(e.clientX, e.clientY, `${near.length} events here`,
              near.slice(0, 8).map((p) => ({
                label: tlTime(p.ev.timestamp, true),
                value: clip(p.ev.label || "Event", 46),
                color: p.ev.color || css("--series-1"),
              })).concat(near.length > 8 ? [{ label: "", value: `…and ${near.length - 8} more` }] : []));
          } else {
            const rows = [
              { label: "Time", value: new Date(ev.timestamp * 1000).toLocaleString() },
              { label: "Severity", value: ev.severity || "Unknown", color },
            ];
            if (ev.meta) rows.push({ label: "Source", value: ev.meta });
            showTooltip(e.clientX, e.clientY, ev.label || "Event", rows);
          }
          dots[i].setAttribute("r", 7);
        });
        hit.addEventListener("mouseleave", () => { hideTooltip(); dots[i].setAttribute("r", 5); });
        hit.addEventListener("click", () => { if (ev.onClick) ev.onClick(ev); });
        svg.appendChild(hit);
      });

      mount.innerHTML = "";
      mount.appendChild(svg);

      // ---- toolbar state ----
      const zoomed = !!view;
      btnOut.disabled = btnLeft.disabled = btnRight.disabled = btnReset.disabled = !zoomed;
      btnIn.disabled = span <= TL_MIN_SPAN * 1.01;
      if (zoomed) {
        btnLeft.disabled = lo <= fullLo + 1e-6;
        btnRight.disabled = hi >= fullHi - 1e-6;
      }
      const parts = [`${visible.length} of ${dated.length} events`, rangeText(lo, hi)];
      if (hidden) {
        parts.push(`${hidden} label${hidden === 1 ? "" : "s"} hidden` +
          (span > 5 ? " — zoom in to show them" : " — hover the dots to list them"));
      }
      if (undated) parts.push(`${undated} without a time (not plotted)`);
      readout.textContent = parts.join(" · ");

      drawOverviewWindow();
    }

    // ---- overview strip: all events, plus the window being viewed ----
    const ovH = 38;
    const ovSvg = el("svg", { class: "chart-svg tl-ov-svg", height: ovH });
    ovWrap.appendChild(ovSvg);
    let ovWin = null, ovL = null, ovR = null;
    let ovW = 800, ovChartW = 764;
    const ovX = (t) => padL + ((t - fullLo) / fullSpan) * ovChartW;

    function buildOverview() {
      ovW = Math.max(container.clientWidth || 800, 320);
      ovChartW = ovW - padL - padR;
      ovSvg.setAttribute("width", ovW);
      ovSvg.setAttribute("viewBox", `0 0 ${ovW} ${ovH}`);
      ovSvg.innerHTML = "";
      ovSvg.appendChild(el("rect", { class: "tl-ov-bg", x: padL, y: 6, width: ovChartW, height: ovH - 12, rx: 4 }));
      dated.forEach((ev) => {
        const x = ovX(ev.timestamp);
        ovSvg.appendChild(el("line", {
          x1: x, x2: x, y1: 10, y2: ovH - 10, stroke: ev.color || css("--series-1"),
          "stroke-width": 1.5, opacity: 0.75,
        }));
      });
      ovWin = el("rect", { class: "tl-ov-win", y: 4, height: ovH - 8, rx: 4 });
      ovL = el("rect", { class: "tl-ov-handle", y: 8, width: 5, height: ovH - 16, rx: 2 });
      ovR = el("rect", { class: "tl-ov-handle", y: 8, width: 5, height: ovH - 16, rx: 2 });
      ovSvg.appendChild(ovWin);
      ovSvg.appendChild(ovL);
      ovSvg.appendChild(ovR);
    }

    function drawOverviewWindow() {
      const { lo, hi } = cur();
      const xl = ovX(lo), xr = ovX(hi);
      ovWin.setAttribute("x", xl);
      ovWin.setAttribute("width", Math.max(xr - xl, 2));
      ovL.setAttribute("x", xl - 2);
      ovR.setAttribute("x", xr - 3);
      const show = view ? "" : "none";
      ovL.style.display = show;
      ovR.style.display = show;
      ovWin.classList.toggle("tl-ov-win-full", !view);
    }

    // ---- interactions: main chart ----
    let suppressClick = false;
    const swallowClick = () => { suppressClick = true; setTimeout(() => { suppressClick = false; }, 0); };
    mount.addEventListener("click", (e) => {
      if (suppressClick) { e.stopPropagation(); e.preventDefault(); }
    }, true);

    const svgScale = (svg) => {
      const r = svg.getBoundingClientRect();
      return { r, k: r.width ? geom.width / r.width : 1 };
    };
    const timeAtX = (x, lo, hi) => lo + ((x - padL) / geom.chartW) * (hi - lo);

    mount.addEventListener("pointerdown", (e) => {
      if (e.button !== 0) return;
      const svg = mount.querySelector("svg");
      if (!svg) return;
      const { r, k } = svgScale(svg);
      const start = cur();
      const startClientX = e.clientX;
      const panning = e.shiftKey;
      const clampX = (cx) => Math.min(Math.max((cx - r.left) * k, padL), padL + geom.chartW);
      const x0 = clampX(startClientX);
      let moved = false, brush = null;

      const onMove = (ev) => {
        if (!moved && Math.abs(ev.clientX - startClientX) < 4) return;
        moved = true;
        if (panning) {
          const dt = -((ev.clientX - startClientX) * k / geom.chartW) * (start.hi - start.lo);
          setView(start.lo + dt, start.hi + dt);
          return;
        }
        const live = mount.querySelector("svg");
        if (!live) return;
        if (!brush || !brush.isConnected) {
          brush = el("rect", { class: "tl-brush", y: 0, height: plotH });
          live.appendChild(brush);
        }
        const x1 = clampX(ev.clientX);
        brush.setAttribute("x", Math.min(x0, x1));
        brush.setAttribute("width", Math.abs(x1 - x0));
      };
      const onUp = (ev) => {
        window.removeEventListener("pointermove", onMove);
        window.removeEventListener("pointerup", onUp);
        if (!moved) return;
        swallowClick();
        if (panning) return;
        if (brush) brush.remove();
        const x1 = clampX(ev.clientX);
        if (Math.abs(x1 - x0) > 6) {
          const a = timeAtX(Math.min(x0, x1), start.lo, start.hi);
          const b = timeAtX(Math.max(x0, x1), start.lo, start.hi);
          setView(a, b);
        }
      };
      window.addEventListener("pointermove", onMove);
      window.addEventListener("pointerup", onUp);
    });

    mount.addEventListener("wheel", (e) => {
      if (!(e.ctrlKey || e.metaKey)) return;            // plain wheel keeps scrolling the page
      e.preventDefault();
      const svg = mount.querySelector("svg");
      if (!svg) return;
      const { r, k } = svgScale(svg);
      const frac = Math.min(Math.max(((e.clientX - r.left) * k - padL) / geom.chartW, 0), 1);
      zoomAt(frac, Math.exp(e.deltaY * 0.0025));
    }, { passive: false });

    mount.addEventListener("dblclick", (e) => {
      const svg = mount.querySelector("svg");
      if (!svg) return;
      const { r, k } = svgScale(svg);
      const frac = Math.min(Math.max(((e.clientX - r.left) * k - padL) / geom.chartW, 0), 1);
      zoomAt(frac, e.shiftKey ? 2 : 0.4);
    });

    // ---- interactions: overview strip ----
    const EDGE = 8;
    function ovMode(px) {
      if (!view) return "new";
      const xl = ovX(view.lo), xr = ovX(view.hi);
      if (Math.abs(px - xl) <= EDGE) return "left";
      if (Math.abs(px - xr) <= EDGE) return "right";
      if (px > xl && px < xr) return "move";
      return "new";
    }
    const ovPx = (ev) => {
      const r = ovSvg.getBoundingClientRect();
      return (ev.clientX - r.left) * (r.width ? ovW / r.width : 1);
    };
    ovSvg.addEventListener("pointermove", (e) => {
      const m = ovMode(ovPx(e));
      ovSvg.style.cursor = m === "left" || m === "right" ? "ew-resize" : m === "move" ? "grab" : "crosshair";
    });
    ovSvg.addEventListener("pointerdown", (e) => {
      if (e.button !== 0) return;
      const px0 = ovPx(e);
      const mode = ovMode(px0);
      const start = cur();
      const t0 = fullLo + ((px0 - padL) / ovChartW) * fullSpan;
      let moved = false;
      const onMove = (ev) => {
        const px = ovPx(ev);
        if (!moved && Math.abs(px - px0) < 3) return;
        moved = true;
        const t = fullLo + ((px - padL) / ovChartW) * fullSpan;
        const dt = t - t0;
        if (mode === "move") setView(start.lo + dt, start.hi + dt);
        else if (mode === "left") setView(Math.min(t, start.hi - TL_MIN_SPAN), start.hi);
        else if (mode === "right") setView(start.lo, Math.max(t, start.lo + TL_MIN_SPAN));
        else setView(Math.min(t0, t), Math.max(t0, t));
      };
      const onUp = () => {
        window.removeEventListener("pointermove", onMove);
        window.removeEventListener("pointerup", onUp);
        if (!moved && mode === "new" && view) {           // a plain click recentres the window
          const half = (view.hi - view.lo) / 2;
          setView(t0 - half, t0 + half);
        }
      };
      window.addEventListener("pointermove", onMove);
      window.addEventListener("pointerup", onUp);
    });

    buildOverview();
    draw();
  }

  // ---- Vertical (narrative) timeline: chronological list, oldest first ----
  function verticalTimeline(container, events) {
    container.innerHTML = "";
    const dated = events.filter((e) => typeof e.timestamp === "number" && !isNaN(e.timestamp));
    if (!dated.length) {
      const empty = document.createElement("div");
      empty.className = "empty-note";
      empty.textContent = "No dated events to plot yet.";
      container.appendChild(empty);
      return;
    }
    const sorted = dated.slice().sort((a, b) => a.timestamp - b.timestamp);

    const wrap = document.createElement("div");
    wrap.className = "vtimeline";

    sorted.forEach((ev) => {
      const item = document.createElement("div");
      item.className = "vtimeline-item";

      const dot = document.createElement("div");
      dot.className = "vtimeline-dot";
      dot.style.background = ev.color || css("--series-1");
      item.appendChild(dot);

      const content = document.createElement("div");
      content.className = "vtimeline-content";
      if (ev.onClick) {
        content.style.cursor = "pointer";
        content.addEventListener("click", () => ev.onClick(ev));
      }

      const head = document.createElement("div");
      head.className = "vtimeline-head";
      const timeEl = document.createElement("span");
      timeEl.className = "vtimeline-time";
      timeEl.textContent = new Date(ev.timestamp * 1000).toLocaleString();
      head.appendChild(timeEl);
      if (ev.severity) {
        const badge = document.createElement("span");
        badge.className = "sev-badge sev-" + ev.severity.toLowerCase();
        badge.textContent = ev.severity;
        head.appendChild(badge);
      }
      content.appendChild(head);

      const desc = document.createElement("div");
      desc.className = "vtimeline-desc";
      desc.textContent = ev.label || "";
      content.appendChild(desc);

      if (ev.meta) {
        const meta = document.createElement("div");
        meta.className = "vtimeline-meta";
        meta.textContent = ev.meta;
        content.appendChild(meta);
      }

      item.appendChild(content);
      wrap.appendChild(item);
    });

    container.appendChild(wrap);
  }

  return { horizontalBar, donut, stackedTimeline, eventTimeline, verticalTimeline, buildLegend, showTooltip, hideTooltip, formatNum };
})();
