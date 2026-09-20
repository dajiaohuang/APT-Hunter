(() => {
  const state = {
    meta: null,
    sheetsByName: {},
    view: "dashboard",
    currentSheet: null,
    dashboardData: null,
    sheetState: {}, // per-sheet: {page,pageSize,sort,dir,q,severity:Set,computer,start,end,advFilters,visibleColumns}
    openPopover: null, // { el, close } — el is checked so clicks inside the popover don't close it
    wrapText: localStorage.getItem("aptdash-wrap-text") === "1",
  };

  const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"];
  const SEVERITY_COLOR_VAR = {
    Critical: "--status-critical",
    High: "--status-serious",
    Medium: "--status-warning",
    Low: "--status-good",
  };
  const FILTER_OPS = [
    { value: "eq", label: "is" },
    { value: "neq", label: "is not" },
    { value: "contains", label: "contains" },
    { value: "ncontains", label: "does not contain" },
  ];

  function cssVar(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  function severityClass(sev) {
    const key = (sev || "").toLowerCase();
    if (["critical", "high", "medium", "low"].includes(key)) return "sev-" + key;
    return "sev-unknown";
  }

  async function fetchJSON(url, opts) {
    const res = await fetch(url, opts);
    if (!res.ok) {
      let detail = "";
      try {
        const body = await res.json();
        detail = body && body.error ? body.error : "";
      } catch (e) { /* body wasn't JSON — fall back to generic message */ }
      throw new Error(detail || `Request failed: ${url}`);
    }
    if (res.status === 204) return null;
    return res.json();
  }

  function closeOpenPopover() {
    if (state.openPopover) {
      state.openPopover.close();
      state.openPopover = null;
    }
  }

  // ---------------- Theme ----------------
  function initTheme() {
    const saved = localStorage.getItem("aptdash-theme");
    if (saved) document.documentElement.setAttribute("data-theme", saved);
    updateThemeButton();
    document.getElementById("theme-toggle").addEventListener("click", () => {
      const current = document.documentElement.getAttribute("data-theme")
        || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
      const next = current === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      localStorage.setItem("aptdash-theme", next);
      updateThemeButton();
      if (state.view === "dashboard" && state.dashboardData) renderDashboard(state.dashboardData);
      if (state.view === "incidents") selectIncidents();
    });
  }

  function updateThemeButton() {
    const current = document.documentElement.getAttribute("data-theme")
      || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    document.getElementById("theme-icon").textContent = current === "dark" ? "☾" : "☀";
    document.getElementById("theme-label").textContent = current === "dark" ? "Dark" : "Light";
  }

  // ---------------- Sidebar / navigation ----------------
  function buildSidebar() {
    const eventsGroup = document.getElementById("nav-events");
    const summaryGroup = document.getElementById("nav-summaries");
    eventsGroup.querySelectorAll(".nav-item").forEach((n) => n.remove());
    summaryGroup.querySelectorAll(".nav-item").forEach((n) => n.remove());

    state.meta.sheets.forEach((sheet) => {
      const btn = document.createElement("button");
      btn.className = "nav-item";
      btn.dataset.sheet = sheet.name;
      const icon = document.createElement("span");
      icon.className = "nav-icon";
      icon.textContent = sheet.kind === "event" ? "☷" : "≡";
      btn.appendChild(icon);
      const label = document.createElement("span");
      label.textContent = sheet.name.replace(/ Events$/, "");
      btn.appendChild(label);
      const count = document.createElement("span");
      count.className = "count";
      count.textContent = Charts.formatNum(sheet.row_count);
      btn.appendChild(count);
      btn.addEventListener("click", () => selectSheet(sheet.name));
      (sheet.kind === "event" ? eventsGroup : summaryGroup).appendChild(btn);
    });

    document.querySelector('.nav-item[data-view="dashboard"]').addEventListener("click", selectDashboard);
    document.querySelector('.nav-item[data-view="incidents"]').addEventListener("click", selectIncidents);
    document.querySelector('.nav-item[data-view="triage"]').addEventListener("click", selectTriage);
    document.querySelector('.nav-item[data-view="settings"]').addEventListener("click", selectSettings);
  }

  function setActiveNav(sheetName, view) {
    document.querySelectorAll(".nav-item").forEach((n) => n.classList.remove("active"));
    if (view === "incidents") {
      document.querySelector('.nav-item[data-view="incidents"]').classList.add("active");
    } else if (view === "triage") {
      document.querySelector('.nav-item[data-view="triage"]').classList.add("active");
    } else if (view === "settings") {
      document.querySelector('.nav-item[data-view="settings"]').classList.add("active");
    } else if (!sheetName) {
      document.querySelector('.nav-item[data-view="dashboard"]').classList.add("active");
    } else {
      const btn = document.querySelector(`.nav-item[data-sheet="${CSS.escape(sheetName)}"]`);
      if (btn) btn.classList.add("active");
    }
  }

  function showView(name) {
    document.getElementById("view-dashboard").style.display = name === "dashboard" ? "" : "none";
    document.getElementById("view-sheet").style.display = name === "sheet" ? "" : "none";
    document.getElementById("view-incidents").style.display = name === "incidents" ? "" : "none";
    document.getElementById("view-triage").style.display = name === "triage" ? "" : "none";
    document.getElementById("view-settings").style.display = name === "settings" ? "" : "none";
  }

  // ---------------- Dashboard ----------------
  async function selectDashboard() {
    closeOpenPopover();
    state.view = "dashboard";
    state.currentSheet = null;
    setActiveNav(null, "dashboard");
    showView("dashboard");
    document.getElementById("report-title").textContent = "Dashboard";
    document.getElementById("report-meta").textContent = metaSubtitle();
    const data = await fetchJSON("/api/dashboard");
    state.dashboardData = data;
    renderDashboard(data);
  }

  function metaSubtitle() {
    if (!state.meta) return "";
    const dt = new Date(state.meta.generated_at * 1000);
    return `${state.meta.report_name} • ${state.meta.total_events.toLocaleString()} events • built ${dt.toLocaleString()}`;
  }

  function severitySegments(counts) {
    return SEVERITY_ORDER.filter((s) => counts[s]).map((s) => ({
      label: s, value: counts[s] || 0, color: cssVar(SEVERITY_COLOR_VAR[s]),
    }));
  }

  function renderDashboard(data) {
    const root = document.getElementById("view-dashboard");
    root.innerHTML = "";

    const kpiRow = document.createElement("div");
    kpiRow.className = "kpi-row";
    const total = Object.values(data.severity_counts).reduce((a, b) => a + b, 0);
    const kpis = [
      { label: "Total events", value: total, colorVar: null },
      ...SEVERITY_ORDER.map((s) => ({ label: s, value: data.severity_counts[s] || 0, colorVar: SEVERITY_COLOR_VAR[s] })),
    ];
    kpis.forEach((k) => {
      const card = document.createElement("div");
      card.className = "card kpi-card";
      const lbl = document.createElement("div");
      lbl.className = "kpi-label";
      if (k.colorVar) {
        const dot = document.createElement("span");
        dot.className = "kpi-dot";
        dot.style.background = cssVar(k.colorVar);
        lbl.appendChild(dot);
      }
      lbl.appendChild(document.createTextNode(k.label));
      const val = document.createElement("div");
      val.className = "kpi-value";
      val.textContent = k.value.toLocaleString();
      card.appendChild(lbl);
      card.appendChild(val);
      kpiRow.appendChild(card);
    });
    root.appendChild(kpiRow);

    const row1 = document.createElement("div");
    row1.className = "charts-row";

    const donutCard = document.createElement("div");
    donutCard.className = "card";
    donutCard.innerHTML = `<div class="card-title">Severity breakdown</div>
      <div class="card-subtitle">Share of all detections by severity</div>`;
    const donutMount = document.createElement("div");
    donutCard.appendChild(donutMount);
    row1.appendChild(donutCard);

    const detCard = document.createElement("div");
    detCard.className = "card";
    detCard.innerHTML = `<div class="card-title">Top detection rules</div>
      <div class="card-subtitle">Most frequently triggered rules across the report</div>`;
    const detMount = document.createElement("div");
    detCard.appendChild(detMount);
    row1.appendChild(detCard);

    root.appendChild(row1);
    Charts.donut(donutMount, severitySegments(data.severity_counts));
    Charts.horizontalBar(detMount, data.top_detections, { color: cssVar("--series-1") });

    const timelineCard = document.createElement("div");
    timelineCard.className = "card";
    timelineCard.innerHTML = `<div class="card-title">Events over time</div>
      <div class="card-subtitle">Daily volume, stacked by severity</div>`;
    const timelineMount = document.createElement("div");
    timelineCard.appendChild(timelineMount);
    root.appendChild(timelineCard);
    const seriesDefs = SEVERITY_ORDER.map((s) => ({ key: s, label: s, color: cssVar(SEVERITY_COLOR_VAR[s]) }));
    Charts.stackedTimeline(timelineMount, data.timeline, seriesDefs);
    const legendWrap = document.createElement("div");
    Charts.buildLegend(legendWrap, seriesDefs.map((s) => ({ label: s.label, color: s.color })));
    timelineCard.appendChild(legendWrap);

    const row2 = document.createElement("div");
    row2.className = "charts-row thirds";
    const compCard = document.createElement("div");
    compCard.className = "card";
    compCard.innerHTML = `<div class="card-title">Top computers</div>
      <div class="card-subtitle">Hosts generating the most detections</div>`;
    const compMount = document.createElement("div");
    compCard.appendChild(compMount);
    row2.appendChild(compCard);

    const eidCard = document.createElement("div");
    eidCard.className = "card";
    eidCard.innerHTML = `<div class="card-title">Top event IDs</div>
      <div class="card-subtitle">Most common source event IDs</div>`;
    const eidMount = document.createElement("div");
    eidCard.appendChild(eidMount);
    row2.appendChild(eidCard);
    root.appendChild(row2);
    Charts.horizontalBar(compMount, data.top_computers, { color: cssVar("--series-5") });
    Charts.horizontalBar(eidMount, data.top_event_ids, { color: cssVar("--series-7") });

    const highlightsRow = document.createElement("div");
    highlightsRow.className = "highlights-row";
    const highlightDefs = [
      { key: "top_processes", title: "Top executed processes", sheet: "Executed Process Summary" },
      { key: "top_powershell", title: "Top PowerShell commands", sheet: "Executed Powershell Summary" },
      { key: "top_failed_logins", title: "Top failed logins", sheet: "Security Authentication Summary" },
      { key: "top_rdp_logons", title: "Top RDP / terminal logons", sheet: "Terminal Services Logon Summary" },
    ];
    highlightDefs.forEach((h) => {
      const card = document.createElement("div");
      card.className = "card";
      const title = document.createElement("div");
      title.className = "card-title";
      title.textContent = h.title;
      card.appendChild(title);
      const items = (data.highlights && data.highlights[h.key]) || [];
      if (!items.length) {
        const empty = document.createElement("div");
        empty.className = "empty-note";
        empty.textContent = "No data available.";
        card.appendChild(empty);
      } else {
        const table = document.createElement("table");
        table.className = "mini-table";
        items.forEach((it) => {
          const tr = document.createElement("tr");
          const tdLabel = document.createElement("td");
          tdLabel.className = "mt-label";
          tdLabel.title = it.label;
          tdLabel.textContent = it.label;
          const tdVal = document.createElement("td");
          tdVal.className = "mt-val";
          tdVal.textContent = Math.round(it.value).toLocaleString();
          tr.appendChild(tdLabel);
          tr.appendChild(tdVal);
          table.appendChild(tr);
        });
        card.appendChild(table);
      }
      if (state.sheetsByName[h.sheet]) {
        const link = document.createElement("div");
        link.style.marginTop = "10px";
        const a = document.createElement("button");
        a.className = "ghost-btn";
        a.style.fontSize = "11.5px";
        a.textContent = "View full table →";
        a.addEventListener("click", () => selectSheet(h.sheet));
        link.appendChild(a);
        card.appendChild(link);
      }
      highlightsRow.appendChild(card);
    });
    root.appendChild(highlightsRow);
  }

  // ---------------- Column visibility (persisted) ----------------
  function columnStorageKey(sheetName) {
    return `aptdash-cols::${sheetName}`;
  }

  function availableColumns(sheet) {
    return sheet.columns.filter((c) => c !== "Original Event Log" && c !== "timestamp");
  }

  function loadVisibleColumns(sheet) {
    const all = availableColumns(sheet);
    try {
      const saved = JSON.parse(localStorage.getItem(columnStorageKey(sheet.name)));
      if (Array.isArray(saved) && saved.length) {
        const filtered = saved.filter((c) => all.includes(c));
        if (filtered.length) return new Set(filtered);
      }
    } catch (e) { /* ignore malformed storage */ }
    return new Set(all);
  }

  function saveVisibleColumns(sheetName, colSet) {
    localStorage.setItem(columnStorageKey(sheetName), JSON.stringify([...colSet]));
  }

  // ---------------- Sheet view ----------------
  function defaultSheetState(sheet) {
    return {
      page: 1,
      pageSize: 50,
      sort: sheet.columns.includes("timestamp") ? "Date and Time" : "_id",
      dir: "desc",
      q: "",
      severity: new Set(),
      computer: "",
      start: "",
      end: "",
      advFilters: [],
      visibleColumns: loadVisibleColumns(sheet),
      selectedRows: new Set(),
    };
  }

  async function selectSheet(name) {
    closeOpenPopover();
    const sheet = state.sheetsByName[name];
    if (!sheet) return;
    state.view = "sheet";
    state.currentSheet = name;
    setActiveNav(name);
    showView("sheet");
    document.getElementById("report-title").textContent = sheet.name;
    document.getElementById("report-meta").textContent = metaSubtitle();

    if (!state.sheetState[name]) state.sheetState[name] = defaultSheetState(sheet);

    renderSheetShell(sheet);
    await loadSheetRows(sheet);
  }

  function renderSheetShell(sheet) {
    const root = document.getElementById("view-sheet");
    root.innerHTML = "";

    const header = document.createElement("div");
    header.className = "sheet-header";
    header.innerHTML = `<h2>${escapeHtmlText(sheet.name)}</h2>`;
    const countEl = document.createElement("div");
    countEl.className = "sheet-count";
    countEl.id = "sheet-total-count";
    header.appendChild(countEl);
    root.appendChild(header);

    const bar = document.createElement("div");
    bar.className = "filter-bar";

    const search = document.createElement("input");
    search.type = "text";
    search.placeholder = "Search this table…";
    search.id = "flt-search";
    search.value = state.sheetState[sheet.name].q;
    bar.appendChild(search);

    if (sheet.columns.includes("Severity")) {
      const chipWrap = document.createElement("div");
      chipWrap.className = "severity-check";
      chipWrap.id = "flt-severity";
      SEVERITY_ORDER.forEach((s) => {
        const chip = document.createElement("span");
        chip.className = "sev-chip";
        chip.dataset.sev = s;
        chip.dataset.active = state.sheetState[sheet.name].severity.has(s) ? "true" : "false";
        chip.textContent = s;
        chip.addEventListener("click", () => {
          const st = state.sheetState[sheet.name];
          if (st.severity.has(s)) st.severity.delete(s); else st.severity.add(s);
          chip.dataset.active = st.severity.has(s) ? "true" : "false";
          st.page = 1;
          loadSheetRows(sheet);
        });
        chipWrap.appendChild(chip);
      });
      bar.appendChild(chipWrap);
    }

    if (sheet.columns.includes("Computer Name")) {
      const sel = document.createElement("select");
      sel.id = "flt-computer";
      sel.innerHTML = '<option value="">All computers</option>';
      bar.appendChild(sel);
    }

    if (sheet.columns.includes("timestamp")) {
      const start = document.createElement("input");
      start.type = "datetime-local";
      start.id = "flt-start";
      start.title = "From";
      bar.appendChild(start);
      const end = document.createElement("input");
      end.type = "datetime-local";
      end.id = "flt-end";
      end.title = "To";
      bar.appendChild(end);
    }

    const spacer = document.createElement("div");
    spacer.className = "spacer";
    bar.appendChild(spacer);

    bar.appendChild(buildColumnChooser(sheet));

    const wrapBtn = document.createElement("button");
    wrapBtn.className = "ghost-btn" + (state.wrapText ? " active" : "");
    wrapBtn.textContent = state.wrapText ? "↕ Wrap: On" : "↕ Wrap text";
    wrapBtn.title = "Wrap long cell text across multiple lines instead of truncating it";
    wrapBtn.addEventListener("click", () => {
      state.wrapText = !state.wrapText;
      localStorage.setItem("aptdash-wrap-text", state.wrapText ? "1" : "0");
      wrapBtn.classList.toggle("active", state.wrapText);
      wrapBtn.textContent = state.wrapText ? "↕ Wrap: On" : "↕ Wrap text";
      renderTableFromCache(sheet);
    });
    bar.appendChild(wrapBtn);

    const exportBtn = document.createElement("button");
    exportBtn.className = "ghost-btn";
    exportBtn.textContent = "⤓ Export CSV";
    exportBtn.addEventListener("click", () => exportCsv(sheet));
    bar.appendChild(exportBtn);

    root.appendChild(bar);
    root.appendChild(buildAdvancedFilters(sheet));

    if (sheet.kind === "event") {
      const selectionBar = document.createElement("div");
      selectionBar.className = "selection-bar";
      selectionBar.id = "selection-bar";
      const selCount = document.createElement("span");
      selCount.className = "sel-count";
      selectionBar.appendChild(selCount);
      const spacer = document.createElement("div");
      spacer.className = "spacer";
      selectionBar.appendChild(spacer);
      const correlateBtn = document.createElement("button");
      correlateBtn.className = "btn-primary";
      correlateBtn.textContent = "🔗 Correlate with LLM";
      correlateBtn.addEventListener("click", () => runCorrelation(sheet, correlateBtn));
      selectionBar.appendChild(correlateBtn);
      const clearBtn = document.createElement("button");
      clearBtn.className = "ghost-btn";
      clearBtn.textContent = "Clear selection";
      clearBtn.addEventListener("click", () => {
        state.sheetState[sheet.name].selectedRows.clear();
        updateSelectionBar(sheet);
        renderTableFromCache(sheet);
      });
      selectionBar.appendChild(clearBtn);
      root.appendChild(selectionBar);
    }

    const tableWrap = document.createElement("div");
    tableWrap.className = "table-wrap";
    tableWrap.innerHTML = '<table class="data-grid"><thead></thead><tbody><tr class="loading-row"><td>Loading…</td></tr></tbody></table>';
    tableWrap.id = "table-wrap";
    root.appendChild(tableWrap);

    const pagination = document.createElement("div");
    pagination.className = "pagination";
    pagination.id = "pagination";
    root.appendChild(pagination);

    let searchTimer = null;
    search.addEventListener("input", () => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(() => {
        state.sheetState[sheet.name].q = search.value;
        state.sheetState[sheet.name].page = 1;
        loadSheetRows(sheet);
      }, 300);
    });

    const computerSel = document.getElementById("flt-computer");
    if (computerSel) {
      computerSel.addEventListener("change", () => {
        state.sheetState[sheet.name].computer = computerSel.value;
        state.sheetState[sheet.name].page = 1;
        loadSheetRows(sheet);
      });
    }
    const startInput = document.getElementById("flt-start");
    const endInput = document.getElementById("flt-end");
    if (startInput) {
      startInput.addEventListener("change", () => {
        state.sheetState[sheet.name].start = startInput.value;
        state.sheetState[sheet.name].page = 1;
        loadSheetRows(sheet);
      });
      endInput.addEventListener("change", () => {
        state.sheetState[sheet.name].end = endInput.value;
        state.sheetState[sheet.name].page = 1;
        loadSheetRows(sheet);
      });
    }
  }

  // ---- Column chooser dropdown ----
  function buildColumnChooser(sheet) {
    const wrap = document.createElement("div");
    wrap.className = "dropdown-wrap";
    const btn = document.createElement("button");
    btn.className = "ghost-btn";
    btn.textContent = "☰ Columns";
    wrap.appendChild(btn);

    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      if (wrap.querySelector(".dropdown-panel")) { closeOpenPopover(); return; }
      closeOpenPopover();
      const panel = document.createElement("div");
      panel.className = "dropdown-panel";
      const head = document.createElement("div");
      head.className = "dropdown-panel-header";
      const headLabel = document.createElement("span");
      headLabel.textContent = "Visible columns";
      head.appendChild(headLabel);
      const resetBtn = document.createElement("button");
      resetBtn.textContent = "Show all";
      resetBtn.addEventListener("click", () => {
        state.sheetState[sheet.name].visibleColumns = new Set(availableColumns(sheet));
        saveVisibleColumns(sheet.name, state.sheetState[sheet.name].visibleColumns);
        loadSheetRows(sheet);
        closeOpenPopover();
      });
      head.appendChild(resetBtn);
      panel.appendChild(head);

      availableColumns(sheet).forEach((col) => {
        const item = document.createElement("label");
        item.className = "col-chooser-item";
        const cb = document.createElement("input");
        cb.type = "checkbox";
        cb.checked = state.sheetState[sheet.name].visibleColumns.has(col);
        cb.addEventListener("change", () => {
          const st = state.sheetState[sheet.name];
          if (cb.checked) st.visibleColumns.add(col); else st.visibleColumns.delete(col);
          saveVisibleColumns(sheet.name, st.visibleColumns);
          renderTableFromCache(sheet);
        });
        item.appendChild(cb);
        const text = document.createElement("span");
        text.textContent = col;
        item.appendChild(text);
        panel.appendChild(item);
      });

      wrap.appendChild(panel);
      state.openPopover = { el: panel, close: () => panel.remove() };
    });

    return wrap;
  }

  // ---- Advanced filters (multi-condition, negate) ----
  function buildAdvancedFilters(sheet) {
    const container = document.createElement("div");
    container.className = "adv-filters";
    container.id = "adv-filters";
    renderAdvancedFilterRows(sheet, container);
    return container;
  }

  function renderAdvancedFilterRows(sheet, container) {
    container.innerHTML = "";
    const st = state.sheetState[sheet.name];
    const cols = availableColumns(sheet);

    st.advFilters.forEach((clause, idx) => {
      const row = document.createElement("div");
      row.className = "adv-filter-row";

      const colSel = document.createElement("select");
      colSel.className = "af-column";
      cols.forEach((c) => {
        const opt = document.createElement("option");
        opt.value = c;
        opt.textContent = c;
        if (c === clause.column) opt.selected = true;
        colSel.appendChild(opt);
      });
      colSel.addEventListener("change", () => { clause.column = colSel.value; loadSheetRows(sheet); });
      row.appendChild(colSel);

      const opSel = document.createElement("select");
      FILTER_OPS.forEach((o) => {
        const opt = document.createElement("option");
        opt.value = o.value;
        opt.textContent = o.label;
        if (o.value === clause.op) opt.selected = true;
        opSel.appendChild(opt);
      });
      opSel.addEventListener("change", () => { clause.op = opSel.value; loadSheetRows(sheet); });
      row.appendChild(opSel);

      const valInput = document.createElement("input");
      valInput.type = "text";
      valInput.className = "af-value";
      valInput.placeholder = "Value…";
      valInput.value = clause.value || "";
      let valTimer = null;
      valInput.addEventListener("input", () => {
        clearTimeout(valTimer);
        valTimer = setTimeout(() => { clause.value = valInput.value; loadSheetRows(sheet); }, 350);
      });
      row.appendChild(valInput);

      const removeBtn = document.createElement("button");
      removeBtn.className = "af-remove";
      removeBtn.textContent = "×";
      removeBtn.title = "Remove filter";
      removeBtn.addEventListener("click", () => {
        st.advFilters.splice(idx, 1);
        renderAdvancedFilterRows(sheet, container);
        loadSheetRows(sheet);
      });
      row.appendChild(removeBtn);

      container.appendChild(row);
    });

    const addBtn = document.createElement("button");
    addBtn.className = "ghost-btn";
    addBtn.style.alignSelf = "flex-start";
    addBtn.textContent = "+ Add filter";
    addBtn.addEventListener("click", () => {
      st.advFilters.push({ column: cols[0], op: "eq", value: "" });
      renderAdvancedFilterRows(sheet, container);
    });
    container.appendChild(addBtn);
  }

  function escapeHtmlText(s) {
    const d = document.createElement("div");
    d.textContent = s;
    return d.innerHTML;
  }

  function buildQuery(sheet) {
    const st = state.sheetState[sheet.name];
    const params = new URLSearchParams();
    params.set("page", st.page);
    params.set("page_size", st.pageSize);
    params.set("sort", st.sort === "Date and Time" ? "timestamp" : st.sort);
    params.set("dir", st.dir);
    if (st.q) params.set("q", st.q);
    st.severity.forEach((s) => params.append("severity", s));
    if (st.computer) params.set("computer", st.computer);
    if (st.start) params.set("start", String(new Date(st.start).getTime() / 1000));
    if (st.end) params.set("end", String(new Date(st.end).getTime() / 1000));
    const validFilters = st.advFilters.filter((f) => f.column && f.value !== "" && f.value !== undefined);
    if (validFilters.length) params.set("filters", JSON.stringify(validFilters));
    return params;
  }

  let lastRowsData = null;

  async function loadSheetRows(sheet) {
    const params = buildQuery(sheet);
    const data = await fetchJSON(`/api/sheets/${encodeURIComponent(sheet.name)}/rows?${params.toString()}`);
    lastRowsData = data;
    renderTableFromCache(sheet);
    renderPagination(sheet, data);
    document.getElementById("sheet-total-count").textContent = `${data.total.toLocaleString()} rows`;

    const computerSel = document.getElementById("flt-computer");
    if (computerSel && data.filters.computer_options && computerSel.options.length <= 1) {
      const st = state.sheetState[sheet.name];
      data.filters.computer_options.forEach((c) => {
        const opt = document.createElement("option");
        opt.value = c;
        opt.textContent = c;
        computerSel.appendChild(opt);
      });
      computerSel.value = st.computer || "";
    }
  }

  function renderTableFromCache(sheet) {
    if (lastRowsData) renderTable(sheet, lastRowsData);
  }

  function renderTable(sheet, data) {
    const wrap = document.getElementById("table-wrap");
    const st = state.sheetState[sheet.name];
    const visibleCols = data.columns.filter((c) => st.visibleColumns.has(c));
    const table = document.createElement("table");
    table.className = "data-grid" + (state.wrapText ? " wrap-cells" : "");
    const thead = document.createElement("thead");
    const headRow = document.createElement("tr");
    if (sheet.kind === "event") {
      const selectTh = document.createElement("th");
      selectTh.className = "col-select";
      const selectAllCb = document.createElement("input");
      selectAllCb.type = "checkbox";
      const pageIds = data.rows.map((r) => r._id);
      const allSelected = pageIds.length > 0 && pageIds.every((id) => st.selectedRows.has(id));
      const someSelected = pageIds.some((id) => st.selectedRows.has(id));
      selectAllCb.checked = allSelected;
      selectAllCb.indeterminate = !allSelected && someSelected;
      selectAllCb.title = "Select all rows on this page";
      selectAllCb.addEventListener("change", () => {
        if (selectAllCb.checked) {
          pageIds.forEach((id) => st.selectedRows.add(id));
        } else {
          pageIds.forEach((id) => st.selectedRows.delete(id));
        }
        updateSelectionBar(sheet);
        renderTableFromCache(sheet);
      });
      selectTh.appendChild(selectAllCb);
      headRow.appendChild(selectTh);
    }
    visibleCols.forEach((col) => {
      const th = document.createElement("th");
      const inner = document.createElement("div");
      inner.className = "th-inner";
      const label = document.createElement("span");
      label.textContent = col;
      inner.appendChild(label);
      if (st.sort === col || (col === "Date and Time" && st.sort === "Date and Time")) {
        const arrow = document.createElement("span");
        arrow.className = "sort-arrow";
        arrow.textContent = st.dir === "asc" ? "▲" : "▼";
        inner.appendChild(arrow);
      }
      const toolBtn = document.createElement("button");
      toolBtn.className = "th-tool-btn";
      toolBtn.textContent = "⋯";
      toolBtn.title = "Show unique values";
      toolBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        openDistinctPopover(sheet, col, toolBtn);
      });
      inner.appendChild(toolBtn);
      th.appendChild(inner);
      label.addEventListener("click", () => {
        if (st.sort === col) {
          st.dir = st.dir === "asc" ? "desc" : "asc";
        } else {
          st.sort = col;
          st.dir = "desc";
        }
        st.page = 1;
        loadSheetRows(sheet);
      });
      label.style.cursor = "pointer";
      headRow.appendChild(th);
    });
    if (sheet.kind === "event") {
      const actionsTh = document.createElement("th");
      actionsTh.textContent = "";
      headRow.appendChild(actionsTh);
    }
    thead.appendChild(headRow);
    table.appendChild(thead);

    const tbody = document.createElement("tbody");
    if (!data.rows.length) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = visibleCols.length + (sheet.kind === "event" ? 2 : 0);
      td.style.textAlign = "center";
      td.style.padding = "30px";
      td.style.color = "var(--text-muted)";
      td.textContent = "No matching events.";
      tr.appendChild(td);
      tbody.appendChild(tr);
    }
    data.rows.forEach((row) => {
      const tr = document.createElement("tr");
      if (sheet.kind === "event") {
        const selectTd = document.createElement("td");
        selectTd.className = "col-select";
        const cb = document.createElement("input");
        cb.type = "checkbox";
        cb.checked = st.selectedRows.has(row._id);
        cb.addEventListener("click", (e) => e.stopPropagation());
        cb.addEventListener("change", () => {
          if (cb.checked) st.selectedRows.add(row._id); else st.selectedRows.delete(row._id);
          updateSelectionBar(sheet);
        });
        selectTd.appendChild(cb);
        tr.appendChild(selectTd);
      }
      visibleCols.forEach((col) => {
        const td = document.createElement("td");
        const val = row[col];
        if (col === "Severity") {
          td.className = "col-severity";
          const badge = document.createElement("span");
          badge.className = "sev-badge " + severityClass(val);
          badge.textContent = val || "Unknown";
          td.appendChild(badge);
        } else {
          td.textContent = val === null || val === undefined ? "" : val;
          td.title = val || "";
        }
        tr.appendChild(td);
      });
      if (sheet.kind === "event") {
        const actionsTd = document.createElement("td");
        actionsTd.className = "col-actions";
        const pinBtn = document.createElement("button");
        pinBtn.className = "pin-btn";
        pinBtn.textContent = "+ Pin";
        pinBtn.title = "Add to incident timeline";
        pinBtn.addEventListener("click", (e) => {
          e.stopPropagation();
          addToIncidentTimeline(sheet.name, row._id, pinBtn);
        });
        actionsTd.appendChild(pinBtn);
        tr.appendChild(actionsTd);
      }
      tr.addEventListener("click", () => openRowDetail(sheet, row._id));
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    wrap.innerHTML = "";
    wrap.appendChild(table);
  }

  // ---- Distinct values popover ----
  async function openDistinctPopover(sheet, column, anchorEl) {
    closeOpenPopover();
    const popover = document.createElement("div");
    popover.className = "distinct-popover";
    const rect = anchorEl.getBoundingClientRect();
    popover.style.top = Math.min(rect.bottom + 6, window.innerHeight - 400) + "px";
    popover.style.left = Math.min(rect.left, window.innerWidth - 330) + "px";
    popover.innerHTML = '<div class="distinct-popover-header">Loading…</div>';
    document.body.appendChild(popover);
    state.openPopover = { el: popover, close: () => popover.remove() };

    const params = buildQuery(sheet);
    params.delete("page"); params.delete("page_size"); params.delete("sort"); params.delete("dir");
    params.set("column", column);
    const data = await fetchJSON(`/api/sheets/${encodeURIComponent(sheet.name)}/distinct?${params.toString()}`);

    popover.innerHTML = "";
    const header = document.createElement("div");
    header.className = "distinct-popover-header";
    const title = document.createElement("span");
    title.textContent = column;
    header.appendChild(title);
    const sub = document.createElement("span");
    sub.className = "dp-sub";
    sub.textContent = `${data.total_distinct.toLocaleString()} unique`;
    header.appendChild(sub);
    popover.appendChild(header);

    const body = document.createElement("div");
    body.className = "distinct-popover-body";
    if (!data.values.length) {
      const empty = document.createElement("div");
      empty.className = "empty-note";
      empty.style.padding = "10px";
      empty.textContent = "No values in the current view.";
      body.appendChild(empty);
    }
    data.values.forEach((v) => {
      const row = document.createElement("div");
      row.className = "distinct-row";
      const valEl = document.createElement("span");
      valEl.className = "distinct-value";
      valEl.title = v.value;
      valEl.textContent = v.value;
      row.appendChild(valEl);
      const countEl = document.createElement("span");
      countEl.className = "distinct-count";
      countEl.textContent = v.count.toLocaleString();
      row.appendChild(countEl);
      const actions = document.createElement("div");
      actions.className = "distinct-actions";
      const includeBtn = document.createElement("button");
      includeBtn.className = "include-btn";
      includeBtn.textContent = "Filter";
      includeBtn.title = "Filter to this value";
      includeBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        addAdvancedFilter(sheet, column, "eq", v.value);
        closeOpenPopover();
      });
      const excludeBtn = document.createElement("button");
      excludeBtn.className = "exclude-btn";
      excludeBtn.textContent = "Exclude";
      excludeBtn.title = "Exclude this value";
      excludeBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        addAdvancedFilter(sheet, column, "neq", v.value);
        closeOpenPopover();
      });
      actions.appendChild(includeBtn);
      actions.appendChild(excludeBtn);
      row.appendChild(actions);
      body.appendChild(row);
    });
    popover.appendChild(body);
  }

  function addAdvancedFilter(sheet, column, op, value) {
    const st = state.sheetState[sheet.name];
    st.advFilters.push({ column, op, value });
    st.page = 1;
    const container = document.getElementById("adv-filters");
    if (container) renderAdvancedFilterRows(sheet, container);
    loadSheetRows(sheet);
  }

  function renderPagination(sheet, data) {
    const st = state.sheetState[sheet.name];
    const container = document.getElementById("pagination");
    container.innerHTML = "";
    const totalPages = Math.max(1, Math.ceil(data.total / data.page_size));

    const prev = document.createElement("button");
    prev.textContent = "← Prev";
    prev.disabled = data.page <= 1;
    prev.addEventListener("click", () => { st.page = Math.max(1, st.page - 1); loadSheetRows(sheet); });
    container.appendChild(prev);

    const next = document.createElement("button");
    next.textContent = "Next →";
    next.disabled = data.page >= totalPages;
    next.addEventListener("click", () => { st.page = Math.min(totalPages, st.page + 1); loadSheetRows(sheet); });
    container.appendChild(next);

    const info = document.createElement("span");
    info.textContent = `Page ${data.page} of ${totalPages}`;
    container.appendChild(info);

    const spacer = document.createElement("div");
    spacer.className = "spacer";
    container.appendChild(spacer);

    const sizeLabel = document.createElement("span");
    sizeLabel.textContent = "Rows per page:";
    container.appendChild(sizeLabel);
    const sizeSel = document.createElement("select");
    [25, 50, 100, 250].forEach((n) => {
      const opt = document.createElement("option");
      opt.value = n;
      opt.textContent = n;
      if (n === st.pageSize) opt.selected = true;
      sizeSel.appendChild(opt);
    });
    sizeSel.addEventListener("change", () => {
      st.pageSize = parseInt(sizeSel.value, 10);
      st.page = 1;
      loadSheetRows(sheet);
    });
    container.appendChild(sizeSel);
  }

  function exportCsv(sheet) {
    const params = buildQuery(sheet);
    params.delete("page");
    params.delete("page_size");
    window.open(`/api/sheets/${encodeURIComponent(sheet.name)}/export.csv?${params.toString()}`, "_blank");
  }

  // ---------------- Multi-select correlation ----------------
  function updateSelectionBar(sheet) {
    const bar = document.getElementById("selection-bar");
    if (!bar) return;
    const count = state.sheetState[sheet.name].selectedRows.size;
    if (count === 0) {
      bar.style.display = "none";
      return;
    }
    bar.style.display = "flex";
    bar.querySelector(".sel-count").textContent = `${count} event${count === 1 ? "" : "s"} selected`;
  }

  async function runCorrelation(sheet, btn) {
    const st = state.sheetState[sheet.name];
    const rowIds = [...st.selectedRows];
    if (!rowIds.length) return;
    const prevText = btn.textContent;
    btn.disabled = true;
    btn.innerHTML = '<span class="btn-spinner"></span>Correlating…';
    try {
      const result = await fetchJSON(`/api/sheets/${encodeURIComponent(sheet.name)}/llm-correlate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ row_ids: rowIds }),
      });
      openCorrelationModal(sheet, result);
    } catch (e) {
      openCorrelationModal(sheet, { error: e.message || "Request failed — check that the dashboard server is reachable." });
    }
    btn.disabled = false;
    btn.textContent = prevText;
  }

  // ---------------- Generic app modal (correlation, custom incident, IR report) ----------------
  function openAppModal(title, opts) {
    opts = opts || {};
    document.getElementById("app-modal-title").textContent = title;
    document.getElementById("app-modal").classList.toggle("modal-wide", !!opts.wide);
    const body = document.getElementById("app-modal-body");
    body.innerHTML = "";
    document.getElementById("app-modal").classList.add("open");
    document.getElementById("app-modal-backdrop").classList.add("open");
    return body;
  }

  function closeAppModal() {
    document.getElementById("app-modal").classList.remove("open");
    document.getElementById("app-modal-backdrop").classList.remove("open");
  }

  function openCorrelationModal(sheet, result) {
    const body = openAppModal("LLM Correlation Result");

    if (result.error) {
      const card = document.createElement("div");
      card.className = "llm-result llm-error";
      const text = document.createElement("div");
      text.className = "llm-error-text";
      text.textContent = result.error;
      card.appendChild(text);
      body.appendChild(card);
    } else {
      const summary = document.createElement("div");
      summary.className = "llm-result";
      const head = document.createElement("div");
      head.className = "llm-result-head";
      const verdict = document.createElement("span");
      verdict.className = "llm-verdict " + (result.correlated ? "malicious" : "clean");
      verdict.textContent = result.correlated ? "Related events found" : "No relationship found";
      head.appendChild(verdict);
      const conf = document.createElement("span");
      conf.className = "llm-score";
      conf.textContent = `confidence ${result.confidence}/100`;
      head.appendChild(conf);
      summary.appendChild(head);
      const narrative = document.createElement("div");
      narrative.className = "llm-text";
      narrative.textContent = result.narrative || "";
      summary.appendChild(narrative);
      body.appendChild(summary);

      const countNote = document.createElement("div");
      countNote.className = "card-subtitle";
      countNote.style.margin = "14px 0 8px";
      countNote.textContent = `${result.total_related} of ${result.total_selected} selected events appear related:`;
      body.appendChild(countNote);

      if (result.rows && result.rows.length) {
        const tableWrap = document.createElement("div");
        tableWrap.className = "table-wrap";
        tableWrap.style.maxHeight = "360px";
        const table = document.createElement("table");
        table.className = "data-grid";
        const thead = document.createElement("thead");
        const headRow = document.createElement("tr");
        result.columns.forEach((col) => {
          const th = document.createElement("th");
          th.textContent = col;
          headRow.appendChild(th);
        });
        thead.appendChild(headRow);
        table.appendChild(thead);
        const tbody = document.createElement("tbody");
        result.rows.forEach((row) => {
          const tr = document.createElement("tr");
          result.columns.forEach((col) => {
            const td = document.createElement("td");
            const val = row[col];
            if (col === "Severity") {
              const badge = document.createElement("span");
              badge.className = "sev-badge " + severityClass(val);
              badge.textContent = val || "Unknown";
              td.appendChild(badge);
            } else {
              td.textContent = val === null || val === undefined ? "" : val;
              td.title = val || "";
            }
            tr.appendChild(td);
          });
          tr.addEventListener("click", () => {
            closeAppModal();
            openRowDetail(sheet, row._id);
          });
          tbody.appendChild(tr);
        });
        table.appendChild(tbody);
        tableWrap.appendChild(table);
        body.appendChild(tableWrap);
      }
    }
  }

  // ---------------- Incident timeline add/pin ----------------
  async function addToIncidentTimeline(sheetName, rowId, btnEl) {
    if (btnEl) { btnEl.disabled = true; btnEl.textContent = "…"; }
    try {
      await fetchJSON("/api/incidents", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sheet_name: sheetName, row_id: rowId }),
      });
      if (btnEl) {
        btnEl.textContent = "✓ Added";
        btnEl.classList.add("pinned");
        setTimeout(() => { btnEl.textContent = "+ Pin"; btnEl.classList.remove("pinned"); btnEl.disabled = false; }, 1500);
      }
    } catch (e) {
      if (btnEl) { btnEl.textContent = "Error"; setTimeout(() => { btnEl.textContent = "+ Pin"; btnEl.disabled = false; }, 1500); }
    }
  }

  // ---------------- Base64 decoder ----------------
  const BASE64_CANDIDATE_RE = /[A-Za-z0-9+/]{40,}={0,2}/g;
  const BASE64_MAX_DISPLAY = 20000;

  function findBase64Candidates(data) {
    const seen = new Set();
    const candidates = [];
    Object.values(data || {}).forEach((val) => {
      if (typeof val !== "string") return;
      const matches = val.match(BASE64_CANDIDATE_RE);
      if (!matches) return;
      matches.forEach((m) => {
        if (!seen.has(m)) {
          seen.add(m);
          candidates.push(m);
        }
      });
    });
    return candidates.slice(0, 8);
  }

  function printableRatio(str) {
    if (!str) return 0;
    let printable = 0;
    for (const ch of str) {
      const code = ch.codePointAt(0);
      if ((code >= 0x20 && code <= 0x7e) || code === 0x9 || code === 0xa || code === 0xd) printable++;
    }
    return printable / str.length;
  }

  function truncateForDisplay(s) {
    if (s.length > BASE64_MAX_DISPLAY) {
      return s.slice(0, BASE64_MAX_DISPLAY) + `\n… [truncated — ${s.length.toLocaleString()} characters total]`;
    }
    return s;
  }

  function decodeBase64Variants(rawInput) {
    const cleaned = (rawInput || "").trim().replace(/[\s\r\n]+/g, "");
    if (!cleaned) return { error: "Enter a Base64 string to decode." };
    const normalized = cleaned.replace(/-/g, "+").replace(/_/g, "/");
    let bytes;
    try {
      const binary = atob(normalized);
      bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    } catch (e) {
      return { error: "Could not decode — this doesn't look like valid Base64." };
    }
    let utf16le = "";
    let utf8 = "";
    try { utf16le = new TextDecoder("utf-16le").decode(bytes); } catch (e) { /* unsupported in this browser */ }
    try { utf8 = new TextDecoder("utf-8").decode(bytes); } catch (e) { /* unsupported in this browser */ }
    const hex = Array.from(bytes.slice(0, 400)).map((b) => b.toString(16).padStart(2, "0")).join(" ");
    const best = printableRatio(utf16le) >= printableRatio(utf8) ? "utf16le" : "utf8";
    return {
      utf16le: truncateForDisplay(utf16le),
      utf8: truncateForDisplay(utf8),
      hex,
      byteLength: bytes.length,
      best,
    };
  }

  function renderBase64Tool(container, data) {
    container.innerHTML = "";
    const card = document.createElement("div");
    card.className = "llm-result b64-tool";

    const head = document.createElement("div");
    head.className = "llm-result-head";
    head.innerHTML = "<strong>🔓 Base64 decoder</strong>";
    card.appendChild(head);

    const sub = document.createElement("div");
    sub.className = "field-hint";
    sub.style.marginBottom = "8px";
    sub.textContent = "Paste, or pick a detected blob below, to decode Base64 (e.g. a PowerShell -EncodedCommand).";
    card.appendChild(sub);

    const candidates = findBase64Candidates(data);
    const input = document.createElement("textarea");
    input.className = "b64-input";
    input.placeholder = "Paste Base64 text here…";
    input.rows = 2;

    if (candidates.length) {
      const chipsWrap = document.createElement("div");
      chipsWrap.className = "b64-chips";
      candidates.forEach((c, i) => {
        const chip = document.createElement("button");
        chip.className = "b64-chip";
        chip.textContent = `Blob ${i + 1} (${c.length} chars)`;
        chip.title = c.length > 60 ? c.slice(0, 60) + "…" : c;
        chip.addEventListener("click", () => {
          input.value = c;
          runDecode();
        });
        chipsWrap.appendChild(chip);
      });
      card.appendChild(chipsWrap);
    }

    card.appendChild(input);

    const actionsRow = document.createElement("div");
    actionsRow.className = "b64-actions";
    const decodeBtn = document.createElement("button");
    decodeBtn.className = "btn-primary";
    decodeBtn.textContent = "Decode";
    actionsRow.appendChild(decodeBtn);
    card.appendChild(actionsRow);

    const outputMount = document.createElement("div");
    card.appendChild(outputMount);

    function runDecode() {
      const result = decodeBase64Variants(input.value);
      outputMount.innerHTML = "";
      if (result.error) {
        const err = document.createElement("div");
        err.className = "llm-error-text";
        err.textContent = result.error;
        outputMount.appendChild(err);
        return;
      }
      [
        { key: "utf16le", label: "UTF-16LE text (common for PowerShell -EncodedCommand)" },
        { key: "utf8", label: "UTF-8 text" },
      ].forEach((v) => {
        const block = document.createElement("div");
        block.className = "b64-variant" + (result.best === v.key ? " b64-best" : "");
        const vHead = document.createElement("div");
        vHead.className = "b64-variant-head";
        const label = document.createElement("span");
        label.textContent = v.label + (result.best === v.key ? " — likely match" : "");
        vHead.appendChild(label);
        const copyBtn = document.createElement("button");
        copyBtn.className = "copy-btn";
        copyBtn.textContent = "Copy";
        copyBtn.addEventListener("click", () => {
          navigator.clipboard.writeText(result[v.key] || "");
          copyBtn.textContent = "Copied!";
          setTimeout(() => { copyBtn.textContent = "Copy"; }, 1200);
        });
        vHead.appendChild(copyBtn);
        block.appendChild(vHead);
        const pre = document.createElement("pre");
        pre.className = "b64-output";
        pre.textContent = result[v.key] || "(empty)";
        block.appendChild(pre);
        outputMount.appendChild(block);
      });

      const meta = document.createElement("div");
      meta.className = "field-hint";
      meta.style.marginTop = "6px";
      meta.textContent = `${result.byteLength.toLocaleString()} bytes decoded.`;
      outputMount.appendChild(meta);
    }

    decodeBtn.addEventListener("click", runDecode);
    container.appendChild(card);

    if (candidates.length) {
      input.value = candidates[0];
      runDecode();
    }
  }

  // ---------------- Row detail drawer ----------------
  function renderDetailFields(body, data, opts) {
    opts = opts || {};
    body.innerHTML = "";
    Object.keys(data).forEach((key) => {
      if (key === "_id" || key === "timestamp" || opts.skipKeys && opts.skipKeys.includes(key)) return;
      const val = data[key];
      const field = document.createElement("div");
      field.className = "detail-field";
      const label = document.createElement("div");
      label.className = "df-label";
      label.textContent = key;
      field.appendChild(label);

      if (key === "Severity") {
        const badge = document.createElement("span");
        badge.className = "sev-badge " + severityClass(val);
        badge.textContent = val || "Unknown";
        field.appendChild(badge);
      } else if (key === "Original Event Log") {
        const btn = document.createElement("button");
        btn.className = "copy-btn";
        btn.textContent = "Copy raw log";
        btn.addEventListener("click", () => {
          navigator.clipboard.writeText(val || "");
          btn.textContent = "Copied!";
          setTimeout(() => { btn.textContent = "Copy raw log"; }, 1200);
        });
        field.appendChild(btn);
        const pre = document.createElement("pre");
        pre.textContent = val || "";
        field.appendChild(pre);
      } else {
        const value = document.createElement("div");
        value.className = "df-value";
        value.textContent = val === null || val === undefined || val === "" ? "—" : val;
        field.appendChild(value);
      }
      body.appendChild(field);
    });
  }

  async function openRowDetail(sheet, rowId) {
    const drawer = document.getElementById("drawer");
    const backdrop = document.getElementById("drawer-backdrop");
    const body = document.getElementById("drawer-body");
    body.innerHTML = '<div class="empty-note">Loading…</div>';
    drawer.classList.add("open");
    backdrop.classList.add("open");

    const data = await fetchJSON(`/api/sheets/${encodeURIComponent(sheet.name)}/row/${rowId}`);
    body.innerHTML = "";

    const actions = document.createElement("div");
    actions.className = "drawer-actions";
    const pinBtn = document.createElement("button");
    pinBtn.className = "btn-primary";
    pinBtn.textContent = "+ Add to incident timeline";
    pinBtn.addEventListener("click", () => addToIncidentTimeline(sheet.name, rowId, pinBtn));
    actions.appendChild(pinBtn);

    const checkBtn = document.createElement("button");
    checkBtn.className = "ghost-btn";
    checkBtn.textContent = "🔍 Check with LLM";
    actions.appendChild(checkBtn);

    const explainBtn = document.createElement("button");
    explainBtn.className = "ghost-btn";
    explainBtn.textContent = "💬 Explain event";
    actions.appendChild(explainBtn);

    body.appendChild(actions);

    const checkSlot = document.createElement("div");
    const explainSlot = document.createElement("div");
    body.appendChild(checkSlot);
    body.appendChild(explainSlot);

    checkBtn.addEventListener("click", () => runLlmCheck(sheet, rowId, checkBtn, checkSlot));
    explainBtn.addEventListener("click", () => runLlmExplain(sheet, rowId, explainBtn, explainSlot));

    const b64Mount = document.createElement("div");
    body.appendChild(b64Mount);
    renderBase64Tool(b64Mount, data);

    const fieldsMount = document.createElement("div");
    body.appendChild(fieldsMount);
    renderDetailFields(fieldsMount, data);
  }

  async function runLlmCheck(sheet, rowId, btn, slot) {
    const prevText = btn.textContent;
    btn.disabled = true;
    btn.innerHTML = '<span class="btn-spinner"></span>Checking…';
    try {
      const result = await fetchJSON(
        `/api/sheets/${encodeURIComponent(sheet.name)}/row/${rowId}/llm-check`,
        { method: "POST" }
      );
      renderLlmCheckResult(slot, result);
    } catch (e) {
      renderLlmError(slot, e.message || "Request failed — check that the dashboard server is reachable.");
    }
    btn.disabled = false;
    btn.textContent = prevText;
  }

  async function runLlmExplain(sheet, rowId, btn, slot) {
    const prevText = btn.textContent;
    btn.disabled = true;
    btn.innerHTML = '<span class="btn-spinner"></span>Explaining…';
    try {
      const result = await fetchJSON(
        `/api/sheets/${encodeURIComponent(sheet.name)}/row/${rowId}/llm-explain`,
        { method: "POST" }
      );
      renderLlmExplainResult(slot, result);
    } catch (e) {
      renderLlmError(slot, e.message || "Request failed — check that the dashboard server is reachable.");
    }
    btn.disabled = false;
    btn.textContent = prevText;
  }

  function renderLlmError(slot, message) {
    slot.innerHTML = "";
    const card = document.createElement("div");
    card.className = "llm-result llm-error";
    const text = document.createElement("div");
    text.className = "llm-error-text";
    text.textContent = message;
    card.appendChild(text);
    slot.appendChild(card);
  }

  function renderLlmCheckResult(slot, result) {
    slot.innerHTML = "";
    const card = document.createElement("div");
    card.className = "llm-result" + (result.is_error ? " llm-error" : "");
    if (result.is_error) {
      const text = document.createElement("div");
      text.className = "llm-error-text";
      text.textContent = result.reason || "The LLM request failed.";
      card.appendChild(text);
    } else {
      const head = document.createElement("div");
      head.className = "llm-result-head";
      const verdict = document.createElement("span");
      verdict.className = "llm-verdict " + (result.is_malicious ? "malicious" : "clean");
      verdict.textContent = result.is_malicious ? "Malicious" : "Clean";
      head.appendChild(verdict);
      const score = document.createElement("span");
      score.className = "llm-score";
      score.textContent = `score ${result.score}/100`;
      head.appendChild(score);
      card.appendChild(head);
      const reason = document.createElement("div");
      reason.className = "llm-text";
      reason.textContent = result.reason || "";
      card.appendChild(reason);
    }
    slot.appendChild(card);
  }

  function renderLlmExplainResult(slot, result) {
    slot.innerHTML = "";
    const card = document.createElement("div");
    card.className = "llm-result" + (result.error ? " llm-error" : "");
    if (result.error) {
      const text = document.createElement("div");
      text.className = "llm-error-text";
      text.textContent = result.error;
      card.appendChild(text);
    } else {
      const head = document.createElement("div");
      head.className = "llm-result-head";
      head.innerHTML = "<strong>LLM explanation</strong>";
      card.appendChild(head);
      const text = document.createElement("div");
      text.className = "llm-text";
      text.textContent = result.explanation || "";
      card.appendChild(text);
    }
    slot.appendChild(card);
  }

  function closeDrawer() {
    document.getElementById("drawer").classList.remove("open");
    document.getElementById("drawer-backdrop").classList.remove("open");
  }

  // ---------------- Incident Timeline view ----------------
  async function selectIncidents() {
    closeOpenPopover();
    state.view = "incidents";
    state.currentSheet = null;
    setActiveNav(null, "incidents");
    showView("incidents");
    document.getElementById("report-title").textContent = "Incident Timeline";
    document.getElementById("report-meta").textContent = metaSubtitle();
    await loadIncidents();
  }

  async function loadIncidents() {
    const incidents = await fetchJSON("/api/incidents");
    // renderIncidentsView empties the view, which collapses the document height and
    // makes the browser clamp the window scroll to the top. Put the analyst back where
    // they were. (After a delete the page is shorter, so this may still clamp - fine.)
    const y = window.scrollY;
    renderIncidentsView(incidents);
    if (y) requestAnimationFrame(() => window.scrollTo(0, y));
  }

  // Timeline rows ticked for bulk removal. Held outside the render function because
  // the view re-renders on resize and refresh, and a half-made selection should survive that.
  const incidentSel = new Set();
  // Parent rows whose sub-events are showing. Module-level so expansion survives the
  // re-render that resize / refresh / delete trigger.
  const incidentOpen = new Set();
  let incidentLastClicked = null;
  // The timeline chart's zoom window (epoch seconds, or null for the whole range).
  // Held here so a re-render - resize, refresh, removing events - keeps you zoomed in.
  let incidentChartView = null;

  function renderIncidentsView(incidents) {
    const root = document.getElementById("view-incidents");
    root.innerHTML = "";

    const knownIds = new Set(incidents.map((i) => i.id));
    [...incidentSel].forEach((id) => { if (!knownIds.has(id)) incidentSel.delete(id); });
    [...incidentOpen].forEach((id) => { if (!knownIds.has(id)) incidentOpen.delete(id); });
    let headerCb = null;

    // Sub-events hang off their finding. They are grouped in the table and left out
    // of the charts, so attaching evidence no longer piles dots on top of each other.
    const topLevel = incidents.filter((i) => i.parent_id == null);
    const childrenOf = new Map();
    incidents.forEach((i) => {
      if (i.parent_id == null) return;
      if (!childrenOf.has(i.parent_id)) childrenOf.set(i.parent_id, []);
      childrenOf.get(i.parent_id).push(i);
    });
    childrenOf.forEach((list) => list.sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0)));
    const subTotal = incidents.length - topLevel.length;
    const byId = new Map(incidents.map((i) => [i.id, i]));
    let toggleAllBtn = null;

    // Expanding is a pure show/hide: every child row is already in the DOM. Repaint
    // locally instead of re-rendering, which would reset the window scroll.
    function refreshToggleLabels() {
      root.querySelectorAll("button.it-toggle").forEach((btn) => {
        const id = Number(btn.dataset.id);
        const open = incidentOpen.has(id);
        const n = Number(btn.dataset.count) || 0;
        btn.textContent = open ? "▾" : "▸";
        btn.title = open ? "Hide sub-events" : `Show ${n} sub-event${n === 1 ? "" : "s"}`;
        btn.setAttribute("aria-expanded", open ? "true" : "false");
      });
      if (toggleAllBtn) {
        const allOpen = topLevel.every((p) => !childrenOf.has(p.id) || incidentOpen.has(p.id));
        toggleAllBtn.textContent = allOpen ? "Collapse all" : "Expand all";
      }
    }

    // Rows in the order they appear on screen right now, so shift-click ranges follow
    // what the analyst can actually see rather than a snapshot taken at render time.
    function visibleRowsNow() {
      const out = [];
      root.querySelectorAll("tr[id^='incident-row-']").forEach((tr) => {
        if (tr.style.display === "none") return;
        const inc = byId.get(Number(tr.id.slice("incident-row-".length)));
        if (inc) out.push(inc);
      });
      return out;
    }

    const toolbar = document.createElement("div");
    toolbar.className = "incident-toolbar";
    const title = document.createElement("div");
    title.innerHTML = `<strong>${topLevel.length}</strong> event${topLevel.length === 1 ? "" : "s"} pinned to this timeline`
      + (subTotal ? ` · <strong>${subTotal}</strong> sub-event${subTotal === 1 ? "" : "s"}` : "");
    toolbar.appendChild(title);
    if (subTotal) {
      toggleAllBtn = document.createElement("button");
      toggleAllBtn.className = "ghost-btn";
      toggleAllBtn.addEventListener("click", () => {
        const allOpen = topLevel.every((p) => !childrenOf.has(p.id) || incidentOpen.has(p.id));
        incidentOpen.clear();
        if (!allOpen) topLevel.forEach((p) => { if (childrenOf.has(p.id)) incidentOpen.add(p.id); });
        refreshToggleLabels();
        syncSelection();
      });
      toolbar.appendChild(toggleAllBtn);
    }
    const spacer = document.createElement("div");
    spacer.className = "spacer";
    toolbar.appendChild(spacer);
    const addCustomBtn = document.createElement("button");
    addCustomBtn.className = "btn-primary";
    addCustomBtn.textContent = "+ Add custom event";
    addCustomBtn.addEventListener("click", () => openAddIncidentModal());
    toolbar.appendChild(addCustomBtn);
    const reportBtn = document.createElement("button");
    reportBtn.className = "ghost-btn";
    reportBtn.textContent = "📄 Generate IR Report";
    reportBtn.addEventListener("click", () => openGenerateReportModal(incidents.length));
    toolbar.appendChild(reportBtn);
    const exportBtn = document.createElement("button");
    exportBtn.className = "ghost-btn";
    exportBtn.textContent = "⤓ Export CSV";
    exportBtn.addEventListener("click", () => exportIncidentsCsv(incidents));
    toolbar.appendChild(exportBtn);
    root.appendChild(toolbar);

    const selBar = document.createElement("div");
    selBar.className = "incident-selection-bar";
    selBar.style.display = "none";
    const selCount = document.createElement("strong");
    selBar.appendChild(selCount);
    const selHint = document.createElement("span");
    selHint.className = "field-hint";
    selHint.textContent = "Shift-click a checkbox to select a range.";
    selBar.appendChild(selHint);
    const selSpacer = document.createElement("div");
    selSpacer.className = "spacer";
    selBar.appendChild(selSpacer);
    const clearSelBtn = document.createElement("button");
    clearSelBtn.className = "ghost-btn";
    clearSelBtn.textContent = "Clear selection";
    selBar.appendChild(clearSelBtn);
    const removeSelBtn = document.createElement("button");
    removeSelBtn.className = "btn-danger";
    selBar.appendChild(removeSelBtn);
    root.appendChild(selBar);

    // Selecting a finding selects its sub-events: they are hidden when collapsed, and
    // removal cascades to them anyway, so the count should say what will actually go.
    function setSelected(inc, on) {
      const ids = [inc.id, ...(childrenOf.get(inc.id) || []).map((k) => k.id)];
      ids.forEach((id) => { if (on) incidentSel.add(id); else incidentSel.delete(id); });
    }

    function syncSelection() {
      const n = incidentSel.size;
      selBar.style.display = n ? "" : "none";
      selCount.textContent = `${n} selected`;
      removeSelBtn.textContent = `🗑 Remove ${n} selected`;
      root.querySelectorAll("input.it-cb").forEach((cb) => {
        const on = incidentSel.has(Number(cb.dataset.id));
        cb.checked = on;
        const row = cb.closest("tr");
        if (row) row.classList.toggle("it-selected", on);
      });
      if (headerCb) {
        headerCb.checked = n > 0 && n === incidents.length;
        headerCb.indeterminate = n > 0 && n < incidents.length;
      }
      root.querySelectorAll("tr.it-child").forEach((tr) => {
        tr.style.display = incidentOpen.has(Number(tr.dataset.parent)) ? "" : "none";
      });
    }

    clearSelBtn.addEventListener("click", () => {
      incidentSel.clear();
      incidentLastClicked = null;
      syncSelection();
    });

    removeSelBtn.addEventListener("click", async () => {
      const n = incidentSel.size;
      if (!n) return;
      const kids = [...incidentSel].filter((id) => incidents.some((i) => i.id === id && i.parent_id != null)).length;
      const what = kids ? `${n} event${n === 1 ? "" : "s"} (including ${kids} sub-event${kids === 1 ? "" : "s"})` : `${n} event${n === 1 ? "" : "s"}`;
      if (!confirm(`Remove ${what} from the incident timeline? This cannot be undone.`)) return;
      removeSelBtn.disabled = true;
      try {
        const res = await fetchJSON("/api/incidents/bulk-delete", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ids: [...incidentSel] }),
        });
        incidentSel.clear();
        incidentLastClicked = null;
        await loadIncidents();
        if (res.findings_reopened) {
          alert(`${res.findings_reopened} triage finding${res.findings_reopened === 1 ? " was" : "s were"} returned to the review queue because ${res.findings_reopened === 1 ? "its" : "their"} timeline entry was removed.`);
        }
      } catch (e) {
        alert(e.message);
        removeSelBtn.disabled = false;
      }
    });

    if (!incidents.length) {
      const empty = document.createElement("div");
      empty.className = "empty-state";
      empty.textContent = "No events pinned yet. Open any event log, click a row, and use “+ Add to incident timeline” (or the Pin button in the table) to start building your timeline.";
      root.appendChild(empty);
      return;
    }

    renderExecutiveSummaryCard(root);

    const chartCard = document.createElement("div");
    chartCard.className = "card timeline-chart-card";
    chartCard.innerHTML = `<div class="card-title">Timeline</div>
      <div class="card-subtitle">Pinned events plotted by time — hover for details, click a dot to jump to its row, drag to zoom into a busy stretch</div>`;
    const chartMount = document.createElement("div");
    chartCard.appendChild(chartMount);
    root.appendChild(chartCard);

    // Sub-events are deliberately absent here: plotting every pinned evidence row is
    // what made the chart unreadable. They remain in the table below.
    const chartEvents = topLevel.map((inc) => ({
      id: inc.id,
      timestamp: inc.timestamp,
      label: inc.description,
      severity: inc.severity,
      meta: [inc.sheet_name, inc.computer].filter(Boolean).join(" • "),
      color: cssVar(SEVERITY_COLOR_VAR[inc.severity] || "--series-1"),
      onClick: () => {
        const rowEl = document.getElementById(`incident-row-${inc.id}`);
        if (rowEl) {
          rowEl.scrollIntoView({ behavior: "smooth", block: "center" });
          rowEl.classList.add("it-row-flash");
          setTimeout(() => rowEl.classList.remove("it-row-flash"), 1200);
        }
      },
    }));
    Charts.eventTimeline(chartMount, chartEvents, {
      view: incidentChartView,
      onViewChange: (v) => { incidentChartView = v; },
    });
    const legendWrap = document.createElement("div");
    Charts.buildLegend(legendWrap, SEVERITY_ORDER.filter((s) => topLevel.some((i) => i.severity === s))
      .map((s) => ({ label: s, color: cssVar(SEVERITY_COLOR_VAR[s]) })));
    chartCard.appendChild(legendWrap);

    const vTimelineCard = document.createElement("div");
    vTimelineCard.className = "card timeline-chart-card";
    vTimelineCard.innerHTML = `<div class="card-title">Chronological timeline</div>
      <div class="card-subtitle">Pinned findings as a readable, oldest-first storyline — click an entry to jump to the row below</div>`;
    const vTimelineMount = document.createElement("div");
    vTimelineCard.appendChild(vTimelineMount);
    root.appendChild(vTimelineCard);
    Charts.verticalTimeline(vTimelineMount, chartEvents);

    const tableWrap = document.createElement("div");
    tableWrap.className = "table-wrap";
    const table = document.createElement("table");
    table.className = "data-grid incident-table";
    table.innerHTML = `<thead><tr>
        <th class="it-select"></th><th>Time</th><th>Severity</th><th>Source</th><th>Description</th><th>Computer</th><th>Note</th><th></th>
      </tr></thead>`;
    headerCb = document.createElement("input");
    headerCb.type = "checkbox";
    headerCb.title = "Select all";
    headerCb.addEventListener("change", () => {
      incidentSel.clear();
      if (headerCb.checked) incidents.forEach((i) => incidentSel.add(i.id));
      incidentLastClicked = null;
      syncSelection();
    });
    table.querySelector("th.it-select").appendChild(headerCb);

    const tbody = document.createElement("tbody");
    function buildIncidentRow(inc) {
      const kids = childrenOf.get(inc.id) || [];
      const isChild = inc.parent_id != null;
      const tr = document.createElement("tr");
      tr.id = `incident-row-${inc.id}`;
      if (isChild) {
        tr.className = "it-child";
        tr.dataset.parent = inc.parent_id;
        tr.style.display = incidentOpen.has(inc.parent_id) ? "" : "none";
      }

      const tdSel = document.createElement("td");
      tdSel.className = "it-select";
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.className = "it-cb";
      cb.dataset.id = inc.id;
      cb.checked = incidentSel.has(inc.id);
      cb.addEventListener("click", (e) => {
        e.stopPropagation();
        const on = cb.checked;
        const rows = visibleRowsNow();
        const here = rows.findIndex((i) => i.id === inc.id);
        const from = rows.findIndex((i) => i.id === incidentLastClicked);
        if (e.shiftKey && incidentLastClicked !== null && from >= 0 && here >= 0) {
          const [lo, hi] = from <= here ? [from, here] : [here, from];
          for (let k = lo; k <= hi; k++) setSelected(rows[k], on);
        } else setSelected(inc, on);
        incidentLastClicked = inc.id;
        syncSelection();
      });
      tdSel.addEventListener("click", (e) => e.stopPropagation());
      tdSel.appendChild(cb);
      tr.appendChild(tdSel);

      const tdTime = document.createElement("td");
      tdTime.className = isChild ? "it-time it-time-child" : "it-time";
      if (kids.length) {
        const toggle = document.createElement("button");
        toggle.className = "it-toggle";
        toggle.type = "button";
        toggle.dataset.id = inc.id;
        toggle.dataset.count = kids.length;
        toggle.addEventListener("click", (e) => {
          e.stopPropagation();
          if (incidentOpen.has(inc.id)) incidentOpen.delete(inc.id); else incidentOpen.add(inc.id);
          refreshToggleLabels();   // glyph/title/aria
          syncSelection();         // shows or hides the child rows
        });
        tdTime.appendChild(toggle);
      }
      const timeText = document.createElement("span");
      // Sub-events carry the source row's raw "Date and Time" (ISO with microseconds),
      // which is unreadable stacked under a finding. Show the clock time instead so the
      // sequence within the group scans; the full value stays in the drawer and CSV.
      if (isChild && typeof inc.timestamp === "number") {
        timeText.textContent = new Date(inc.timestamp * 1000).toLocaleTimeString(undefined, {
          hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
        });
        timeText.title = inc.date_text || "";
      } else {
        timeText.textContent = inc.date_text || (inc.timestamp ? new Date(inc.timestamp * 1000).toLocaleString() : "—");
      }
      tdTime.appendChild(timeText);
      tr.appendChild(tdTime);

      const tdSev = document.createElement("td");
      const badge = document.createElement("span");
      badge.className = "sev-badge " + severityClass(inc.severity);
      badge.textContent = inc.severity || "Unknown";
      tdSev.appendChild(badge);
      tr.appendChild(tdSev);

      const tdSource = document.createElement("td");
      tdSource.textContent = inc.sheet_name || "";
      tr.appendChild(tdSource);

      const tdDesc = document.createElement("td");
      tdDesc.title = inc.description || "";
      tdDesc.style.maxWidth = "420px";
      const descText = document.createElement("span");
      descText.textContent = inc.description || "";
      tdDesc.appendChild(descText);
      if (kids.length) {
        const badge = document.createElement("span");
        badge.className = "it-subcount";
        badge.textContent = `${kids.length} sub-event${kids.length === 1 ? "" : "s"}`;
        tdDesc.appendChild(badge);
      }
      tr.appendChild(tdDesc);

      const tdComputer = document.createElement("td");
      tdComputer.textContent = inc.computer || "";
      tr.appendChild(tdComputer);

      const tdNote = document.createElement("td");
      tdNote.className = "it-note";
      const noteInput = document.createElement("input");
      noteInput.type = "text";
      noteInput.placeholder = "Add a note…";
      noteInput.value = inc.note || "";
      let noteTimer = null;
      noteInput.addEventListener("click", (e) => e.stopPropagation());
      noteInput.addEventListener("input", () => {
        clearTimeout(noteTimer);
        noteTimer = setTimeout(() => {
          fetchJSON(`/api/incidents/${inc.id}`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ note: noteInput.value }),
          });
        }, 400);
      });
      tdNote.appendChild(noteInput);
      tr.appendChild(tdNote);

      const tdRemove = document.createElement("td");
      tdRemove.className = "it-remove";
      const removeBtn = document.createElement("button");
      removeBtn.textContent = "🗑";
      removeBtn.title = "Remove from timeline";
      removeBtn.addEventListener("click", async (e) => {
        e.stopPropagation();
        if (!confirm("Remove this event from the incident timeline?")) return;
        const res = await fetchJSON(`/api/incidents/${inc.id}`, { method: "DELETE" });
        incidentSel.delete(inc.id);
        await loadIncidents();
        if (res && res.findings_reopened) {
          alert("The triage finding behind this entry was returned to the review queue.");
        }
      });
      tdRemove.appendChild(removeBtn);
      tr.appendChild(tdRemove);

      tr.addEventListener("click", () => {
        const drawer = document.getElementById("drawer");
        const backdrop = document.getElementById("drawer-backdrop");
        const body = document.getElementById("drawer-body");
        drawer.classList.add("open");
        backdrop.classList.add("open");
        body.innerHTML = "";
        const b64Mount = document.createElement("div");
        body.appendChild(b64Mount);
        renderBase64Tool(b64Mount, inc.fields || {});
        const fieldsMount = document.createElement("div");
        body.appendChild(fieldsMount);
        renderDetailFields(fieldsMount, inc.fields || {});
      });

      return tr;
    }

    topLevel.forEach((parent) => {
      tbody.appendChild(buildIncidentRow(parent));
      // Children stay in the DOM and are shown/hidden, so toggling needs no rebuild.
      (childrenOf.get(parent.id) || []).forEach((kid) => tbody.appendChild(buildIncidentRow(kid)));
    });
    table.appendChild(tbody);
    tableWrap.appendChild(table);
    root.appendChild(tableWrap);
    refreshToggleLabels();
    syncSelection();
  }

  // ---------------- Add custom (manual) incident ----------------
  function openAddIncidentModal() {
    const body = openAppModal("Add custom event to timeline");
    const form = document.createElement("div");

    const timeGroup = document.createElement("div");
    timeGroup.className = "field-group";
    timeGroup.innerHTML = "<label>Date &amp; time</label>";
    const timeInput = document.createElement("input");
    timeInput.type = "datetime-local";
    const now = new Date();
    now.setMinutes(now.getMinutes() - now.getTimezoneOffset());
    timeInput.value = now.toISOString().slice(0, 16);
    timeGroup.appendChild(timeInput);
    form.appendChild(timeGroup);

    const sevGroup = document.createElement("div");
    sevGroup.className = "field-group";
    sevGroup.innerHTML = "<label>Severity</label>";
    const sevSel = document.createElement("select");
    ["Critical", "High", "Medium", "Low", "Informational"].forEach((s) => {
      const opt = document.createElement("option");
      opt.value = s;
      opt.textContent = s;
      sevSel.appendChild(opt);
    });
    sevGroup.appendChild(sevSel);
    form.appendChild(sevGroup);

    const descGroup = document.createElement("div");
    descGroup.className = "field-group";
    descGroup.innerHTML = "<label>Description *</label>";
    const descInput = document.createElement("textarea");
    descInput.rows = 3;
    descInput.placeholder = 'What happened? e.g. "Confirmed with helpdesk that user X\'s account was disabled at this time."';
    descGroup.appendChild(descInput);
    form.appendChild(descGroup);

    const compGroup = document.createElement("div");
    compGroup.className = "field-group";
    compGroup.innerHTML = "<label>Computer / host (optional)</label>";
    const compInput = document.createElement("input");
    compInput.type = "text";
    compGroup.appendChild(compInput);
    form.appendChild(compGroup);

    const noteGroup = document.createElement("div");
    noteGroup.className = "field-group";
    noteGroup.innerHTML = "<label>Note (optional)</label>";
    const noteInput = document.createElement("input");
    noteInput.type = "text";
    noteGroup.appendChild(noteInput);
    form.appendChild(noteGroup);

    const errorEl = document.createElement("div");
    errorEl.className = "llm-error-text";
    errorEl.style.display = "none";
    errorEl.style.marginBottom = "10px";
    form.appendChild(errorEl);

    const actions = document.createElement("div");
    actions.className = "settings-actions";
    const addBtn = document.createElement("button");
    addBtn.className = "btn-primary";
    addBtn.textContent = "Add to timeline";
    const cancelBtn = document.createElement("button");
    cancelBtn.className = "ghost-btn";
    cancelBtn.textContent = "Cancel";
    cancelBtn.addEventListener("click", closeAppModal);
    actions.appendChild(addBtn);
    actions.appendChild(cancelBtn);
    form.appendChild(actions);

    addBtn.addEventListener("click", async () => {
      const description = descInput.value.trim();
      if (!description) {
        errorEl.textContent = "Description is required.";
        errorEl.style.display = "block";
        return;
      }
      addBtn.disabled = true;
      addBtn.textContent = "Adding…";
      try {
        const timestamp = timeInput.value ? new Date(timeInput.value).getTime() / 1000 : null;
        const dateText = timeInput.value ? new Date(timeInput.value).toLocaleString() : "";
        await fetchJSON("/api/incidents", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            description,
            severity: sevSel.value,
            computer: compInput.value.trim(),
            note: noteInput.value.trim(),
            timestamp,
            date_text: dateText,
          }),
        });
        closeAppModal();
        loadIncidents();
      } catch (e) {
        errorEl.textContent = e.message || "Failed to add event.";
        errorEl.style.display = "block";
        addBtn.disabled = false;
        addBtn.textContent = "Add to timeline";
      }
    });

    body.appendChild(form);
  }

  // ---------------- Executive Summary panel ----------------
  function renderExecutiveSummaryCard(root) {
    const card = document.createElement("div");
    card.className = "card exec-summary-card";
    card.innerHTML = `<div class="card-title">Executive Summary</div>
      <div class="card-subtitle">AI-generated, plain-language summary of this incident timeline, written for executives and C-level stakeholders — ready to paste into a report.</div>`;

    const controls = document.createElement("div");
    controls.className = "exec-summary-controls";
    const orgInput = document.createElement("input");
    orgInput.type = "text";
    orgInput.placeholder = "Organization name (optional)";
    controls.appendChild(orgInput);

    const genBtn = document.createElement("button");
    genBtn.className = "btn-primary";
    genBtn.textContent = "✨ Generate executive summary";
    controls.appendChild(genBtn);
    card.appendChild(controls);

    const resultMount = document.createElement("div");
    resultMount.className = "exec-summary-result";
    card.appendChild(resultMount);

    genBtn.addEventListener("click", async () => {
      genBtn.disabled = true;
      genBtn.innerHTML = '<span class="btn-spinner"></span>Generating…';
      resultMount.innerHTML = "";
      try {
        const result = await fetchJSON("/api/incidents/summary", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ organization: orgInput.value.trim() }),
        });
        renderExecutiveSummaryResult(resultMount, orgInput.value.trim(), result.content);
        genBtn.textContent = "↻ Regenerate";
      } catch (e) {
        const err = document.createElement("div");
        err.className = "llm-error-text";
        err.textContent = e.message || "Failed to generate executive summary.";
        resultMount.appendChild(err);
        genBtn.textContent = "✨ Generate executive summary";
      }
      genBtn.disabled = false;
    });

    root.appendChild(card);
  }

  function renderExecutiveSummaryResult(mount, organization, content) {
    mount.innerHTML = "";
    const textarea = document.createElement("textarea");
    textarea.className = "report-draft exec-summary-text";
    textarea.value = content;
    mount.appendChild(textarea);

    const actions = document.createElement("div");
    actions.className = "settings-actions";

    const copyBtn = document.createElement("button");
    copyBtn.className = "ghost-btn";
    copyBtn.textContent = "⧉ Copy text";
    copyBtn.addEventListener("click", () => {
      navigator.clipboard.writeText(textarea.value);
      copyBtn.textContent = "✓ Copied";
      setTimeout(() => (copyBtn.textContent = "⧉ Copy text"), 1500);
    });
    actions.appendChild(copyBtn);

    const downloadBtn = document.createElement("button");
    downloadBtn.className = "btn-primary";
    downloadBtn.textContent = "⬇ Download Word document";
    downloadBtn.addEventListener("click", async () => {
      downloadBtn.disabled = true;
      downloadBtn.textContent = "Preparing…";
      try {
        const res = await fetch("/api/incidents/report/docx", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            title: "Executive Summary",
            prepared_by: organization,
            content: textarea.value,
          }),
        });
        if (!res.ok) throw new Error("Failed to generate document.");
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "executive_summary.docx";
        a.click();
        URL.revokeObjectURL(url);
      } catch (e) {
        alert(e.message || "Failed to download document.");
      }
      downloadBtn.disabled = false;
      downloadBtn.textContent = "⬇ Download Word document";
    });
    actions.appendChild(downloadBtn);
    mount.appendChild(actions);
  }

  // ---------------- Generate incident response report ----------------
  function openGenerateReportModal(incidentsCount) {
    const body = openAppModal("Generate incident response report", { wide: true });

    if (!incidentsCount) {
      const empty = document.createElement("div");
      empty.className = "empty-note";
      empty.textContent = "No events are pinned to the timeline yet — add some before generating a report.";
      body.appendChild(empty);
      return;
    }

    const form = document.createElement("div");

    const titleGroup = document.createElement("div");
    titleGroup.className = "field-group";
    titleGroup.innerHTML = "<label>Report title</label>";
    const titleInput = document.createElement("input");
    titleInput.type = "text";
    titleInput.value = "Incident Response Report";
    titleGroup.appendChild(titleInput);
    form.appendChild(titleGroup);

    const byGroup = document.createElement("div");
    byGroup.className = "field-group";
    byGroup.innerHTML = "<label>Prepared by (optional)</label>";
    const byInput = document.createElement("input");
    byInput.type = "text";
    byInput.placeholder = "Analyst name";
    byGroup.appendChild(byInput);
    form.appendChild(byGroup);

    const hint = document.createElement("div");
    hint.className = "field-hint";
    hint.style.marginBottom = "10px";
    hint.textContent = `The LLM will draft a report from the ${incidentsCount} event${incidentsCount === 1 ? "" : "s"} currently pinned to this timeline. This can take a while depending on your model.`;
    form.appendChild(hint);

    const genBtn = document.createElement("button");
    genBtn.className = "btn-primary";
    genBtn.textContent = "Generate report";
    form.appendChild(genBtn);

    const resultMount = document.createElement("div");
    resultMount.style.marginTop = "14px";
    form.appendChild(resultMount);

    genBtn.addEventListener("click", async () => {
      genBtn.disabled = true;
      genBtn.innerHTML = '<span class="btn-spinner"></span>Generating… this may take a while';
      resultMount.innerHTML = "";
      try {
        const result = await fetchJSON("/api/incidents/report", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ title: titleInput.value.trim(), prepared_by: byInput.value.trim() }),
        });
        renderReportDraft(resultMount, titleInput.value.trim(), byInput.value.trim(), result.content);
      } catch (e) {
        const err = document.createElement("div");
        err.className = "llm-result llm-error";
        const t = document.createElement("div");
        t.className = "llm-error-text";
        t.textContent = e.message || "Report generation failed.";
        err.appendChild(t);
        resultMount.appendChild(err);
      }
      genBtn.disabled = false;
      genBtn.textContent = "Generate report";
    });

    body.appendChild(form);
  }

  function renderReportDraft(mount, title, preparedBy, content) {
    mount.innerHTML = "";
    const label = document.createElement("div");
    label.className = "field-hint";
    label.style.marginBottom = "6px";
    label.textContent = "Draft report (Markdown) — review and edit before exporting:";
    mount.appendChild(label);

    const textarea = document.createElement("textarea");
    textarea.className = "report-draft";
    textarea.value = content;
    mount.appendChild(textarea);

    const actions = document.createElement("div");
    actions.className = "settings-actions";
    const downloadBtn = document.createElement("button");
    downloadBtn.className = "btn-primary";
    downloadBtn.textContent = "⬇ Download Word document";
    downloadBtn.addEventListener("click", async () => {
      downloadBtn.disabled = true;
      downloadBtn.textContent = "Preparing…";
      try {
        const res = await fetch("/api/incidents/report/docx", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ title, prepared_by: preparedBy, content: textarea.value }),
        });
        if (!res.ok) throw new Error("Failed to generate document.");
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = (title || "incident_report").replace(/[^0-9a-zA-Z_.-]/g, "_") + ".docx";
        a.click();
        URL.revokeObjectURL(url);
      } catch (e) {
        alert(e.message || "Failed to download document.");
      }
      downloadBtn.disabled = false;
      downloadBtn.textContent = "⬇ Download Word document";
    });
    actions.appendChild(downloadBtn);
    mount.appendChild(actions);
  }

  function exportIncidentsCsv(incidents) {
    const cols = ["date_text", "severity", "sheet_name", "description", "computer", "note"];
    const lines = [cols.concat(["parent_id", "parent_description"]).join(",")];
    const byId = new Map(incidents.map((i) => [i.id, i]));
    const kids = new Map();
    incidents.forEach((i) => {
      if (i.parent_id == null) return;
      if (!kids.has(i.parent_id)) kids.set(i.parent_id, []);
      kids.get(i.parent_id).push(i);
    });
    const q = (v) => `"${String(v == null ? "" : v).replace(/"/g, '""')}"`;
    // Emit each finding followed by its sub-events, so the grouping survives in Excel.
    const emit = (inc) => {
      const parent = inc.parent_id != null ? byId.get(inc.parent_id) : null;
      lines.push(cols.map((c) => q(inc[c]))
        .concat([q(inc.parent_id), q(parent ? parent.description : "")]).join(","));
    };
    incidents.filter((i) => i.parent_id == null).forEach((p) => {
      emit(p);
      (kids.get(p.id) || []).sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0)).forEach(emit);
    });
    const blob = new Blob([lines.join("\n")], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "incident_timeline.csv";
    a.click();
    URL.revokeObjectURL(url);
  }

  // ---------------- Settings ----------------
  const LLM_PROVIDER_DEFAULT_URL = {
    ollama: "http://localhost:11434/v1",
    llmstudio: "http://localhost:1234/v1",
    "llama.cpp": "http://localhost:8080/v1",
  };

  async function selectSettings() {
    closeOpenPopover();
    state.view = "settings";
    state.currentSheet = null;
    setActiveNav(null, "settings");
    showView("settings");
    document.getElementById("report-title").textContent = "Settings";
    document.getElementById("report-meta").textContent = metaSubtitle();
    const settings = await fetchJSON("/api/settings");
    renderSettingsView(settings);
  }

  function renderSettingsView(settings) {
    const root = document.getElementById("view-settings");
    root.innerHTML = "";

    const card = document.createElement("div");
    card.className = "card settings-card";
    card.innerHTML = `<div class="card-title">LLM configuration</div>
      <div class="card-subtitle">Used by the "Check with LLM" and "Explain event" actions in the event detail panel. Requires a running OpenAI-compatible local LLM server (Ollama, LM Studio, llama.cpp).</div>`;

    const form = document.createElement("div");
    form.style.marginTop = "16px";

    const row1 = document.createElement("div");
    row1.className = "settings-row";

    const providerGroup = document.createElement("div");
    providerGroup.className = "field-group";
    providerGroup.innerHTML = "<label>Provider</label>";
    const providerSel = document.createElement("select");
    [["ollama", "Ollama"], ["llmstudio", "LM Studio"], ["llama.cpp", "llama.cpp"]].forEach(([val, label]) => {
      const opt = document.createElement("option");
      opt.value = val;
      opt.textContent = label;
      if (val === settings.llm_provider) opt.selected = true;
      providerSel.appendChild(opt);
    });
    providerGroup.appendChild(providerSel);
    row1.appendChild(providerGroup);

    const modelGroup = document.createElement("div");
    modelGroup.className = "field-group";
    modelGroup.innerHTML = "<label>Model name</label>";
    const modelInput = document.createElement("input");
    modelInput.type = "text";
    modelInput.value = settings.llm_model || "";
    modelInput.placeholder = "e.g. llama3";
    modelGroup.appendChild(modelInput);
    row1.appendChild(modelGroup);
    form.appendChild(row1);

    const urlGroup = document.createElement("div");
    urlGroup.className = "field-group";
    urlGroup.innerHTML = "<label>Base URL</label>";
    const urlInput = document.createElement("input");
    urlInput.type = "text";
    urlInput.value = settings.llm_base_url || "";
    urlInput.placeholder = LLM_PROVIDER_DEFAULT_URL[settings.llm_provider] || LLM_PROVIDER_DEFAULT_URL.ollama;
    urlGroup.appendChild(urlInput);
    const urlHint = document.createElement("div");
    urlHint.className = "field-hint";
    urlHint.textContent = "Leave blank to use the provider's default.";
    urlGroup.appendChild(urlHint);
    form.appendChild(urlGroup);

    providerSel.addEventListener("change", () => {
      urlInput.placeholder = LLM_PROVIDER_DEFAULT_URL[providerSel.value] || LLM_PROVIDER_DEFAULT_URL.ollama;
    });

    const row2 = document.createElement("div");
    row2.className = "settings-row";

    const keyGroup = document.createElement("div");
    keyGroup.className = "field-group";
    keyGroup.innerHTML = "<label>API key</label>";
    const keyInput = document.createElement("input");
    keyInput.type = "text";
    keyInput.value = settings.llm_api_key || "";
    keyInput.placeholder = "Optional — provider default is used if blank";
    keyGroup.appendChild(keyInput);
    row2.appendChild(keyGroup);

    const timeoutGroup = document.createElement("div");
    timeoutGroup.className = "field-group";
    timeoutGroup.innerHTML = "<label>Request timeout (seconds)</label>";
    const timeoutInput = document.createElement("input");
    timeoutInput.type = "number";
    timeoutInput.min = "5";
    timeoutInput.value = settings.llm_timeout || "200";
    timeoutGroup.appendChild(timeoutInput);
    row2.appendChild(timeoutGroup);
    form.appendChild(row2);

    const actions = document.createElement("div");
    actions.className = "settings-actions";
    const saveBtn = document.createElement("button");
    saveBtn.className = "btn-primary";
    saveBtn.textContent = "Save settings";
    const testBtn = document.createElement("button");
    testBtn.className = "ghost-btn";
    testBtn.textContent = "Test connection";
    const statusEl = document.createElement("span");
    statusEl.className = "settings-status";
    actions.appendChild(saveBtn);
    actions.appendChild(testBtn);
    actions.appendChild(statusEl);
    form.appendChild(actions);

    function collectValues() {
      return {
        llm_provider: providerSel.value,
        llm_model: modelInput.value.trim() || "llama3",
        llm_base_url: urlInput.value.trim(),
        llm_api_key: keyInput.value.trim(),
        llm_timeout: String(parseInt(timeoutInput.value, 10) || 200),
      };
    }

    saveBtn.addEventListener("click", async () => {
      saveBtn.disabled = true;
      statusEl.className = "settings-status";
      statusEl.textContent = "Saving…";
      try {
        await fetchJSON("/api/settings", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(collectValues()),
        });
        statusEl.className = "settings-status ok";
        statusEl.textContent = "Saved.";
      } catch (e) {
        statusEl.className = "settings-status error";
        statusEl.textContent = "Failed to save settings.";
      }
      saveBtn.disabled = false;
    });

    testBtn.addEventListener("click", async () => {
      testBtn.disabled = true;
      const prevText = testBtn.textContent;
      testBtn.textContent = "Testing…";
      statusEl.className = "settings-status";
      statusEl.textContent = "";
      try {
        const result = await fetchJSON("/api/settings/test", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(collectValues()),
        });
        statusEl.className = "settings-status " + (result.ok ? "ok" : "error");
        statusEl.textContent = result.message;
      } catch (e) {
        statusEl.className = "settings-status error";
        statusEl.textContent = "Test request failed.";
      }
      testBtn.disabled = false;
      testBtn.textContent = prevText;
    });

    card.appendChild(form);
    root.appendChild(card);
    renderTriageSettingsCard(settings, root);
  }

  // ---------------- Agentic triage ----------------
  const TRIAGE_STAGE_LABEL = {
    scope: "Reading report", cluster: "Clustering alerts", triage: "Triaging clusters",
    pivot: "Gathering context", investigate: "Investigating leads",
    correlate: "Linking attack chains", finalize: "Building findings",
  };
  const triageUi = { pollTimer: null };

  function fmtEpoch(ts) {
    return typeof ts === "number" ? new Date(ts * 1000).toLocaleString() : "—";
  }

  function fmtClock(ts) {
    return typeof ts === "number" ? new Date(ts * 1000).toLocaleTimeString() : "—";
  }

  function fmtDuration(seconds) {
    if (typeof seconds !== "number" || seconds < 0) return "—";
    const s = Math.round(seconds);
    if (s < 60) return `${s}s`;
    const m = Math.floor(s / 60);
    if (m < 60) return `${m}m ${String(s % 60).padStart(2, "0")}s`;
    return `${Math.floor(m / 60)}h ${String(m % 60).padStart(2, "0")}m`;
  }

  function describeScope(scope) {
    if (!scope) return "—";
    const parts = [];
    parts.push(scope.severity_min ? `${scope.severity_min}+` : "any severity");
    const hosts = scope.computers || [];
    if (hosts.length === 1) parts.push(hosts[0]);
    else if (hosts.length > 1) parts.push(`${hosts.length} hosts`);
    else parts.push("all hosts");
    if (scope.start || scope.end) parts.push("time-filtered");
    return parts.join(" · ");
  }

  function stopTriagePolling() {
    if (triageUi.pollTimer) clearInterval(triageUi.pollTimer);
    if (triageUi.tickTimer) clearInterval(triageUi.tickTimer);
    triageUi.pollTimer = null;
    triageUi.tickTimer = null;
  }

  async function selectTriage() {
    closeOpenPopover();
    state.view = "triage";
    state.currentSheet = null;
    setActiveNav(null, "triage");
    showView("triage");
    document.getElementById("report-title").textContent = "Agentic Triage";
    document.getElementById("report-meta").textContent = metaSubtitle();
    await renderTriageView();
  }

  async function renderTriageView(runId) {
    const root = document.getElementById("view-triage");
    const qs = runId ? `?run_id=${runId}` : "";
    const [status, data, history] = await Promise.all([
      fetchJSON("/api/triage/status"),
      fetchJSON("/api/triage/findings" + qs),
      fetchJSON("/api/triage/runs").catch(() => ({ runs: [] })),
    ]);
    triageUi.viewingRun = data.run ? data.run.id : null;
    triageUi.latestRunId = (history.runs || []).reduce(
      (max, r) => (r.id > max ? r.id : max), 0) || null;
    root.innerHTML = "";

    const head = document.createElement("div");
    head.className = "card";
    head.innerHTML = `<div class="card-title">Agentic alert triage</div>
      <div class="card-subtitle">Clusters similar alerts, has the LLM judge each cluster (pulling extra context when it is unsure), then links related findings into attack chains. Accepted findings are added to the Incident Timeline.</div>`;
    const runRow = document.createElement("div");
    runRow.className = "settings-actions";
    const runBtn = document.createElement("button");
    runBtn.className = "btn-primary";
    runBtn.textContent = "Run triage…";
    runBtn.disabled = status.status === "running";
    runBtn.addEventListener("click", openTriageRunModal);
    runRow.appendChild(runBtn);
    head.appendChild(runRow);
    root.appendChild(head);

    const progressMount = document.createElement("div");
    progressMount.id = "triage-progress";
    root.appendChild(progressMount);
    const historyMount = document.createElement("div");
    historyMount.id = "triage-history";
    root.appendChild(historyMount);

    const findingsMount = document.createElement("div");
    findingsMount.id = "triage-findings";
    root.appendChild(findingsMount);

    renderTriageProgress(status);
    renderRunHistory(history.runs || [], data.run);
    renderTriageFindings(data);
    if (status.status === "running") startTriagePolling();
  }

  function renderRunHistory(runs, current) {
    const mount = document.getElementById("triage-history");
    if (!mount) return;
    mount.innerHTML = "";
    if (!runs.length) return;

    const card = document.createElement("div");
    card.className = "card";
    card.style.marginTop = "16px";
    card.innerHTML = `<div class="card-title">Run history</div>
      <div class="card-subtitle">Every triage run on this report. Click one to see the findings it produced.</div>`;

    const table = document.createElement("table");
    table.className = "data-grid run-history";
    table.innerHTML = `<thead><tr>
        <th>Started</th><th>Finished</th><th>Duration</th><th>Scope</th>
        <th>Status</th><th>Alerts</th><th>Clusters</th><th>Findings</th><th>LLM calls</th>
      </tr></thead>`;
    const tb = document.createElement("tbody");

    runs.forEach((r) => {
      const tr = document.createElement("tr");
      tr.className = "run-row";
      if (current && r.id === current.id) tr.classList.add("run-current");

      const add = (text, title) => {
        const td = document.createElement("td");
        td.textContent = text;
        if (title) td.title = title;
        tr.appendChild(td);
        return td;
      };
      add(fmtEpoch(r.started_at));
      add(r.running ? "in progress" : fmtClock(r.finished_at),
          r.finished_at ? fmtEpoch(r.finished_at) : "");
      const dur = add(fmtDuration(r.duration));
      if (r.running) {
        dur.classList.add("run-live");
        dur.dataset.startedAt = r.started_at || "";
      }
      add(describeScope(r.scope), JSON.stringify(r.scope || {}));

      const tdStatus = document.createElement("td");
      const pill = document.createElement("span");
      pill.className = "run-status run-status-" + (r.status || "unknown");
      pill.textContent = r.status || "unknown";
      if (r.error) pill.title = r.error;
      tdStatus.appendChild(pill);
      tr.appendChild(tdStatus);

      const s = r.stats || {};
      add(s.alerts != null ? Charts.formatNum(s.alerts) : "—");
      add(s.clusters != null ? Charts.formatNum(s.clusters) : "—");
      const parts = Object.entries(r.finding_counts || {})
        .map(([k, v]) => `${v} ${k.replace("_", " ")}`).join(", ");
      add(String(r.finding_total || 0), parts);
      add(s.llm_calls != null ? String(s.llm_calls) : "—",
          s.timings ? Object.entries(s.timings).map(([k, v]) => `${k}: ${fmtDuration(v)}`).join("\n") : "");

      if (r.finding_total) {
        tr.classList.add("run-clickable");
        tr.addEventListener("click", () => renderTriageView(r.id));
      }
      tb.appendChild(tr);
    });

    table.appendChild(tb);
    const wrap = document.createElement("div");
    wrap.className = "table-wrap";
    wrap.appendChild(table);
    card.appendChild(wrap);
    mount.appendChild(card);
  }

  function tickElapsed() {
    // Cheap local tick so the clock moves between the 2s status polls.
    document.querySelectorAll(".triage-elapsed, .run-live").forEach((el) => {
      const started = parseFloat(el.dataset.startedAt);
      if (!started) return;
      const d = fmtDuration(Date.now() / 1000 - started);
      if (el.classList.contains("run-live")) el.textContent = d;
      else el.textContent = `Started ${fmtEpoch(started)} · running ${d}`;
    });
  }

  function startTriagePolling() {
    stopTriagePolling();
    triageUi.tickTimer = setInterval(tickElapsed, 1000);
    triageUi.pollTimer = setInterval(async () => {
      if (state.view !== "triage") { stopTriagePolling(); return; }
      let status;
      try { status = await fetchJSON("/api/triage/status"); } catch (e) { return; }
      renderTriageProgress(status);
      if (status.status !== "running") {
        stopTriagePolling();
        await renderTriageView();
      }
    }, 2000);
  }

  function renderTriageProgress(status) {
    const mount = document.getElementById("triage-progress");
    if (!mount) return;
    mount.innerHTML = "";
    if (status.status === "idle") return;

    const card = document.createElement("div");
    card.className = "card triage-progress";
    const line = document.createElement("div");
    line.className = "triage-progress-line";
    if (status.status === "running") {
      const label = document.createElement("strong");
      label.textContent = TRIAGE_STAGE_LABEL[status.stage] || status.stage;
      line.appendChild(label);
      const msg = document.createElement("span");
      msg.className = "triage-progress-msg";
      msg.textContent = status.message ? ` — ${status.message}` : "";
      line.appendChild(msg);
      card.appendChild(line);
      const bar = document.createElement("div");
      bar.className = "triage-bar";
      const fill = document.createElement("div");
      fill.className = "triage-bar-fill";
      const pct = status.total ? Math.min(100, Math.round((status.done / status.total) * 100)) : 0;
      fill.style.width = pct + "%";
      bar.appendChild(fill);
      card.appendChild(bar);
      if (status.started_at) {
        const elapsed = document.createElement("div");
        elapsed.className = "triage-progress-msg triage-elapsed";
        elapsed.dataset.startedAt = status.started_at;
        elapsed.textContent = `Started ${fmtEpoch(status.started_at)} · running ${fmtDuration(Date.now() / 1000 - status.started_at)}`;
        card.appendChild(elapsed);
      }
      const cancelBtn = document.createElement("button");
      cancelBtn.className = "ghost-btn";
      cancelBtn.textContent = "Cancel run";
      cancelBtn.addEventListener("click", async () => {
        cancelBtn.disabled = true;
        cancelBtn.textContent = "Cancelling…";
        await fetchJSON("/api/triage/cancel", { method: "POST" });
      });
      card.appendChild(cancelBtn);
    } else {
      const s = status.stats || {};
      const parts = {
        completed: "Last run completed", cancelled: "Last run was cancelled (partial results shown)",
        failed: "Last run failed",
      };
      line.className += " triage-status-" + status.status;
      const noAlerts = status.status === "completed" && s.alerts === 0;
      if (noAlerts) line.className += " triage-status-failed";
      line.textContent = (noAlerts ? "Last run matched no alerts, so nothing was triaged" : (parts[status.status] || status.status))
        + (status.status === "failed" && status.error ? `: ${status.error}` : "")
        + (s.alerts ? ` — ${s.alerts} alerts → ${s.clusters} clusters → ${s.findings || 0} findings (${s.llm_calls} LLM calls)` : "");
      card.appendChild(line);
      if (s.aborted || s.failed) {
        const warn = document.createElement("div");
        warn.className = "triage-progress-msg triage-status-failed";
        warn.style.marginTop = "6px";
        warn.textContent = [
          s.aborted || "",
          s.failed ? `${s.failed} cluster${s.failed === 1 ? "" : "s"} got no answer from the LLM and are flagged for manual review.` : "",
        ].filter(Boolean).join(" ");
        card.appendChild(warn);
      }
      if (status.started_at) {
        const when = document.createElement("div");
        when.className = "triage-progress-msg";
        when.style.marginTop = "6px";
        const finished = s.finished_at || status.finished_at;
        when.textContent = `Started ${fmtEpoch(status.started_at)}`
          + (finished ? ` · finished ${fmtClock(finished)}` : "")
          + (s.duration != null ? ` · took ${fmtDuration(s.duration)}` : "")
          + (s.timings ? ` (${Object.entries(s.timings)
              .filter(([, v]) => v >= 1)
              .map(([k, v]) => `${TRIAGE_STAGE_LABEL[k] || k} ${fmtDuration(v)}`).join(", ")})` : "");
        card.appendChild(when);
      }
      if (s.alerts) {
        const sub = document.createElement("div");
        sub.className = "triage-progress-msg";
        sub.style.marginTop = "6px";
        sub.textContent = s.agent
          ? `Investigation agent: ${s.leads_examined || 0} of ${s.leads || 0} leads examined, `
            + `${s.agent_tools || 0} tool calls (${s.agent_stop || "finished"}). `
            + `Leads it did not examine still appear as first-pass findings.`
          : "Investigation agent off or unsupported by this LLM — used the fixed pivot/correlate pipeline.";
        card.appendChild(sub);
      }
    }
    mount.appendChild(card);
  }

  function renderTriageFindings(data) {
    const mount = document.getElementById("triage-findings");
    if (!mount) return;
    mount.innerHTML = "";
    const findings = data.findings || [];
    if (!findings.length) {
      const empty = document.createElement("div");
      empty.className = "empty-note";
      empty.textContent = data.run
        ? "The last run produced no findings."
        : "No triage runs yet. Click “Run triage…” to start.";
      mount.appendChild(empty);
      return;
    }

    const pending = findings.filter((f) => f.status === "pending").length;
    const bar = document.createElement("div");
    bar.className = "incident-toolbar";
    const title = document.createElement("div");
    const run = data.run || {};
    title.innerHTML = `<strong>${findings.length}</strong> finding${findings.length === 1 ? "" : "s"} · <strong>${pending}</strong> awaiting review`;
    if (run.started_at) {
      const sub = document.createElement("div");
      sub.className = "field-hint";
      sub.style.marginTop = "2px";
      sub.textContent = `From the run of ${fmtEpoch(run.started_at)}`
        + (run.duration != null && !run.running ? ` · took ${fmtDuration(run.duration)}` : "");
      title.appendChild(sub);
    }
    bar.appendChild(title);
    if (triageUi.latestRunId && run.id && run.id !== triageUi.latestRunId) {
      const back = document.createElement("button");
      back.className = "ghost-btn";
      back.textContent = "← Back to latest run";
      back.addEventListener("click", () => renderTriageView());
      bar.appendChild(back);
    }
    if (pending) {
      const acceptAll = document.createElement("button");
      acceptAll.className = "ghost-btn";
      acceptAll.textContent = `Accept all ${pending} pending`;
      acceptAll.addEventListener("click", async () => {
        if (!confirm(`Add all ${pending} pending findings to the incident timeline?`)) return;
        await fetchJSON("/api/triage/findings/accept-all", { method: "POST" });
        renderTriageView(triageUi.viewingRun);
      });
      bar.appendChild(acceptAll);
    }
    mount.appendChild(bar);

    findings.forEach((f) => mount.appendChild(buildFindingCard(f)));
  }

  function buildFindingCard(f) {
    const card = document.createElement("div");
    card.className = "card finding-card finding-" + f.status;

    const top = document.createElement("div");
    top.className = "finding-top";
    const score = document.createElement("span");
    score.className = "finding-score";
    score.textContent = f.score;
    top.appendChild(score);
    const titleWrap = document.createElement("div");
    titleWrap.className = "finding-title-wrap";
    const title = document.createElement("div");
    title.className = "finding-title";
    title.textContent = f.title;
    titleWrap.appendChild(title);
    const meta = document.createElement("div");
    meta.className = "finding-meta";
    const isChain = (f.cluster_key || "").startsWith("chain:");
    meta.textContent = [
      isChain ? "Attack chain" : null,
      f.examined_by_agent ? "Investigated" : null,
      f.computer, f.mitre,
      `${f.event_count} event${f.event_count === 1 ? "" : "s"}`,
      `${fmtEpoch(f.first_ts)} → ${fmtEpoch(f.last_ts)}`,
    ].filter(Boolean).join(" · ");
    titleWrap.appendChild(meta);
    top.appendChild(titleWrap);
    const sev = document.createElement("span");
    sev.className = "sev-badge " + severityClass(f.severity);
    sev.textContent = f.severity;
    top.appendChild(sev);
    const verdict = document.createElement("span");
    verdict.className = "verdict-pill verdict-" + f.verdict;
    verdict.textContent = f.verdict;
    top.appendChild(verdict);
    card.appendChild(top);

    if (f.narrative) {
      const n = document.createElement("div");
      n.className = "finding-narrative";
      n.textContent = f.narrative;
      card.appendChild(n);
    }

    if ((f.evidence || []).length) {
      const det = document.createElement("details");
      det.className = "finding-evidence";
      const sum = document.createElement("summary");
      sum.textContent = `Evidence (${f.evidence.length} event${f.evidence.length === 1 ? "" : "s"} shown)`;
      det.appendChild(sum);
      const table = document.createElement("table");
      table.className = "data-grid";
      table.innerHTML = "<thead><tr><th>Time</th><th>Sheet</th><th>Rule</th><th>Description</th></tr></thead>";
      const tb = document.createElement("tbody");
      f.evidence.forEach((e) => {
        const tr = document.createElement("tr");
        [e.date || fmtEpoch(e.timestamp), e.sheet, e.rule, e.description].forEach((v) => {
          const td = document.createElement("td");
          td.textContent = v || "";
          tr.appendChild(td);
        });
        tb.appendChild(tr);
      });
      table.appendChild(tb);
      det.appendChild(table);
      card.appendChild(det);
    }

    if ((f.tool_trace || []).length) {
      const det = document.createElement("details");
      det.className = "finding-evidence";
      const sum = document.createElement("summary");
      sum.textContent = `Investigation trace (${f.tool_trace.length} tool call${f.tool_trace.length === 1 ? "" : "s"})`;
      det.appendChild(sum);
      const ol = document.createElement("ol");
      ol.className = "finding-trace";
      f.tool_trace.forEach((t) => {
        const li = document.createElement("li");
        li.textContent = t.summary || t.tool || "";
        ol.appendChild(li);
      });
      det.appendChild(ol);
      card.appendChild(det);
    }

    const actions = document.createElement("div");
    actions.className = "finding-actions";
    if (f.status === "pending") {
      const decide = (path, body) => async (e) => {
        e.target.disabled = true;
        try {
          await fetchJSON(`/api/triage/findings/${f.id}/${path}`, {
            method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}),
          });
          renderTriageView(triageUi.viewingRun);
        } catch (err) { alert(err.message); e.target.disabled = false; }
      };
      const accept = document.createElement("button");
      accept.className = "btn-primary";
      accept.textContent = "Accept → timeline";
      accept.title = "Adds the finding to the incident timeline, with its evidence attached as sub-events";
      accept.addEventListener("click", decide("accept"));
      actions.appendChild(accept);
      const reject = document.createElement("button");
      reject.className = "ghost-btn";
      reject.textContent = "Reject";
      reject.addEventListener("click", decide("reject"));
      actions.appendChild(reject);
    } else {
      const st = document.createElement("span");
      st.className = "finding-decided";
      st.textContent = f.status === "rejected" ? "Rejected"
        : f.status === "auto_accepted" ? "Auto-added to timeline" : "Added to timeline";
      actions.appendChild(st);
      if (f.status !== "rejected") {
        const link = document.createElement("button");
        link.className = "ghost-btn";
        link.textContent = "View timeline";
        link.addEventListener("click", selectIncidents);
        actions.appendChild(link);
      }
    }
    card.appendChild(actions);
    return card;
  }

  async function openTriageRunModal() {
    const body = openAppModal("Run agentic triage");
    const form = document.createElement("div");

    const sevGroup = document.createElement("div");
    sevGroup.className = "field-group";
    sevGroup.innerHTML = "<label>Minimum severity</label>";
    const sevSel = document.createElement("select");
    [["", "Any"], ["Low", "Low and above"], ["Medium", "Medium and above"], ["High", "High and above"], ["Critical", "Critical only"]]
      .forEach(([v, l]) => {
        const o = document.createElement("option");
        o.value = v; o.textContent = l;
        if (v === "High") o.selected = true;
        sevSel.appendChild(o);
      });
    sevGroup.appendChild(sevSel);
    form.appendChild(sevGroup);

    const compGroup = document.createElement("div");
    compGroup.className = "field-group";
    compGroup.innerHTML = "<label>Computers</label>";
    const compList = document.createElement("div");
    compList.className = "triage-computers";
    compList.textContent = "Loading…";
    compGroup.appendChild(compList);
    const compHint = document.createElement("div");
    compHint.className = "field-hint";
    compHint.textContent = "Leave all unchecked to include every computer.";
    compGroup.appendChild(compHint);
    form.appendChild(compGroup);

    const row = document.createElement("div");
    row.className = "settings-row";
    const mkTime = (label) => {
      const g = document.createElement("div");
      g.className = "field-group";
      g.innerHTML = `<label>${label} (local time, optional)</label>`;
      const i = document.createElement("input");
      i.type = "datetime-local";
      g.appendChild(i);
      row.appendChild(g);
      return i;
    };
    const startIn = mkTime("From");
    const endIn = mkTime("To");
    form.appendChild(row);
    const spanHint = document.createElement("div");
    spanHint.className = "field-hint";
    form.appendChild(spanHint);
    fetchJSON("/api/triage/scope").then((d) => {
      if (d.first_ts != null) {
        spanHint.textContent = `This report's alerts span ${fmtEpoch(d.first_ts)} → ${fmtEpoch(d.last_ts)} (${d.matched} alerts). Times outside this range match nothing.`;
      }
    }).catch(() => {});

    const pinGroup = document.createElement("div");
    pinGroup.className = "field-group";
    pinGroup.innerHTML = "<label>Auto-add findings scoring at or above (optional)</label>";
    const pinIn = document.createElement("input");
    pinIn.type = "number"; pinIn.min = "0"; pinIn.max = "100";
    pinIn.placeholder = "Blank = use the value from Settings (default: review everything)";
    pinGroup.appendChild(pinIn);
    form.appendChild(pinGroup);

    const actions = document.createElement("div");
    actions.className = "settings-actions";
    const go = document.createElement("button");
    go.className = "btn-primary";
    go.textContent = "Start triage";
    const err = document.createElement("span");
    err.className = "settings-status error";
    actions.appendChild(go);
    actions.appendChild(err);
    form.appendChild(actions);
    body.appendChild(form);

    // Union of computer names across the event sheets.
    const names = new Set();
    await Promise.all(state.meta.sheets
      .filter((s) => s.kind === "event" && s.name !== "LLM Analysis" && s.row_count > 0)
      .map(async (s) => {
        try {
          const d = await fetchJSON(`/api/sheets/${encodeURIComponent(s.name)}/distinct?column=${encodeURIComponent("Computer Name")}`);
          d.values.forEach((v) => v.value && names.add(v.value));
        } catch (e) { /* sheet has no Computer Name column */ }
      }));
    compList.textContent = "";
    if (!names.size) compList.textContent = "No computers found.";
    [...names].sort().forEach((n) => {
      const lab = document.createElement("label");
      lab.className = "triage-computer";
      const cb = document.createElement("input");
      cb.type = "checkbox"; cb.value = n;
      lab.appendChild(cb);
      lab.appendChild(document.createTextNode(" " + n));
      compList.appendChild(lab);
    });

    const toEpoch = (el) => (el.value ? new Date(el.value).getTime() / 1000 : null);
    go.addEventListener("click", async () => {
      go.disabled = true;
      err.textContent = "";
      try {
        await fetchJSON("/api/triage/run", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            severity_min: sevSel.value,
            computers: [...compList.querySelectorAll("input:checked")].map((c) => c.value),
            start: toEpoch(startIn), end: toEpoch(endIn),
            auto_pin_threshold: pinIn.value === "" ? null : Number(pinIn.value),
          }),
        });
        closeAppModal();
        renderTriageView();
      } catch (e) {
        err.textContent = e.message;
        go.disabled = false;
      }
    });
  }

  function renderTriageSettingsCard(settings, root) {
    const card = document.createElement("div");
    card.className = "card settings-card";
    card.style.marginTop = "16px";
    card.innerHTML = `<div class="card-title">Agentic triage</div>
      <div class="card-subtitle">Findings wait in the review queue unless they score at or above the auto-add threshold.</div>`;

    const agentGroup = document.createElement("div");
    agentGroup.className = "field-group";
    agentGroup.style.marginTop = "16px";
    const agentLabel = document.createElement("label");
    const agentCb = document.createElement("input");
    agentCb.type = "checkbox";
    agentCb.checked = String(settings.triage_agent_enabled || "1") !== "0";
    agentLabel.appendChild(agentCb);
    agentLabel.appendChild(document.createTextNode(" Let the agent investigate leads with tools"));
    agentGroup.appendChild(agentLabel);
    const agentHint = document.createElement("div");
    agentHint.className = "field-hint";
    agentHint.textContent = "After every cluster has a first-pass verdict, the agent searches, reads events and "
      + "walks the timeline to link leads into attack chains. Needs an LLM that supports tool calling — "
      + "if yours does not, the fixed pipeline is used instead. Turning this off never reduces coverage.";
    agentGroup.appendChild(agentHint);
    card.appendChild(agentGroup);

    const fastGroup = document.createElement("div");
    fastGroup.className = "field-group";
    const fastLabel = document.createElement("label");
    const fastCb = document.createElement("input");
    fastCb.type = "checkbox";
    fastCb.checked = String(settings.triage_fast_first_pass || "1") !== "0";
    fastLabel.appendChild(fastCb);
    fastLabel.appendChild(document.createTextNode(" Skip the model's thinking pass when classifying clusters"));
    fastGroup.appendChild(fastLabel);
    const fastHint = document.createElement("div");
    fastHint.className = "field-hint";
    fastHint.textContent = "Reasoning models spend most of their time thinking. For the first-pass verdict that "
      + "measured ~5x slower with no change to the verdict, so it is skipped by default. The investigation "
      + "agent always keeps its reasoning. Ignored by servers that do not support the option.";
    fastGroup.appendChild(fastHint);
    card.appendChild(fastGroup);

    const row = document.createElement("div");
    row.className = "settings-row";
    row.style.marginTop = "16px";
    const mk = (container, label, key, placeholder, hint) => {
      const g = document.createElement("div");
      g.className = "field-group";
      g.innerHTML = `<label>${label}</label>`;
      const i = document.createElement("input");
      i.type = "number"; i.min = "0";
      i.value = settings[key] || "";
      i.placeholder = placeholder;
      g.appendChild(i);
      const h = document.createElement("div");
      h.className = "field-hint";
      h.textContent = hint;
      g.appendChild(h);
      container.appendChild(g);
      return i;
    };
    const pinIn = mk(row, "Auto-add threshold (0–100)", "triage_auto_pin_threshold", "Off",
      "Blank = never auto-add. Every finding goes to the review queue.");
    const pivotIn = mk(row, "Max context lookups per run", "triage_max_pivots", "20",
      "Caps the fixed pipeline's context lookups (used when the agent is off).");
    card.appendChild(row);

    const row2 = document.createElement("div");
    row2.className = "settings-row";
    const roundsIn = mk(row2, "Agent tool rounds", "triage_agent_rounds", "40",
      "Hard cap on investigation steps per run.");
    const secondsIn = mk(row2, "Agent time limit (seconds)", "triage_agent_seconds", "900",
      "Investigation stops here even if the agent is not done.");
    card.appendChild(row2);

    const actions = document.createElement("div");
    actions.className = "settings-actions";
    const save = document.createElement("button");
    save.className = "btn-primary";
    save.textContent = "Save triage settings";
    const status = document.createElement("span");
    status.className = "settings-status";
    actions.appendChild(save);
    actions.appendChild(status);
    card.appendChild(actions);
    save.addEventListener("click", async () => {
      save.disabled = true;
      try {
        await fetchJSON("/api/settings", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            triage_auto_pin_threshold: pinIn.value.trim(),
            triage_max_pivots: String(parseInt(pivotIn.value, 10) || 20),
            triage_agent_enabled: agentCb.checked ? "1" : "0",
            triage_agent_rounds: String(parseInt(roundsIn.value, 10) || 40),
            triage_agent_seconds: String(parseInt(secondsIn.value, 10) || 900),
            triage_fast_first_pass: fastCb.checked ? "1" : "0",
          }),
        });
        status.className = "settings-status ok";
        status.textContent = "Saved.";
      } catch (e) {
        status.className = "settings-status error";
        status.textContent = "Failed to save settings.";
      }
      save.disabled = false;
    });
    root.appendChild(card);
  }

  // ---------------- Init ----------------
  async function init() {
    initTheme();
    document.getElementById("drawer-close").addEventListener("click", closeDrawer);
    document.getElementById("drawer-backdrop").addEventListener("click", closeDrawer);
    document.getElementById("app-modal-close").addEventListener("click", closeAppModal);
    document.getElementById("app-modal-backdrop").addEventListener("click", closeAppModal);
    document.getElementById("refresh-btn").addEventListener("click", () => {
      if (state.view === "dashboard") selectDashboard();
      else if (state.view === "incidents") loadIncidents();
      else if (state.view === "triage") selectTriage();
      else if (state.view === "settings") selectSettings();
      else if (state.currentSheet) loadSheetRows(state.sheetsByName[state.currentSheet]);
    });

    document.addEventListener("click", (e) => {
      if (state.openPopover && state.openPopover.el.contains(e.target)) return;
      closeOpenPopover();
    });

    window.addEventListener("resize", debounce(() => {
      if (state.view === "dashboard" && state.dashboardData) renderDashboard(state.dashboardData);
      if (state.view === "incidents") loadIncidents();
    }, 200));

    const meta = await fetchJSON("/api/meta");
    state.meta = meta;
    meta.sheets.forEach((s) => { state.sheetsByName[s.name] = s; });
    buildSidebar();
    document.getElementById("report-meta").textContent = metaSubtitle();
    await selectDashboard();
  }

  function debounce(fn, ms) {
    let t = null;
    return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
  }

  document.addEventListener("DOMContentLoaded", init);
})();
