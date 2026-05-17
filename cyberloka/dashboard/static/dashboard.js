// Vanilla-JS line chart for host trend. Zero external deps.

(function () {
  const canvas = document.getElementById("trend-chart");
  if (!canvas) return;
  const host = canvas.dataset.host;
  if (!host) return;

  fetch(`/api/host/${encodeURIComponent(host)}/trend`)
    .then((r) => r.json())
    .then((data) => render(canvas, data))
    .catch(() => {});

  function render(canvas, data) {
    if (!data || data.length === 0) return;
    const dpr = window.devicePixelRatio || 1;
    const cssW = canvas.clientWidth || 720;
    const cssH = canvas.clientHeight || 240;
    canvas.width = cssW * dpr;
    canvas.height = cssH * dpr;
    const ctx = canvas.getContext("2d");
    ctx.scale(dpr, dpr);

    // Layout
    const pad = { l: 40, r: 16, t: 16, b: 30 };
    const w = cssW - pad.l - pad.r;
    const h = cssH - pad.t - pad.b;

    // Axes (score 0-100, x indexed)
    ctx.fillStyle = "#1a1d27";
    ctx.fillRect(0, 0, cssW, cssH);
    ctx.strokeStyle = "#2a2f3d";
    ctx.lineWidth = 1;

    // gridlines for 0,25,50,75,100
    ctx.fillStyle = "#8a94a6";
    ctx.font = "11px ui-monospace, monospace";
    for (let v = 0; v <= 100; v += 25) {
      const y = pad.t + h - (v / 100) * h;
      ctx.beginPath();
      ctx.moveTo(pad.l, y);
      ctx.lineTo(pad.l + w, y);
      ctx.stroke();
      ctx.fillText(String(v), 8, y + 3);
    }

    if (data.length === 1) {
      // single point: dot in the middle
      data = [data[0], data[0]];
    }
    const xStep = w / (data.length - 1);

    // Line
    ctx.strokeStyle = "#8b5cf6";
    ctx.lineWidth = 2;
    ctx.beginPath();
    data.forEach((d, i) => {
      const x = pad.l + i * xStep;
      const y = pad.t + h - (d.score / 100) * h;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();

    // Points (color by grade)
    const gradeColor = {
      "A+": "#10b981",
      A: "#22c55e",
      B: "#06b6d4",
      C: "#eab308",
      D: "#f97316",
      F: "#ef4444",
    };
    data.forEach((d, i) => {
      const x = pad.l + i * xStep;
      const y = pad.t + h - (d.score / 100) * h;
      ctx.fillStyle = gradeColor[d.grade] || "#8b5cf6";
      ctx.beginPath();
      ctx.arc(x, y, 5, 0, Math.PI * 2);
      ctx.fill();
    });

    // X labels (show first, middle, last to avoid overlap)
    ctx.fillStyle = "#8a94a6";
    const showIdx = new Set([0, Math.floor((data.length - 1) / 2), data.length - 1]);
    data.forEach((d, i) => {
      if (!showIdx.has(i)) return;
      const x = pad.l + i * xStep;
      const lbl = (d.generated_at || "").slice(0, 10);
      ctx.fillText(lbl, x - 30, pad.t + h + 18);
    });

    // Click to navigate
    canvas.addEventListener("click", (ev) => {
      const rect = canvas.getBoundingClientRect();
      const cx = ev.clientX - rect.left;
      const i = Math.round((cx - pad.l) / xStep);
      const d = data[i];
      if (d && d.scan_id) {
        window.location.href = `/scan/${encodeURIComponent(d.scan_id)}`;
      }
    });
  }
})();
