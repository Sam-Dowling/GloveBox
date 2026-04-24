// ════════════════════════════════════════════════════════════════════════════
// app-bg.js — Subtle per-theme animated background for the landing surface.
//
// A single <canvas id="bg-canvas"> is injected as the first child of <body>,
// fixed to the viewport at z-index:-1 so body's own background paints beneath
// it and every opaque chrome surface (toolbar, sidebar, loaded viewer panes)
// paints above it. The canvas is hidden entirely via CSS when:
//   • a file is loaded     →  body:has(#drop-zone.has-document)
//   • theme-midnight       →  OLED pure-black stays pure-black
//   • prefers-reduced-motion
//
// Five engines, one picked per theme:
//   penroseLight — light baseline: aperiodic P3 rhombic tiling in soft
//                  blue / warm lavender. Slightly larger tiles and faster
//                  breathing than the Solarized variant for an airier feel.
//                  Non-interactive.
//   networkDark  — dark baseline: wandering nodes connected by fading
//                  lines when within proximity (network / plexus effect).
//                  Cool white nodes, accent cyan connections. Slow ambient
//                  drift — no cursor interaction. Non-interactive.
//   cuteKitties  — mocha: ~14 floating kitten silhouettes with gentle
//                  upward drift; cursor acts as a breeze that pushes
//                  nearby shapes away.
//   cuteHearts   — latte: same physics, simple hearts instead.
//   penrose      — solarized: aperiodic P3 rhombic tiling (thick + thin
//                  golden-ratio rhombs) built by recursive subdivision from
//                  a ring of thick rhombs. Tiling is static; per-tile
//                  fill alpha breathes on independent phases.
//                  Alpha is intentionally whisper-low.
//
// The engine-per-theme map treats "midnight" as null (no canvas painted) and
// any theme not in the map falls through to the `penroseLight` baseline.
//
// Frame-rate policy: the three Penrose engines are throttled to ~24 fps via
// a timestamp gate inside the RAF loop — the motion is slow enough that
// 60 fps draws are wasted work and a measurable CPU drain. The physics
// engines (`cuteHearts`, `cuteKitties`) keep 60 fps so cursor-breeze
// response stays crisp.
//
// No eval, no `new Function`, no network, no new vendor deps, no new
// localStorage keys. Honours `prefers-reduced-motion` dynamically and pauses
// the animation loop when the tab is hidden (`visibilitychange`).
//
// Wiring:
//   • app-core.js::init() calls  window.BgCanvas.init()  last-ish.
//   • app-ui.js::_setTheme()  calls  window.BgCanvas.setTheme(id)  after
//     applying the body class.  First-boot: BgCanvas.init() reads whatever
//     theme class is already on <body> (set by the FOUC-prevention script in
//     build.py) so the correct engine spins up on the first frame.
//
// Exposes `window.BgCanvas = { init, setTheme }`.
// ════════════════════════════════════════════════════════════════════════════

(function () {
  'use strict';

  // Per-theme engine picker. Midnight intentionally maps to null — the canvas
  // stays present but drawn-empty so the CSS rule can also flip display:none
  // for belt-and-suspenders. Anything not listed here falls through to the
  // `penroseLight` baseline at call-time.
  const THEME_ENGINES = {
    light:     'penroseLight',
    dark:      'networkDark',
    mocha:     'cuteKitties',
    latte:     'cuteHearts',
    solarized: 'penrose',
    midnight:  null,
  };

  // Hard-coded RGB tuples per theme. Kept here (not read from computed CSS
  // vars at render time) so the animation stays glitch-free across a theme
  // switch — the engine rebuilds its palette on setTheme(), never mid-loop.
  const PALETTES = {
    // Penrose palette for the light baseline — soft blue for thick rhombs,
    // warm lavender for thin rhombs. Reads as a faint watermark against the
    // paper-white body, resolving into a tiling only on deliberate inspection.
    light: {
      penroseThick: [26, 115, 232],   // Google-blue — carried over from the old moiré
      penroseThin:  [142, 120, 180],   // Warm lavender — second species contrast
    },
    // Network palette for the dark baseline — cool white nodes, accent
    // cyan connection lines. Lower alpha than Solarized because dark
    // backgrounds make geometry more prominent at the same fill level.
    dark: {
      nodeColor: [230, 240, 255],   // Cool white — nodes
      lineColor: [120, 200, 255],   // Accent cyan — connections
    },
    mocha: { cute: [[203, 166, 247], [245, 194, 231], [180, 190, 254], [249, 226, 175]] },
    latte: { cute: [[136, 57, 239], [234, 118, 203], [114, 135, 253], [223, 142, 29]]  },
    // Penrose P3 rhomb fills / strokes — thick (fat) rhombs in Solarized
    // yellow, thin (skinny) rhombs in Solarized cyan, so the aperiodic
    // tiling is legible as two interleaved tile species.
    solarized: {
      penroseThick: [181, 137, 0],   // Solarized yellow — fat rhombs
      penroseThin:  [42, 161, 152],  // Solarized cyan   — skinny rhombs
    },
  };


  let _canvas = null;
  let _ctx = null;
  let _theme = null;

  let _raf = null;
  let _dpr = 1;
  let _w = 0, _h = 0;
  // Mouse: target is raw event position, _mouseX/Y is lerped for silky feel.
  let _mouseTX = 0, _mouseTY = 0;
  let _mouseX = 0,  _mouseY = 0;
  let _hasMouse = false;
  let _state = null;

  // ── Prefs / shims ─────────────────────────────────────────────────────
  const _reducedMotion = () => {
    try {
      return !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
    } catch (_) { return false; }
  };

  // ── Canvas lifecycle ──────────────────────────────────────────────────
  function _ensureCanvas() {
    if (_canvas) return _canvas;
    _canvas = document.createElement('canvas');
    _canvas.id = 'bg-canvas';
    _canvas.setAttribute('aria-hidden', 'true');
    // Insert as the first body child so document order matches the CSS
    // stacking intent: body's own background paints first, then the canvas
    // at z-index:-1, then every in-flow chrome element on top.
    if (document.body.firstChild) {
      document.body.insertBefore(_canvas, document.body.firstChild);
    } else {
      document.body.appendChild(_canvas);
    }
    _ctx = _canvas.getContext('2d');
    return _canvas;
  }

  function _resize() {
    if (!_canvas) return;
    // Cap devicePixelRatio so 4K displays don't torch the GPU on what is
    // supposed to be an ambient effect. The geometric-stroke engines
    // (penrose variants) keep 1.5× — thin lines at 1.0× on a HiDPI display
    // look noticeably aliased. Physics engines (cute*) also stay at 1.5×
    // so heart / kitty silhouettes keep crisp edges.
    const dprCap = 1.5;
    _dpr = Math.min(window.devicePixelRatio || 1, dprCap);
    _w = window.innerWidth;
    _h = window.innerHeight;
    _canvas.width  = Math.round(_w * _dpr);
    _canvas.height = Math.round(_h * _dpr);
    _canvas.style.width  = _w + 'px';
    _canvas.style.height = _h + 'px';
    _ctx.setTransform(_dpr, 0, 0, _dpr, 0, 0);
    if (_state && _state.onResize) _state.onResize(_w, _h);
  }


  function _onMouseMove(e) {
    _mouseTX = e.clientX;
    _mouseTY = e.clientY;
    _hasMouse = true;
  }

  // Ambient engines draw at this cadence (~24 fps) instead of 60 — the
  // motion is slow enough that the missing frames are invisible but the CPU
  // saving is large (≈60% fewer draws). Physics engines ignore this gate.
  const _AMBIENT_FRAME_MS = 1000 / 24;

  function _loop(t) {
    if (!_state) { _raf = null; return; }
    // Lerp the smoothed cursor position toward the raw target — produces a
    // silky response with no single-frame jitter regardless of the browser's
    // mousemove rate. Only meaningful for engines that actually read the
    // cursor; ambient engines leave it alone.
    if (_state.usesCursor) {
      _mouseX += (_mouseTX - _mouseX) * 0.08;
      _mouseY += (_mouseTY - _mouseY) * 0.08;
    }
    // Frame-rate gate for ambient engines.
    if (_state.throttle) {
      const last = _state.lastDraw || 0;
      if (t - last < _AMBIENT_FRAME_MS) { _raf = requestAnimationFrame(_loop); return; }
      _state.lastDraw = t;
    }
    const dt = Math.min(0.05, ((t - (_state.lastT || t)) / 1000));
    _state.lastT = t;
    _state.draw(t, dt);
    _raf = requestAnimationFrame(_loop);
  }


  function _stop() {
    if (_raf) { cancelAnimationFrame(_raf); _raf = null; }
  }

  function _start() {
    _stop();
    if (_state) _raf = requestAnimationFrame(_loop);
  }

  // ──────────────────────────────────────────────────────────────────────
  // Shared Penrose P3 tiling builder
  // ──────────────────────────────────────────────────────────────────────
  // Aperiodic Penrose P3 rhombic tiling. Built by recursive subdivision
  // from a ring of "fat" rhomb triangles around the centre: each fat
  // triangle splits into one fat + one thin sub-triangle, each thin
  // triangle splits into one thin + one fat, and after several levels we
  // have a few hundred tiles covering a disc. We pair adjacent triangles
  // back into their parent rhombs for drawing.
  //
  // This helper is shared by all three penrose variants (light, dark,
  // solarized). Each variant supplies its own palette, alpha, disc scale,
  // and breathing parameters.
  const PHI = (1 + Math.sqrt(5)) / 2;

  function _subdividePenrose(triangles) {
    const next = [];
    for (const [kind, A, B, C] of triangles) {
      if (kind === 0) {
        // Fat triangle: split into one fat + one thin sub-triangle.
        const P = [
          A[0] + (B[0] - A[0]) / PHI,
          A[1] + (B[1] - A[1]) / PHI,
        ];
        next.push([0, C, P, B]);
        next.push([1, P, C, A]);
      } else {
        // Thin triangle: split into one thin + one fat sub-triangle.
        const Q = [
          B[0] + (A[0] - B[0]) / PHI,
          B[1] + (A[1] - B[1]) / PHI,
        ];
        const R = [
          B[0] + (C[0] - B[0]) / PHI,
          B[1] + (C[1] - B[1]) / PHI,
        ];
        next.push([1, R, C, A]);
        next.push([1, Q, R, B]);
        next.push([0, R, Q, A]);
      }
    }
    return next;
  }

  // Build the full set of rhombs for a given viewport size.
  // discScale  — fraction of viewport diagonal used as the tiling disc radius
  // levels     — subdivision depth (4 = bigger tiles, 5 = denser)
  // speedMin/Max — per-rhomb breathing speed range (rad / ms)
  function _buildPenroseRhombs(w, h, discScale, levels, speedMin, speedMax) {
    // Disc radius — large enough that the tiling always reaches the
    // viewport corners even with the centre sitting at (w/2, h/2).
    const R = Math.hypot(w, h) * discScale;
    // Seed: 10 fat triangles around the centre (classic "sun" start).
    let tris = [];
    for (let i = 0; i < 10; i++) {
      const a1 = ((2 * i) * Math.PI) / 10 - Math.PI / 10;
      const a2 = ((2 * (i + 1)) * Math.PI) / 10 - Math.PI / 10;
      const B = [R * Math.cos(a1), R * Math.sin(a1)];
      const C = [R * Math.cos(a2), R * Math.sin(a2)];
      // Flip every other triangle so shared edges line up correctly.
      if (i % 2 === 0) tris.push([0, [0, 0], B, C]);
      else             tris.push([0, [0, 0], C, B]);
    }
    for (let l = 0; l < levels; l++) tris = _subdividePenrose(tris);

    // Pair each triangle with its partner across the shared A-C edge
    // to get rhombs. Build a map keyed by the midpoint of the A-C
    // edge — colliding triangles share that midpoint.
    const midKey = (p, q) => {
      const mx = ((p[0] + q[0]) * 0.5);
      const my = ((p[1] + q[1]) * 0.5);
      return Math.round(mx * 100) + ',' + Math.round(my * 100);
    };
    const byMid = new Map();
    for (const tri of tris) {
      const [, A, , C] = tri;
      const k = midKey(A, C);
      if (byMid.has(k)) byMid.get(k).push(tri);
      else byMid.set(k, [tri]);
    }
    const rhombs = [];
    for (const pair of byMid.values()) {
      if (pair.length !== 2) continue; // edge-of-disc orphan
      const [t1, t2] = pair;
      // A rhomb's 4 vertices: A, B1, C, B2 where B1 / B2 are the two
      // "far" corners of the two triangles (they sit on opposite sides
      // of the shared A-C edge).
      const A = t1[1], C = t1[3];
      const B1 = t1[2];
      const B2 = t2[2];
      rhombs.push({
        kind: t1[0],      // 0 = fat rhomb, 1 = thin rhomb
        pts: [A, B1, C, B2],
        // Independent slow breathing phase per rhomb.
        phase: Math.random() * Math.PI * 2,
        speed: speedMin + Math.random() * (speedMax - speedMin),
      });
    }
    return rhombs;
  }

  // Shared draw routine for all three Penrose engines. Renders the cached
  // rhomb list with the given palette, alpha, and breathing parameters.
  // breathFloor controls the minimum fraction of baseAlpha a rhomb can
  // reach at its dimmest breathing phase (higher = tighter swing).
  function _drawPenroseFrame(ctx, w, h, t, rhombs, pal, baseAlpha, strokeAlpha, breathFloor) {
    ctx.clearRect(0, 0, w, h);
    const cx = w * 0.5, cy = h * 0.5;
    const breathSwing = 1 - breathFloor;
    for (const r of rhombs) {
      const breath = breathFloor + breathSwing * (0.5 + 0.5 * Math.sin(t * r.speed + r.phase));
      const fillRgb = (r.kind === 0) ? pal.penroseThick : pal.penroseThin;
      ctx.fillStyle =
        'rgba(' + fillRgb[0] + ',' + fillRgb[1] + ',' + fillRgb[2] + ',' + (baseAlpha * breath) + ')';
      ctx.strokeStyle =
        'rgba(' + fillRgb[0] + ',' + fillRgb[1] + ',' + fillRgb[2] + ',' + strokeAlpha + ')';
      ctx.lineWidth = 0.8;
      ctx.beginPath();
      for (let k = 0; k < 4; k++) {
        const p = r.pts[k];
        const rx = p[0] + cx;
        const ry = p[1] + cy;
        if (k === 0) ctx.moveTo(rx, ry);
        else ctx.lineTo(rx, ry);
      }
      ctx.closePath();
      ctx.fill();
      ctx.stroke();
    }
  }

  // ──────────────────────────────────────────────────────────────────────
  // Engine: penroseLight  (light baseline)
  // ──────────────────────────────────────────────────────────────────────
  // Aperiodic P3 rhombic tiling in soft blue / warm lavender. Slightly
  // larger tiles (fewer subdivision levels → bigger rhombs) and ~20%
  // faster breathing than the Solarized variant for a brighter, airier
  // feel that suits the light theme's paper-white body.
  function _initPenroseLight() {
    const pal = PALETTES.light;
    const baseAlpha  = 0.045;
    const strokeAlpha = 0.065;
    // Breathing floor at 0.40 — wider swing than Solarized's 0.55 so the
    // breathing motion is perceptible against the bright background.  The
    // higher base alphas (vs the original 0.014/0.024) are needed because
    // low-alpha fills on a near-white surface produce sub-pixel colour
    // differences that are invisible on most displays.
    const breathFloor = 0.40;
    // Disc scale 0.55 → fewer, larger rhombs (airier). 4 subdivision levels
    // instead of Solarized's 5.
    const DISC_SCALE = 0.55;
    const LEVELS = 4;
    const SPEED_MIN = 0.0005;
    const SPEED_MAX = 0.0012;

    let rhombs = [];
    function rebuild() {
      rhombs = _buildPenroseRhombs(_w, _h, DISC_SCALE, LEVELS, SPEED_MIN, SPEED_MAX);
    }
    rebuild();

    return {
      throttle: true,
      usesCursor: false,
      draw(t) {
        _drawPenroseFrame(_ctx, _w, _h, t, rhombs, pal, baseAlpha, strokeAlpha, breathFloor);
      },
      onResize() { rebuild(); },
    };
  }

  // ──────────────────────────────────────────────────────────────────────
  // Shared network-nodes builder + draw routine
  // ──────────────────────────────────────────────────────────────────────
  // Spawns `count` nodes at random positions with random velocity vectors.
  // Each node drifts at a constant speed and wraps toroidally around the
  // viewport edges. Nearby nodes are connected by fading lines.

  function _buildNetworkNodes(count, w, h, speedMin, speedMax) {
    const nodes = [];
    for (let i = 0; i < count; i++) {
      const angle = Math.random() * Math.PI * 2;
      const speed = speedMin + Math.random() * (speedMax - speedMin);
      nodes.push({
        x: Math.random() * w,
        y: Math.random() * h,
        vx: Math.cos(angle) * speed,
        vy: Math.sin(angle) * speed,
      });
    }
    return nodes;
  }

  function _drawNetworkFrame(ctx, w, h, dt, nodes, cfg) {
    ctx.clearRect(0, 0, w, h);
    const maxDist = cfg.maxDist;
    const maxDist2 = maxDist * maxDist;

    // Move nodes and wrap around viewport edges.
    for (const n of nodes) {
      n.x += n.vx * dt;
      n.y += n.vy * dt;
      if (n.x < 0)  n.x += w;
      else if (n.x > w) n.x -= w;
      if (n.y < 0)  n.y += h;
      else if (n.y > h) n.y -= h;
    }

    // Draw connections between nearby nodes.
    const nc = cfg.nodeColor;
    const lc = cfg.lineColor;
    ctx.lineWidth = cfg.lineWidth;
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const dx = nodes[i].x - nodes[j].x;
        const dy = nodes[i].y - nodes[j].y;
        const d2 = dx * dx + dy * dy;
        if (d2 < maxDist2) {
          const d = Math.sqrt(d2);
          const a = cfg.lineAlpha * (1 - d / maxDist);
          ctx.strokeStyle = 'rgba(' + lc[0] + ',' + lc[1] + ',' + lc[2] + ',' + a + ')';
          ctx.beginPath();
          ctx.moveTo(nodes[i].x, nodes[i].y);
          ctx.lineTo(nodes[j].x, nodes[j].y);
          ctx.stroke();
        }
      }
    }

    // Draw nodes as small filled circles.
    ctx.fillStyle = 'rgba(' + nc[0] + ',' + nc[1] + ',' + nc[2] + ',' + cfg.nodeAlpha + ')';
    for (const n of nodes) {
      ctx.beginPath();
      ctx.arc(n.x, n.y, cfg.nodeRadius, 0, Math.PI * 2);
      ctx.fill();
    }
  }

  // ──────────────────────────────────────────────────────────────────────
  // Engine: networkDark  (dark baseline)
  // ──────────────────────────────────────────────────────────────────────
  // Wandering nodes connected by fading lines when within proximity.
  // Cool white nodes with accent cyan connections. Slow ambient drift —
  // no cursor interaction. Throttled to ~24 fps like the Penrose engines.
  function _initNetworkDark() {
    const pal = PALETTES.dark;
    const NODE_COUNT = 45;
    const SPEED_MIN = 6;
    const SPEED_MAX = 14;
    const cfg = {
      nodeColor:  pal.nodeColor,
      lineColor:  pal.lineColor,
      nodeRadius: 1.8,
      nodeAlpha:  0.08,
      lineAlpha:  0.045,
      lineWidth:  0.6,
      maxDist:    160,
    };

    let nodes = [];
    function rebuild() {
      nodes = _buildNetworkNodes(NODE_COUNT, _w, _h, SPEED_MIN, SPEED_MAX);
    }
    rebuild();

    return {
      throttle: true,
      usesCursor: false,
      draw(t, dt) {
        _drawNetworkFrame(_ctx, _w, _h, dt, nodes, cfg);
      },
      onResize() { rebuild(); },
    };
  }

  // ──────────────────────────────────────────────────────────────────────
  // Engine: penrose  (solarized)
  // ──────────────────────────────────────────────────────────────────────
  // The original Penrose engine. Aperiodic P3 rhombic tiling with thick
  // rhombs in Solarized yellow and thin rhombs in Solarized cyan. Mid-
  // range alpha and breathing speed — sits between the light (airier) and
  // dark (calmer) variants.
  function _initPenrose() {
    const pal = PALETTES.solarized;
    const isDark = document.body.classList.contains('dark');
    const baseAlpha  = isDark ? 0.032 : 0.028;
    const strokeAlpha = isDark ? 0.050 : 0.044;
    const breathFloor = 0.55;
    const DISC_SCALE = 0.62;
    const LEVELS = 5;
    const SPEED_MIN = 0.0004;
    const SPEED_MAX = 0.0010;

    let rhombs = [];
    function rebuild() {
      rhombs = _buildPenroseRhombs(_w, _h, DISC_SCALE, LEVELS, SPEED_MIN, SPEED_MAX);
    }
    rebuild();

    return {
      throttle: true,
      usesCursor: false,
      draw(t) {
        _drawPenroseFrame(_ctx, _w, _h, t, rhombs, pal, baseAlpha, strokeAlpha, breathFloor);
      },
      onResize() { rebuild(); },
    };
  }



  // ──────────────────────────────────────────────────────────────────────
  // Engine: cute  (hearts for latte, kitties for mocha)
  // ──────────────────────────────────────────────────────────────────────
  function _initCute(variant) {
    const pal = (PALETTES[_theme] && PALETTES[_theme].cute) || PALETTES.mocha.cute;
    const isDark = document.body.classList.contains('dark');
    const baseAlpha = isDark ? 0.13 : 0.11;
    const count = 14;
    const shapes = [];
    for (let i = 0; i < count; i++) shapes.push(_spawnCute(pal, baseAlpha, true));

    const draw = (variant === 'kitties') ? _drawKitty : _drawHeart;

    return {
      usesCursor: true,
      draw(t, dt) {
        const ctx = _ctx;
        ctx.clearRect(0, 0, _w, _h);
        for (const s of shapes) {
          // Physics
          s.x += s.vx * dt;
          s.y += s.vy * dt;
          s.rot += s.rotSpeed * dt;
          // Light drag so cursor breeze decays
          s.vx *= (1 - 0.8 * dt);
          s.vy += (s.vyBase - s.vy) * 0.5 * dt; // pull back toward drift velocity
          // Cursor breeze — push away when within ~140 px.
          if (_hasMouse) {
            const dx = s.x - _mouseX, dy = s.y - _mouseY;
            const d2 = dx * dx + dy * dy;
            if (d2 < 140 * 140 && d2 > 1) {
              const d = Math.sqrt(d2);
              const f = (1 - d / 140) * 260;
              s.vx += (dx / d) * f * dt;
              s.vy += (dy / d) * f * dt;
            }
          }
          // Clamp max speed so a long cursor hover can't catapult a shape.
          const maxV = 120;
          const v2 = s.vx * s.vx + s.vy * s.vy;
          if (v2 > maxV * maxV) {
            const v = Math.sqrt(v2);
            s.vx = (s.vx / v) * maxV;
            s.vy = (s.vy / v) * maxV;
          }
          // Wrap / respawn when the shape drifts fully off the top.
          if (s.y < -s.size * 2) {
            const n = _spawnCute(pal, baseAlpha, false);
            Object.assign(s, n);
          }
          if (s.x < -s.size * 2) s.x = _w + s.size;
          else if (s.x > _w + s.size * 2) s.x = -s.size;
          if (s.y > _h + s.size * 2) s.y = -s.size;
          const [r, g, b] = s.color;
          draw(ctx, s.x, s.y, s.size, s.rot, 'rgba(' + r + ',' + g + ',' + b + ',' + s.a + ')');
        }
      },
      onResize() {
        // Deliberately no-op — existing shapes drift naturally into the new
        // viewport; spawning a fresh flock on every resize would look jumpy.
      },
    };
  }

  // Initial flock can start anywhere on screen; respawns enter from below.
  function _spawnCute(pal, baseAlpha, initial) {
    const size = 14 + Math.random() * 18;
    const vyBase = -8 - Math.random() * 12;
    return {
      x: Math.random() * _w,
      y: initial ? Math.random() * _h : _h + size + Math.random() * 60,
      vx: (Math.random() - 0.5) * 6,
      vy: vyBase,
      vyBase,
      size,
      rot: Math.random() * Math.PI * 2,
      rotSpeed: (Math.random() - 0.5) * 0.25,
      color: pal[(Math.random() * pal.length) | 0],
      a: baseAlpha * (0.6 + Math.random() * 0.6),
    };
  }

  function _drawHeart(ctx, x, y, size, rot, rgba) {
    ctx.save();
    ctx.translate(x, y);
    ctx.rotate(rot);
    ctx.scale(size / 30, size / 30);
    ctx.fillStyle = rgba;
    ctx.beginPath();
    // Classic two-bezier heart, roughly 30 × 28 centred at origin.
    ctx.moveTo(0, 8);
    ctx.bezierCurveTo(0, 3, -6, -10, -14, -4);
    ctx.bezierCurveTo(-22, 2, -14, 12, 0, 22);
    ctx.bezierCurveTo(14, 12, 22, 2, 14, -4);
    ctx.bezierCurveTo(6, -10, 0, 3, 0, 8);
    ctx.closePath();
    ctx.fill();
    ctx.restore();
  }

  function _drawKitty(ctx, x, y, size, rot, rgba) {
    ctx.save();
    ctx.translate(x, y);
    ctx.rotate(rot);
    ctx.scale(size / 30, size / 30);
    ctx.fillStyle = rgba;
    // Head
    ctx.beginPath();
    ctx.arc(0, 2, 12, 0, Math.PI * 2);
    ctx.fill();
    // Ears (two triangles)
    ctx.beginPath();
    ctx.moveTo(-11, -4); ctx.lineTo(-6, -16); ctx.lineTo(-2, -8); ctx.closePath();
    ctx.moveTo(11, -4);  ctx.lineTo(6, -16);  ctx.lineTo(2, -8);  ctx.closePath();
    ctx.fill();
    // Knock out eyes + whiskers for a silhouette with just enough detail.
    ctx.globalCompositeOperation = 'destination-out';
    ctx.beginPath();
    ctx.arc(-4, 0, 1.6, 0, Math.PI * 2);
    ctx.arc(4, 0, 1.6, 0, Math.PI * 2);
    ctx.fill();
    ctx.lineWidth = 0.9;
    ctx.strokeStyle = '#000';
    ctx.beginPath();
    ctx.moveTo(-12, 5); ctx.lineTo(-4, 5);
    ctx.moveTo(-12, 8); ctx.lineTo(-4, 7);
    ctx.moveTo(12, 5);  ctx.lineTo(4, 5);
    ctx.moveTo(12, 8);  ctx.lineTo(4, 7);
    ctx.stroke();
    ctx.globalCompositeOperation = 'source-over';
    ctx.restore();
  }

  // ── Public API ────────────────────────────────────────────────────────
  function init() {
    _ensureCanvas();
    _resize();
    window.addEventListener('resize', _resize, { passive: true });
    window.addEventListener('mousemove', _onMouseMove, { passive: true });
    // Pause the RAF loop when the tab isn't visible — saves battery and
    // avoids the first post-wake frame integrating a huge dt (we clamp it
    // to 50 ms anyway, but this is cleaner).
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) _stop();
      else if (_state) _start();
    });
    // React to live prefers-reduced-motion toggles (macOS Accessibility, etc.)
    try {
      const m = window.matchMedia('(prefers-reduced-motion: reduce)');
      const onChange = () => { if (_theme) setTheme(_theme); };
      if (m.addEventListener) m.addEventListener('change', onChange);
      else if (m.addListener) m.addListener(onChange);
    } catch (_) { /* matchMedia unavailable */ }
    // First-boot bootstrap: adopt whatever theme the FOUC-prevention script
    // in build.py already applied to <body>. `_setTheme()` in app-ui.js will
    // call us again on user theme changes.
    const cls = Array.from(document.body.classList).find(c => c.indexOf('theme-') === 0);
    if (cls) setTheme(cls.slice(6));
  }

  function setTheme(themeId) {
    _theme = themeId;
    _stop();
    _state = null;

    if (!_canvas) _ensureCanvas();
    if (_ctx) _ctx.clearRect(0, 0, _w, _h);
    if (_reducedMotion()) return;
    const engineId = THEME_ENGINES.hasOwnProperty(themeId) ? THEME_ENGINES[themeId] : 'penroseLight';
    if (!engineId) return; // e.g. midnight — canvas stays cleared

    if (engineId === 'penroseLight')       _state = _initPenroseLight();
    else if (engineId === 'networkDark')   _state = _initNetworkDark();
    else if (engineId === 'penrose')       _state = _initPenrose();
    else if (engineId === 'cuteHearts')    _state = _initCute('hearts');
    else if (engineId === 'cuteKitties')   _state = _initCute('kitties');
    if (_state) {
      // Seed the smoothed cursor at the centre so the first frame doesn't
      // lurch from (0,0) to the real pointer position.
      _mouseTX = _w * 0.5;
      _mouseTY = _h * 0.5;
      _mouseX = _mouseTX;
      _mouseY = _mouseTY;
      _start();
    }
  }

  window.BgCanvas = { init, setTheme };
})();
