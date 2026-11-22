(function () {
  "use strict";

  var st = null;
  var selected = null;

  function $(id) { return document.getElementById(id); }

  function apiGet(path) {
    return fetch(path, { cache: "no-store" }).then(function (r) { return r.json(); });
  }

  function apiPost(path, body) {
    return fetch(path, {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: body
    }).then(function (r) { return r.json(); });
  }

  function appendLog(text) {
    if (!text) return;
    var log = $("log");
    log.textContent += text;
    if (log.textContent.charAt(log.textContent.length - 1) !== "\n") {
      log.textContent += "\n";
    }
    log.scrollTop = log.scrollHeight;
  }

  function setStatus(msg) { $("status").textContent = msg; }

  function svgEl(name, attrs) {
    var e = document.createElementNS("http://www.w3.org/2000/svg", name);
    if (attrs) {
      for (var k in attrs) {
        if (Object.prototype.hasOwnProperty.call(attrs, k)) e.setAttribute(k, attrs[k]);
      }
    }
    return e;
  }

  function layout() {
    var out = {};
    if (!st || !st.devices) return out;
    var n = st.devices.length;
    var cols = Math.max(1, Math.ceil(Math.sqrt(n)));
    for (var i = 0; i < n; i++) {
      var c = i % cols;
      var r = Math.floor(i / cols);
      out[st.devices[i].name] = { x: 130 + c * 190, y: 110 + r * 150 };
    }
    return out;
  }

  function kindColor(kind) {
    if (kind === "router") return "#b26a00";
    if (kind === "switch") return "#2e7d32";
    return "#305a9e";
  }

  function portState(dev, idx) {
    if (!dev || !dev.ports || idx >= dev.ports.length) return "up";
    return dev.ports[idx].state;
  }

  function devByName(name) {
    if (!st || !st.devices) return null;
    for (var i = 0; i < st.devices.length; i++) {
      if (st.devices[i].name === name) return st.devices[i];
    }
    return null;
  }

  function draw() {
    var svg = $("topo");
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    if (!st) return;

    var wrap = svg.parentNode;
    var W = Math.max(300, wrap.clientWidth);
    var H = Math.max(200, wrap.clientHeight);
    svg.setAttribute("viewBox", "0 0 " + W + " " + H);

    var grid = svgEl("g", { stroke: "#d7e2ea", "stroke-width": "1" });
    for (var x = 0; x < W; x += 40) grid.appendChild(svgEl("line", { x1: x, y1: 0, x2: x, y2: H }));
    for (var y = 0; y < H; y += 40) grid.appendChild(svgEl("line", { x1: 0, y1: y, x2: W, y2: y }));
    svg.appendChild(grid);

    var pos = layout();

    (st.links || []).forEach(function (l) {
      var a = pos[l.a];
      var b = pos[l.b];
      if (!a || !b) return;
      var blocked = portState(devByName(l.a), l.aPort) === "blocking" ||
                    portState(devByName(l.b), l.bPort) === "blocking";
      var down = l.up === false;
      var stroke = down ? "#c62828" : (blocked ? "#e0a000" : "#59636e");
      var dash = (down || blocked) ? "6 5" : null;
      var line = svgEl("line", {
        x1: a.x, y1: a.y, x2: b.x, y2: b.y,
        stroke: stroke, "stroke-width": "3"
      });
      if (dash) line.setAttribute("stroke-dasharray", dash);
      svg.appendChild(line);

      var mx = (a.x + b.x) / 2;
      var my = (a.y + b.y) / 2;
      var t = svgEl("text", { x: mx + 4, y: my - 4, fill: "#33414d", "font-size": "10" });
      t.textContent = (down ? "down " : "") + l.delay;
      svg.appendChild(t);
    });

    (st.devices || []).forEach(function (d) {
      var p = pos[d.name];
      if (!p) return;
      var color = kindColor(d.kind);
      var isSel = d.name === selected;

      var g = svgEl("g", { class: "node", transform: "translate(" + (p.x - 38) + "," + (p.y - 24) + ")" });
      g.addEventListener("click", function () { select(d.name); });

      g.appendChild(svgEl("rect", {
        x: 0, y: 0, width: 76, height: 44,
        fill: "#ffffff", stroke: isSel ? "#c81e1e" : color,
        "stroke-width": isSel ? "3" : "2"
      }));
      g.appendChild(svgEl("rect", { x: 0, y: 0, width: 76, height: 14, fill: color }));

      var kind = svgEl("text", { x: 4, y: 11, fill: "#ffffff", "font-size": "9" });
      kind.textContent = d.kind.toUpperCase();
      g.appendChild(kind);

      var name = svgEl("text", { x: 6, y: 29, fill: "#10202e", "font-size": "12", "font-weight": "bold" });
      name.textContent = d.name;
      g.appendChild(name);

      var ip = "";
      if (d.ports && d.ports.length && d.ports[0].ip) ip = d.ports[0].ip;
      if (ip) {
        var ipt = svgEl("text", { x: 6, y: 40, fill: "#455a64", "font-size": "9" });
        ipt.textContent = ip;
        g.appendChild(ipt);
      }

      var portCount = (d.ports || []).length;
      var pt = svgEl("text", { x: 62, y: 40, fill: "#455a64", "font-size": "9" });
      pt.textContent = portCount + "p";
      g.appendChild(pt);

      svg.appendChild(g);
    });
  }

  function select(name) {
    selected = name;
    draw();
    showInspector(name);
  }

  function showInspector(name) {
    var d = devByName(name);
    var box = $("inspector");
    while (box.firstChild) box.removeChild(box.firstChild);
    if (!d) { box.textContent = "Select a device."; return; }

    var title = document.createElement("div");
    title.textContent = d.name + "  [" + d.kind + "]";
    title.style.fontWeight = "bold";
    box.appendChild(title);

    (d.ports || []).forEach(function (p) {
      var row = document.createElement("div");
      row.textContent = "p" + p.index + "  " + (p.ip || "(L2)") +
        "  vlan=" + p.vlan + (p.tagged ? " T" : "") +
        "  " + p.state +
        "  rx=" + p.rx + " tx=" + p.tx + " drop=" + p.drop;
      box.appendChild(row);
    });

    if (!d.ports || d.ports.length === 0) {
      var none = document.createElement("div");
      none.textContent = "(no ports)";
      box.appendChild(none);
    }
  }

  function applyState(next, output) {
    if (output) appendLog(output);
    if (next) { st = next; draw(); updateStatus(); }
  }

  function updateStatus() {
    if (!st) return;
    $("clock").textContent = "t=" + st.time;
    $("count").textContent = (st.devices ? st.devices.length : 0) + " devices, " +
      (st.links ? st.links.length : 0) + " links";
  }

  function sendCmd(line, quiet) {
    if (!line) return Promise.resolve();
    if (!quiet) setStatus("Running: " + line);
    return apiPost("/api/cmd", line).then(function (r) {
      appendLog("> " + line);
      applyState(r.state, r.output);
      setStatus("Ready");
    }).catch(function (e) {
      appendLog("error: " + e);
      setStatus("Error");
    });
  }

  function runSim() {
    setStatus("Running...");
    return apiPost("/api/run", "200").then(function (r) {
      applyState(r.state, r.output);
      setStatus("Ready");
    }).catch(function (e) {
      appendLog("error: " + e);
      setStatus("Error");
    });
  }

  function stepSim() {
    return apiPost("/api/step", "1").then(function (r) {
      applyState(r.state, r.output);
    });
  }

  function suggestName(kind) {
    var base = kind === "router" ? "R" : (kind === "switch" ? "SW" : "PC");
    var used = {};
    (st && st.devices ? st.devices : []).forEach(function (d) { used[d.name] = true; });
    var i = 1;
    while (used[base + i]) i++;
    return base + i;
  }

  function promptAdd(kind) {
    var name = window.prompt("Device name", suggestName(kind));
    if (!name) return;
    sendCmd("add-device " + name + " " + kind);
  }

  function promptPort() {
    var dev = window.prompt("Device name");
    if (!dev) return;
    var mac = window.prompt("MAC (e.g. aa:aa:aa:aa:aa:01)");
    if (!mac) return;
    var ip = window.prompt("IP/prefix (leave empty for L2/switch port)", "");
    var line = "add-port " + dev + " " + mac;
    if (ip) line += " " + ip;
    sendCmd(line);
  }

  function promptConnect() {
    var a = window.prompt("Endpoint A (device:port)", "");
    if (!a) return;
    var b = window.prompt("Endpoint B (device:port)", "");
    if (!b) return;
    sendCmd("connect " + a + " " + b);
  }

  function promptPing() {
    var dev = window.prompt("From device", "");
    if (!dev) return;
    var ip = window.prompt("Target IP", "192.168.1.2");
    if (!ip) return;
    sendCmd("ping " + dev + " " + ip);
  }

  function promptStp() {
    var dev = window.prompt("Switch", "");
    if (!dev) return;
    var mode = window.prompt("on / off / rstp", "on");
    if (!mode) return;
    if (mode === "rstp") {
      sendCmd("set-stp-mode " + dev + " rstp").then(function () {
        return sendCmd("set-stp " + dev + " on");
      });
    } else {
      sendCmd("set-stp " + dev + " " + mode);
    }
  }

  function promptSave() {
    var f = window.prompt("Save topology as", "scene.yn");
    if (f) sendCmd("save " + f);
  }

  function promptLoad() {
    var f = window.prompt("Load scene (.yn)", "tests/config.yn");
    if (f) sendCmd("load " + f);
  }

  function bind() {
    $("btnHost").addEventListener("click", function () { promptAdd("end"); });
    $("btnSwitch").addEventListener("click", function () { promptAdd("switch"); });
    $("btnRouter").addEventListener("click", function () { promptAdd("router"); });
    $("btnPort").addEventListener("click", promptPort);
    $("btnConnect").addEventListener("click", promptConnect);
    $("btnRun").addEventListener("click", runSim);
    $("btnStep").addEventListener("click", stepSim);
    $("btnPing").addEventListener("click", promptPing);
    $("btnStp").addEventListener("click", promptStp);
    $("btnSave").addEventListener("click", promptSave);
    $("btnLoad").addEventListener("click", promptLoad);
    $("btnRefresh").addEventListener("click", refresh);

    $("btnSend").addEventListener("click", function () {
      var inp = $("cmdInput");
      var v = inp.value.trim();
      if (v) { inp.value = ""; sendCmd(v); }
    });
    $("cmdInput").addEventListener("keydown", function (e) {
      if (e.key === "Enter") $("btnSend").click();
    });

    window.addEventListener("resize", draw);
  }

  function refresh() {
    return apiGet("/api/state").then(function (s) {
      st = s;
      draw();
      updateStatus();
    }).catch(function (e) {
      setStatus("Cannot reach server");
      appendLog("error: " + e);
    });
  }

  bind();
  appendLog("yanas net — Network Simulator");
  refresh();
})();
