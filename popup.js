const DEFAULTS = { model: "gemma4:12b", host: "http://localhost:11434", think: false };
const $ = (id) => document.getElementById(id);

let settings = { ...DEFAULTS };
let history = [];
let progress = {};
let controller = null;
let generating = false;

const messagesEl = $("messages"), emptyEl = $("empty"), inputEl = $("input"), sendBtn = $("sendBtn");

/* ---------- Almacenamiento ---------- */
async function load() {
  const d = await chrome.storage.local.get(["settings", "history", "progress"]);
  settings = { ...DEFAULTS, ...(d.settings || {}) };
  history = d.history || [];
  progress = d.progress || {};
  $("modelLabel").textContent = settings.model;
  $("modelInput").value = settings.model;
  $("hostInput").value = settings.host;
  $("thinkInput").checked = settings.think;
  renderCards();
  renderEscalation();
  renderChips();
  renderChat();
  checkStatus();
}
const saveHistory = () => chrome.storage.local.set({ history });
const saveProgress = () => chrome.storage.local.set({ progress });

async function checkStatus() {
  const dot = $("status");
  try {
    const r = await fetch(`${settings.host}/api/tags`);
    dot.className = "dot " + (r.ok ? "ok" : "bad");
    dot.title = r.ok ? "Ollama conectado" : "Ollama no responde";
  } catch {
    dot.className = "dot bad";
    dot.title = "No se puede conectar con Ollama";
  }
}

/* ---------- Texto ---------- */
const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const inline = (s) => esc(s).replace(/`([^`\n]+)`/g, "<code>$1</code>");

function formatText(text) {
  return text.split(/```/).map((part, i) => {
    if (i % 2 === 1) {
      return `<pre><code>${esc(part.replace(/^[\w+-]*\n/, "").replace(/\n$/, ""))}</code></pre>`;
    }
    return esc(part)
      .replace(/^#{1,6}\s+(.+)$/gm, "<strong>$1</strong>")
      .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
      .replace(/`([^`\n]+)`/g, "<code>$1</code>")
      .replace(/^\s*[-*]\s+/gm, "• ");
  }).join("");
}

/* ---------- Pestañas ---------- */
function showTab(name) {
  document.querySelectorAll(".tab").forEach((t) => {
    const on = t.dataset.tab === name;
    t.classList.toggle("active", on);
    t.setAttribute("aria-selected", on);
  });
  $("viewProtocols").hidden = name !== "protocols";
  $("viewChat").hidden = name !== "chat";
  $("viewEthical").hidden = name !== "ethical";
  if (name === "chat") { scrollDown(false); inputEl.focus(); }
}
document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => showTab(t.dataset.tab)));

/* ---------- Protocolos ---------- */
const totalSteps = (pb) => pb.phases.reduce((n, ph) => n + ph[1].length, 0);
const doneSteps = (pb) => (progress[pb.id] || []).filter(Boolean).length;

function renderCards() {
  const box = $("cards");
  box.innerHTML = "";
  PLAYBOOKS.forEach((pb) => {
    const pct = Math.round((doneSteps(pb) / totalSteps(pb)) * 100);
    const b = document.createElement("button");
    b.className = "pcard";
    b.innerHTML = `
      <div class="pcard-top"><span class="pcard-title">${esc(pb.title)}</span><span class="pill ${pb.level}">${pb.level}</span></div>
      <div class="pcard-desc">${esc(pb.desc)}</div>
      ${pct > 0 ? `<div class="pcard-prog"><i style="width:${pct}%"></i></div>` : ""}`;
    b.addEventListener("click", () => openPlaybook(pb.id));
    box.appendChild(b);
  });
}

function renderEscalation() {
  $("escalateBody").innerHTML =
    `<dl>${ESCALATION.map(([n, d]) => `<dt>${esc(n)}</dt><dd>${esc(d)}</dd>`).join("")}</dl>
     <p class="foot">Comprueba los datos de contacto en las webs oficiales. Escala siempre que haya datos personales, ransomware, fraude económico o sistemas críticos.</p>`;
}

function openPlaybook(id) {
  const pb = PLAYBOOKS.find((p) => p.id === id);
  const flat = totalSteps(pb);
  const state = progress[id] && progress[id].length === flat ? progress[id] : new Array(flat).fill(false);
  progress[id] = state;

  const view = $("detailView");
  view.innerHTML = `
    <button class="back" id="backBtn">← Todos los protocolos</button>
    <div class="d-head"><h2 class="d-title">${esc(pb.title)}</h2><span class="pill ${pb.level}">${pb.level}</span></div>
    <p class="d-desc">${esc(pb.desc)}</p>
    <div class="progress"><div class="bar"><i id="barFill"></i></div><span id="barText"></span></div>
    <div id="phases"></div>
    <div class="d-actions">
      <button class="btn primary" id="askBtn">Preguntar al asistente sobre mi caso</button>
      <button class="btn" id="resetBtn">Reiniciar progreso</button>
    </div>`;

  let idx = 0;
  const phasesEl = view.querySelector("#phases");
  pb.phases.forEach(([name, steps], pi) => {
    const sec = document.createElement("section");
    sec.className = "phase";
    sec.innerHTML = `<h3>${pi + 1}. ${esc(name)}</h3>`;
    steps.forEach((text) => {
      const i = idx++;
      const lab = document.createElement("label");
      lab.className = "step";
      lab.innerHTML = `<input type="checkbox" ${state[i] ? "checked" : ""}><span>${inline(text)}</span>`;
      lab.querySelector("input").addEventListener("change", (e) => {
        state[i] = e.target.checked;
        saveProgress();
        updateBar();
      });
      sec.appendChild(lab);
    });
    phasesEl.appendChild(sec);
  });

  function updateBar() {
    const n = state.filter(Boolean).length;
    view.querySelector("#barFill").style.width = Math.round((n / flat) * 100) + "%";
    view.querySelector("#barText").textContent = `${n} de ${flat} pasos`;
  }
  updateBar();

  view.querySelector("#backBtn").onclick = closePlaybook;
  view.querySelector("#resetBtn").onclick = () => {
    progress[id] = new Array(flat).fill(false);
    saveProgress();
    openPlaybook(id);
  };
  view.querySelector("#askBtn").onclick = () => {
    showTab("chat");
    inputEl.value = `Estoy gestionando este incidente: "${pb.title}". Esta es mi situación concreta: `;
    autoResize();
    inputEl.focus();
    inputEl.setSelectionRange(inputEl.value.length, inputEl.value.length);
  };

  $("listView").hidden = true;
  view.hidden = false;
  $("viewProtocols").scrollTo({ top: 0 });
}

function closePlaybook() {
  $("detailView").hidden = true;
  $("listView").hidden = false;
  renderCards();
  $("viewProtocols").scrollTo({ top: 0 });
}

/* ---------- Chat ---------- */
const CHIPS = [
  "Creo que mi ordenador tiene un virus, ¿qué hago?",
  "He hecho clic en un enlace sospechoso de un correo",
  "¿Cómo funciona el phishing y cómo lo reconozco?",
  "¿Qué es el hacking ético y cómo empiezo de forma legal?",
];
function renderChips() {
  const box = $("chips");
  box.innerHTML = "";
  CHIPS.forEach((t) => {
    const b = document.createElement("button");
    b.className = "chip";
    b.textContent = t;
    b.onclick = () => { inputEl.value = t; autoResize(); send(); };
    box.appendChild(b);
  });
}

function buildMessage(m) {
  const el = document.createElement("div");
  el.className = `msg ${m.role}` + (m.error ? " error" : "");
  if (m.role === "user") el.textContent = m.content;
  else {
    const b = document.createElement("div");
    b.className = "body";
    el.appendChild(b);
    setBody(el, m.content, false);
  }
  return el;
}
function setBody(el, text, thinking) {
  const body = el.querySelector(".body");
  body.innerHTML = !text && thinking
    ? `<span class="thinking"><span class="pulse"><i></i><i></i><i></i></span>Pensando</span>`
    : formatText(text);
}
function addTools(el, text) {
  if (el.querySelector(".tools")) return;
  const t = document.createElement("div");
  t.className = "tools";
  const b = document.createElement("button");
  b.textContent = "Copiar";
  b.onclick = async () => {
    await navigator.clipboard.writeText(text);
    b.textContent = "Copiado";
    setTimeout(() => (b.textContent = "Copiar"), 1200);
  };
  t.appendChild(b);
  el.appendChild(t);
}
function renderChat() {
  messagesEl.querySelectorAll(".msg").forEach((n) => n.remove());
  emptyEl.hidden = history.length > 0;
  history.forEach((m) => {
    const el = buildMessage(m);
    if (m.role === "assistant" && !m.error && m.content) addTools(el, m.content);
    messagesEl.appendChild(el);
  });
  scrollDown(false);
}
const scrollDown = (smooth = true) => messagesEl.scrollTo({ top: messagesEl.scrollHeight, behavior: smooth ? "smooth" : "auto" });

function setGenerating(on) {
  generating = on;
  $("sendIcon").hidden = on;
  $("stopIcon").hidden = !on;
  sendBtn.disabled = !on && !inputEl.value.trim();
}

async function send() {
  const text = inputEl.value.trim();
  if (!text || generating) return;
  inputEl.value = "";
  autoResize();
  emptyEl.hidden = true;

  history.push({ role: "user", content: text });
  messagesEl.appendChild(buildMessage(history[history.length - 1]));
  const reply = { role: "assistant", content: "" };
  const replyEl = buildMessage(reply);
  messagesEl.appendChild(replyEl);
  setBody(replyEl, "", true);
  scrollDown();

  controller = new AbortController();
  setGenerating(true);
  try {
    const res = await fetch(`${settings.host}/api/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      signal: controller.signal,
      body: JSON.stringify({
        model: settings.model,
        stream: true,
        think: settings.think,
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          ...history.filter((m) => !m.error).map(({ role, content }) => ({ role, content })),
        ],
      }),
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => "");
      throw Object.assign(new Error(detail || res.statusText), { status: res.status });
    }
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let buf = "";
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      const lines = buf.split("\n");
      buf = lines.pop();
      for (const line of lines) {
        if (!line.trim()) continue;
        const chunk = JSON.parse(line);
        if (chunk.error) throw new Error(chunk.error);
        if (chunk.message?.content) reply.content += chunk.message.content;
        setBody(replyEl, reply.content, true);
        scrollDown(false);
      }
    }
    if (!reply.content.trim()) reply.content = "(Sin respuesta)";
    setBody(replyEl, reply.content, false);
    addTools(replyEl, reply.content);
    history.push(reply);
  } catch (err) {
    if (err.name === "AbortError") {
      if (reply.content.trim()) { setBody(replyEl, reply.content, false); history.push(reply); }
      else { replyEl.remove(); history.pop(); inputEl.value = text; autoResize(); }
    } else {
      reply.error = true;
      reply.content = explainError(err);
      replyEl.classList.add("error");
      setBody(replyEl, reply.content, false);
      history.push(reply);
    }
  } finally {
    controller = null;
    setGenerating(false);
    saveHistory();
    scrollDown();
    checkStatus();
  }
}

function explainError(err) {
  if (err.status === 403) return "Ollama ha rechazado la conexión (403). Reinicia Ollama con la variable OLLAMA_ORIGINS=chrome-extension://* para permitir esta extensión.";
  if (err.status === 404) return `No se encuentra el modelo "${settings.model}". Ejecuta "ollama list" para ver el nombre exacto, o descárgalo con "ollama pull ${settings.model}". Puedes cambiarlo en Ajustes.`;
  if (err instanceof TypeError) return "No se puede conectar con Ollama. Comprueba que está en marcha y que la dirección en Ajustes es correcta. Los protocolos siguen disponibles sin el modelo.";
  return err.message || "Error desconocido.";
}

/* ---------- Eventos ---------- */
function autoResize() {
  inputEl.style.height = "auto";
  inputEl.style.height = Math.min(inputEl.scrollHeight, 140) + "px";
  sendBtn.disabled = !generating && !inputEl.value.trim();
}
inputEl.addEventListener("input", autoResize);
inputEl.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); }
});
sendBtn.addEventListener("click", () => (generating ? controller?.abort() : send()));

$("newBtn").addEventListener("click", () => {
  controller?.abort();
  history = [];
  saveHistory();
  renderChat();
  inputEl.value = "";
  autoResize();
  inputEl.focus();
});
$("settingsBtn").addEventListener("click", () => { $("settings").hidden = !$("settings").hidden; });
$("saveSettings").addEventListener("click", async () => {
  settings.model = $("modelInput").value.trim() || DEFAULTS.model;
  settings.host = ($("hostInput").value.trim() || DEFAULTS.host).replace(/\/+$/, "");
  settings.think = $("thinkInput").checked;
  await chrome.storage.local.set({ settings });
  $("modelLabel").textContent = settings.model;
  $("settings").hidden = true;
  checkStatus();
});

load().then(() => { sendBtn.disabled = true; inputEl.focus(); });
