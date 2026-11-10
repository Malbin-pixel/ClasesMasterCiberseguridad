// Interfaz de la pestaña "Hacking ético": temas de lectura y autoevaluación.
const rich = (s) => esc(s)
  .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
  .replace(/`([^`\n]+)`/g, "<code>$1</code>");

function renderTopics() {
  const box = $("ethCards");
  box.innerHTML = "";
  AWARENESS.forEach((t) => {
    const b = document.createElement("button");
    b.className = "pcard";
    b.innerHTML = `
      <div class="pcard-top"><span class="pcard-title">${esc(t.title)}</span><span class="pill ${t.level}">${t.level}</span></div>
      <div class="pcard-desc">${esc(t.desc)}</div>`;
    b.addEventListener("click", () => openTopic(t.id));
    box.appendChild(b);
  });
}

function showEthDetail(html) {
  const view = $("ethDetail");
  view.innerHTML = html;
  $("ethList").hidden = true;
  view.hidden = false;
  $("viewEthical").scrollTo({ top: 0 });
  view.querySelector("[data-back]").onclick = closeTopic;
  return view;
}

function closeTopic() {
  $("ethDetail").hidden = true;
  $("ethList").hidden = false;
  $("viewEthical").scrollTo({ top: 0 });
}

function openTopic(id) {
  const t = AWARENESS.find((x) => x.id === id);
  if (t.quiz) return startQuiz(t);

  const body = t.sections.map(([h, items, para]) => `
    <section class="phase">
      <h3>${esc(h)}</h3>
      ${para
        ? items.map((i) => `<p class="para">${rich(i)}</p>`).join("")
        : `<ul class="points">${items.map((i) => `<li>${rich(i)}</li>`).join("")}</ul>`}
    </section>`).join("");

  const view = showEthDetail(`
    <button class="back" data-back>← Todos los temas</button>
    <div class="d-head"><h2 class="d-title">${esc(t.title)}</h2><span class="pill ${t.level}">${t.level}</span></div>
    <p class="d-desc">${esc(t.desc)}</p>
    ${body}
    <div class="d-actions">
      <button class="btn primary" id="ethAsk">Preguntar al asistente</button>
    </div>`);

  view.querySelector("#ethAsk").onclick = () => {
    showTab("chat");
    inputEl.value = `Quiero entender mejor «${t.title}» a nivel de concienciación. Mi duda: `;
    autoResize();
    inputEl.focus();
    inputEl.setSelectionRange(inputEl.value.length, inputEl.value.length);
  };
}

/* ---------- Autoevaluación ---------- */
function startQuiz(t) {
  const state = { i: 0, score: 0 };

  function renderQuestion() {
    const q = QUIZ[state.i];
    const view = showEthDetail(`
      <button class="back" data-back>← Todos los temas</button>
      <div class="q-count">Pregunta ${state.i + 1} de ${QUIZ.length}</div>
      <h2 class="q-text">${esc(q.q)}</h2>
      <div class="opts" id="opts"></div>
      <div id="feedback"></div>`);

    const opts = view.querySelector("#opts");
    q.options.forEach((text, idx) => {
      const b = document.createElement("button");
      b.className = "opt";
      b.textContent = text;
      b.onclick = () => answer(idx);
      opts.appendChild(b);
    });

    function answer(idx) {
      const ok = idx === q.correct;
      if (ok) state.score++;
      [...opts.children].forEach((b, n) => {
        b.disabled = true;
        if (n === q.correct) b.classList.add("correct");
        else if (n === idx) b.classList.add("wrong");
      });
      const last = state.i === QUIZ.length - 1;
      view.querySelector("#feedback").innerHTML = `
        <div class="explain"><strong>${ok ? "Correcto." : "No exactamente."}</strong> ${esc(q.explain)}</div>
        <div class="d-actions"><button class="btn primary" id="nextBtn">${last ? "Ver resultado" : "Siguiente"}</button></div>`;
      view.querySelector("#nextBtn").onclick = () => {
        if (last) renderResult();
        else { state.i++; renderQuestion(); }
      };
    }
  }

  function renderResult() {
    const n = QUIZ.length, s = state.score;
    const msg = s === n ? "Excelente. Tienes muy buenos reflejos de seguridad."
      : s >= n - 2 ? "Muy bien. Repasa los temas donde has dudado."
      : "Merece la pena repasar los temas anteriores y volver a intentarlo.";
    const view = showEthDetail(`
      <button class="back" data-back>← Todos los temas</button>
      <div class="score">${s} / ${n}</div>
      <p class="d-desc">${msg}</p>
      <div class="d-actions">
        <button class="btn primary" id="again">Repetir</button>
        <button class="btn" id="toTopics">Volver a los temas</button>
      </div>`);
    view.querySelector("#again").onclick = () => { state.i = 0; state.score = 0; renderQuestion(); };
    view.querySelector("#toTopics").onclick = closeTopic;
  }

  renderQuestion();
}

renderTopics();
