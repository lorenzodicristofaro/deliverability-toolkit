// DKIM results from the M3-16 SSE route (same origin, CSP script-src 'self').
// Server fragments are autoescaped HTML. The EventSource is closed on `done` and on `error`,
// otherwise the browser reconnects and the probe would run again.
(function () {
  "use strict";
  var box = document.getElementById("dkim-stream");
  if (!box || !window.EventSource) { return; }
  var pending = box.querySelector(".dkim-pending");
  var source = new EventSource(box.getAttribute("data-src"));

  function clearPending() {
    if (pending) { pending.remove(); pending = null; }
  }
  function add(html) {
    clearPending();
    box.insertAdjacentHTML("beforeend", html);
  }
  function stop() { source.close(); }

  source.addEventListener("selector", function (ev) { add(ev.data); });
  source.addEventListener("done", function (ev) { add(ev.data); stop(); });
  source.addEventListener("error", function () {
    stop();
    clearPending();
    var p = document.createElement("p");
    p.setAttribute("role", "alert");
    p.setAttribute("data-testid", "dkim-error");
    p.textContent = box.getAttribute("data-error-text") || "";
    box.appendChild(p);
  });
  window.addEventListener("pagehide", stop);
})();
