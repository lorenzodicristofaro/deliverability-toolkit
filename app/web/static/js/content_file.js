// Reads a chosen .eml into the .eml textarea (M5-16). Progressive enhancement: without JS the
// picker stays hidden and pasting works. The file is never uploaded as a file; its text is
// submitted with the ordinary urlencoded form. Same origin, CSP script-src 'self'.
(function () {
  "use strict";
  var input = document.getElementById("content-file");
  var row = document.getElementById("content-file-row");
  if (!input || !row || !window.FileReader) { return; }
  var target = document.getElementById(input.getAttribute("data-target"));
  var maxBytes = parseInt(input.getAttribute("data-max-bytes"), 10);
  if (!target) { return; }
  row.hidden = false;

  var note = document.createElement("span");
  note.setAttribute("role", "alert");
  note.setAttribute("data-testid", "content-file-error");
  row.appendChild(note);

  input.addEventListener("change", function () {
    note.textContent = "";
    var file = input.files && input.files[0];
    if (!file) { return; }
    if (maxBytes > 0 && file.size > maxBytes) {
      note.textContent = input.getAttribute("data-too-large-text") || "";
      input.value = "";
      return;
    }
    var reader = new FileReader();
    reader.onload = function () { target.value = String(reader.result); };
    reader.onerror = function () {
      note.textContent = input.getAttribute("data-unreadable-text") || "";
    };
    reader.readAsText(file);
  });
})();
