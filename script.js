// Types the scan command, then reveals each result line like a live scan.
// Without JavaScript (or with reduced motion), everything is simply visible.
(function () {
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var cmd = document.getElementById("cmd");
  var lines = Array.prototype.slice.call(document.querySelectorAll("[data-line]"));
  if (reduce || !cmd || !lines.length) return;

  var text = cmd.getAttribute("data-text") || "";
  cmd.textContent = "";
  lines.forEach(function (el) { el.hidden = true; });

  function reveal(n) {
    if (n >= lines.length) return;
    lines[n].hidden = false;
    setTimeout(function () { reveal(n + 1); }, n === 0 ? 450 : 150);
  }

  var i = 0;
  function type() {
    if (i < text.length) {
      cmd.textContent += text.charAt(i++);
      setTimeout(type, 26);
    } else {
      reveal(0);
    }
  }
  type();
})();
