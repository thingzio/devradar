// Minimal, dependency-free UI behavior. DevRadar is server-rendered; this only
// handles the account dropdown (toggle + click-outside/Escape to close).
(function () {
  "use strict";
  document.addEventListener("DOMContentLoaded", function () {
    var toggle = document.getElementById("user-menu-toggle");
    var menu = document.getElementById("user-menu");
    if (!toggle || !menu) return;

    function open() {
      menu.hidden = false;
      toggle.setAttribute("aria-expanded", "true");
    }
    function close() {
      menu.hidden = true;
      toggle.setAttribute("aria-expanded", "false");
    }

    toggle.addEventListener("click", function (e) {
      e.stopPropagation();
      if (menu.hidden) open();
      else close();
    });
    document.addEventListener("click", function (e) {
      if (!menu.hidden && !menu.contains(e.target) && e.target !== toggle) close();
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") close();
    });
  });

  // Copy-to-clipboard for code blocks on the submit guide. Each .copyable wraps
  // a <pre> and a <button class="copy-btn">; clicking copies the <pre> text.
  document.addEventListener("DOMContentLoaded", function () {
    var btns = document.querySelectorAll(".copy-btn");
    btns.forEach(function (btn) {
      btn.addEventListener("click", function () {
        var wrap = btn.closest(".copyable");
        var pre = wrap && wrap.querySelector("pre");
        if (!pre || !navigator.clipboard) return;
        navigator.clipboard.writeText(pre.innerText).then(function () {
          var prev = btn.textContent;
          btn.textContent = "Copied";
          btn.classList.add("copied");
          setTimeout(function () {
            btn.textContent = prev;
            btn.classList.remove("copied");
          }, 1500);
        });
      });
    });
  });
})();
