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

  // Auto-submit controls. The CSP (script-src 'self', no 'unsafe-inline') blocks
  // inline onchange/onsubmit attributes, so filter dropdowns and toggle inputs are
  // wired here instead. Any control with [data-autosubmit] submits its form on
  // change (min-severity and label filters, the unrated toggle, VEX upload, etc.).
  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("[data-autosubmit]").forEach(function (el) {
      el.addEventListener("change", function () {
        if (el.form) el.form.submit();
      });
    });
  });

  // Confirm-before-submit. Forms with [data-confirm="message"] prompt before
  // submitting (destructive admin actions), replacing inline onsubmit=return confirm().
  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("form[data-confirm]").forEach(function (form) {
      form.addEventListener("submit", function (e) {
        if (!window.confirm(form.getAttribute("data-confirm"))) {
          e.preventDefault();
        }
      });
    });
  });

  // CSRF token for the always-present nav logout form. The double-submit token
  // lives in a non-HttpOnly cookie (by design); RequireAuth guarantees it exists
  // on every authenticated page. Echo it into any hidden [data-csrf-cookie]
  // field so the form carries a matching token without every page handler having
  // to render one. CSP-safe: this is first-party script-src 'self'.
  document.addEventListener("DOMContentLoaded", function () {
    var fields = document.querySelectorAll("input[data-csrf-cookie]");
    if (!fields.length) return;
    var m = document.cookie.match(/(?:^|;\s*)(?:__Host-csrf|csrf)=([^;]+)/);
    if (!m) return;
    fields.forEach(function (f) {
      f.value = decodeURIComponent(m[1]);
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
