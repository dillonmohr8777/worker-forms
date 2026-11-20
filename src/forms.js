/*
 * forms.js: drop-in for pages whose forms submit by script to "/" (the Netlify AJAX pattern: fetch("/", {method:"POST", body}))
 * instead of by a plain <form> post. Add one tag to the page:
 *
 *   <script src="https://YOUR-WORKER.workers.dev/forms.js" data-site="your-site-key" defer></script>
 *
 * It wraps window.fetch. A same-origin POST to "/" (or to the page's own path) whose body carries a "form-name" field is sent
 * to the Worker (<worker>/f/<data-site>) with Accept: application/json; the page gets the Worker's answer (200 {"ok":true}
 * when stored, an error status or a network error otherwise, which the page's own failure message handles).
 * Every other request is left alone. XMLHttpRequest and navigator.sendBeacon are not covered.
 */
(function () {
  var s = document.currentScript;
  if (!s || window.__formsJs) return;
  var site = s.getAttribute("data-site") || "";
  if (!/^[a-z0-9][a-z0-9-]*$/.test(site) || !window.fetch) return;
  window.__formsJs = 1;
  var target = new URL(s.src).origin + "/f/" + site;
  var orig = window.fetch;

  function carriesForm(body) {
    try {
      if (typeof body === "string") return /(^|&)form-name=/.test(body) || /"form-name"\s*:/.test(body);
      if (body && typeof body.has === "function") return body.has("form-name"); // FormData, URLSearchParams
    } catch (e) {}
    return false;
  }

  window.fetch = function (input, init) {
    try {
      var href = typeof input === "string" ? input : input instanceof URL ? input.href : null; // Request objects pass through
      if (href && init && init.body != null && String(init.method || "GET").toUpperCase() === "POST") {
        var u = new URL(href, location.href);
        if (u.origin === location.origin && (u.pathname === "/" || u.pathname === location.pathname) && carriesForm(init.body)) {
          var headers = new Headers(init.headers || {});
          headers.set("Accept", "application/json");
          var next = {};
          for (var k in init) next[k] = init[k];
          next.headers = headers;
          next.mode = "cors";
          next.credentials = "omit";
          return orig.call(this, target, next);
        }
      }
    } catch (e) {}
    return orig.apply(this, arguments);
  };
})();
