// ShieldsVPN landing page (served as a file, not inline, so the CSP in vercel.json can forbid inline scripts).
document.getElementById('y').textContent = new Date().getFullYear();
// When the real portal is live, set PORTAL_URL to its address (e.g. "https://yourname.playit.gg:PORT/").
var PORTAL_URL = "";
if (PORTAL_URL) {
  document.querySelectorAll('#signin,#signin2').forEach(function(a){ a.href = PORTAL_URL; a.target = "_blank"; a.rel = "noopener"; });
  var n = document.getElementById('portal-note'); if (n) n.style.display = "none";
}
// Browser extension: once a store has approved it, paste its page here (https only) and the button goes live.
var STORE_LINKS = {
  chrome: "",   // https://chromewebstore.google.com/detail/...
  edge: "",     // https://microsoftedge.microsoft.com/addons/detail/...
  firefox: ""   // https://addons.mozilla.org/firefox/addon/...
};
var NAMES = { chrome: "Chrome", edge: "Edge", firefox: "Firefox" };
var live = 0;
document.querySelectorAll('.store').forEach(function (a) {
  var key = a.getAttribute('data-store'), url = STORE_LINKS[key];
  if (!url || url.indexOf('https://') !== 0) return;
  a.href = url; a.target = "_blank"; a.rel = "noopener";
  a.classList.remove('soon'); a.classList.add('live');
  a.querySelector('.cta').textContent = "Add to " + NAMES[key];
  live++;
});
if (live) {
  var e = document.getElementById('ext-note');
  if (e) e.textContent = "Free. Requires the ShieldsVPN app for Windows.";
}
