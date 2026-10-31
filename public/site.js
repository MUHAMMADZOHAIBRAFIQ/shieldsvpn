// ShieldsVPN landing page (served as a file, not inline, so the CSP in vercel.json can forbid inline scripts).
document.getElementById('y').textContent = new Date().getFullYear();
// The administrators' portal, linked small in the footer once it has a permanent https address (never a
// temporary tunnel address).  Visitors connect from the apps, not from this page.
var PORTAL_URL = "";
if (PORTAL_URL.indexOf('https://') === 0) {
  var admin = document.getElementById('admin-link');
  admin.href = PORTAL_URL; admin.rel = "noopener"; admin.hidden = false;
  document.getElementById('admin-sep').hidden = false;
}
// The apps: once published, paste the store or download page here (https only) and the card's button goes live.
var APP_LINKS = {
  android: "",  // https://play.google.com/store/apps/details?id=com.shieldsvpn.vpn
  windows: ""   // https://.../ShieldsVPN-Setup.exe
};
var APP_LABELS = { android: "Get it on Google Play", windows: "Download for Windows" };
document.querySelectorAll('.app-card[data-app]').forEach(function (card) {
  var key = card.getAttribute('data-app'), url = APP_LINKS[key];
  if (!url || url.indexOf('https://') !== 0) return;
  var a = card.querySelector('.get');
  a.href = url; a.target = "_blank"; a.rel = "noopener";
  a.classList.remove('soon'); a.classList.add('live');
  a.textContent = APP_LABELS[key];
});
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
