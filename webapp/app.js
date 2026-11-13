(() => {
const tg = window.Telegram && Telegram.WebApp;
const app = document.getElementById('app');
const TOOLS = [
 {id:'ip', label:'IP lookup', ph:'8.8.8.8', hint:'Location, network and ISP for a public IP.'},
 {id:'domain', label:'Domain', ph:'example.com', hint:'DNS records, registrar and dates.'},
 {id:'dns', label:'DNS records', ph:'example.com', hint:'A, MX, NS, TXT, SPF and DMARC records.'},
 {id:'username', label:'Username', ph:'octocat', hint:'Quick check on social platforms.'},
 {id:'deepuser', label:'Deep username', ph:'octocat', hint:'Hundreds of verified sites. Can take a minute.'},
 {id:'email', label:'Email', ph:'name@example.com', hint:'Mail setup, provider type and public Gravatar profile.'},
 {id:'phone', label:'Phone', ph:'+14155552671', hint:'Country, line type and original carrier. Include the country code.'},
 {id:'web', label:'Website', ph:'example.com', hint:'Server, page title and missing security headers.'},
 {id:'archive', label:'Web archive', ph:'example.com', hint:'First and latest Wayback Machine snapshots.'},
 {id:'subdomains', label:'Subdomains', ph:'example.com', hint:'Found through public certificate logs.'},
 {id:'ports', label:'Exposure', ph:'8.8.8.8', hint:'Open ports and known CVEs from a passive index.'},
 {id:'ssl', label:'SSL certificate', ph:'example.com', hint:'Issuer, expiry and alternative names of the HTTPS certificate.'},
 {id:'telegram', label:'Telegram', ph:'durov', hint:'Public Telegram page: name, bio and audience size.'},
 {id:'github', label:'GitHub', ph:'octocat', hint:'Public GitHub profile details.'},
 {id:'reverseip', label:'Reverse IP', ph:'8.8.8.8', hint:'Other domains hosted on the same IP.'},
 {id:'btc', label:'Bitcoin', ph:'1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', hint:'Balance and transaction count of a Bitcoin address.'},
 {id:'mac', label:'MAC vendor', ph:'00:1A:2B:3C:4D:5E', hint:'The hardware maker, not the owner.'},
 {id:'ipwhois', label:'IP owner', ph:'8.8.8.8', hint:'Registered network owner, range and abuse contact.'},
 {id:'cve', label:'CVE', ph:'CVE-2024-3094', hint:'Severity, score and description of a vulnerability.'},
 {id:'unshort', label:'Unshorten link', ph:'bit.ly/example', hint:'Follows redirects without opening the final page.'},
 {id:'urlscan', label:'Past scans', ph:'example.com', hint:'Public scan history from urlscan.io.'},
 {id:'location', label:'Coordinates', ph:'48.8584, 2.2945', hint:'Neighbourhood-level place for coordinates.'},
 {id:'breach', label:'Breach check', ph:'you@example.com or adobe.com', hint:'Email or website domain. Only check addresses you own or have permission to check.'}];
let me, cur = TOOLS[0], last = null, timer = null;

function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === 'class') e.className = v; else if (k.startsWith('on')) e[k] = v; else e.setAttribute(k, v);
  }
  for (const c of kids.flat()) if (c != null) e.append(c.nodeType ? c : document.createTextNode(String(c)));
  return e;
}
function link(url, label) {
  return h('a', {href: url, onclick: ev => { ev.preventDefault(); tg.openLink(url); }}, label || url);
}
function linkify(s) {
  return String(s).split(/(https?:\/\/\S+)/).map(p => /^https?:\/\//.test(p) ? link(p) : p);
}
async function api(path, body) {
  const r = await fetch('/api/' + path, {method: body ? 'POST' : 'GET',
    headers: {'Content-Type': 'application/json', 'Authorization': 'tma ' + tg.initData},
    body: body ? JSON.stringify(body) : undefined});
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw Object.assign(new Error(j.detail || 'Request failed (' + r.status + ')'), {code: r.status});
  return j;
}
function cell(v) {
  if (v === null || v === undefined || v === '' || (Array.isArray(v) && !v.length)) return 'none';
  if (typeof v === 'boolean') return v ? 'yes' : 'no';
  if (Array.isArray(v)) return h('span', {}, v.map(x => h('div', {}, typeof x === 'object' ? Object.values(x).join(' | ') : linkify(x))));
  if (typeof v === 'object') return h('span', {}, Object.entries(v).map(([a, b]) => h('div', {}, a + ': ' + b)));
  return h('span', {}, linkify(v));
}
function renderResult(d) {
  const box = h('div', {class: 'glass', 'aria-live': 'polite'});
  if (d.profiles_found) {
    const f = d.profiles_found, b = d.blocked_or_uncertain || [];
    box.append(h('p', {class: 'big'}, 'Found on ' + f.length + ' sites'),
      h('p', {class: 'sub'}, d.sites_verified_and_checked + ' verified sites checked' + (b.length ? ' · ' + b.length + ' blocked, so uncertain' : '')));
    const by = {};
    f.forEach(r => (by[r.category] = by[r.category] || []).push(r));
    Object.keys(by).sort().forEach(cat => {
      box.append(h('h3', {}, cat + ' (' + by[cat].length + ')'));
      by[cat].forEach(r => box.append(h('div', {class: 'prof'}, r.site, link(r.url))));
    });
    if (!f.length) box.append(h('p', {class: 'sub'}, 'No public profiles found with this exact name.'));
    box.append(h('p', {class: 'hint'}, 'A match means a page with this name exists. It may not be the same person, so open the link to check.'));
  } else {
    Object.entries(d).forEach(([k, v]) => box.append(h('div', {class: 'row'}, h('span', {class: 'k'}, k.replace(/_/g, ' ')), h('span', {class: 'v'}, cell(v)))));
  }
  box.append(h('button', {class: 'link', onclick: copyJson}, 'Copy as JSON'));
  return box;
}
function copyJson() {
  const t = JSON.stringify(last, null, 2);
  const done = () => { try { tg.HapticFeedback.notificationOccurred('success'); } catch (e) {} };
  (navigator.clipboard ? navigator.clipboard.writeText(t) : Promise.reject()).then(done).catch(() => {
    const ta = h('textarea'); ta.value = t; document.body.append(ta); ta.select();
    try { document.execCommand('copy'); done(); } catch (e) { tg.showAlert('Copy failed'); } ta.remove();
  });
}
function pick(t, ui) {
  cur = t; ui.input.placeholder = t.ph;
  const cost = me.costs[t.id];
  ui.hint.textContent = t.hint + (cost ? ' Costs ' + cost + ' credits.' : '');
  ui.chips.querySelectorAll('.chip').forEach(c => c.setAttribute('aria-pressed', c.dataset.id === t.id));
}
async function run(ev, ui) {
  ev.preventDefault();
  const v = ui.input.value.trim(); if (!v) return;
  ui.go.disabled = true; ui.go.textContent = 'Running';
  const sec = h('span', {}, '0s'), t0 = Date.now();
  ui.out.replaceChildren(h('div', {class: 'glass'}, h('span', {class: 'spin'}), 'Working… ', sec));
  clearInterval(timer); timer = setInterval(() => sec.textContent = Math.floor((Date.now() - t0) / 1000) + 's', 1000);
  try {
    last = await api('tool/' + cur.id, {q: v});
    ui.out.replaceChildren(renderResult(last));
    try { tg.HapticFeedback.notificationOccurred('success'); } catch (e) {}
    me = await api('me'); ui.bal.textContent = me.credits;
  } catch (err) {
    ui.out.replaceChildren(h('div', {class: 'glass err'}, err.message));
    if (err.code === 402 && ui.openBuy) ui.openBuy();
  } finally { clearInterval(timer); ui.go.disabled = false; ui.go.textContent = 'Run'; }
}
function overlay(cls, ...kids) { const o = h('div', {class: 'overlay ' + cls}, ...kids); document.body.append(o); return o; }
function build() {
  const ui = {};
  ui.bal = h('span', {}, me.credits);
  ui.input = h('input', {autocapitalize: 'off', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Target'});
  ui.go = h('button', {class: 'go'}, 'Run');
  ui.hint = h('p', {class: 'hint'});
  ui.out = h('div');
  ui.chips = h('div', {class: 'chips'}, TOOLS.map(t => h('button', {class: 'chip', 'data-id': t.id, 'aria-pressed': 'false', onclick: () => pick(t, ui)}, t.label)));
  const badge = me.free ? h('div', {class: 'badge'}, h('span', {class: 'dot'}), 'Free') : h('button', {class: 'badge', onclick: () => ui.openBuy()}, h('span', {class: 'dot'}), ui.bal, ' credits');
  app.replaceChildren(
    h('header', {}, h('h1', {}, 'OSINT Hub'), badge),
    h('div', {class: 'glass'}, ui.chips, h('form', {onsubmit: e => run(e, ui)}, ui.input, ui.go), ui.hint),
    ui.out);
  pick(cur, ui);
  if (!me.free) {
    ui.openBuy = () => {
      const o = overlay('sheet');
      const card = h('div', {class: 'glass'}, h('b', {}, 'Buy credits with Telegram Stars'));
      Object.entries(me.packs).forEach(([k, p]) => {
        card.append(h('button', {class: 'pack', onclick: async () => {
          try {
            const r = await api('invoice', {pack: k});
            tg.openInvoice(r.url, s => {
              if (s === 'paid') {
                o.remove();
                setTimeout(async () => { me = await api('me'); ui.bal.textContent = me.credits; }, 1500);
              }
            });
          } catch (e) { tg.showAlert(e.message); }
        }}, h('span', {}, p.credits + ' credits'), h('span', {}, p.stars + ' ★')));
      });
      card.append(h('button', {class: 'link', onclick: () => o.remove()}, 'Close'));
      o.append(card);
    };
  }
  if (!me.consent) {
    const o = overlay('', h('h2', {}, 'Before you start'),
      h('p', {class: 'sub'}, 'This tool uses public and passive data. Do not use it to stalk, harass, dox or target anyone. Lookups are logged and rate-limited. To remove an identifier, send /optout in the bot chat.'),
      h('button', {class: 'go', onclick: async () => { await api('consent', {}); o.remove(); }}, 'I agree and will use it lawfully'));
  }
}
async function boot() {
  if (!tg || !tg.initData) {
    app.replaceChildren(h('p', {class: 'msg'}, 'Open this app from the button in the Telegram bot chat.'));
    return;
  }
  tg.ready(); tg.expand();
  try { tg.setHeaderColor('#020617'); tg.setBackgroundColor('#020617'); } catch (e) {}
  try { me = await api('me'); build(); }
  catch (e) { app.replaceChildren(h('p', {class: 'msg err'}, e.message)); }
}
boot();
})();
