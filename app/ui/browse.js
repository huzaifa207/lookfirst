// Read-only browsing. Files come back from the Rust side as plain text and only ever go on screen
// through textContent, so markup, scripts and links in them are shown, never run or followed.

/** Characters that change how code reads without being seen. */
function hiddenName(code) {
  if (code === 0x202a) return "left-to-right embedding";
  if (code === 0x202b) return "right-to-left embedding";
  if (code === 0x202c) return "pop directional formatting";
  if (code === 0x202d) return "left-to-right override";
  if (code === 0x202e) return "right-to-left override";
  if (code >= 0x2066 && code <= 0x2069) return "directional isolate";
  if (code === 0x200e || code === 0x200f || code === 0x061c) return "direction mark";
  if (code === 0x200b || code === 0x200c || code === 0x200d || code === 0x2060) return "zero-width character";
  if (code === 0xfeff) return "byte order mark";
  if (code === 0x00ad) return "soft hyphen";
  if (code >= 0xe0000 && code <= 0xe007f) return "invisible tag character";
  if ((code < 0x20 && code !== 0x09) || (code >= 0x7f && code <= 0x9f)) return "control character";
  return null;
}
const DIRECTIONAL = new Set(["left-to-right embedding", "right-to-left embedding", "pop directional formatting",
  "left-to-right override", "right-to-left override", "directional isolate", "direction mark"]);
const PADDING = /[ \t]{40,}(?=\S)/g;
const MAX_LINES = 20000;

const browse = { source: null, nodes: [], open: null };

/** Where to find a finding's file: in the files as they are now, or on its first branch. */
function locationFor(f) {
  if (!f.branch) return { kind: "file", path: f.path };
  const branch = f.branch.split(", ")[0];
  const repo = current.report.repos
    .filter((r) => f.path.startsWith(r.path.replace(/\.git$/, "")))
    .sort((a, b) => b.path.length - a.path.length)[0];
  return repo ? { kind: "branch", repo: repo.path, branch, path: f.path } : { kind: "file", path: f.path };
}

// The branch picker: drawn by the app, because the system's popup menu opens on top of the field.
const picker = { options: [], value: "" };

function renderPicker() {
  const chosen = picker.options.find((o) => o.value === picker.value) || picker.options[0];
  $("source-label").textContent = chosen.label;
  const menu = $("source-menu");
  menu.replaceChildren(...picker.options.map((o, i) => {
    const li = document.createElement("li");
    li.id = `source-option-${i}`;
    li.role = "option";
    li.tabIndex = -1;
    li.textContent = o.label;
    li.setAttribute("aria-selected", String(o.value === picker.value));
    li.addEventListener("click", () => pickSource(o.value));
    return li;
  }));
}

function openPicker(open) {
  $("source-menu").hidden = !open;
  $("source").setAttribute("aria-expanded", String(open));
  if (open) ($("source-menu").querySelector('[aria-selected="true"]') || $("source-menu").firstChild)?.focus();
}

function pickSource(value) {
  openPicker(false);
  $("source").focus();
  if (value === picker.value) return;
  picker.value = value;
  renderPicker();
  loadSource();
}

$("source").addEventListener("click", () => openPicker($("source-menu").hidden));
$("source").addEventListener("keydown", (e) => {
  if (["ArrowDown", "ArrowUp"].includes(e.key)) { e.preventDefault(); openPicker(true); }
});
$("source-menu").addEventListener("keydown", (e) => {
  const items = [...$("source-menu").children];
  const at = items.indexOf(document.activeElement);
  if (e.key === "ArrowDown" || e.key === "ArrowUp") {
    e.preventDefault();
    items[Math.min(items.length - 1, Math.max(0, at + (e.key === "ArrowDown" ? 1 : -1)))].focus();
  } else if (e.key === "Home" || e.key === "End") {
    e.preventDefault();
    items[e.key === "Home" ? 0 : items.length - 1].focus();
  } else if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    if (at >= 0) pickSource(picker.options[at].value);
  } else if (e.key === "Escape") {
    openPicker(false);
    $("source").focus();
  } else if (e.key === "Tab") {
    openPicker(false);
  }
});
document.addEventListener("click", (e) => {
  if (!$("source-menu").hidden && !e.target.closest(".picker")) openPicker(false);
});

async function openBrowser(location) {
  picker.options = [{ label: "Files as they are now", value: "" }];
  for (const r of current.report.repos) {
    const where = current.report.repos.length > 1 ? ` in ${r.path.replace(/\/?\.git$/, "") || "the top folder"}` : "";
    for (const b of r.branches) {
      if (b === r.head) continue;
      picker.options.push({ label: `Branch ${b}${where}`, value: JSON.stringify({ repo: r.path, branch: b }) });
    }
    for (const t of r.tags) picker.options.push({ label: `Tag ${t}${where}`, value: JSON.stringify({ repo: r.path, branch: `tag ${t}` }) });
  }
  const source = location?.kind === "branch" ? JSON.stringify({ repo: location.repo, branch: location.branch }) : "";
  picker.value = picker.options.some((o) => o.value === source) ? source : "";
  renderPicker();
  openPicker(false);
  $("filter").value = "";
  show("browse");
  await loadSource();
  if (location) openFile(location.path);
}

async function loadSource() {
  browse.source = picker.value ? JSON.parse(picker.value) : null;
  if (browse.source) {
    $("tree").replaceChildren(note("Reading the branch…"));
    browse.nodes = await invoke("branch", { path: current.path, repo: browse.source.repo, branch: browse.source.branch });
  } else {
    browse.nodes = current.report.entries || [];
  }
  renderTree();
}

/** The findings that belong to what's being shown: the files now, or one branch. */
function findingsHere() {
  const branch = browse.source?.branch;
  return current.report.findings.filter((f) => (branch ? (f.branch || "").split(", ").includes(branch) : !f.branch));
}

function note(text) {
  const p = document.createElement("p");
  p.className = "empty";
  p.textContent = text;
  return p;
}

/** "pack/more.zip › x/run.sh" → ["pack", "more.zip", "x", "run.sh"]: nested archives become folders. */
function parts(path) {
  return path.split(" › ").flatMap((p) => p.split("/")).filter(Boolean);
}

function renderTree() {
  const levels = new Map();
  for (const f of findingsHere()) levels.set(f.path, Math.max(levels.get(f.path) || 0, f.level === "danger" ? 2 : 1));

  // Build folders from the paths, so every file shows even when its folders weren't listed.
  const root = { children: new Map(), level: 0 };
  for (const node of browse.nodes) {
    let at = root;
    const segs = parts(node.path);
    segs.forEach((name, i) => {
      if (!at.children.has(name)) at.children.set(name, { name, children: new Map(), level: 0 });
      at = at.children.get(name);
      if (i === segs.length - 1 && node.kind !== "dir") at.node = node;
    });
    let level = levels.get(node.path) || 0;
    if (level) {
      let up = root;
      for (const name of segs) { up.level = Math.max(up.level, level); up = up.children.get(name); }
      up.level = Math.max(up.level, level);
    }
  }
  const tree = $("tree");
  tree.replaceChildren(list(root, 0));
  if (current.report.entries_truncated && !browse.source) tree.append(note("Only the first 100,000 entries are listed."));
  if (!browse.nodes.length) tree.replaceChildren(note("Nothing to show."));
}

function badge(level) {
  const b = document.createElement("span");
  b.className = `dot ${level === 2 ? "danger" : "check"}`;
  b.title = level === 2 ? "Danger inside" : "Worth a look inside";
  return b;
}

function sorted(folder) {
  // Folders first, then files, each alphabetically.
  return [...folder.children.values()].sort((a, b) => (a.node ? 1 : 0) - (b.node ? 1 : 0) || a.name.localeCompare(b.name));
}

function list(folder, depth) {
  const ul = document.createElement("ul");
  for (const item of sorted(folder)) {
    const li = document.createElement("li");
    if (item.node) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "file";
      button.dataset.path = item.node.path;
      button.textContent = item.name;
      if (item.level) button.append(badge(item.level));
      button.addEventListener("click", () => openFile(item.node.path));
      li.append(button);
    } else {
      const details = document.createElement("details");
      const summary = document.createElement("summary");
      summary.textContent = item.name;
      if (item.level) summary.append(badge(item.level));
      details.append(summary);
      // Children are built on first open, so huge folders don't slow the window.
      const fill = () => { if (details.children.length === 1) details.append(list(item, depth + 1)); };
      details.addEventListener("toggle", () => details.open && fill());
      details.open = (depth < 2 && item.name !== ".git" && item.name !== "node_modules") || item.level > 0;
      if (details.open) fill();
      li.append(details);
    }
    ul.append(li);
  }
  return ul;
}

function showMatches(query) {
  const tree = $("tree");
  if (!query) return renderTree();
  const q = query.toLowerCase();
  const matches = browse.nodes.filter((n) => n.kind !== "dir" && n.path.toLowerCase().includes(q)).slice(0, 500);
  const ul = document.createElement("ul");
  for (const n of matches) {
    const li = document.createElement("li");
    const button = document.createElement("button");
    button.type = "button";
    button.className = "file";
    button.dataset.path = n.path;
    button.textContent = n.path;
    button.addEventListener("click", () => openFile(n.path));
    li.append(button);
    ul.append(li);
  }
  tree.replaceChildren(matches.length ? ul : note("No file names match."));
}

async function openFile(path) {
  browse.open = path;
  for (const b of document.querySelectorAll("#tree .file")) b.classList.toggle("active", b.dataset.path === path);
  const viewer = $("viewer");
  viewer.replaceChildren(note("Reading…"));
  const location = browse.source ? { kind: "branch", ...browse.source, path } : { kind: "file", path };
  let view;
  try {
    view = await invoke("read", { path: current.path, location });
  } catch (e) {
    view = { kind: "missing" };
  }
  if (browse.open !== path) return; // another file was chosen meanwhile

  const head = document.createElement("header");
  const name = document.createElement("div");
  name.className = "path";
  name.textContent = (browse.source ? `${browse.source.branch.startsWith("tag ") ? "" : "branch "}${browse.source.branch} · ` : "") + path;
  head.append(name);
  for (const f of findingsHere().filter((f) => f.path === path)) {
    const flag = document.createElement("p");
    flag.className = `flag ${f.level}`;
    flag.textContent = f.campaign ? `${f.title} Matches ${f.campaign}.` : f.title;
    head.append(flag);
  }
  viewer.replaceChildren(head);

  if (view.kind === "binary") return viewer.append(note(`A binary file (${size(view.size)}). It isn't shown, and LookFirst never opens it.`));
  if (view.kind === "link") return viewer.append(note(`A link to ${view.target}. LookFirst shows where it points, and never follows it.`));
  if (view.kind !== "text") return viewer.append(note("This file couldn't be read."));
  renderText(viewer, view);
}

function size(bytes) {
  if (bytes < 1024) return `${bytes} bytes`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function renderText(viewer, view) {
  const lines = view.text.split(/\r?\n/);
  if (lines.length > 1 && lines[lines.length - 1] === "") lines.pop();
  let hidden = 0, directional = 0, padded = 0;
  const body = document.createElement("div");
  body.className = "code";
  for (const [i, line] of lines.slice(0, MAX_LINES).entries()) {
    const row = document.createElement("div");
    row.className = "line";
    const num = document.createElement("span");
    num.className = "n";
    num.textContent = i + 1;
    const code = document.createElement("span");
    code.className = "c";
    let text = "";
    const flush = () => { if (text) { code.append(text); text = ""; } };
    // Long runs of spaces that push code off to the right are shortened to a visible marker.
    const pads = [...line.matchAll(PADDING)].map((m) => [m.index, m[0].length]);
    for (let at = 0; at < line.length;) {
      const pad = pads.find(([start]) => start === at);
      if (pad) {
        flush();
        const mark = document.createElement("span");
        mark.className = "pad";
        mark.textContent = `⟶ ${pad[1]} spaces`;
        code.append(mark);
        padded++;
        row.classList.add("flagged");
        at += pad[1];
        continue;
      }
      const ch = String.fromCodePoint(line.codePointAt(at));
      const what = hiddenName(ch.codePointAt(0));
      if (what) {
        flush();
        const mark = document.createElement("span");
        mark.className = "hidden";
        const hex = ch.codePointAt(0).toString(16).toUpperCase().padStart(4, "0");
        mark.textContent = `U+${hex}`;
        mark.title = what;
        code.append(mark);
        hidden++;
        if (DIRECTIONAL.has(what)) directional++;
        row.classList.add("flagged");
      } else {
        text += ch;
      }
      at += ch.length;
    }
    flush();
    row.append(num, code);
    body.append(row);
  }

  const warnings = [];
  if (directional) warnings.push(`${directional} character${directional === 1 ? "" : "s"} that reverse the direction of text, which can make code read differently from how it runs`);
  if (hidden - directional) warnings.push(`${hidden - directional} other invisible or control character${hidden - directional === 1 ? "" : "s"}`);
  if (padded) warnings.push(`${padded} long run${padded === 1 ? "" : "s"} of spaces pushing code off to the right`);
  for (const w of warnings) {
    const p = document.createElement("p");
    p.className = "flag check";
    p.textContent = `This file has ${w}. They're marked below.`;
    viewer.append(p);
  }
  if (view.truncated) viewer.append(note("Only the first 2 MB is shown."));
  if (lines.length > MAX_LINES) viewer.append(note(`Only the first ${MAX_LINES.toLocaleString()} lines are shown.`));

  const tools = document.createElement("label");
  tools.className = "wrap";
  const box = document.createElement("input");
  box.type = "checkbox";
  box.checked = !viewer.classList.contains("nowrap");
  box.addEventListener("change", () => viewer.classList.toggle("nowrap", !box.checked));
  tools.append(box, " Wrap long lines");
  viewer.append(tools, body);
}

$("back").addEventListener("click", () => show("result"));
$("filter").addEventListener("input", (e) => showMatches(e.target.value.trim()));
