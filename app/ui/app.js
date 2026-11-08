// The window: pick or drop a file, ask the Rust side to scan it, show the verdict.
const { invoke } = window.__TAURI__.core;
const { open } = window.__TAURI__.dialog;
const { getCurrentWebview } = window.__TAURI__.webview;

const $ = (id) => document.getElementById(id);

const VERDICTS = {
  danger: {
    title: "Don't open this",
    text: "It contains code that runs by itself. Don't extract it, open it in a code editor, or use Git on it. " +
      "Send this report to your IT or security team, and ask the sender to explain.",
  },
  check: {
    title: "Look closer before opening",
    text: "Nothing here is known to be malicious, but some files can run code. " +
      "Ask a developer you trust to look at the items below before anyone opens it.",
  },
  clear: {
    title: "No known traps found",
    text: "LookFirst didn't find anything that runs code by itself. That isn't a guarantee, " +
      "so still be careful with files from people you haven't verified.",
  },
  unreadable: {
    title: "This couldn't be read",
    text: "It may be damaged, or not an archive LookFirst can open. Don't extract it until someone has checked it.",
  },
};

let lastText = "";

function show(section) {
  for (const id of ["home", "busy", "result"]) $(id).hidden = id !== section;
}

function fileName(path) {
  return path.split(/[\\/]/).filter(Boolean).pop() || path;
}

async function scan(path) {
  $("busy-name").textContent = fileName(path);
  show("busy");
  try {
    render(path, await invoke("scan", { path }));
  } catch (e) {
    render(path, { verdict: "unreadable", report: { files: 0, findings: [], repos: [], errors: [String(e)], has_git: false } });
  }
}

function render(path, { verdict, report }) {
  const v = VERDICTS[verdict];
  $("verdict").className = `verdict ${verdict}`;
  $("verdict-title").textContent = v.title;
  $("verdict-text").textContent = v.text;

  const files = `${report.files.toLocaleString()} file${report.files === 1 ? "" : "s"} checked`;
  const git = report.has_git ? " · contains a Git repository, where hooks live" : "";
  $("meta").textContent = `${fileName(path)} · ${files}${git}`;

  const list = $("findings");
  list.replaceChildren();
  for (const f of report.findings) {
    const li = document.createElement("li");
    li.className = f.level;
    const tag = document.createElement("div");
    tag.className = "tag";
    tag.textContent = f.level === "danger" ? "Danger" : "Check";
    const title = document.createElement("p");
    title.className = "title";
    title.textContent = f.title;
    const where = document.createElement("div");
    where.className = "path";
    where.textContent = f.path;
    const branch = document.createElement("div");
    branch.className = "branch";
    branch.textContent = `On branch ${f.branch}, not in the files as they are now`;
    const details = document.createElement("details");
    const summary = document.createElement("summary");
    summary.textContent = "Details for a developer";
    const detail = document.createElement("p");
    detail.textContent = f.detail;
    details.append(summary, detail);
    li.append(tag, title, ...(f.branch ? [branch] : []), where, details);
    list.append(li);
  }
  for (const e of report.errors) {
    const li = document.createElement("li");
    li.textContent = e;
    list.append(li);
  }

  const repos = $("repos");
  repos.replaceChildren();
  for (const r of report.repos) {
    const box = document.createElement("div");
    box.className = "repo";
    const head = document.createElement("p");
    const count = r.branches.length;
    head.textContent = `Git repository in ${r.path.replace(/\/?\.git$/, "") || "the top folder"}: ` +
      `${count} branch${count === 1 ? "" : "es"}${r.tags.length ? ` and ${r.tags.length} tag${r.tags.length === 1 ? "" : "s"}` : ""}, ${r.note ? "some couldn't be checked" : "all checked"}`;
    const names = document.createElement("p");
    names.className = "names";
    names.textContent = r.branches.map((b) => (b === r.head ? `${b} (open now)` : b)).join(" · ") +
      (r.tags.length ? `  ·  tags: ${r.tags.join(", ")}` : "");
    box.append(head, names);
    if (r.note) {
      const note = document.createElement("p");
      note.className = "note";
      note.textContent = r.note;
      box.append(note);
    }
    repos.append(box);
  }

  lastText = [
    `LookFirst report: ${v.title}`,
    `${path}`,
    files + (report.has_git ? ", contains a Git repository" : ""),
    "",
    ...report.findings.map((f) => `[${f.level.toUpperCase()}] ${f.path}${f.branch ? ` (on branch ${f.branch})` : ""}\n  ${f.title}\n  ${f.detail}`),
    ...report.repos.map((r) => `[GIT] ${r.path}: branches ${r.branches.join(", ") || "none"}` +
      (r.tags.length ? `; tags ${r.tags.join(", ")}` : "") + (r.note ? `\n  ${r.note}` : "")),
    ...report.errors.map((e) => `[ERROR] ${e}`),
  ].join("\n");
  show("result");
  window.scrollTo(0, 0);
  $("again").focus({ preventScroll: true });
}

async function choose(directory) {
  const path = await open({
    directory,
    multiple: false,
    filters: directory ? [] : [{ name: "Archives", extensions: ["zip", "tar", "gz", "tgz", "bz2", "xz", "7z", "rar"] }],
  });
  if (path) scan(path);
}

$("drop").addEventListener("click", () => choose(false));
$("folder").addEventListener("click", () => choose(true));
$("again").addEventListener("click", () => show("home"));
$("copy").addEventListener("click", async () => {
  await navigator.clipboard.writeText(lastText);
  $("copy").textContent = "Copied";
  setTimeout(() => ($("copy").textContent = "Copy the report"), 1500);
});

// Drag and drop works anywhere in the window.
getCurrentWebview().onDragDropEvent(({ payload }) => {
  if (payload.type === "enter" || payload.type === "over") {
    $("dropping").hidden = false;
  } else {
    $("dropping").hidden = true;
    if (payload.type === "drop" && payload.paths.length) scan(payload.paths[0]);
  }
});
