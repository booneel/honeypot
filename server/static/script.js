// 공격자가 제어하는 값(username, command, ip)은 모두 textContent로만 넣는다.

// analyzer.py의 분류 체계를 그대로 미러링한다.
const CATEGORY = {
    whoami: "discovery", ls: "discovery", ip: "discovery",
    hostname: "discovery", uname: "discovery", id: "discovery", pwd: "discovery",
    cat: "file",
    curl: "download", wget: "download",
    su: "priv", sudo: "priv",
};

const CAT_LABEL = {
    discovery: "Discovery",
    file:      "File access",
    download:  "Download",
    priv:      "Priv-esc",
    other:     "Other",
};

// 위협 단계: 버퍼 안 최고 위험 카테고리로 결정
const THREAT_RANK = { other: 0, discovery: 1, file: 2, download: 3, priv: 4 };
const THREAT_LEVEL = [
    { level: "calm",     label: "Calm" },
    { level: "recon",    label: "Recon" },
    { level: "probing",  label: "Probing" },
    { level: "elevated", label: "Elevated" },
    { level: "critical", label: "Critical" },
];

function categoryOf(command) {
    const first = (command || "").trim().split(/\s+/)[0];
    return CATEGORY[first] || "other";
}

const seen = new Set();
function signature(cmd) {
    return [cmd.time, cmd.protocol, cmd.ip, cmd.username, cmd.command].join("|");
}

// ── 상태 ──────────────────────────────────────────
let lastSessions = {};
let lastCommands = [];   // 라이브 버퍼 (/recent_commands)
let filterQuery  = "";   // 즉시 필터용 검색어
let historyMode  = false; // true 면 목록은 /history 결과를 보여주는 중

const IP_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

// session / ip / username / command 전부를 대상으로 부분일치
function matchesQuery(cmd, q) {
    return [cmd.session_id, cmd.ip, cmd.username, cmd.command]
        .some(v => String(v ?? "").toLowerCase().includes(q));
}

function setLink(online) {
    const pill = document.getElementById("link-state");
    pill.className = "link-pill " + (online ? "is-live" : "is-off");
    pill.querySelector(".link-label").textContent = online ? "LIVE" : "OFFLINE";
}

function renderSessions(data) {
    const list = document.getElementById("sessions");
    const sessions = Object.values(data || {});

    document.getElementById("session-count").textContent = sessions.length;
    document.getElementById("m-sessions").textContent = sessions.length;
    list.innerHTML = "";

    if (sessions.length === 0) {
        const empty = document.createElement("div");
        empty.className = "empty";
        const b = document.createElement("b");
        b.textContent = "No active sessions";
        empty.appendChild(b);
        empty.appendChild(document.createTextNode("The trap is armed and waiting."));
        list.appendChild(empty);
        return;
    }

    sessions.forEach(conn => {
        const card = document.createElement("div");
        card.className = "session-card";

        const top = document.createElement("div");
        top.className = "session-top";
        const dot = document.createElement("span");
        dot.className = "session-live";
        const tag = document.createElement("span");
        tag.className = "session-tag " + (conn.protocol || "TCP").toLowerCase();
        tag.textContent = conn.protocol || "TCP";
        top.append(dot, tag);

        const ip = document.createElement("div");
        ip.className = "session-ip";
        ip.textContent = conn.ip ?? "—";

        const meta = document.createElement("div");
        meta.className = "session-meta";
        const protocol = document.createElement("div");
        protocol.className = "session-protocol";
        protocol.textContent = conn.protocol;
        meta.appendChild(protocol);
        meta.appendChild(document.createTextNode("as "));
        const user = document.createElement("b");
        user.textContent = conn.username ?? "—";
        meta.appendChild(user);

        card.append(top, ip, meta);
        list.appendChild(card);
    });
}

// 명령 한 줄을 만드는 공통 헬퍼 (라이브 스트림 / 히스토리 공용)
function buildCmdRow(cmd, isNew) {
    const cat = categoryOf(cmd.command);

    const row = document.createElement("div");
    row.className = "cmd" + (isNew ? " is-new" : "");
    row.dataset.cat = cat;
    row.dataset.session = cmd.session_id ?? "";
    row.dataset.ip = cmd.ip ?? "";
    row.style.cursor = "pointer";

    const time = document.createElement("span");
    time.className = "cmd-time";
    time.textContent = (cmd.time || "").split("_")[1] || cmd.time || "";

    const proto = document.createElement("span");
    proto.className = "cmd-protocol " + (cmd.protocol || "TCP").toLowerCase();
    proto.textContent = cmd.protocol || "TCP";

    const label = document.createElement("span");
    label.className = "cmd-cat-label";
    label.textContent = CAT_LABEL[cat];

    const text = document.createElement("span");
    text.className = "cmd-text";
    text.textContent = cmd.command ?? "";

    const who = document.createElement("span");
    who.className = "cmd-who";
    const ipEl = document.createElement("span");
    ipEl.className = "cmd-ip";
    ipEl.textContent = cmd.ip ?? "";
    who.append(ipEl, document.createTextNode(" · " + (cmd.username ?? "")));

    row.append(time, proto, label, text, who);
    return row;
}

// 지표(버퍼 명령 수 / 위협 단계)는 항상 라이브 버퍼 전체 기준
function updateMetrics(all) {
    all = all || [];
    document.getElementById("m-commands").textContent = all.length;

    let maxRank = 0;
    all.forEach(c => {
        const r = THREAT_RANK[categoryOf(c.command)] || 0;
        if (r > maxRank) maxRank = r;
    });
    const threat = THREAT_LEVEL[all.length ? maxRank : 0];
    document.getElementById("m-threat").textContent = threat.label;
    document.getElementById("m-threat-wrap").dataset.level = threat.level;
}

// 라이브 스트림 목록 (즉시 필터 적용)
function renderCommandList(data) {
    const list = document.getElementById("commands");
    const all  = data || [];

    const q = filterQuery.trim().toLowerCase();
    let rows = all.slice().reverse(); // newest first
    if (q) rows = rows.filter(c => matchesQuery(c, q));

    list.innerHTML = "";

    if (rows.length === 0) {
        const empty = document.createElement("div");
        empty.className = "empty";
        const b = document.createElement("b");
        if (q) {
            b.textContent = "No matching commands in buffer";
            empty.appendChild(b);
            empty.appendChild(
                document.createTextNode("Press Enter to search the full history.")
            );
        } else {
            b.textContent = "No commands captured yet";
            empty.appendChild(b);
            empty.appendChild(
                document.createTextNode("Activity will appear here as attackers type.")
            );
        }
        list.appendChild(empty);
        all.forEach(c => seen.add(signature(c)));
        return;
    }

    rows.forEach(cmd => {
        const sig = signature(cmd);
        const isNew = !seen.has(sig);
        seen.add(sig);
        list.appendChild(buildCmdRow(cmd, isNew));
    });

    all.forEach(c => seen.add(signature(c))); // 가려진 항목도 seen 처리
    if (seen.size > 200) seen.clear();
}

function tickClock() {
    const now = new Date();
    const p = n => String(n).padStart(2, "0");
    document.getElementById("clock").textContent =
        `${p(now.getHours())}:${p(now.getMinutes())}:${p(now.getSeconds())}`;
}

async function refresh() {
    try {
        const [cRes, kRes] = await Promise.all([
            fetch("/connections"),
            fetch("/recent_commands"),
        ]);
        if (!cRes.ok || !kRes.ok) throw new Error(`HTTP ${cRes.status}/${kRes.status}`);

        const conns = await cRes.json();
        const cmds  = await kRes.json();
        setLink(true);

        lastSessions = conns;
        lastCommands = cmds;

        renderSessions(conns);
        updateMetrics(cmds);
        if (!historyMode) renderCommandList(cmds); // 히스토리 보는 중엔 목록 보존
        updateHint();
    } catch (e) {
        console.error("refresh failed:", e);
        setLink(false);
    }
}

// ── replay 패널 열기 / 닫기 ───────────────────────
const replayPanel    = document.getElementById("replay");
const replayBackdrop = document.getElementById("replay-backdrop");

function openReplay() {
    replayPanel.classList.add("open");
    if (replayBackdrop) replayBackdrop.classList.add("open");
}

function closeReplay() {
    replayPanel.classList.remove("open");
    if (replayBackdrop) replayBackdrop.classList.remove("open");
}

if (replayBackdrop) replayBackdrop.addEventListener("click", closeReplay);

document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && replayPanel.classList.contains("open")) {
        closeReplay();
    }
});

// 명령 행 클릭 → 세션 리플레이 (이벤트 위임)
document.getElementById("commands").addEventListener("click", (e) => {
    const row = e.target.closest(".cmd");
    if (!row || !row.dataset.session) return;
    openSession(row.dataset.session);
});

async function openSession(sessionId) {
    const res = await fetch(`/session/${encodeURIComponent(sessionId)}`);
    if (!res.ok) return;
    renderReplay(await res.json());
}

function renderReplay(data) {
    const panel = document.getElementById("replay");
    panel.innerHTML = "";

    const head = document.createElement("div");
    head.className = "replay-head";
    const title = document.createElement("b");
    title.textContent = `${data.username}@${data.ip ?? "—"}`;

    const closeBtn = document.createElement("button");
    closeBtn.className = "replay-close";
    closeBtn.type = "button";
    closeBtn.setAttribute("aria-label", "Close");
    closeBtn.textContent = "×";
    closeBtn.addEventListener("click", closeReplay);

    head.append(title, closeBtn);

    const meta = document.createElement("div");
    meta.className = "replay-meta";
    // 모두 textContent — XSS 방어 (기존 코드 원칙 유지)
    const fields = [
        ["Session", data.session_id],
        ["User",     data.username],
        ["Password", data.password],
        ["IP",       data.ip],
        ["Protocol", data.protocol],
    ];
    fields.forEach(([k, v]) => {
        const line = document.createElement("div");
        const key = document.createElement("span");
        key.className = "replay-key";
        key.textContent = k;
        const val = document.createElement("span");
        val.className = "replay-val mono";
        val.textContent = v ?? "—";
        line.append(key, val);
        meta.appendChild(line);
    });

    const log = document.createElement("div");
    log.className = "replay-log";
    (data.commands || []).forEach(c => {
        const line = document.createElement("div");
        line.className = "replay-cmd mono";
        const t = document.createElement("span");
        t.className = "replay-time";
        t.textContent = (c.time || "").split("_")[1] || c.time || "";
        const cmd = document.createElement("span");
        cmd.textContent = c.command ?? "";
        line.append(t, cmd);
        log.appendChild(line);
    });

    panel.append(head, meta, log);
    openReplay();
}

// ── 검색 / 필터 ───────────────────────────────────
const search = document.getElementById("replay-search");
const hint   = document.getElementById("search-hint");

function detectType(v) {
    const q = v.toLowerCase();
    if (IP_RE.test(v)) return "ip";
    if ((lastCommands || []).some(c => String(c.username ?? "").toLowerCase() === q))
        return "username";
    if ((lastCommands || []).some(c => String(c.session_id ?? "").toLowerCase() === q))
        return "session";
    return "text";
}

function updateHint() {
    const v = filterQuery.trim();
    if (!v || historyMode) { hint.textContent = ""; return; }

    const q = v.toLowerCase();
    const matches = (lastCommands || []).filter(c => matchesQuery(c, q)).length;

    let label, color;
    switch (detectType(v)) {
        case "ip":       label = "IP address";  color = "var(--t-discover)"; break;
        case "username": label = "Username";    color = "var(--honey-soft)"; break;
        case "session":  label = "Session ID";  color = "var(--honey-soft)"; break;
        default:         label = "Filter";      color = "var(--muted)";
    }

    hint.textContent = `${label} · ${matches} in buffer · ↵ full history`;
    hint.style.color = color;
}

// 디스크의 전체 기록 검색 (/history)
async function searchHistory(query) {
    const q = query.trim();
    if (!q) return;
    try {
        const res = await fetch(`/history?q=${encodeURIComponent(q)}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        renderHistory(await res.json(), q, false);
    } catch (e) {
        console.error("history search failed:", e);
        renderHistory([], q, true);
    }
}

function renderHistory(data, query, isError) {
    historyMode = true;
    hint.textContent = "";

    const list = document.getElementById("commands");
    list.innerHTML = "";

    const rows = (data || []).slice().reverse(); // newest first

    // 배너 (결과 수 + 라이브로 복귀 버튼)
    const banner = document.createElement("div");
    banner.className = "stream-banner";

    const metaWrap = document.createElement("span");
    metaWrap.className = "sb-meta";
    const tagSpan = document.createElement("b");
    tagSpan.textContent = "History";
    metaWrap.append(tagSpan, document.createTextNode(" · "));
    const qSpan = document.createElement("span");
    qSpan.className = "sb-q mono";
    qSpan.textContent = query;            // textContent — XSS 안전
    metaWrap.append(qSpan);
    metaWrap.append(document.createTextNode(
        isError ? " · search failed" : ` · ${rows.length} result${rows.length === 1 ? "" : "s"}`
    ));

    const back = document.createElement("button");
    back.className = "sb-back";
    back.type = "button";
    back.textContent = "← Back to live";
    back.addEventListener("click", exitHistory);

    banner.append(metaWrap, back);
    list.appendChild(banner);

    if (rows.length === 0) {
        const empty = document.createElement("div");
        empty.className = "empty";
        const b = document.createElement("b");
        b.textContent = isError ? "Search failed" : "No history found";
        empty.appendChild(b);
        empty.appendChild(document.createTextNode(
            isError ? "Could not reach /history." : "Nothing in the log matches this query."
        ));
        list.appendChild(empty);
        return;
    }

    rows.forEach(cmd => list.appendChild(buildCmdRow(cmd, false)));
}

function exitHistory() {
    historyMode = false;
    filterQuery = "";
    search.value = "";
    updateHint();
    renderCommandList(lastCommands);
}

// 타이핑 → 라이브 버퍼 즉시 필터 (히스토리 모드면 라이브로 복귀)
search.addEventListener("input", () => {
    filterQuery = search.value;
    if (historyMode) historyMode = false;
    updateHint();
    renderCommandList(lastCommands);
});

search.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && search.value.trim()) {
        searchHistory(search.value.trim());   // 전체 기록 검색
    } else if (e.key === "Escape") {
        e.stopPropagation();
        if (historyMode) {
            exitHistory();
        } else if (search.value) {
            search.value = "";
            filterQuery = "";
            updateHint();
            renderCommandList(lastCommands);
        }
    }
});

tickClock();
setInterval(tickClock, 1000);

refresh();
setInterval(refresh, 2000);