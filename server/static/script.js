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
    return [cmd.time, cmd.ip, cmd.username, cmd.command].join("|");
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
        tag.className = "session-tag";
        tag.textContent = "Connected";
        top.append(dot, tag);

        const ip = document.createElement("div");
        ip.className = "session-ip";
        ip.textContent = conn.ip ?? "—";

        const meta = document.createElement("div");
        meta.className = "session-meta";
        meta.appendChild(document.createTextNode("as "));
        const user = document.createElement("b");
        user.textContent = conn.username ?? "—";
        meta.appendChild(user);

        card.append(top, ip, meta);
        list.appendChild(card);
    });
}

function renderCommands(data) {
    const list = document.getElementById("commands");
    const rows = (data || []).slice().reverse(); // newest first

    document.getElementById("m-commands").textContent = (data || []).length;

    // 위협 단계 계산
    let maxRank = 0;
    rows.forEach(c => {
        const r = THREAT_RANK[categoryOf(c.command)] || 0;
        if (r > maxRank) maxRank = r;
    });
    const threat = THREAT_LEVEL[rows.length ? maxRank : 0];
    document.getElementById("m-threat").textContent = threat.label;
    document.getElementById("m-threat-wrap").dataset.level = threat.level;

    list.innerHTML = "";

    if (rows.length === 0) {
        const empty = document.createElement("div");
        empty.className = "empty";
        const b = document.createElement("b");
        b.textContent = "No commands captured yet";
        empty.appendChild(b);
        empty.appendChild(document.createTextNode("Activity will appear here as attackers type."));
        list.appendChild(empty);
        return;
    }

    rows.forEach(cmd => {
        const cat = categoryOf(cmd.command);
        const sig = signature(cmd);
        const isNew = !seen.has(sig);
        seen.add(sig);

        const row = document.createElement("div");
        row.className = "cmd" + (isNew ? " is-new" : "");
        row.dataset.cat = cat;

        const time = document.createElement("span");
        time.className = "cmd-time";
        time.textContent = (cmd.time || "").split(" ")[1] || cmd.time || "";

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

        row.append(time, label, text, who);
        list.appendChild(row);
    });

    // seen 집합이 무한정 커지지 않도록 정리
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
        if (!cRes.ok || !kRes.ok) throw new Error("bad response");

        renderSessions(await cRes.json());
        renderCommands(await kRes.json());
        setLink(true);
    } catch (e) {
        setLink(false);
    }
}

tickClock();
setInterval(tickClock, 1000);

refresh();
setInterval(refresh, 2000);
