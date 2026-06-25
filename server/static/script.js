async function loadConnections(){

    const response = await fetch("/connections");

    const data = await response.json();

    const tbody = document.querySelector("#connections tbody");

    tbody.innerHTML = "";

    Object.values(data).forEach(conn=>{

        tbody.innerHTML += `
            <tr>
                <td>${conn.ip}</td>
                <td>${conn.username}</td>
            </tr>
        `;
    });

}


async function loadCommands(){

    const response = await fetch("/recent_commands");

    const data = await response.json();

    const tbody = document.querySelector("#commands tbody");

    tbody.innerHTML = "";

    data.slice().reverse().forEach(cmd=>{

        tbody.innerHTML += `
            <tr>
                <td>${cmd.time}</td>
                <td>${cmd.ip}</td>
                <td>${cmd.username}</td>
                <td>${cmd.command}</td>
            </tr>
        `;
    });

}

async function refresh(){

    await loadConnections();

    await loadCommands();

}

refresh();

setInterval(refresh,2000);