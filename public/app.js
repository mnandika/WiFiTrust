const $ = id => document.getElementById(id);

let currentRole = null;

function formBody(form) {
    return new URLSearchParams(new FormData(form)).toString();
}

async function api(url, options = {}) {

    const response = await fetch(url, {
        ...options,
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            ...(options.headers || {})
        }
    });

    const data = await response.json().catch(() => ({
        error: "Unexpected server response."
    }));

    if (!response.ok) {
        throw new Error(data.error || "Request failed.");
    }

    return data;
}

function showLogin() {
    $("loginView").classList.remove("hidden");
    $("appView").classList.add("hidden");
}

function showDashboard(user) {

    currentRole = user.role;

    $("loginView").classList.add("hidden");
    $("appView").classList.remove("hidden");

    $("welcomeName").textContent = "Hello, " + user.name;

    $("accountInfo").textContent =
        user.userId + " · " + user.role;

    $("ownerPanel").classList.toggle(
        "hidden", user.role !== "OWNER"
    );

    $("employeePanel").classList.toggle(
        "hidden", user.role !== "EMPLOYEE"
    );

    $("requestsTitle").textContent =
        user.role === "OWNER"
        ? "All employee access requests"
        : "Your device access requests";

    refreshAll();
}

// LOGIN
$("loginForm").addEventListener("submit", async event => {

    event.preventDefault();

    $("loginMessage").textContent = "";

    try {

        await api("/api/login", {
            method: "POST",
            body: formBody(event.target)
        });

        const user = await api("/api/me");

        showDashboard(user);

    } catch (error) {

        $("loginMessage").textContent = error.message;
    }
});

// LOGOUT
$("logoutButton").addEventListener("click", async () => {

    try {
        await api("/api/logout", { method: "POST" });
    } finally {
        currentRole = null;
        showLogin();
    }
});

// ADD EMPLOYEE
$("employeeForm").addEventListener("submit", async event => {

    event.preventDefault();

    $("employeeMessage").textContent = "";

    try {

        const result = await api("/api/employees", {
            method: "POST",
            body: formBody(event.target)
        });

        $("employeeMessage").textContent = result.message;

        event.target.reset();

        await refreshAll();

    } catch (error) {

        $("employeeMessage").textContent = error.message;
    }
});

// EMPLOYEE DEVICE REQUEST
$("requestForm").addEventListener("submit", async event => {

    event.preventDefault();

    $("requestMessage").textContent = "";

    try {

        const result = await api("/api/requests", {
            method: "POST",
            body: formBody(event.target)
        });

        $("requestMessage").textContent = result.message;

        event.target.reset();

        await refreshAll();

    } catch (error) {

        $("requestMessage").textContent = error.message;
    }
});

// REFRESH BUTTONS
$("refreshEmployees").addEventListener("click", refreshAll);
$("refreshRequests").addEventListener("click", refreshAll);

// LOAD ALL DATA
async function refreshAll() {

    try {

        const requestData = await api("/api/requests");

        renderRequests(requestData.requests);

        const historyData = await api("/api/history");

        renderHistory(historyData.history);

        if (currentRole === "OWNER") {

            const employeeData = await api("/api/employees");

            renderEmployees(employeeData.employees);
        }

    } catch (error) {

        console.error(error);
    }
}

// DISPLAY EMPLOYEES
function renderEmployees(employees) {

    $("employeeCount").textContent = employees.length;

    if (employees.length === 0) {

        $("employeeTable").innerHTML =
            "<p class='muted'>No employee accounts created yet.</p>";

        return;
    }

    $("employeeTable").innerHTML = `
        <table>
            <thead>
                <tr>
                    <th>USER ID</th>
                    <th>NAME</th>
                    <th>STATUS</th>
                    <th>ACTION</th>
                </tr>
            </thead>

            <tbody>
                ${employees.map(employee => `
                    <tr>
                        <td>${safe(employee.userId)}</td>
                        <td>${safe(employee.name)}</td>

                        <td>
                            <span class="pill">
                                ${employee.active ? "ACTIVE" : "INACTIVE"}
                            </span>
                        </td>

                        <td>
                            ${
                                employee.active
                                ? `<button class="small-button danger"
                                    onclick="deactivateEmployee(${employee.id})">
                                    Deactivate
                                   </button>`
                                : "—"
                            }
                        </td>
                    </tr>
                `).join("")}
            </tbody>
        </table>
    `;
}

// DEACTIVATE EMPLOYEE
async function deactivateEmployee(id) {

    const confirmed = confirm(
        "Are you sure you want to deactivate this employee?"
    );

    if (!confirmed) return;

    try {

        await api("/api/deactivate", {
            method: "POST",
            body: new URLSearchParams({ id })
        });

        await refreshAll();

    } catch (error) {

        alert(error.message);
    }
}

// DISPLAY REQUESTS
function renderRequests(requests) {

    const pending = requests.filter(
        item => item.status === "PENDING"
    ).length;

    const allowed = requests.filter(
        item => item.status === "ALLOWED"
    ).length;

    if (currentRole === "OWNER") {

        $("requestCount").textContent = requests.length;
        $("pendingCount").textContent = pending;
        $("allowedCount").textContent = allowed;
    }

    if (requests.length === 0) {

        $("requestTable").innerHTML =
            "<p class='muted'>No access requests found.</p>";

        return;
    }

    $("requestTable").innerHTML = `
        <table>
            <thead>
                <tr>
                    ${currentRole === "OWNER" ? "<th>EMPLOYEE</th>" : ""}
                    <th>DEVICE</th>
                    <th>TYPE</th>
                    <th>MAC ADDRESS</th>
                    <th>STATUS</th>
                    <th>DATE</th>
                    ${currentRole === "OWNER" ? "<th>DECISION</th>" : ""}
                </tr>
            </thead>

            <tbody>
                ${requests.map(item => `

                    <tr>

                        ${
                            currentRole === "OWNER"
                            ? `<td>
                                ${safe(item.employee)}
                                <br>
                                <small>${safe(item.userId)}</small>
                               </td>`
                            : ""
                        }

                        <td>${safe(item.device)}</td>
                        <td>${safe(item.type)}</td>
                        <td>${safe(item.mac)}</td>

                        <td>
                            <span class="pill ${item.status}">
                                ${
                                    item.status === "ALLOWED"
                                    ? "ACCESS ALLOWED"
                                    : item.status === "DENIED"
                                    ? "ACCESS DENIED"
                                    : item.status
                                }
                            </span>
                        </td>

                        <td>${safe(item.created || "")}</td>

                        ${
                            currentRole === "OWNER"
                            ? `<td>
                                ${
                                    item.status === "PENDING"
                                    ? `
                                        <button class="small-button"
                                            onclick="changeDecision(${item.id}, 'ALLOWED')">
                                            Allow
                                        </button>

                                        <button class="small-button danger"
                                            onclick="changeDecision(${item.id}, 'DENIED')">
                                            Deny
                                        </button>
                                      `
                                    : item.status === "ALLOWED"
                                    ? `
                                        <button class="small-button danger"
                                            onclick="changeDecision(${item.id}, 'REVOKED')">
                                            Revoke
                                        </button>
                                      `
                                    : "—"
                                }
                               </td>`
                            : ""
                        }

                    </tr>

                `).join("")}
            </tbody>
        </table>
    `;
}

// OWNER DECISION
async function changeDecision(id, status) {

    let message = "";

    if (status === "ALLOWED") {
        message = "Allow this device request?";
    } else if (status === "DENIED") {
        message = "Deny this device request?";
    } else {
        message = "Revoke this device's application approval?";
    }

    if (!confirm(message)) return;

    try {

        await api("/api/decision", {
            method: "POST",
            body: new URLSearchParams({ id, status })
        });

        await refreshAll();

    } catch (error) {

        alert(error.message);
    }
}

// DISPLAY REQUEST HISTORY
function renderHistory(history) {

    if (history.length === 0) {

        $("historyTable").innerHTML =
            "<p class='muted'>No history available yet.</p>";

        return;
    }

    $("historyTable").innerHTML = `
        <table>
            <thead>
                <tr>
                    <th>REQUEST ID</th>
                    <th>ACTION</th>
                    <th>CHANGED BY</th>
                    <th>DETAILS</th>
                    <th>DATE</th>
                </tr>
            </thead>

            <tbody>
                ${history.map(item => `
                    <tr>
                        <td>#${item.requestId}</td>
                        <td>
                            <span class="pill ${safe(item.action)}">
                                ${safe(item.action)}
                            </span>
                        </td>
                        <td>${safe(item.name)} (${safe(item.userId)})</td>
                        <td>${safe(item.notes)}</td>
                        <td>${safe(item.changedAt || "")}</td>
                    </tr>
                `).join("")}
            </tbody>
        </table>
    `;
}

// PROTECT TEXT INSERTED INTO HTML
function safe(value) {

    return String(value ?? "").replace(
        /[&<>"']/g,
        character => ({
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;"
        })[character]
    );
}

// CHECK EXISTING LOGIN SESSION
(async function startApp() {

    try {

        const user = await api("/api/me");

        showDashboard(user);

    } catch (error) {

        showLogin();
    }

})();