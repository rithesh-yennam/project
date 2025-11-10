let adminChartInstance=null
// =========================
// CONFIG
// =========================
const API_BASE = "http://127.0.0.1:5000";
const TOKEN_KEY = "fb_token";
const USER_KEY = "fb_user";
let sentimentChart = null;

// =========================
// HELPERS
// =========================
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

function saveAuth(token, user) {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(USER_KEY, JSON.stringify(user));
  updateNav();
}

function getAuth() {
  return {
    token: localStorage.getItem(TOKEN_KEY),
    user: JSON.parse(localStorage.getItem(USER_KEY) || "null"),
  };
}

function clearAuth() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
  updateNav();
}

// function updateNav() {
//   const { token, user } = getAuth();
//   $("#openAuthBtn").style.display = token ? "none" : "inline-block";
//   $("#logoutBtn").style.display = token ? "inline-block" : "none";
//   $("#navHistory").style.display = token ? "inline-block" : "none";
//   $("#navAdmin").style.display = token && user?.role === "admin" ? "inline-block" : "none";
  
// }


function updateNav() {
  const { token, user } = getAuth();

  const openAuthBtn = $("#openAuthBtn");
  if (openAuthBtn) openAuthBtn.style.display = token ? "none" : "inline-block";

  const logoutBtn = $("#logoutBtn");
  if (logoutBtn) logoutBtn.style.display = token ? "inline-block" : "none";

  const navHistory = $("#navHistory");
  if (navHistory) navHistory.style.display = token ? "inline-block" : "none";

  const navAdmin = $("#navAdmin");
  if (navAdmin) navAdmin.style.display = (token && user?.role === "admin") ? "inline-block" : "none";
}
navAdmin.onclick = () => {
  window.location.href = "/admin";
};


// =========================
// MODAL CONTROL
// =========================
$("#openAuthBtn").onclick = () => {
  $("#authModal").classList.remove("hidden");
  $("#loginBox").classList.remove("hidden");
  $("#registerBox").classList.add("hidden");
};

function closeAuthModal() {
  $("#authModal").classList.add("hidden");
}

$("#switchToRegister").onclick = (e) => {
  e.preventDefault();
  $("#loginBox").classList.add("hidden");
  $("#registerBox").classList.remove("hidden");
};

$("#switchToLogin").onclick = (e) => {
  e.preventDefault();
  $("#registerBox").classList.add("hidden");
  $("#loginBox").classList.remove("hidden");
};

function alertSuccess(title, message) {
  Swal.fire({ icon: "success", title, text: message, showConfirmButton: false, timer: 1500 });
}
function alertError(title, message) {
  Swal.fire({ icon: "error", title, text: message });
}
function alertWarn(title, message) {
  Swal.fire({ icon: "warning", title, text: message });
}

// =========================
// LOGIN
// =========================
async function handleLogin(e) {
  e.preventDefault();

  const email = $("#loginEmail").value.trim();
  const password = $("#loginPassword").value.trim();

  const res = await fetch(`${API_BASE}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });

  const data = await res.json();
  if (!res.ok) return alertError("Login Failed", data.error || "Invalid Credentials");

  // ✅ SAVE TOKEN & USER
  localStorage.setItem("fb_token", data.access_token);
  localStorage.setItem("fb_user", JSON.stringify(data.user));

  alertSuccess("Login Successful!", `Welcome ${data.user.name}!`);

  updateNav();
  closeAuthModal();
  showSection("user-history");
   loadChart();          // ✅ IMPORTANT (Redraw chart)

  // slight delay ensures token is available when fetching
  setTimeout(loadUserHistory, 150);
}


document.querySelector("#loginForm").addEventListener("submit", handleLogin);

// =========================
// REGISTER
// =========================
async function handleRegister(e) {
  e.preventDefault();

  const name = $("#regName").value.trim();
  const email = $("#regEmail").value.trim();
  const password = $("#regPassword").value.trim();

  // ✅ Strong Password Check
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!#%*?&])[A-Za-z\d@$!#%*?&]{8,}$/;

  if (!passwordRegex.test(password)) {
    return alertError(
      "Weak Password",
      "Password must be at least 8 characters long & include:\n• Uppercase\n• Lowercase\n• Number\n• Special Symbol"
    );
  }

  const res = await fetch(`${API_BASE}/api/auth/register`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ name, email, password }),
  });

  const data = await res.json();
  if (!res.ok) return alertError("Registration Failed", data.error);

  alertSuccess("Success", "Account created! Please login.");
  $("#registerBox").classList.add("hidden");
  $("#loginBox").classList.remove("hidden");
}

document.querySelector("#registerForm").addEventListener("submit", handleRegister);

// =========================
// LOGOUT
// =========================

showSection("home");

// --- universal logout handler ---
function doLogout() {
  clearAuth();
  // If we're on admin page, redirect to index.html. Otherwise, go to "home" section.
  
    Swal.fire("Logged Out", "You have been logged out.", "info").then(() => {
      window.location.href = "/";
    });
 
}

// attach only if button exists on the current page
const logoutBtn = document.querySelector("#logoutBtn");
if (logoutBtn) {
  logoutBtn.onclick = doLogout;
}


// =========================
// VIEW SWITCH
// =========================
function showSection(id) {
  $$(".page-section").forEach((s) => s.classList.add("hidden"));
  $(`#${id}`).classList.remove("hidden");
}

// =========================
// SUBMIT FEEDBACK
// =========================
$("#feedbackForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const payload = {
    message: $("#message").value.trim(),
    topic: $("#topic").value.trim(),
    rating: $("#rating").value,
    feedback_type: $("#feedback_type").value || null
  };

  const token = localStorage.getItem("fb_token");

  const res = await fetch(`${API_BASE}/api/feedback`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { "Authorization": `Bearer ${token}` } : {})
    },
    body: JSON.stringify(payload),
  });

  const data = await res.json();
  if (!res.ok) return alertError("Error", data.error);

  alertSuccess("Submitted!", `Sentiment: ${data.sentiment}`);
  showSection("home");
  loadChart();
});


// =========================
// USER HISTORY (TOKEN REQUIRED)
// =========================
async function loadUserHistory() {
  const token = localStorage.getItem("fb_token");
  if (!token) return alertWarn("Login Required", "Please login first.");

  const res = await fetch(`${API_BASE}/api/me/feedback`, {
    headers: { "Authorization": `Bearer ${token}` }
  });

  // ✅ If token invalid → logout cleanly
  if (res.status === 401) {
    clearAuth();
    alertWarn("Session expired", "Please login again.");
    return;
  }

  const data = await res.json();
  const tbody = $("#historyTable tbody");

  tbody.innerHTML = data.map(f => `
    <tr>
      <td>${f.id}</td>
      <td>${f.message}</td>
      <td>${f.sentiment}</td>
      <td>${f.score.toFixed(2)}</td>
      <td>${f.created_at.split("T")[0]}</td>
    </tr>
  `).join("");
}

$("#navHistory").onclick = () => { showSection("user-history"); loadUserHistory(); };

async function exportJSON() {
  const token = localStorage.getItem("fb_token");
  if (!token) return alertWarn("Login Required", "Please login as Admin.");

  const res = await fetch(`${API_BASE}/api/admin/export/json`, {
    headers: { "Authorization": `Bearer ${token}` }
  });

  if (!res.ok) return alertError("Export Failed", "You are not authorized.");

  const data = await res.json();
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = "feedback_data.json";
  a.click();
  URL.revokeObjectURL(url);

  alertSuccess("Exported!", "JSON file downloaded successfully.");
}

// document.getElementById("exportJsonBtn").addEventListener("click", exportJSON);

// =========================
// CHART
// =========================
async function loadChart() {
const token = localStorage.getItem("fb_token");
const res = await fetch(`${API_BASE}/api/summary`, {
  headers: token ? { "Authorization": `Bearer ${token}` } : {}
});
  const stats = await res.json();

  if (sentimentChart) sentimentChart.destroy();

  sentimentChart = new Chart($("#sentimentChart"), {
    type: "pie",
    data: {
      labels: ["Positive", "Neutral", "Negative"],
      datasets: [{ data: [stats.positive, stats.neutral, stats.negative], backgroundColor: ["green", "gray", "red"] }],
    }
  });
}

$("#refreshBtn").onclick = loadChart;


async function loadAdminTable() {
  const token = localStorage.getItem("fb_token");
  if (!token) return alertWarn("Login Required", "Please login as Admin.");

  const res = await fetch(`${API_BASE}/api/admin/feedback`, {
    headers: { "Authorization": `Bearer ${token}` }
  });

  if (res.status === 401 || res.status === 403) {
    return alertError("Access Denied", "Admin Only Access.");
  }

  const data = await res.json();

  // ✅ Ensure data is array
  if (!Array.isArray(data)) {
    console.warn("Unexpected response:", data);
    return;
  }

  const tbody = document.querySelector("#adminTable tbody");
  tbody.innerHTML = data.map(f => `
    <tr>
      <td>${f.id}</td>
      <td>${f.user_id || "Guest"}</td>
      <td>${f.message}</td>
      <td>${f.sentiment}</td>
      <td>${f.rating ?? "-"}</td>
      <td><button class="deleteBtn" data-id="${f.id}">🗑</button></td>
    </tr>
  `).join("");

  document.querySelectorAll(".deleteBtn").forEach(btn => {
    btn.onclick = async () => {
      await deleteFeedback(btn.dataset.id);
      loadAdminTable();
    };
  });
}

async function deleteFeedback(id) {
  const { token } = getAuth();
  await fetch(`${API_BASE}/api/admin/feedback/${id}`, {
    method: "DELETE",
    headers: { "Authorization": `Bearer ${token}` }
  });
  loadAdminTable();
}
// Function
async function loadAdminChart() {
  const res = await fetch(`${API_BASE}/api/summary`);
  const stats = await res.json();

  const ctx = document.getElementById("adminChart");

  // Destroy old chart if exists
  if (adminChartInstance) {
    adminChartInstance.destroy();
  }

  adminChartInstance = new Chart(ctx, {
    type: "pie",
    data: {
      labels: ["Positive", "Neutral", "Negative"],
      datasets: [
        {
          data: [stats.positive, stats.neutral, stats.negative],
          backgroundColor: ["#22c55e", "#cfcfcf", "#ef4444"]
        }
      ]
    }
  });
}





// =========================
// INIT
// =========================
document.addEventListener("DOMContentLoaded", () => {
  
  const adminBtn = document.querySelector("#navAdmin");
if (adminBtn) {
 adminBtn.onclick = () => {
    window.location.href = "/admin";
}
}
   showSection("home");
  updateNav();
  loadChart();
})
const messageBox = document.getElementById("message");
const charCount = document.getElementById("charCount");
const MAX_CHARS = 300;
const stars = document.querySelectorAll("#starRating span");
const ratingInput = document.getElementById("rating");

stars.forEach(star => {
  // Hover effect
  star.addEventListener("mouseover", () => {
    resetStars();
    star.classList.add("hovered");
    highlightPrevious(star);
  });

  // Remove hover when leaving area
  star.addEventListener("mouseout", () => {
    resetStars();
    applySavedRating();
  });

  // Click to save rating
  star.addEventListener("click", () => {
    ratingInput.value = star.dataset.value;
    applySavedRating();
  });
});

function highlightPrevious(star) {
  let previous = star.previousElementSibling;
  while (previous) {
    previous.classList.add("hovered");
    previous = previous.previousElementSibling;
  }
}

function applySavedRating() {
  const saved = ratingInput.value;
  stars.forEach(s => s.classList.remove("selected"));
  if (saved) {
    stars.forEach(s => {
      if (s.dataset.value <= saved) s.classList.add("selected");
    });
  }
}

function resetStars() {
  stars.forEach(s => s.classList.remove("hovered"));
}

messageBox.addEventListener("input", () => {
  const length = messageBox.value.length;
  charCount.textContent = `${length} / ${MAX_CHARS} characters`;

  if (length > MAX_CHARS) {
    charCount.style.color = "red";
    if (messageBox.value.length > MAX_CHARS) {
  messageBox.value = messageBox.value.substring(0, MAX_CHARS);
}

  } else {
    charCount.style.color = "#6f6f6f";
  }
});
