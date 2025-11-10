// // backend/app.py
// // # app.py
// // import os
// // from datetime import datetime
// // from dotenv import load_dotenv

// // from flask import Flask, request, jsonify
// // from flask_sqlalchemy import SQLAlchemy
// // from flask_cors import CORS
// // from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
// // from werkzeug.security import generate_password_hash, check_password_hash
// // from flask_jwt_extended import (
// //     JWTManager,
// //     create_access_token,
// //     jwt_required,
// //     get_jwt_identity,
// //     verify_jwt_in_request
// // )

// // # -------------------------
// // # Load env & App setup
// // # -------------------------
// // load_dotenv()

// // app = Flask(__name__)

// // # JWT config (keep secret stable)
// // app.config["JWT_SECRET_KEY"] = "supersecret123"
// // app.config["JWT_TOKEN_LOCATION"] = ["headers"]  # Bearer token in Authorization header
// // app.config["JWT_HEADER_NAME"] = "Authorization"
// // app.config["JWT_HEADER_TYPE"] = "Bearer"

// // # DB config
// // DB_USER = os.getenv("DB_USER", "root")
// // DB_PASS = os.getenv("DB_PASS", "")
// // DB_HOST = os.getenv("DB_HOST", "localhost")
// // DB_PORT = os.getenv("DB_PORT", "3306")
// // DB_NAME = os.getenv("DB_NAME", "feedback_db")

// // app.config["SQLALCHEMY_DATABASE_URI"] = (
// //     f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
// // )
// // app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

// // CORS(
// //     app,
// //     resources={r"/*": {"origins": ["http://127.0.0.1:5500", "http://localhost:5500"]}},
// //     supports_credentials=True,
// //     allow_headers=["Content-Type", "Authorization"],
// //     expose_headers=["Content-Type", "Authorization"],
// // )

// // db = SQLAlchemy(app)
// // jwt = JWTManager(app)
// // analyzer = SentimentIntensityAnalyzer()

// // # -------------------------
// // # Standardized JWT error responses (return 401 not 422)
// // # -------------------------
// // @jwt.unauthorized_loader
// // def jwt_unauthorized(err_msg):
// //     return jsonify({"error": "Unauthorized", "details": err_msg}), 401

// // @jwt.invalid_token_loader
// // def jwt_invalid(err_msg):
// //     return jsonify({"error": "Invalid token", "details": err_msg}), 401

// // @jwt.expired_token_loader
// // def jwt_expired(jwt_header, jwt_payload):
// //     return jsonify({"error": "Token expired"}), 401

// // @jwt.revoked_token_loader
// // def jwt_revoked(jwt_header, jwt_payload):
// //     return jsonify({"error": "Token revoked"}), 401

// // # -------------------------
// // # Models
// // # -------------------------
// // class User(db.Model):
// //     __tablename__ = "users"
// //     id = db.Column(db.Integer, primary_key=True)
// //     name = db.Column(db.String(100), nullable=False)
// //     email = db.Column(db.String(150), nullable=False, unique=True)
// //     password = db.Column(db.String(255), nullable=False)
// //     role = db.Column(db.String(20), default="user")  # "user" | "admin"
// //     created_at = db.Column(db.DateTime, default=datetime.utcnow)

// // class Feedback(db.Model):
// //     __tablename__ = "feedback"
// //     id = db.Column(db.Integer, primary_key=True)
// //     user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
// //     message = db.Column(db.Text, nullable=False)
// //     sentiment = db.Column(db.String(20), nullable=False)   # positive | neutral | negative
// //     score = db.Column(db.Float, nullable=False)            # compound score
// //     pos = db.Column(db.Float, default=0)
// //     neu = db.Column(db.Float, default=0)
// //     neg = db.Column(db.Float, default=0)
// //     product_topic = db.Column(db.String(150))
// //     rating = db.Column(db.Integer, nullable=True)
// //     feedback_type = db.Column(db.Enum("complaint", "suggestion", "appreciation", "bug", name="feedback_types"), nullable=True)
// //     created_at = db.Column(db.DateTime, default=datetime.utcnow)

// // # -------------------------
// // # Auth Routes
// // # -------------------------
// // @app.route("/api/auth/register", methods=["POST"])
// // def register():
// //     data = request.get_json() or {}
// //     name = (data.get("name") or "").strip()
// //     email = (data.get("email") or "").strip().lower()
// //     password = data.get("password") or ""

// //     if not name or not email or not password:
// //         return jsonify({"error": "Missing fields"}), 400

// //     if User.query.filter_by(email=email).first():
// //         return jsonify({"error": "Email already registered"}), 400

// //     user = User(
// //         name=name,
// //         email=email,
// //         password=generate_password_hash(password),
// //         role="user"
// //     )
// //     db.session.add(user)
// //     db.session.commit()
// //     return jsonify({"message": "Registered successfully!"}), 201


// // @app.route("/api/auth/login", methods=["POST"])
// // def login():
// //     data = request.get_json() or {}
// //     email = (data.get("email") or "").strip().lower()
// //     password = data.get("password") or ""

// //     user = User.query.filter_by(email=email).first()
// //     if not user or not check_password_hash(user.password, password):
// //         return jsonify({"error": "Invalid email or password"}), 401

// //     # IMPORTANT: identity must be a STRING to avoid "Subject must be a string" (422 later)
// //     token = create_access_token(identity=str(user.id))
// //     return jsonify({
// //         "access_token": token,
// //         "user": {"id": user.id, "name": user.name, "email": user.email, "role": user.role}
// //     }), 200

// // # -------------------------
// // # Feedback Routes
// // # -------------------------
// // @app.route("/api/feedback", methods=["POST"])
// // def submit_feedback():
// //     """
// //     Public endpoint. If logged in and a Bearer token is sent,
// //     we'll attach feedback to that user; otherwise user_id stays None.
// //     """
// //     try:
// //         # Try to read an optional JWT (no error if missing)
// //         try:
// //             verify_jwt_in_request(optional=True)
// //             uid = get_jwt_identity()
// //             user_id = int(uid) if uid is not None else None
// //         except Exception:
// //             user_id = None

// //         data = request.get_json() or {}
// //         message = (data.get("message") or "").strip()
// //         topic = (data.get("topic") or "").strip()
// //         name = (data.get("name") or "").strip()
// //         email = (data.get("email") or "").strip()
        

// //         # rating: normalize to None or int
// //         rating_val = data.get("rating")
// //         if rating_val in ("", None):
// //             rating = None
// //         else:
// //             try:
// //                 rating = int(rating_val)
// //             except Exception:
// //                 rating = None

// //         if not message:
// //             return jsonify({"error": "Feedback message is required"}), 400

// //         scores = analyzer.polarity_scores(message)
// //         compound = scores["compound"]
// //         if compound > 0.05:
// //             sentiment = "positive"
// //         elif compound < -0.05:
// //             sentiment = "negative"
// //         else:
// //             sentiment = "neutral"

// //         fb = Feedback(
// //             user_id=user_id,  # <-- now attaches to the logged-in user if available
// //             message=message,
// //             sentiment=sentiment,
// //             score=compound,
// //             pos=scores.get("pos", 0.0),
// //             neu=scores.get("neu", 0.0),
// //             neg=scores.get("neg", 0.0),
// //             product_topic=topic,
// //             rating=rating,
// //         )
// //         db.session.add(fb)
// //         db.session.commit()

// //         return jsonify({
// //             "sentiment": sentiment,
// //             "score": round(compound, 3),
// //             "positive": scores.get("pos", 0.0),
// //             "neutral": scores.get("neu", 0.0),
// //             "negative": scores.get("neg", 0.0)
// //         }), 200

// //     except Exception as e:
// //         import traceback
// //         traceback.print_exc()
// //         return jsonify({"error": "Internal Server Error", "details": str(e)}), 500


// // @app.route("/api/summary", methods=["GET"])
// // def summary():
// //     total = db.session.query(Feedback).count()
// //     pos = db.session.query(Feedback).filter_by(sentiment="positive").count()
// //     neu = db.session.query(Feedback).filter_by(sentiment="neutral").count()
// //     neg = db.session.query(Feedback).filter_by(sentiment="negative").count()
// //     return jsonify({"total": total, "positive": pos, "neutral": neu, "negative": neg}), 200


// // @app.route("/api/me/feedback", methods=["GET"])
// // @jwt_required()
// // def get_my_feedback():
// //     # identity is string now; cast to int
// //     uid = get_jwt_identity()
// //     try:
// //         user_id = int(uid) if uid is not None else None
// //     except ValueError:
// //         return jsonify({"error": "Invalid token identity"}), 401

// //     feedback = (
// //         Feedback.query
// //         .filter_by(user_id=user_id)
// //         .order_by(Feedback.created_at.desc())
// //         .all()
// //     )
    

// //     return jsonify([
// //         {
// //             "id": f.id,
// //             "message": f.message,
// //             "sentiment": f.sentiment,
// //             "score": f.score,
// //             "created_at": f.created_at.isoformat()
// //         }
// //         for f in feedback
// //     ]), 200

// // @app.route("/api/admin/feedback", methods=["GET"])
// // @jwt_required()
// // def admin_feedback():
// //     uid = get_jwt_identity()
// //     try:
// //         uid_int = int(uid)
// //     except (TypeError, ValueError):
// //         return jsonify({"error": "Invalid token identity"}), 401

// //     me = User.query.get(uid_int)
// //     if not me or me.role != "admin":
// //         return jsonify({"error": "Unauthorized"}), 403

// //     rows = Feedback.query.order_by(Feedback.created_at.desc()).all()
// //     return jsonify([
// //         {
// //             "id": f.id,
// //             "user_id": f.user_id,
// //             "message": f.message,
// //             "sentiment": f.sentiment,
// //             "rating": f.rating,
// //             "created_at": f.created_at.isoformat()
// //         } for f in rows
// //     ]), 200


// // @app.route("/api/admin/feedback/<int:fid>", methods=["DELETE"])
// // @jwt_required()
// // def admin_delete_feedback(fid):
// //     uid = get_jwt_identity()
// //     try:
// //         uid_int = int(uid)
// //     except (TypeError, ValueError):
// //         return jsonify({"error": "Invalid token identity"}), 401

// //     me = User.query.get(uid_int)
// //     if not me or me.role != "admin":
// //         return jsonify({"error": "Unauthorized"}), 403

// //     fb = Feedback.query.get(fid)
// //     if not fb:
// //         return jsonify({"error": "Not found"}), 404
// //     db.session.delete(fb)
// //     db.session.commit()
// //     return jsonify({"message": "Deleted"}), 200

// // # -------------------------
// // # Friendly root
// // # -------------------------
// // @app.route("/")
// // def root():
// //     return """
// //     <html>
// //       <head><title>Smart Feedback API</title></head>
// //       <body style="font-family:Arial; display:flex; align-items:center; justify-content:center; height:100vh; background:#1f7dd0;">
// //         <div style="text-align:center; color:white;">
// //           <h1>✅ Smart Feedback API is running</h1>
// //           <p>Try <code>/api/summary</code></p>
// //           <a href="/api/summary" style="background:#fff; color:#1f7dd0; padding:10px 16px; border-radius:8px; text-decoration:none;">View Summary</a>
// //         </div>
// //       </body>
// //     </html>
// //     """

// // if __name__ == "__main__":
// //     with app.app_context():
// //         db.create_all()
// //     app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)
// // /frontend/index.html
// // <!DOCTYPE html>
// // <html lang="en">
// // <head>
// //   <meta charset="UTF-8" />
// //   <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
// //   <title>Smart Feedback System</title>
// //   <link rel="stylesheet" href="style.css"/>
// //   <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
// //   <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
// // </head>
// // <body>
// //   <header class="glass topbar">
// //     <h1>🧠 Smart Feedback Analyzer</h1>
// //     <nav>
// //       <button class="chip" onclick="showSection('home')">Home</button>
// //       <button class="chip" id="openAuthBtn">Login / Register</button>
// //       <button class="chip" id="navHistory" style="display:none;">My History</button>
// //       <button class="chip" id="navAdmin" style="display:none;">Admin</button>
// //       <button class="chip danger" id="logoutBtn" style="display:none;">Logout</button>
// //     </nav>
// //   </header>

// //   <main>
// //     <!-- HOME -->
// //     <section id="home" class="page-section">
// //       <div class="card glass">
// //         <h2>💬 Share Your Feedback</h2>
// //         <form id="feedbackForm" class="form">
// //           <input type="text" id="name" placeholder="Your Name (Optional)"/>
// //           <input type="email" id="email" placeholder="Your Email (Optional)"/>
// //           <input type="text" id="topic" placeholder="Product / Service Topic (Optional)"/>
// //           <textarea id="message" placeholder="Write your feedback..." required></textarea>
// //           <label>Rate Us (1–5):</label>
// //           <input type="number" id="rating" min="1" max="5" placeholder="1–5"/>
// //           <button type="submit" class="btn primary">Submit Feedback</button>
// //         </form>
// //       </div>
// // <select id="feedback_type">
// //   <option value="">Select Feedback Type</option>
// //   <option value="complaint">Complaint</option>
// //   <option value="suggestion">Suggestion</option>
// //   <option value="appreciation">Appreciation</option>
// //   <option value="bug">Bug Report</option>
// // </select>

// //       <div class="card glass">
// //         <h2>📊 Sentiment Overview</h2>
// //         <div class="chart-wrap"><canvas id="sentimentChart"></canvas></div>
// //         <button class="btn secondary" id="refreshBtn">Refresh Chart</button>
// //       </div>
// //     </section>

// //     <!-- USER HISTORY -->
// //     <section id="user-history" class="page-section hidden">
// //       <div class="card glass wide">
// //         <h2>📜 My Feedback History</h2>
// //         <table id="historyTable">
// //           <thead>
// //             <tr>
// //               <th>ID</th><th>Message</th><th>Sentiment</th><th>Score</th><th>Date</th>
// //             </tr>
// //           </thead>
// //           <tbody></tbody>
// //         </table>
// //       </div>
// //     </section>

// //     <!-- ADMIN -->
// //     <section id="admin-dashboard" class="page-section hidden">
// //       <div class="card glass wide">
// //         <h2>🧑‍💼 Admin Dashboard</h2>
// //         <table id="adminTable">
// //           <thead>
// //             <tr>
// //               <th>ID</th><th>User</th><th>Message</th><th>Sentiment</th><th>Rating</th><th>Action</th>
// //             </tr>
// //           </thead>
// //           <tbody></tbody>
// //         </table>
// //       </div>
// //     </section>

// //     <!-- AUTH MODAL -->
// //     <div id="authModal" class="modal hidden">
// //   <div class="modal-content">
// //     <span class="close" onclick="closeAuthModal()">&times;</span>

// //     <!-- LOGIN -->
// //     <div id="loginBox">
// //       <h2>🔐 Login</h2>
// //       <form id="loginForm">
// //         <input type="email" id="loginEmail" placeholder="Email" required />
// //         <input type="password" id="loginPassword" placeholder="Password" required />
// //         <button type="submit" id="loginBtn" class="btn primary">Login</button>
// //       </form>
// //       <p>Don’t have an account? <a href="#" id="switchToRegister">Register</a></p>
// //     </div>

// //     <!-- REGISTER -->
// //     <div id="registerBox" class="hidden">
// //       <h2>📝 Register</h2>
// //       <form id="registerForm">
// //         <input type="text" id="regName" placeholder="Full Name" required />
// //         <input type="email" id="regEmail" placeholder="Email" required />
// //         <input type="password" id="regPassword" placeholder="Password" required />
// //         <button type="submit" id="registerBtn" class="btn secondary">Register</button>
// //       </form>
// //       <p>Already registered? <a href="#" id="switchToLogin">Login</a></p>
// //     </div>

// //   </div>
// // </div>

// //   </main>

// //   <footer class="glass footer">
// //     <p>© 2025 Smart Feedback System • Designed by <b>Rithesh Yennam</b></p>
// //   </footer>
// // <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
// //   <script src="script.js"></script>
// // </body>
// // </html>
// // /frontend/script.js
// // // =========================
// // // CONFIG
// // // =========================
// // const API_BASE = "http://127.0.0.1:5000";
// // const TOKEN_KEY = "fb_token";
// // const USER_KEY = "fb_user";
// // let sentimentChart = null;

// // // =========================
// // // HELPERS
// // // =========================
// // const $ = (sel) => document.querySelector(sel);
// // const $$ = (sel) => Array.from(document.querySelectorAll(sel));

// // function saveAuth(token, user) {
// //   localStorage.setItem(TOKEN_KEY, token);
// //   localStorage.setItem(USER_KEY, JSON.stringify(user));
// //   updateNav();
// // }

// // function getAuth() {
// //   return {
// //     token: localStorage.getItem(TOKEN_KEY),
// //     user: JSON.parse(localStorage.getItem(USER_KEY) || "null"),
// //   };
// // }

// // function clearAuth() {
// //   localStorage.removeItem(TOKEN_KEY);
// //   localStorage.removeItem(USER_KEY);
// //   updateNav();
// // }

// // function updateNav() {
// //   const { token, user } = getAuth();
// //   $("#openAuthBtn").style.display = token ? "none" : "inline-block";
// //   $("#logoutBtn").style.display = token ? "inline-block" : "none";
// //   $("#navHistory").style.display = token ? "inline-block" : "none";
// //   $("#navAdmin").style.display = token && user?.role === "admin" ? "inline-block" : "none";
// // }

// // // =========================
// // // MODAL CONTROL
// // // =========================
// // $("#openAuthBtn").onclick = () => {
// //   $("#authModal").classList.remove("hidden");
// //   $("#loginBox").classList.remove("hidden");
// //   $("#registerBox").classList.add("hidden");
// // };

// // function closeAuthModal() {
// //   $("#authModal").classList.add("hidden");
// // }

// // $("#switchToRegister").onclick = (e) => {
// //   e.preventDefault();
// //   $("#loginBox").classList.add("hidden");
// //   $("#registerBox").classList.remove("hidden");
// // };

// // $("#switchToLogin").onclick = (e) => {
// //   e.preventDefault();
// //   $("#registerBox").classList.add("hidden");
// //   $("#loginBox").classList.remove("hidden");
// // };

// // function alertSuccess(title, message) {
// //   Swal.fire({ icon: "success", title, text: message, showConfirmButton: false, timer: 1500 });
// // }
// // function alertError(title, message) {
// //   Swal.fire({ icon: "error", title, text: message });
// // }
// // function alertWarn(title, message) {
// //   Swal.fire({ icon: "warning", title, text: message });
// // }

// // // =========================
// // // LOGIN
// // // =========================
// // async function handleLogin(e) {
// //   e.preventDefault();

// //   const email = $("#loginEmail").value.trim();
// //   const password = $("#loginPassword").value.trim();

// //   const res = await fetch(`${API_BASE}/api/auth/login`, {
// //     method: "POST",
// //     headers: { "Content-Type": "application/json" },
// //     body: JSON.stringify({ email, password }),
// //   });

// //   const data = await res.json();
// //   if (!res.ok) return alertError("Login Failed", data.error || "Invalid Credentials");

// //   saveAuth(data.access_token, data.user);
// //   alertSuccess("Login Successful!", `Welcome ${data.user.name}!`);

// //   closeAuthModal();
// //   updateNav();
// //   showSection("user-history");
// //   loadUserHistory();
// // }

// // document.querySelector("#loginForm").addEventListener("submit", handleLogin);

// // // =========================
// // // REGISTER
// // // =========================
// // async function handleRegister(e) {
// //   e.preventDefault();

// //   const name = $("#regName").value.trim();
// //   const email = $("#regEmail").value.trim();
// //   const password = $("#regPassword").value.trim();

// //   const res = await fetch(`${API_BASE}/api/auth/register`, {
// //     method: "POST",
// //     headers: {"Content-Type": "application/json"},
// //     body: JSON.stringify({ name, email, password }),
// //   });

// //   const data = await res.json();
// //   if (!res.ok) return alertError("Registration Failed", data.error);

// //   alertSuccess("Success", "Account created! Please login.");
// //   $("#registerBox").classList.add("hidden");
// //   $("#loginBox").classList.remove("hidden");
// // }

// // document.querySelector("#registerForm").addEventListener("submit", handleRegister);

// // // =========================
// // // LOGOUT
// // // =========================
// // $("#logoutBtn").onclick = () => {
// //   clearAuth();
// //   showSection("home");
// //   Swal.fire("Logged Out", "You have been logged out.", "info");
// // };

// // // =========================
// // // VIEW SWITCH
// // // =========================
// // function showSection(id) {
// //   $$(".page-section").forEach((s) => s.classList.add("hidden"));
// //   $(`#${id}`).classList.remove("hidden");
// // }

// // // =========================
// // // SUBMIT FEEDBACK
// // // =========================
// // $("#feedbackForm").addEventListener("submit", async (e) => {
// //   e.preventDefault();
// //   const payload = {
// //     name: $("#name").value.trim(),
// //     email: $("#email").value.trim(),
// //     topic: $("#topic").value.trim(),
// //     message: $("#message").value.trim(),
// //     rating: $("#rating").value === "" ? null : Number($("#rating").value),
// //   };
 
// //  const token = localStorage.getItem("fb_token");

// // const res = await fetch(`${API_BASE}/api/feedback`, {
// //   method: "POST",
// //   headers: {
// //     "Content-Type": "application/json",
// //     ...(token ? { "Authorization": `Bearer ${token}` } : {}) // ✅ send token only if logged in
// //   },
// //   body: JSON.stringify(payload),
// // });

// //   const data = await res.json();
// //   if (!res.ok) return alertError("Error", data.error);

// //   alertSuccess("Submitted!", `Sentiment: ${data.sentiment}`);
// //   loadChart();
// // });

// // // =========================
// // // USER HISTORY (TOKEN REQUIRED)
// // // =========================
// // async function loadUserHistory() {
// //   const token = localStorage.getItem("fb_token");
// //   if (!token) return alertWarn("Login Required", "Please login first.");

// //   const res = await fetch(`${API_BASE}/api/me/feedback`, {
// //     headers: { "Authorization": `Bearer ${token}` }
// //   });

// //   // ✅ Only logout when token is INVALID
// //   if (res.status === 401) {
// //     clearAuth();
// //     alertWarn("Session Expired", "Please login again.");
// //     return;
// //   }

// //   const data = await res.json();
// //   // TODO: Fill table here...
// //   console.log("User Feedback Data:", data);
// // }

// // $("#navHistory").onclick = () => { showSection("user-history"); loadUserHistory(); };

// // // =========================
// // // CHART
// // // =========================
// // async function loadChart() {
// //   const res = await fetch(`${API_BASE}/api/summary`);
// //   const stats = await res.json();

// //   if (sentimentChart) sentimentChart.destroy();

// //   sentimentChart = new Chart($("#sentimentChart"), {
// //     type: "pie",
// //     data: {
// //       labels: ["Positive", "Neutral", "Negative"],
// //       datasets: [{ data: [stats.positive, stats.neutral, stats.negative], backgroundColor: ["green", "gray", "red"] }],
// //     }
// //   });
// // }

// // $("#refreshBtn").onclick = loadChart;

// // // =========================
// // // INIT
// // // =========================
// // document.addEventListener("DOMContentLoaded", () => {
// //   updateNav();
// //   loadChart();
// // })
// // /sql/schema.sql
// // -- replace `feedback_db` with your DB name if different
// // USE feedback_db;

// // DROP TABLE IF EXISTS feedback;
// // DROP TABLE IF EXISTS users;

// // CREATE TABLE users (
// //   id INT AUTO_INCREMENT PRIMARY KEY,
// //   name VARCHAR(100) NOT NULL,
// //   email VARCHAR(150) NOT NULL UNIQUE,
// //   password VARCHAR(255) NOT NULL,
// //   role ENUM('guest','user','admin') DEFAULT 'user',
// //   created_at DATETIME DEFAULT CURRENT_TIMESTAMP
// // );

// // CREATE TABLE feedback (
// //   id INT AUTO_INCREMENT PRIMARY KEY,
// //   user_id INT NULL,
// //   message TEXT NOT NULL,
// //   sentiment VARCHAR(20) NOT NULL,
// //   score FLOAT NOT NULL,
// //   pos FLOAT DEFAULT 0,
// //   neu FLOAT DEFAULT 0,
// //   neg FLOAT DEFAULT 0,
// //   product_topic VARCHAR(150),
// //   rating INT,
// //   created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
// //   FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
// // );
// // ALTER TABLE feedback 
// // ADD COLUMN feedback_type ENUM('complaint','suggestion','appreciation','bug') NULL AFTER product_topic;
// // /frontend/style.css
// // /* Glass / modern */
// // :root{
// //   --bg1:#0d5ea7;
// //   --bg2:#1a79d8;
// //   --glass: rgba(255,255,255,0.12);
// //   --border: rgba(255,255,255,0.25);
// // }

// // *{ box-sizing:border-box; }
// // body{
// //   margin:0; font-family:system-ui,Segoe UI,Arial;
// //   min-height:100vh;
// //   background: linear-gradient(180deg, var(--bg1), var(--bg2));
// //   color:#fff;
// // }
// // .hidden{ display:none !important; }

// // .glass{
// //   backdrop-filter: blur(10px);
// //   background: var(--glass);
// //   border:1px solid var(--border);
// //   border-radius:16px;
// //   box-shadow:0 10px 30px rgba(0,0,0,0.15);
// // }

// // .topbar{
// //   display:flex; align-items:center; justify-content:space-between;
// //   padding:16px 24px; margin:12px;
// // }

// // nav .chip{
// //   background:#fff; color:#0d5ea7; border:none;
// //   padding:8px 14px; margin-left:6px; border-radius:999px; cursor:pointer;
// //   font-weight:600;
// // }
// // nav .chip.danger{ background:#ffebee; color:#c62828; }

// // main{ max-width:1000px; margin:30px auto; padding:0 14px; }

// // .card{ padding:20px; margin:18px 0; }
// // .card.wide{ overflow:auto; }

// // .form{ display:flex; flex-direction:column; gap:10px; }
// // input, textarea{
// //   width:100%; padding:12px; border-radius:10px; border:1px solid var(--border);
// //   background:rgba(255,255,255,0.2); color:#fff; outline:none;
// // }
// // textarea{ min-height:120px; resize:vertical; }

// // .btn{
// //   padding:10px 14px; border:none; border-radius:10px; cursor:pointer; font-weight:700;
// // }
// // .btn.primary{ background:#0b3f8a; color:#fff; }
// // .btn.secondary{ background:#12a36e; color:#fff; }

// // .chart-wrap{ width:420px; max-width:100%; margin:auto; }

// // table{ width:100%; border-collapse:collapse; }
// // thead{ background:rgba(255,255,255,0.15); }
// // th, td{ padding:10px; border-bottom:1px solid rgba(255,255,255,0.15); }
// // tbody tr:nth-child(even){ background:rgba(255,255,255,0.06); }

// // .footer{ text-align:center; padding:14px; margin:12px; }

// // /* Modal */
// // .modal{
// //   position:fixed; inset:0; display:flex; align-items:center; justify-content:center;
// //   background:rgba(0,0,0,0.45); z-index:50;
// // }
// // .modal-content{ width:95%; max-width:420px; padding:22px; position:relative; }
// // .close{ position:absolute; right:14px; top:12px; font-size:20px; cursor:pointer; }
// // .switch-msg{ margin-top:10px; }
// // .page-section{ margin-top:8px; }
// // fix the issues improve ui ux
// // develop based on my explination by using the some of the code 























// /* === Modern Flat UI (No Blur) — crisp, hover-first design === */
// /* Safe to use with your existing HTML/JS. No IDs/classes changed. */

// :root{
//   /* palette */
//   --bg-1:#0f1320;
//   --bg-2:#141a2b;
//   --surface:#1b2236;
//   --surface-2:#202946;
//   --border:#2b3558;
//   --text:#e8eefc;
//   --muted:#aab4d4;

//   /* accents */
//   --primary:#53a9ff;      /* normal */
//   --primary-600:#3a93ef;  /* hover */
//   --primary-700:#2c7cd1;  /* active */
//   --success:#22c55e;
//   --warning:#f59e0b;
//   --danger:#ef4444;

//   /* misc */
//   --radius:14px;
//   --shadow:0 6px 18px rgba(0,0,0,.28);
//   --shadow-sm:0 4px 12px rgba(0,0,0,.22);
//   --ring:0 0 0 3px rgba(83,169,255,.35);
// }

// *{box-sizing:border-box;}
// html,body{height:100%;}
// body{
//   margin:0;
//   font-family: Inter, system-ui, Segoe UI, Roboto, Arial, sans-serif;
//   color:var(--text);
//   background:
//     linear-gradient(180deg, var(--bg-1), var(--bg-2));
// }

// /* utilities */
// .hidden{display:none!important;}
// .sr-only{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0);}

// /* layout */
// .topbar{
//   display:flex;align-items:center;justify-content:space-between;
//   margin:16px;padding:14px 20px;
//   background:var(--surface);
//   border:1px solid var(--border);
//   border-radius:var(--radius);
//   box-shadow:var(--shadow-sm);
// }
// main{max-width:1080px;margin:22px auto 56px;padding:0 16px;}
// .card{
//   background:var(--surface);
//   border:1px solid var(--border);
//   border-radius:var(--radius);
//   padding:18px;
//   margin:18px 0;
//   box-shadow:var(--shadow);
// }
// .card.wide{overflow:auto;}
// .footer{ text-align:center; color:var(--muted); padding:16px; margin:16px;}

// /* “glass” class stays but WITHOUT blur */
// .glass{
//   background:var(--surface);
//   border:1px solid var(--border);
//   border-radius:var(--radius);
//   box-shadow:var(--shadow);
// }

// /* chips in nav */
// nav{display:flex;gap:10px;flex-wrap:wrap;}
// nav .chip{
//   appearance:none;border:none;cursor:pointer;
//   padding:9px 14px;border-radius:999px;font-weight:700;letter-spacing:.2px;
//   background:var(--primary);
//   color:#061423;
//   box-shadow:var(--shadow-sm);
//   transition:background-color .18s ease, transform .1s ease, box-shadow .18s ease;
// }
// nav .chip:hover{ background:var(--primary-600); transform:translateY(-1px); box-shadow:0 8px 18px rgba(0,0,0,.3);}
// nav .chip:active{ background:var(--primary-700); transform:translateY(0);}
// nav .chip.danger{ background:#ff6b6b; color:#1d0a0a;}
// nav .chip.danger:hover{ background:#ff4b4b;}

// /* buttons */
// .btn{
//   appearance:none;border:none;cursor:pointer;
//   padding:12px 16px;border-radius:12px;font-weight:800;letter-spacing:.2px;
//   background:var(--primary); color:#061423;
//   box-shadow:var(--shadow-sm);
//   transition:background-color .18s ease, transform .1s ease, box-shadow .18s ease, filter .18s;
// }
// .btn:hover{ background:var(--primary-600); transform:translateY(-1px); box-shadow:0 10px 22px rgba(0,0,0,.32);}
// .btn:active{ background:var(--primary-700); transform:translateY(0);}
// .btn.secondary{ background:var(--success); color:#05150c;}
// .btn.secondary:hover{ filter:saturate(1.1) brightness(1.02); }
// .btn.ghost{
//   background:transparent; color:var(--text);
//   border:1px solid var(--border);
// }
// .btn.ghost:hover{ background:var(--surface-2); }

// /* inputs & form */
// .form{display:flex;flex-direction:column;gap:12px;}
// input,textarea,select{
//   width:100%; padding:12px 14px; border-radius:12px;
//   border:1px solid var(--border);
//   background:var(--surface-2);
//   color:var(--text);
//   outline: none;
//   transition: border-color .18s ease, box-shadow .18s ease, background-color .18s ease;
// }
// input::placeholder,textarea::placeholder{ color:#9ba6c6; }
// textarea{ min-height:120px; resize:vertical; }
// input:focus,textarea:focus,select:focus{ border-color:var(--primary); box-shadow:var(--ring); }
// input:disabled,textarea:disabled,select:disabled{ opacity:.6; cursor:not-allowed; }

// /* number input tidy */
// input[type=number]::-webkit-outer-spin-button,
// input[type=number]::-webkit-inner-spin-button{ -webkit-appearance:none; margin:0; }
// input[type=number]{ -moz-appearance:textfield; }

// /* section switching (your JS uses .page-section + .hidden) */
// .page-section{ margin-top:10px; }

// /* table */
// table{ width:100%; border-collapse:collapse; }
// thead{
//   background:var(--surface-2);
//   border-bottom:2px solid var(--primary);
//   text-transform:uppercase;
// }
// th,td{
//   padding:12px 10px;
//   border-bottom:1px solid var(--border);
//   text-align:left; vertical-align:top;
// }
// tbody tr:hover{ background:#1e2745; }

// /* chart block */
// .chart-wrap{ width:460px; max-width:100%; margin:8px auto 0; }

// /* modal (no blur) */
// .modal{
//   position:fixed; inset:0; display:flex; align-items:center; justify-content:center;
//   background:rgba(0,0,0,.55); z-index:50;
// }
// .modal-content{
//   width:min(92vw, 440px);
//   background:var(--surface);
//   border:1px solid var(--border);
//   border-radius:var(--radius);
//   padding:22px;
//   box-shadow:var(--shadow);
//   position:relative;
// }
// .close{ position:absolute; right:14px; top:12px; font-size:20px; cursor:pointer; color:var(--muted); }
// .close:hover{ color:var(--text); }

// /* hover affordances for actionable things inside tables */
// table button.chip,
// table .chip{
//   padding:6px 10px; border-radius:999px; border:1px solid var(--border);
//   background:#2a355b; color:#dfe7ff; cursor:pointer;
//   transition: background-color .18s ease, transform .1s ease;
// }
// table .chip:hover{ background:#34406a; transform:translateY(-1px); }
// table .chip.danger{ background:#5b2a2a; border-color:#7a3a3a; }
// table .chip.danger:hover{ background:#7a3a3a; }

// /* links (if any) */
// a{ color:var(--primary); text-decoration:none; }
// a:hover{ color:var(--primary-600); }

// /* accessibility: focus visible */
// :where(button, .chip, .btn, a, input, select, textarea):focus-visible{
//   outline: none;
//   box-shadow: var(--ring);
// }

// /* reduced motion */
// @media (prefers-reduced-motion: reduce){
//   *{ transition:none!important; animation:none!important; }
// }

// /* responsive */
// @media (max-width: 720px){
//   .topbar{ flex-direction:column; align-items:flex-start; gap:10px;}
//   .card{ padding:16px; }
//   nav{ gap:8px; }
// }
