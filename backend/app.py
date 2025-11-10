# app.py
import os
from datetime import datetime
from dotenv import load_dotenv

from flask import Flask, request, jsonify,render_template
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
    verify_jwt_in_request
)

# -------------------------
# Load env & App setup
# -------------------------
load_dotenv()

app = Flask(__name__)

# JWT config (keep secret stable)
app.config["JWT_SECRET_KEY"] = "supersecret123"
app.config["JWT_TOKEN_LOCATION"] = ["headers"]  # Bearer token in Authorization header
app.config["JWT_HEADER_NAME"] = "Authorization"
app.config["JWT_HEADER_TYPE"] = "Bearer"

# DB config
DB_USER = os.getenv("DB_USER", "root")
DB_PASS = os.getenv("DB_PASS", "")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "3306")
DB_NAME = os.getenv("DB_NAME", "feedback_db")

app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

CORS(
    app,
    resources={r"/*": {"origins": ["http://127.0.0.1:5500", "http://localhost:5500"]}},
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization"],
    expose_headers=["Content-Type", "Authorization"],
)

db = SQLAlchemy(app)
jwt = JWTManager(app)
analyzer = SentimentIntensityAnalyzer()

# -------------------------
# Standardized JWT error responses (return 401 not 422)
# -------------------------
@jwt.unauthorized_loader
def jwt_unauthorized(err_msg):
    return jsonify({"error": "Unauthorized", "details": err_msg}), 401

@jwt.invalid_token_loader
def jwt_invalid(err_msg):
    return jsonify({"error": "Invalid token", "details": err_msg}), 401

@jwt.expired_token_loader
def jwt_expired(jwt_header, jwt_payload):
    return jsonify({"error": "Token expired"}), 401

@jwt.revoked_token_loader
def jwt_revoked(jwt_header, jwt_payload):
    return jsonify({"error": "Token revoked"}), 401

# -------------------------
# Models
# -------------------------
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="user")  # "user" | "admin"
    role = db.Column(db.String(20), default="user")  # Add this line
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Feedback(db.Model):
    __tablename__ = "feedback"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    message = db.Column(db.Text, nullable=False)
    sentiment = db.Column(db.String(20), nullable=False)   # positive | neutral | negative
    score = db.Column(db.Float, nullable=False)            # compound score
    pos = db.Column(db.Float, default=0)
    neu = db.Column(db.Float, default=0)
    neg = db.Column(db.Float, default=0)
    product_topic = db.Column(db.String(150))
    rating = db.Column(db.Integer, nullable=True)
    feedback_type = db.Column(db.Enum("complaint", "suggestion", "appreciation", "bug", name="feedback_types"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)




#---------------------
#Index Page
#---------------------


@app.route("/")
def root():
    return render_template("index.html")

@app.route('/admin')
def admin_page():
    return render_template('admin.html')



# -------------------------
# Auth Routes
# -------------------------
@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not name or not email or not password:
        return jsonify({"error": "Missing fields"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already registered"}), 400

    user = User(
        name=name,
        email=email,
        password=generate_password_hash(password),
        role="user"
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "Registered successfully!"}), 201


@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({"error": "Invalid email or password"}), 401

    # IMPORTANT: identity must be a STRING to avoid "Subject must be a string" (422 later)
    token = create_access_token(identity=str(user.id))
    return jsonify({
        "access_token": token,
        "user": {"id": user.id, "name": user.name, "email": user.email, "role": user.role}
    }), 200

# -------------------------
# Feedback Routes
# -------------------------
@app.route("/api/feedback", methods=["POST"])
def submit_feedback():
    """
    Public endpoint. If logged in and a Bearer token is sent,
    we'll attach feedback to that user; otherwise user_id stays None.
    """
    try:
        # Try to read an optional JWT (no error if missing)
        try:
            verify_jwt_in_request(optional=True)
            uid = get_jwt_identity()
            user_id = int(uid) if uid is not None else None
        except Exception:
            user_id = None

        data = request.get_json() or {}
        message = (data.get("message") or "").strip()
        topic = (data.get("topic") or "").strip()
        name = (data.get("name") or "").strip()
        email = (data.get("email") or "").strip()
        

        # rating: normalize to None or int
        rating_val = data.get("rating")
        if rating_val in ("", None):
            rating = None
        else:
            try:
                rating = int(rating_val)
            except Exception:
                rating = None

        if not message:
            return jsonify({"error": "Feedback message is required"}), 400

        scores = analyzer.polarity_scores(message)
        compound = scores["compound"]
        text = message.lower()

# Sarcasm / negation keyword boost
        sarcasm_keywords = ["(not)", "yeah right", "as if", "sure...", "great... not"]
        for sk in sarcasm_keywords:
          if sk in text:
            compound -= 0.4   # push sentiment more negative

# Stricter sentiment cutoffs
        if compound >= 0.2:
          sentiment = "positive"
        elif compound <= -0.2:
           sentiment = "negative"
        else:
            sentiment = "neutral"


        fb = Feedback(
            user_id=user_id,  # <-- now attaches to the logged-in user if available
            message=message,
            sentiment=sentiment,
            score=compound,
            pos=scores.get("pos", 0.0),
            neu=scores.get("neu", 0.0),
            neg=scores.get("neg", 0.0),
            product_topic=topic,
            rating=rating,
        )
        db.session.add(fb)
        db.session.commit()

        return jsonify({
            "sentiment": sentiment,
            "score": round(compound, 3),
            "positive": scores.get("pos", 0.0),
            "neutral": scores.get("neu", 0.0),
            "negative": scores.get("neg", 0.0)
        }), 200

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500


@app.route("/api/summary", methods=["GET"])
def summary():
    total = db.session.query(Feedback).count()
    pos = db.session.query(Feedback).filter_by(sentiment="positive").count()
    neu = db.session.query(Feedback).filter_by(sentiment="neutral").count()
    neg = db.session.query(Feedback).filter_by(sentiment="negative").count()
    return jsonify({"total": total, "positive": pos, "neutral": neu, "negative": neg}), 200


@app.route("/api/me/feedback", methods=["GET"])
@jwt_required()    # <-- requires login
def my_feedback():
    try:
        uid = get_jwt_identity()   # user_id stored inside token (string)
        uid = int(uid)             # convert to integer
    except:
        return jsonify({"error": "Invalid token"}), 401

    rows = (
        Feedback.query
        .filter_by(user_id=uid)                         # <-- Only logged-in user feedback
        .order_by(Feedback.created_at.desc())
        .all()
    )

    return jsonify([
        {
            "id": f.id,
            "message": f.message,
            "sentiment": f.sentiment,
            "score": f.score,
            "created_at": f.created_at.isoformat()
        }
        for f in rows
    ]), 200

@app.route("/api/admin/feedback", methods=["GET"])
@jwt_required()
def admin_feedback():
    uid = get_jwt_identity()
    try:
        uid_int = int(uid)
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid token identity"}), 401

    me = User.query.get(uid_int)
    if not me or me.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    rows = Feedback.query.order_by(Feedback.created_at.desc()).all()
    return jsonify([
        {
            "id": f.id,
            "user_id": f.user_id,
            "message": f.message,
            "sentiment": f.sentiment,
            "rating": f.rating,
            "created_at": f.created_at.isoformat()
        } for f in rows
    ]), 200


@app.route("/api/admin/feedback/<int:fid>", methods=["DELETE"])
@jwt_required()
def admin_delete_feedback(fid):
    uid = get_jwt_identity()
    try:
        uid_int = int(uid)
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid token identity"}), 401

    me = User.query.get(uid_int)
    if not me or me.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    fb = Feedback.query.get(fid)
    if not fb:
        return jsonify({"error": "Not found"}), 404
    db.session.delete(fb)
    db.session.commit()
    return jsonify({"message": "Deleted"}), 200


@app.route("/api/admin/export/csv", methods=["GET"])
@jwt_required()
def export_csv():
    uid = int(get_jwt_identity())
    user = User.query.get(uid)
    if not user or user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    rows = Feedback.query.all()
    import csv
    from io import StringIO

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "User ID", "Message", "Sentiment", "Rating", "Date"])

    for f in rows:
        writer.writerow([f.id, f.user_id, f.message, f.sentiment, f.rating, f.created_at])

    return output.getvalue(), 200, {
        "Content-Disposition": "attachment; filename=feedback_export.csv",
        "Content-Type": "text/csv"
    }


@app.route("/api/admin/export/json", methods=["GET"])
@jwt_required()
def export_json():
    uid = int(get_jwt_identity())
    user = User.query.get(uid)
    if not user or user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    rows = Feedback.query.all()
    data = [
        {
            "id": f.id,
            "user_id": f.user_id,
            "message": f.message,
            "sentiment": f.sentiment,
            "rating": f.rating,
            "created_at": f.created_at.isoformat()
        }
        for f in rows
    ]
    return jsonify(data), 200

# --------- AUTO CREATE ADMIN IF NOT EXISTS ----------
with app.app_context():
    db.create_all()
    from werkzeug.security import generate_password_hash
    
    admin_email = "riteshyennam@gmail.com"     # change if needed
    admin_password = "Ritesh123#"            # change if needed

    existing_admin = User.query.filter_by(email=admin_email).first()
    if not existing_admin:
        admin_user = User(
            name="System Admin",
            email=admin_email,
            password=generate_password_hash(admin_password),
            role="admin"
        )
        db.session.add(admin_user)
        db.session.commit()
        print("✅ Admin user created:")
        print(f"   Email: {admin_email}")
        print(f"   Password: {admin_password}")
    else:
        print("✅ Admin already exists")


# -----------------------------
# RUN APPLICATION
# -----------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)



if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)