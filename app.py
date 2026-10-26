import ipaddress
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import geoip2.database
import geoip2.errors
from dotenv import load_dotenv
from flask import (
    Flask, request, jsonify, render_template,
    redirect, url_for, session, abort, flash
)
from flask_pymongo import PyMongo
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.security import check_password_hash

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
app.config["MONGO_URI"] = os.environ["MONGO_URI"]

mongo = PyMongo(app)
comments = mongo.db.comments

try:
    comments.create_index([("created_at", -1)])
    comments.create_index([("status", 1), ("created_at", -1)])
except Exception:
    app.logger.exception("Could not create MongoDB indexes during startup")

csrf = CSRFProtect(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
)

GEOIP_PATH = Path(os.getenv("GEOIP_DB_PATH", "geoip/GeoLite2-City.mmdb"))
geo_reader = None
if GEOIP_PATH.is_file():
    try:
        geo_reader = geoip2.database.Reader(str(GEOIP_PATH))
    except (OSError, geoip2.errors.GeoIP2Error):
        app.logger.exception("Could not open GeoIP database")


BLOG = {
    "title": "AI Data Breaches: What You Need to Know",
    "category": "AI SECURITY",
    "reading_time": "3 min read",
    "published": "AI Security Brief",
    "summary": (
        "AI tools can process large amounts of information, but sensitive data can be exposed "
        "when credentials are stolen, systems are misconfigured, or confidential information "
        "is shared without appropriate safeguards."
    ),
    "sections": [
        {
            "heading": "How can an AI-related breach happen?",
            "body": (
                "Common causes include exposed API keys, weak access controls, insecure data "
                "storage, vulnerable integrations, and accidentally sharing private information "
                "with an AI service."
            ),
        },
        {
            "heading": "How can you reduce the risk?",
            "body": (
                "Limit access to sensitive information, enable multi-factor authentication, keep "
                "software updated, rotate exposed credentials, review vendor data policies, and "
                "monitor systems for unusual activity."
            ),
        },
    ],
}


def get_client_ip():
    """
    request.remote_addr is the peer IP unless a trusted proxy is configured.
    Do not blindly trust arbitrary X-Forwarded-For headers.
    """
    raw_ip = request.remote_addr
    if not raw_ip:
        return None

    try:
        parsed = ipaddress.ip_address(raw_ip)
        if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
            parsed = parsed.ipv4_mapped
        return str(parsed)
    except ValueError:
        return None


def lookup_location(ip):
    result = {
        "country": None,
        "country_code": None,
        "region": None,
        "city": None,
        "latitude": None,
        "longitude": None,
    }

    if not ip or not geo_reader:
        return result

    try:
        address = ipaddress.ip_address(ip)
        if not address.is_global:
            return result

        record = geo_reader.city(str(address))
        result.update({
            "country": record.country.name,
            "country_code": record.country.iso_code,
            "region": (
                record.subdivisions.most_specific.name
                if record.subdivisions else None
            ),
            "city": record.city.name,
            "latitude": record.location.latitude,
            "longitude": record.location.longitude,
        })
    except (
        ValueError,
        geoip2.errors.AddressNotFoundError,
        geoip2.errors.GeoIP2Error,
    ):
        pass

    return result


def get_approved_comments(limit=50):
    rows = list(
        comments.find(
            {"status": "approved"},
            {"name": 1, "comment": 1, "created_at": 1},
        ).sort("created_at", -1).limit(limit)
    )
    for row in rows:
        row["id"] = str(row.pop("_id"))
        created_at = row.get("created_at")
        row["created_at_display"] = (
            created_at.strftime("%d %b %Y, %I:%M %p")
            if isinstance(created_at, datetime) else ""
        )
    return rows


@app.get("/")
def index():
    db_error = None
    try:
        public_comments = get_approved_comments()
    except Exception:
        app.logger.exception("Could not retrieve approved comments")
        public_comments = []
        db_error = "Comments are temporarily unavailable. Please try again later."

    return render_template(
        "index.html",
        blog=BLOG,
        comments=public_comments,
        db_error=db_error,
    )


@app.route("/api/comments", methods=["POST"])
@limiter.limit("5 per minute")
def create_comment():
    # Accept both JSON clients (existing API) and the homepage HTML form.
    if request.is_json:
        data = request.get_json(silent=True) or {}
        name = data.get("name")
        comment = data.get("comment")
    else:
        name = request.form.get("name")
        comment = request.form.get("comment")

    if not isinstance(name, str) or not isinstance(comment, str):
        message = "Name and comment are required."
        if request.is_json:
            return jsonify(error=message), 400
        flash(message, "error")
        return redirect(url_for("index") + "#comments")

    name = name.strip()
    comment = comment.strip()

    if not name or len(name) > 100:
        message = "Name must be 1–100 characters."
        if request.is_json:
            return jsonify(error=message), 400
        flash(message, "error")
        return redirect(url_for("index") + "#comments")

    if not comment or len(comment) > 3000:
        message = "Comment must be 1–3000 characters."
        if request.is_json:
            return jsonify(error=message), 400
        flash(message, "error")
        return redirect(url_for("index") + "#comments")

    ip = get_client_ip()
    location = lookup_location(ip)

    document = {
        "blog_slug": "ai-data-breaches",
        "name": name,
        "comment": comment,
        "ip_address": ip,
        "country": location["country"],
        "country_code": location["country_code"],
        "region": location["region"],
        "city": location["city"],
        "latitude": location["latitude"],
        "longitude": location["longitude"],
        "created_at": datetime.now(timezone.utc),
        "status": "pending",
    }

    try:
        result = comments.insert_one(document)
    except Exception:
        app.logger.exception("Could not save comment to MongoDB")
        message = "We couldn't save your comment right now. Please try again later."
        if request.is_json:
            return jsonify(error=message), 503
        flash(message, "error")
        return redirect(url_for("index") + "#comments")

    message = "Thanks! Your comment was submitted and will appear after moderation."
    if request.is_json:
        return jsonify(
            message=message,
            id=str(result.inserted_id),
            status="pending",
        ), 201

    flash(message, "success")
    return redirect(url_for("index") + "#comments")


def admin_required():
    if not session.get("is_admin"):
        abort(401)


@app.route("/admin/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        password_hash = os.getenv("ADMIN_PASSWORD_HASH", "")

        if (
            username == os.getenv("ADMIN_USERNAME", "")
            and password_hash
            and check_password_hash(password_hash, password)
        ):
            session.clear()
            session["is_admin"] = True
            return redirect(url_for("admin_comments"))

        return render_template(
            "login.html",
            csrf_token=generate_csrf(),
            error="Invalid credentials",
        ), 401

    return render_template(
        "login.html",
        csrf_token=generate_csrf(),
        error=None,
    )


@app.post("/admin/logout")
def admin_logout():
    admin_required()
    session.clear()
    return redirect(url_for("admin_login"))


@app.get("/admin/comments")
def admin_comments():
    admin_required()

    rows = comments.find(
        {},
        {
            "name": 1,
            "comment": 1,
            "ip_address": 1,
            "country": 1,
            "country_code": 1,
            "region": 1,
            "city": 1,
            "created_at": 1,
            "status": 1,
        },
    ).sort("created_at", -1).limit(100)

    items = list(rows)
    for row in items:
        row["id"] = str(row.pop("_id"))
        created_at = row.get("created_at")
        row["created_at_display"] = (
            created_at.strftime("%d %b %Y, %I:%M %p")
            if isinstance(created_at, datetime) else ""
        )

    return render_template(
        "admin.html",
        comments=items,
        csrf_token=generate_csrf(),
    )


@app.post("/admin/comments/<comment_id>/approve")
def approve_comment(comment_id):
    admin_required()

    from bson import ObjectId
    from bson.errors import InvalidId

    try:
        oid = ObjectId(comment_id)
    except (InvalidId, TypeError):
        abort(404)

    comments.update_one(
        {"_id": oid},
        {"$set": {"status": "approved", "moderated_at": datetime.now(timezone.utc)}},
    )
    flash("Comment approved.", "success")
    return redirect(url_for("admin_comments"))


@app.post("/admin/comments/<comment_id>/delete")
def delete_comment(comment_id):
    admin_required()

    from bson import ObjectId
    from bson.errors import InvalidId

    try:
        oid = ObjectId(comment_id)
    except (InvalidId, TypeError):
        abort(404)

    comments.delete_one({"_id": oid})
    flash("Comment deleted.", "success")
    return redirect(url_for("admin_comments"))


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.cli.command("purge-expired-ips")
def purge_expired_ips():
    """Remove IP and location metadata after the configured retention period."""
    days = max(1, int(os.getenv("IP_RETENTION_DAYS", "30")))
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    result = comments.update_many(
        {"created_at": {"$lt": cutoff}},
        {
            "$unset": {
                "ip_address": "",
                "country": "",
                "country_code": "",
                "region": "",
                "city": "",
                "latitude": "",
                "longitude": "",
            }
        },
    )
    print(f"Removed location metadata from {result.modified_count} comments")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)
