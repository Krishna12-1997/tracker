
import ipaddress
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import geoip2.database
import geoip2.errors
from dotenv import load_dotenv
from flask import (
    Flask, request, jsonify, render_template,
    redirect, url_for, session, abort
)
from flask_pymongo import PyMongo
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
app.config["MONGO_URI"] = os.environ["MONGO_URI"]

mongo = PyMongo(app)
comments = mongo.db.comments

comments.create_index([("created_at", -1)])
comments.create_index([("status", 1), ("created_at", -1)])

csrf = CSRFProtect(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[]
)

GEOIP_PATH = Path(
    os.getenv("GEOIP_DB_PATH", "geoip/GeoLite2-City.mmdb")
)

geo_reader = (
    geoip2.database.Reader(str(GEOIP_PATH))
    if GEOIP_PATH.is_file()
    else None
)


def get_client_ip():
    """
    request.remote_addr is the client IP only when the direct
    connection is the client or ProxyFix is configured correctly.
    Do not manually trust arbitrary X-Forwarded-For headers.
    """
    raw_ip = request.remote_addr

    if not raw_ip:
        return None

    # Normalize IPv4-mapped IPv6 addresses.
    try:
        parsed = ipaddress.ip_address(raw_ip)
        if isinstance(parsed, ipaddress.IPv6Address):
            if parsed.ipv4_mapped:
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

        # Don't geolocate localhost, private or reserved addresses.
        if not address.is_global:
            return result

        record = geo_reader.city(ip)

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
        # Unknown IP, invalid input or unavailable GeoIP record.
        pass

    return result


@app.post("/api/comments")
@csrf.exempt
@limiter.limit("5 per minute")
def create_comment():
    data = request.get_json(silent=True) or {}

    name = data.get("name")
    comment = data.get("comment")

    if not isinstance(name, str) or not isinstance(comment, str):
        return jsonify(error="Name and comment are required"), 400

    name = name.strip()
    comment = comment.strip()

    if not name or len(name) > 100:
        return jsonify(error="Name must be 1–100 characters"), 400

    if not comment or len(comment) > 3000:
        return jsonify(error="Comment must be 1–3000 characters"), 400

    ip = get_client_ip()
    location = lookup_location(ip)

    document = {
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

    result = comments.insert_one(document)

    return jsonify(
        message="Comment submitted for moderation",
        id=str(result.inserted_id),
        status="pending",
    ), 201


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
            username == os.getenv("ADMIN_USERNAME")
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

    return render_template(
        "admin.html",
        comments=list(rows),
        csrf_token=generate_csrf(),
    )


@app.post("/admin/comments/<comment_id>/approve")
def approve_comment(comment_id):
    admin_required()

    from bson import ObjectId
    from bson.errors import InvalidId

    try:
        oid = ObjectId(comment_id)
    except InvalidId:
        abort(404)

    comments.update_one(
        {"_id": oid},
        {"$set": {"status": "approved"}},
    )
    return redirect(url_for("admin_comments"))


@app.post("/admin/comments/<comment_id>/delete")
def delete_comment(comment_id):
    admin_required()

    from bson import ObjectId
    from bson.errors import InvalidId

    try:
        oid = ObjectId(comment_id)
    except InvalidId:
        abort(404)

    comments.delete_one({"_id": oid})
    return redirect(url_for("admin_comments"))


@app.cli.command("purge-expired-ips")
def purge_expired_ips():
    """Remove IP and location metadata after the configured period."""
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
    app.run(debug=False)
