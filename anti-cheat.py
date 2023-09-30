import re
from flask import Flask, request, abort

app = Flask(__name__)

# תגרום לקוד זה לעצור את הבקשות מאתרים שאינם מורשים
@app.before_request
def validate_origin():
    allowed_origins = ["https://example.com", "https://yourdomain.com"]
    if request.headers.get("Origin") not in allowed_origins:
        abort(403)  # אם מקור הבקשה אינו מורשה, עצור את הבקשה

# מנע פריצה באמצעות התקפות Cross-Site Scripting (XSS)
@app.after_request
def set_secure_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

# מנע פריצה באמצעות התקפת SQL Injection
def sanitize_input(input_str):
    # פונקציה זו תסנן את הקלט כך שלא יהיה בו תווים מסוכנים
    sanitized_str = re.sub(r"[;<>&'\"/]", "", input_str)
    return sanitized_str

# השתמש בפונקציה זו לפני שאתה מבצע שאילתות למסד נתונים
def safe_query(database, query):
    sanitized_query = sanitize_input(query)
    result = database.execute(sanitized_query)
    return result

if __name__ == "__main__":
    app.run()
