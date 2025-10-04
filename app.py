import os
import io
import json
import tempfile
import secrets
import base64
import shutil
from pathlib import Path
from threading import Thread
from datetime import datetime, timedelta

from flask import (
    Flask, request, render_template, redirect, url_for, send_file,
    flash, jsonify
)
from pyngrok import ngrok, conf
import qrcode
from werkzeug.utils import secure_filename
import subprocess
import platform
import time


# Configuration
UPLOAD_FOLDER = Path(tempfile.gettempdir()) / "xerox_uploads"
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
ALLOWED_EXTENSIONS = {'.pdf'}
SESSION_TIMEOUT_MINUTES = 60  # safety fallback (delete & shutdown after this if unused)
CONFIG_PATH = Path.home() / ".xerox_share_config.json"

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(24)
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # 200 MB limit

# Global state for single-session enforcement
state = {
    "ngrok_authtoken": None,
    "tunnel": None,
    "session_token": None,
    "public_url": None,
    "uploaded_path": None,
    "uploaded_name": None,
    "started_at": None,
    "timeout_thread": None
}


# -------------------------
# Config persistence
# -------------------------
def save_config():
    data = {"ngrok_authtoken": state.get("ngrok_authtoken")}
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.chmod(CONFIG_PATH, 0o600)
    except Exception:
        pass


def load_config():
    if not CONFIG_PATH.exists():
        return
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        token = data.get("ngrok_authtoken")
        if token:
            conf.get_default().auth_token = token
            try:
                ngrok.set_auth_token(token)
            except Exception:
                # pyngrok may raise if something else wrong; continue but store token in state
                pass
            state['ngrok_authtoken'] = token
    except Exception:
        pass


# load persisted config at startup
load_config()


# -------------------------
# Utility functions
# -------------------------
def allowed_file(filename):
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS


def generate_qr_data_url(text: str) -> str:
    img = qrcode.make(text)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    b64 = base64.b64encode(buf.getvalue()).decode('ascii')
    return f"data:image/png;base64,{b64}"


def send_to_printer(file_path: str):
    """
    Cross-platform best-effort printing:
      - Windows: os.startfile(path, "print")
      - POSIX: use `lp` or `lpr` (CUPS)
    Raises RuntimeError on failure.
    """
    if not file_path or not os.path.exists(file_path):
        raise FileNotFoundError("File not found for printing.")

    if os.name == 'nt':
        # Windows: use default associated application's print verb
        try:
            # This returns immediately in many cases while the app handles the job.
            os.startfile(str(file_path), "print")
            return True
        except Exception as e:
            raise RuntimeError(f"Windows printing failed: {e}")
    else:
        # POSIX (Linux/macOS): try lp then lpr
        last_exc = None
        for cmd in (["lp", file_path], ["lpr", file_path]):
            try:
                subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return True
            except FileNotFoundError:
                last_exc = FileNotFoundError("lp/lpr command not found")
                continue
            except subprocess.CalledProcessError as e:
                last_exc = e
        raise RuntimeError(f"Printing failed or no print command available: {last_exc}")


@app.route('/print_and_confirm/<token>', methods=['POST'])
def print_and_confirm(token):
    """
    Print the uploaded PDF using the shopkeeper's machine (server-side),
    then delete the entire temp folder and shut down.
    This bypasses the browser print dialog (so 'Save as PDF' is not available there).
    """
    if state.get('session_token') != token:
        flash("Invalid/expired session token.", "error")
        return redirect(url_for('admin'))

    p = state.get('uploaded_path')
    if not p or not os.path.exists(p):
        flash("No file uploaded to print.", "error")
        return redirect(url_for('admin'))

    try:
        send_to_printer(p)
    except Exception as e:
        flash(f"Printing failed: {e}", "error")
        return redirect(url_for('admin'))

    # If we reached here, printing was started successfully.
    # Remove entire upload folder and shut down (auto-confirm).
    cleanup_entire_upload_folder()
    state['session_token'] = None
    state['public_url'] = None

    Thread(target=stop_ngrok_and_shutdown, daemon=True).start()
    return render_template('printed.html')


def cleanup_uploaded_file():
    """Remove the single uploaded file (if any) but leave folder intact."""
    p = state.get('uploaded_path')
    if p and os.path.exists(p):
        try:
            os.remove(p)
        except Exception:
            pass
    state['uploaded_path'] = None
    state['uploaded_name'] = None


def cleanup_entire_upload_folder():
    """
    Remove the entire upload folder (recursively). This is called before shutdown
    so no traces remain in that folder.
    """
    try:
        if UPLOAD_FOLDER.exists():
            shutil.rmtree(UPLOAD_FOLDER)
    except Exception:
        pass
    # create a new empty folder for safety if the server continues running
    try:
        UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    state['uploaded_path'] = None
    state['uploaded_name'] = None


def stop_ngrok_and_shutdown():
    # disconnect & kill ngrok tunnel
    try:
        if state.get('tunnel'):
            try:
                ngrok.disconnect(state['tunnel'].public_url)
            except Exception:
                pass
        ngrok.kill()
    except Exception:
        pass

    # try to trigger Werkzeug shutdown via internal endpoint
    try:
        import requests
        try:
            requests.get("http://127.0.0.1:5000/_internal_shutdown_trigger", timeout=1)
        except Exception:
            pass
    except Exception:
        pass

    # fallback to process exit
    try:
        os._exit(0)
    except Exception:
        pass


def start_session_tunnel(local_port=5000):
    """
    Start an ngrok tunnel if not already running and return public URL.
    Requires that state['ngrok_authtoken'] has been set and pyngrok has the auth token.
    """
    if state.get('tunnel') is not None:
        return state['tunnel'].public_url
    tunnel = ngrok.connect(addr=local_port, proto="http")
    state['tunnel'] = tunnel
    state['public_url'] = tunnel.public_url
    return tunnel.public_url


def session_timeout_watcher():
    """
    Background thread to enforce timeout: if session isn't completed within SESSION_TIMEOUT_MINUTES,
    remove files, kill tunnel and shutdown.
    """
    timeout = SESSION_TIMEOUT_MINUTES
    while True:
        if not state.get('started_at'):
            return
        started = state['started_at']
        if datetime.utcnow() - started > timedelta(minutes=timeout):
            # timeout reached: cleanup and shutdown
            cleanup_entire_upload_folder()
            state['session_token'] = None
            state['public_url'] = None
            Thread(target=stop_ngrok_and_shutdown, daemon=True).start()
            return
        import time
        time.sleep(3)


# -------------------------
# Routes
# -------------------------
@app.route('/')
def root():
    return redirect(url_for('admin'))


@app.route('/admin', methods=['GET'])
def admin():
    # Admin page for shopkeeper (local)
    has_token = bool(state.get('ngrok_authtoken'))
    active = bool(state.get('session_token'))
    uploaded = bool(state.get('uploaded_path'))
    qr = None
    # Determine base public URL: prefer an explicit ngrok public URL if present,
    # otherwise use the current request host (server-hosted mode).
    base_url = state.get('public_url') or request.host_url.rstrip('/')
    upload_link = None
    session_token = state.get('session_token')
    if active and session_token:
        upload_link = f"{base_url}/upload/{session_token}"
        try:
            qr = generate_qr_data_url(upload_link)
        except Exception:
            qr = None

    # Only build print/confirm URLs when there's a valid session token to avoid url_for errors
    print_url = url_for('print_view', token=session_token) if session_token else None
    confirm_url = url_for('confirm_print', token=session_token) if session_token else None
    print_and_confirm_url = url_for('print_and_confirm', token=session_token) if session_token else None

    return render_template(
        'admin.html',
        has_token=has_token,
        active=active,
        uploaded=uploaded,
        uploaded_name=state.get('uploaded_name'),
        qr=qr,
        upload_link=upload_link,
        session_token=session_token,
        print_url=print_url,
        confirm_url=confirm_url,
        print_and_confirm_url=print_and_confirm_url
    )


@app.route('/admin_status', methods=['GET'])
def admin_status():
    """
    JSON endpoint polled by admin UI for auto-refresh.
    """
    active = bool(state.get('session_token'))
    uploaded = bool(state.get('uploaded_path'))
    session_token = state.get('session_token')
    # Build upload link using explicit ngrok public URL if available, else request host
    base_url = state.get('public_url') or request.host_url.rstrip('/')
    upload_link = None
    qr = None
    if active and session_token:
        upload_link = f"{base_url}/upload/{session_token}"
        # return the QR as a data URL (small)
        try:
            qr = generate_qr_data_url(upload_link)
        except Exception:
            qr = None
    return jsonify({
        "has_token": bool(state.get('ngrok_authtoken')),
        "active": active,
        "uploaded": uploaded,
        "uploaded_name": state.get('uploaded_name'),
        "upload_link": upload_link,
        "qr": qr
    })


@app.route('/setup_ngrok', methods=['POST'])
def setup_ngrok():
    token = request.form.get('authtoken', '').strip()
    if not token:
        flash("Authtoken cannot be empty.", "error")
        return redirect(url_for('admin'))
    try:
        conf.get_default().auth_token = token
        ngrok.set_auth_token(token)
        state['ngrok_authtoken'] = token
        save_config()  # persist for future runs
        flash("ngrok authtoken saved and persisted.", "success")
    except Exception as e:
        flash(f"Failed to set ngrok authtoken: {e}", "error")
    return redirect(url_for('admin'))


@app.route('/clear_ngrok', methods=['POST'])
def clear_ngrok():
    # Clear stored authtoken (both in-memory & on-disk)
    state['ngrok_authtoken'] = None
    try:
        if CONFIG_PATH.exists():
            CONFIG_PATH.unlink()
    except Exception:
        pass
    flash("ngrok authtoken cleared.", "info")
    return redirect(url_for('admin'))


@app.route('/start_session', methods=['POST'])
def start_session():
    if state.get('session_token'):
        flash("There is already an active session. Finish it first.", "error")
        return redirect(url_for('admin'))

    # Start a new single-use session. If an ngrok authtoken is configured start a tunnel,
    # otherwise assume the app is already hosted publicly and use the server's host URL.
    token = secrets.token_urlsafe(24)
    state['session_token'] = token
    if state.get('ngrok_authtoken'):
        try:
            public_url = start_session_tunnel(local_port=5000)
            state['public_url'] = public_url
        except Exception as e:
            state['session_token'] = None
            flash(f"Could not start ngrok tunnel: {e}", "error")
            return redirect(url_for('admin'))
    else:
        # Server-hosted mode: public URL will be derived from request.host_url when needed
        state['public_url'] = None

    state['started_at'] = datetime.utcnow()

    t = Thread(target=session_timeout_watcher, daemon=True)
    state['timeout_thread'] = t
    t.start()

    flash("Session started. Show the QR code to the customer.", "success")
    return redirect(url_for('admin'))


@app.route('/upload/<token>', methods=['GET', 'POST'])
def upload(token):
    # public upload endpoint used by customer via ngrok url
    if state.get('session_token') != token:
        return render_template('upload.html', error="This upload link is invalid or expired."), 404

    if request.method == 'GET':
        if state.get('uploaded_path'):
            return render_template('upload.html', message="A file has already been uploaded for this session. The link will remain available until the shopkeeper prints it.", token=token), 200
        return render_template('upload.html', token=token)

    # POST -> handle file
    if state.get('uploaded_path'):
        return render_template('upload.html', message="A file has already been uploaded for this session.", token=token), 400

    file = request.files.get('file')
    if not file:
        return render_template('upload.html', error="No file provided.", token=token), 400

    filename = secure_filename(file.filename)
    if not allowed_file(filename):
        return render_template('upload.html', error="Only PDF files are allowed.", token=token), 400

    unique_name = f"{secrets.token_hex(12)}_{filename}"
    save_path = UPLOAD_FOLDER / unique_name
    try:
        file.save(save_path)
    except Exception as e:
        return render_template('upload.html', error=f"Failed to save file: {e}", token=token), 500

    state['uploaded_path'] = str(save_path)
    state['uploaded_name'] = filename
    flash("File uploaded successfully. The shopkeeper has been notified in their local UI.", "success")
    return render_template('upload.html', message="Upload successful. The shopkeeper will receive the file shortly.", token=token)


@app.route('/file/<token>')
def serve_file(token):
    # Serve the uploaded PDF for the shopkeeper's browser
    if state.get('session_token') != token:
        return "Invalid token", 404
    p = state.get('uploaded_path')
    if not p or not os.path.exists(p):
        return "No file uploaded", 404
    return send_file(p, mimetype='application/pdf', as_attachment=False,
                     download_name=state.get('uploaded_name'))


@app.route('/print/<token>', methods=['GET'])
def print_view(token):
    if state.get('session_token') != token:
        return "Invalid token", 404
    if not state.get('uploaded_path'):
        return "No uploaded file to print", 404
    file_url = url_for('serve_file', token=token)
    return render_template('print_view.html', file_url=file_url, token=token)


@app.route('/confirm_print/<token>', methods=['POST'])
def confirm_print(token):
    if state.get('session_token') != token:
        return jsonify({"status": "error", "msg": "invalid token"}), 403

    # Remove entire upload folder before closing
    cleanup_entire_upload_folder()

    # clear session state
    state['session_token'] = None
    state['public_url'] = None

    # stop ngrok & shutdown server (best-effort)
    Thread(target=stop_ngrok_and_shutdown, daemon=True).start()
    return render_template('printed.html')


@app.route('/_internal_shutdown_trigger', methods=['GET'])
def _shutdown_trigger():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        return "No shutdown", 500
    func()
    return "Shutting down..."


@app.route('/stop_session', methods=['POST'])
def stop_session():
    # manual stop: cleanup entire folder and shutdown
    cleanup_entire_upload_folder()
    state['session_token'] = None
    state['public_url'] = None
    Thread(target=stop_ngrok_and_shutdown, daemon=True).start()
    flash("Stopping session and shutting down.", "info")
    return redirect(url_for('admin'))


if __name__ == '__main__':
    print("Starting Flask app. Open http://127.0.0.1:5000/admin to set up ngrok and start a session.")
    app.run(host='127.0.0.1', port=5000, debug=False)
