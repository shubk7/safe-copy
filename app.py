from flask import Flask, request, render_template, redirect, url_for, flash, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from pyngrok import ngrok
import qrcode
import uuid
import os
import io
import base64
import secrets
from pathlib import Path
from datetime import datetime, timedelta
import subprocess
from threading import Thread
import shutil

#Config
UPLOAD_FOLDER = 'static/uploads/'
ALLOWED_EXTENSIONS = {'.pdf'}
SESSION_TIMEOUT_MINUTES = 60

app = Flask(__name__)

#Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

#Database model
class Room(db.Model):
    id = db.Column(db.String, primary_key=True)
    admin_uuid = db.Column(db.String, nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

################    State dict
current_session_state = {
    "session_token": None,  #UUID for current session
    "public_url": None,  #ngrok public url
    "upload_name": None,  #Uploaded file name
    "started_at": None,  #Session start time
    "file_name" : None
    #TODO add checkout thread
}

#Utility functions
def allowed_file(filename):
    return Path(filename).suffix in ALLOWED_EXTENSIONS

def generate_qr_data_url(text: str) -> str:
    img = qrcode.make(text)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    b64 = base64.b64encode(buf.getvalue()).decode('ascii')
    return f'data:image/png;base64,{b64}'

def send_to_printer(file_path: str):
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
    if current_session_state.get('session_token') != token:
        flash("Invalid/expired session token.", "error")
        return redirect(url_for('admin'))

    p = current_session_state.get('uploaded_path')
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
    current_session_state['session_token'] = None
    current_session_state['public_url'] = None

    Thread(target=stop_ngrok_and_shutdown, daemon=True).start()
    return render_template('printed.html')

def cleanup_uploaded_file():
    p = UPLOAD_FOLDER + current_session_state.get('file_name')
    
    if p and os.path.exists(p):
        try:
            os.remove(p)
        except Exception:
            pass
    current_session_state['uploaded_path'] = None
    current_session_state['uploaded_name'] = None

def cleanup_entire_upload_folder():
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
    current_session_state['uploaded_path'] = None
    current_session_state['uploaded_name'] = None

def stop_ngrok_and_shutdown():
    # disconnect & kill ngrok tunnel
    try:
        if current_session_state.get('tunnel'):
            try:
                ngrok.disconnect(current_session_state['tunnel'].public_url)
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

def session_timeout_watcher():
    """
    Background thread to enforce timeout: if session isn't completed within SESSION_TIMEOUT_MINUTES,
    remove files, kill tunnel and shutdown.
    """
    timeout = SESSION_TIMEOUT_MINUTES
    while True:
        if not current_session_state.get('started_at'):
            return
        started = current_session_state['started_at']
        if datetime.utcnow() - started > timedelta(minutes=timeout):
            # timeout reached: cleanup and shutdown
            cleanup_entire_upload_folder()
            current_session_state['session_token'] = None
            current_session_state['public_url'] = None
            Thread(target=stop_ngrok_and_shutdown, daemon=True).start()
            return
        import time
        time.sleep(3)

@app.route('/file/<token>')
def serve_file(token):
    # Serve the uploaded PDF for the shopkeeper's browser
    if current_session_state.get('session_token') != token:
        return "Invalid token", 404
    p = current_session_state.get('uploaded_path')
    if not p or not os.path.exists(p):
        return "No file uploaded", 404
    return send_file(p, mimetype='application/pdf', as_attachment=False,
                     download_name=current_session_state.get('uploaded_name'))

@app.route('/print/<token>', methods=['GET'])
def print_view(token):
    if current_session_state.get('session_token') != token:
        return "Invalid token", 404
    if not current_session_state.get('uploaded_path'):
        return "No uploaded file to print", 404
    file_url = url_for('serve_file', token=token)
    return render_template('print_view.html', file_url=file_url, token=token)

@app.route('/confirm_print/<token>', methods=['POST'])
def confirm_print(token):
    if current_session_state.get('session_token') != token:
        return jsonify({"status": "error", "msg": "invalid token"}), 403

    # Remove entire upload folder before closing
    cleanup_entire_upload_folder()

    # clear session state
    current_session_state['session_token'] = None
    current_session_state['public_url'] = None

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

#TODO: clean file
#TODO: clean folder

#TODO: stop session

#TODO: thread



########## Routes
@app.route('/')
def root():
    return render_template('index.html')



#For Printers
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    #Admin page for shopkeepers

    #Session states
    is_session_active = bool(current_session_state.get("session_token"))
    has_uploaded = bool(current_session_state.get("upload_name"))

    qr = None
    upload_link = None

    if is_session_active: #TODO and session_token 'exists'
        upload_link = f"{current_session_state['public_url']}/upload/{current_session_state['session_token']}"
        qr = generate_qr_data_url(upload_link)
    
    #TODO: build print/confirm urls

    #TODO: add print/confirm links
    return render_template(
        'admin.html',
        active=is_session_active, 
        uploaded=has_uploaded, 
        uploaded_name = current_session_state.get("upload_name"),
        qr=qr,
        upload_link=upload_link,
        session_token=current_session_state.get("session_token")
    )




@app.route('/admin_status', methods=['GET'])
def admin_status():
    #Check status and send back to html
    #polled by admin ui (in admin.html script) for auto-refresh
    
    is_session_active = bool(current_session_state.get("session_token"))
    has_uploaded = bool(current_session_state.get("upload_name"))

    #TODO: complete method



#Start a temporary session
@app.route('/start_session', methods=['POST'])
def start_session():
    if current_session_state.get("session_token"):
        flash("There is already an active session. Finish it first.", "error")
        return redirect(url_for('admin'))

    room = Room(id = str(uuid.uuid4()), admin_uuid = str(uuid.uuid4()), date_created = datetime.utcnow())
    db.session.add(room)
    db.session.commit()

    current_session_state['session_token'] = room.id
    current_session_state['started_at'] = datetime.utcnow()

    #TODO: Add thread

    #flash("Session started. Show the QR code to the customer.", "success")
    return redirect(url_for('admin', session_started=1, session_token=room.id))


#When user uploads a file
@app.route('/upload/<token>', methods=['GET', 'POST'])
def upload(token):
    # public upload endpoint used by customer via ngrok url
    if current_session_state.get('session_token') != token:
        return render_template('upload.html', error="This upload link is invalid or expired."), 404

    if request.method == 'GET':
        if current_session_state.get('uploaded_path'):
            return render_template('upload.html', message="A file has already been uploaded for this session. The link will remain available until the shopkeeper prints it.", token=token), 200
        return render_template('upload.html', token=token)

    # POST -> handle file
    if current_session_state.get('uploaded_path'):
        return render_template('upload.html', message="A file has already been uploaded for this session.", token=token), 400

    file = request.files.get('file')
    if not file:
        return render_template('upload.html', error="No file provided.", token=token), 400

    filename = secure_filename(file.filename)
    if not allowed_file(filename):
        return render_template('upload.html', error="Only PDF files are allowed.", token=token), 400

    unique_name = f"{secrets.token_hex(12)}_{filename}"
    current_session_state['file_name'] = unique_name
    save_path = f'static/uploads/{unique_name}'
    try:
        file.save(save_path)
    except Exception as e:
        return render_template('upload.html', error=f"Failed to save file: {e}", token=token), 500

    current_session_state['uploaded_path'] = str(save_path)
    current_session_state['uploaded_name'] = filename
    flash("File uploaded successfully. The shopkeeper has been notified in their local UI.", "success")
    return render_template('upload.html', message="Upload successful. The shopkeeper will receive the file shortly.", token=token)

#Stop session and delete room from database, and delete uploaded files
@app.route('/stop_session', methods=['POST'])
def stop_session():
    pass


if __name__ == '__main__':
    with app.app_context():   # Create database tables if they don't exist
        db.create_all()

    app.run(debug=True, port=5000)