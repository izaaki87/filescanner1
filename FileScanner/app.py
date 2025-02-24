import os
import time
import threading
import psutil
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from flask import Flask, render_template, request, redirect, url_for, flash


yara_available = False


LOG_FILENAME = "ransomware_detection.txt"


logging.basicConfig(
    filename=LOG_FILENAME,
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)


SUSPICIOUS_EXTENSIONS = (
    ".locked",  ".zip", ".scr", ".vbs", ".crypt",  ".enc", ".ransom",
     ".locky", ".diablo",
    ".zepto", ".exx", ".odin", ".txt"
)


detected_files = []


MONITOR_DIR = None
monitor_thread = None
observer_global = None


class RansomwareMonitor(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory:
            file_path = event.src_path
            print(f"DEBUG: Detected modification: {file_path}")
            alert_triggered = False

            # Check if file extension is suspicious.
            if file_path.lower().endswith(SUSPICIOUS_EXTENSIONS):
                alert_triggered = True
                print("DEBUG: File extension match found!")

            if alert_triggered:
                msg = f"Suspicious File Change Detected: {file_path}"
                logging.warning(msg)
                print(f"[ALERT] {msg}")
                if file_path not in [f["path"] for f in detected_files]:
                    detected_files.append({
                        "path": file_path,
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                    })


def detect_suspicious_processes():
    ransomware_like_processes = []
    for proc in psutil.process_iter(attrs=['pid', 'name', 'cpu_percent']):
        try:
            process_info = proc.info
            if process_info.get("cpu_percent", 0) > 50:
                ransomware_like_processes.append(process_info)
                logging.warning(f"High CPU Process: {process_info['name']} (PID: {process_info['pid']})")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return ransomware_like_processes

def kill_suspicious_processes():
    suspicious_processes = detect_suspicious_processes()
    for proc in suspicious_processes:
        pid = proc["pid"]
        try:
            psutil.Process(pid).terminate()
            logging.info(f"Killed Suspicious Process: {proc['name']} (PID: {pid})")
            print(f"[ACTION] Terminated: {proc['name']} (PID: {pid})")
        except Exception as e:
            logging.error(f"Failed to kill {proc['name']} (PID: {pid}): {e}")

# Monitoring loop running in a separate thread.
def start_monitoring(folder):
    global observer_global
    event_handler = RansomwareMonitor()
    observer = Observer()
    observer.schedule(event_handler, path=folder, recursive=True)
    observer.start()
    observer_global = observer  # Save observer for later stopping.
    print(f"Monitoring directory: {folder} for ransomware-like activity...")
    try:
        while True:
            kill_suspicious_processes()
            time.sleep(5)
    except Exception as e:
        observer.stop()
    observer.join()

# Folder scanning function.
def scan_folder_for_malicious(folder):
    scanned_files = []
    for root, dirs, files in os.walk(folder):
        for file in files:
            filepath = os.path.join(root, file)
            if filepath.lower().endswith(SUSPICIOUS_EXTENSIONS):
                # For now, we consider the extension match as the signature.
                msg = f"Malicious file detected: {filepath}"
                logging.warning(msg)
                print(f"[SCAN] {msg}")
                scanned_files.append({
                    "path": filepath,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                })
    return scanned_files


app = Flask(__name__)
app.secret_key = "your_key"

@app.route("/")
def index():
    return render_template("index.html", files=detected_files, monitor_dir=MONITOR_DIR)


@app.route("/set_monitor", methods=["GET", "POST"])
def set_monitor():
    global MONITOR_DIR, monitor_thread, observer_global
    if request.method == "POST":
        folder = request.form.get("folder_path", "").strip()
        print(f"DEBUG: User submitted folder: '{folder}'")
        if folder and os.path.isdir(folder):
            if observer_global is not None:
                observer_global.stop()
                observer_global.join()
                observer_global = None
            MONITOR_DIR = folder
            detected_files.clear()  # Clear previous detections.
            monitor_thread = threading.Thread(target=start_monitoring, args=(MONITOR_DIR,), daemon=True)
            monitor_thread.start()
            flash(f"Monitoring folder set to: {MONITOR_DIR}", "success")
            return redirect(url_for("index"))
        else:
            flash("Folder does not exist. Please enter a valid folder path.", "danger")
    return render_template("set_monitor.html")


@app.route("/scan")
def scan_folder():
    if MONITOR_DIR and os.path.isdir(MONITOR_DIR):
        scanned = scan_folder_for_malicious(MONITOR_DIR)
        global detected_files
        for file in scanned:
            if file["path"] not in [f["path"] for f in detected_files]:
                detected_files.append(file)
        flash("Folder scan completed.", "success")
    else:
        flash("No valid monitored folder set.", "danger")
    return redirect(url_for("index"))

@app.route("/delete", methods=["POST"])
def delete_file():
    file_path = request.form.get("file_path")
    if file_path and os.path.exists(file_path):
        try:
            os.remove(file_path)
            logging.info(f"Deleted file: {file_path}")
            flash(f"Deleted file: {file_path}", "success")
            global detected_files
            detected_files = [f for f in detected_files if f["path"] != file_path]
        except Exception as e:
            flash(f"Error deleting file: {file_path}. Error: {str(e)}", "danger")
    else:
        flash("File not found.", "warning")
    return redirect(url_for("index"))

@app.route("/upload", methods=["GET", "POST"])
def upload_file():
    if request.method == "POST":
        if "file" not in request.files:
            flash("No file part", "warning")
            return redirect(request.url)
        file = request.files["file"]
        if file.filename == "":
            flash("No selected file", "warning")
            return redirect(request.url)
        if file:
            from werkzeug.utils import secure_filename
            filename = secure_filename(file.filename)
            upload_folder = os.path.join(os.getcwd(), "uploads")
            os.makedirs(upload_folder, exist_ok=True)
            upload_path = os.path.join(upload_folder, filename)
            file.save(upload_path)
            flash(f"File uploaded: {filename}", "success")
            if filename.lower().endswith(SUSPICIOUS_EXTENSIONS):
                detected_files.append({
                    "path": upload_path,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                })
            return redirect(url_for("index"))
    return render_template("upload.html")

@app.route("/logs")
def view_logs():
    if os.path.exists(LOG_FILENAME):
        with open(LOG_FILENAME, "r") as f:
            log_content = f.read()
    else:
        log_content = "Log file not found."
    return render_template("logs.html", log_content=log_content)

@app.route("/clear_logs", methods=["POST"])
def clear_logs():
    try:
        with open(LOG_FILENAME, "w") as f:
            f.truncate(0)
        logging.info("Log file cleared.")
        flash("Log file cleared.", "success")
    except Exception as e:
        flash(f"Error clearing log file: {str(e)}", "danger")
    return redirect(url_for("view_logs"))



if __name__ == "__main__":

    app.run(debug=True)
