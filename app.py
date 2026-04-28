from flask import Flask, request, jsonify, render_template, send_from_directory
from database import init_db, get_alerts, get_scan_logs, clear_alerts, get_stats
from scanner import scan_ip, scan_website, LOGS_DIR
import os

app = Flask(__name__)

# Initialise DB on startup
init_db()

# ─── API Routes ──────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json(force=True)
    target = (data.get('target') or '').strip()
    scan_type = (data.get('scan_type') or 'ip').lower()

    if not target:
        return jsonify({'error': 'No target provided'}), 400

    try:
        if scan_type == 'website':
            result = scan_website(target)
        else:
            result = scan_ip(target)

        if 'error' in result:
            return jsonify({'error': result['error']}), 400

        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts', methods=['GET'])
def api_alerts():
    return jsonify(get_alerts())


@app.route('/api/alerts', methods=['DELETE'])
def api_clear_alerts():
    clear_alerts()
    return jsonify({'message': 'All alerts cleared'})


@app.route('/api/logs', methods=['GET'])
def api_logs():
    return jsonify(get_scan_logs())


@app.route('/api/stats', methods=['GET'])
def api_stats():
    return jsonify(get_stats())


@app.route('/api/logfiles', methods=['GET'])
def api_logfiles():
    """Return a list of saved scan log files (newest first)."""
    try:
        files = []
        for fname in sorted(os.listdir(LOGS_DIR), reverse=True):
            if fname.endswith('.log'):
                fpath = os.path.join(LOGS_DIR, fname)
                files.append({
                    'name': fname,
                    'size': os.path.getsize(fpath),
                    'modified': os.path.getmtime(fpath)
                })
        return jsonify(files)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/logfiles/<path:filename>', methods=['GET'])
def api_download_logfile(filename):
    """Download a specific log file."""
    return send_from_directory(LOGS_DIR, filename, as_attachment=True)


# ─── Run ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("=" * 60)
    print("  SnortIDS Dashboard  –  http://localhost:5000")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)
