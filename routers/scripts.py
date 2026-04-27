import os
import asyncio
import subprocess
from pathlib import Path
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse

router = APIRouter(prefix="/scripts", tags=["scripts"])

BASE_DIR = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = BASE_DIR / "scripts"
VENV_PYTHON = BASE_DIR / "venv" / "bin" / "python"


@router.get("/list")
async def list_scripts():
    """Liste tous les scripts .py disponibles."""
    scripts = []
    if SCRIPTS_DIR.exists():
        for f in sorted(SCRIPTS_DIR.glob("*.py")):
            scripts.append({
                "name": f.name,
                "size": f.stat().st_size,
                "modified": f.stat().st_mtime
            })
    return JSONResponse(content={"scripts": scripts})


@router.websocket("/ws/run")
async def run_script(websocket: WebSocket):
    """
    WebSocket qui lance un script et streame stdout/stderr en live.
    
    Le client envoie un JSON : {"script": "download_nvd.py", "args": ["year", "--year", "2024"]}
    Le serveur streame chaque ligne de sortie puis envoie {"status": "done", "code": 0}
    """
    await websocket.accept()

    try:
        # Recevoir la commande
        data = await websocket.receive_json()
        script_name = data.get("script", "")
        script_args = data.get("args", [])

        # Validation sécurité : le script doit exister dans SCRIPTS_DIR
        script_path = SCRIPTS_DIR / script_name
        if not script_path.exists() or not script_path.is_file() or not script_name.endswith(".py"):
            await websocket.send_json({"type": "error", "data": f"Script invalide: {script_name}"})
            await websocket.close()
            return

        # Validation sécurité : interdire path traversal
        if ".." in script_name or "/" in script_name:
            await websocket.send_json({"type": "error", "data": "Nom de script interdit"})
            await websocket.close()
            return

        await websocket.send_json({"type": "info", "data": f"▶ Lancement: {script_name} {' '.join(script_args)}"})

        # Lancer le subprocess
        env = os.environ.copy()
        process = await asyncio.create_subprocess_exec(
            str(VENV_PYTHON), str(script_path), *script_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(SCRIPTS_DIR.parent),
            env=env
        )

        # Streamer la sortie ligne par ligne
        while True:
            line = await process.stdout.readline()
            if not line:
                break
            text = line.decode("utf-8", errors="replace").rstrip()
            await websocket.send_json({"type": "stdout", "data": text})

        # Attendre la fin du process
        return_code = await process.wait()

        await websocket.send_json({
            "type": "done",
            "data": f"✓ Terminé (code: {return_code})",
            "code": return_code
        })

    except WebSocketDisconnect:
        # Le client a fermé la connexion, tuer le process si encore actif
        if 'process' in locals() and process.returncode is None:
            process.kill()
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "data": str(e)})
        except:
            pass
    finally:
        try:
            await websocket.close()
        except:
            pass


@router.get("/console", response_class=HTMLResponse)
async def console_page():
    """Page HTML avec la console interactive."""
    return HTMLResponse(content=CONSOLE_HTML)


# ─────────────────────────────────────────────
# Page HTML intégrée
# ─────────────────────────────────────────────

CONSOLE_HTML = """
<!DOCTYPE html>
<html lang="fr" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Asset Manager — Console Scripts</title>
    <link rel="stylesheet" href="/static/bootstrap.min.css">
    <link rel="stylesheet" href="/static/app-search.css">
    <link rel="stylesheet" href="/static/app-premium.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            background-color: #0d1117;
            color: #c9d1d9;
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            height: 100vh;
            display: flex;
            flex-direction: column;
        }

        /* Navbar dot */
        .header-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #3fb950;
            animation: pulse 2s infinite;
            display: inline-block;
            margin-right: 8px;
        }


            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #3fb950;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.4; }
        }

        /* Controls */
        .controls {
            background: #161b22;
            padding: 16px 24px;
            display: flex;
            gap: 12px;
            align-items: center;
            flex-wrap: wrap;
            border-bottom: 1px solid #30363d;
        }

        select, input, button {
            font-family: 'SF Mono', 'Cascadia Code', 'Consolas', monospace;
            font-size: 13px;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 8px 12px;
            background: #0d1117;
            color: #c9d1d9;
            outline: none;
        }

        select:focus, input:focus {
            border-color: #58a6ff;
            box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.15);
        }

        select {
            min-width: 250px;
        }

        input {
            flex: 1;
            min-width: 200px;
        }

        button {
            cursor: pointer;
            font-weight: 600;
            transition: all 0.15s;
        }

        .btn-run {
            background: #238636;
            border-color: #2ea043;
            color: #fff;
        }

        .btn-run:hover {
            background: #2ea043;
        }

        .btn-run:disabled {
            background: #21262d;
            border-color: #30363d;
            color: #484f58;
            cursor: not-allowed;
        }

        .btn-clear {
            background: #21262d;
            border-color: #30363d;
            color: #c9d1d9;
        }

        .btn-clear:hover {
            background: #30363d;
        }

        .btn-stop {
            background: #da3633;
            border-color: #f85149;
            color: #fff;
        }

        .btn-stop:hover {
            background: #f85149;
        }

        /* Status bar */
        .status-bar {
            padding: 6px 24px;
            font-size: 12px;
            color: #8b949e;
            background: #0d1117;
            border-bottom: 1px solid #21262d;
            font-family: 'SF Mono', 'Cascadia Code', 'Consolas', monospace;
            display: flex;
            justify-content: space-between;
        }

        .status-indicator {
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .status-dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: #484f58;
        }

        .status-dot.running {
            background: #d29922;
            animation: pulse 1s infinite;
        }

        .status-dot.success {
            background: #3fb950;
        }

        .status-dot.error {
            background: #f85149;
        }

        /* Console */
        .console-wrapper {
            flex: 1;
            overflow: hidden;
            position: relative;
        }

        .console {
            height: 100%;
            overflow-y: auto;
            padding: 16px 24px;
            font-family: 'SF Mono', 'Cascadia Code', 'Consolas', monospace;
            font-size: 13px;
            line-height: 1.6;
            white-space: pre-wrap;
            word-wrap: break-word;
        }

        .console .line {
            padding: 1px 0;
        }

        .console .line.stdout {
            color: #c9d1d9;
        }

        .console .line.info {
            color: #58a6ff;
        }

        .console .line.error {
            color: #f85149;
        }

        .console .line.done {
            color: #3fb950;
            font-weight: 600;
        }

        .console .line.done.failed {
            color: #f85149;
        }

        .console .timestamp {
            color: #484f58;
            margin-right: 12px;
            user-select: none;
        }

        /* Scrollbar */
        .console::-webkit-scrollbar {
            width: 8px;
        }

        .console::-webkit-scrollbar-track {
            background: #0d1117;
        }

        .console::-webkit-scrollbar-thumb {
            background: #30363d;
            border-radius: 4px;
        }

        .console::-webkit-scrollbar-thumb:hover {
            background: #484f58;
        }

        /* Welcome message */
        .welcome {
            color: #484f58;
            text-align: center;
            margin-top: 20vh;
        }

        .welcome pre {
            font-size: 11px;
            line-height: 1.3;
            margin-bottom: 16px;
            color: #30363d;
        }
    </style>
</head>
<body>

    <nav class="navbar navbar-expand-lg navbar-dark sticky-top">
        <div class="container">
            <a class="navbar-brand fw-bold" href="/">🛡️ Asset Manager</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#nav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="nav">
                <div class="d-flex ms-auto align-items-center gap-3">
                    <div class="position-relative am-search" data-am-search-root>
                        <input class="form-control form-control-sm" type="search"
                               placeholder="Rechercher client, site, asset…"
                               autocomplete="off" data-am-search-input>
                        <div class="dropdown-menu am-search-menu mt-2" data-am-search-menu></div>
                    </div>
                    <ul class="navbar-nav ms-auto">
                        <li class="nav-item"><a class="nav-link" href="/">Accueil</a></li>
                        <li class="nav-item"><a class="nav-link" href="/ui/vulns">Vulnérabilités</a></li>
                        <li class="nav-item dropdown">
                            <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
                                Référentiels
                            </a>
                            <ul class="dropdown-menu dropdown-menu-dark">
                                <li><a class="dropdown-item" href="/ui/clients">👥 Clients</a></li>
                                <li><a class="dropdown-item" href="/ui/sites">🏢 Sites</a></li>
                                <li><a class="dropdown-item" href="/ui/assets">💻 Assets</a></li>
                                <li><hr class="dropdown-divider"></li>
                                <li><a class="dropdown-item" href="/ui/vendors">🏭 Fabricants</a></li>
                                <li><a class="dropdown-item" href="/ui/models">📦 Modèles</a></li>
                            </ul>
                        </li>
                        <li class="nav-item"><a class="nav-link" href="/docs">API Docs</a></li>
                        <li class="nav-item"><a class="nav-link active" href="/scripts/console">Console</a></li>
                    </ul>
                </div>
            </div>
        </div>
    </nav>

    <div class="controls">
        <select id="scriptSelect">
            <option value="">-- Sélectionner un script --</option>
        </select>
        <input type="text" id="argsInput" placeholder="Arguments (ex: year --year 2024)" />
        <button class="btn-run" id="btnRun" onclick="runScript()">▶ Exécuter</button>
        <button class="btn-stop" id="btnStop" onclick="stopScript()" style="display:none">■ Arrêter</button>
        <button class="btn-clear" onclick="clearConsole()">Effacer</button>
    </div>

    <div class="status-bar">
        <div class="status-indicator">
            <div class="status-dot" id="statusDot"></div>
            <span id="statusText">Prêt</span>
        </div>
        <div>
            <span id="lineCount">0 lignes</span>
        </div>
    </div>

    <div class="console-wrapper">
        <div class="console" id="console">
            <div class="welcome">
                <pre>
    ___                 __     __  ___                                 
   /   |  _____________/ /_   /  |/  /___ _____  ____ _____ ____  _____
  / /| | / ___/ ___/ _ \\/ __/  / /|_/ / __ `/ __ \\/ __ `/ __ `/ _ \\/ ___/
 / ___ |(__  |__  )  __/ /_   / /  / / /_/ / / / / /_/ / /_/ /  __/ /    
/_/  |_/____/____/\\___/\\__/  /_/  /_/\\__,_/_/ /_/\\__,_/\\__, /\\___/_/     
                                                       /____/            
                </pre>
                <p>Sélectionnez un script et cliquez sur Exécuter.</p>
            </div>
        </div>
    </div>

<script>
    let ws = null;
    let lineCounter = 0;
    let autoScroll = true;

    // Charger la liste des scripts au démarrage
    async function loadScripts() {
        try {
            const resp = await fetch('/scripts/list');
            const data = await resp.json();
            const select = document.getElementById('scriptSelect');

            data.scripts.forEach(s => {
                const opt = document.createElement('option');
                opt.value = s.name;
                opt.textContent = s.name;
                select.appendChild(opt);
            });
        } catch (e) {
            appendLine('error', 'Impossible de charger la liste des scripts: ' + e.message);
        }
    }

    function getTimestamp() {
        const now = new Date();
        return now.toLocaleTimeString('fr-FR', { hour12: false }) + '.' +
               String(now.getMilliseconds()).padStart(3, '0');
    }

    function appendLine(type, text) {
        const consoleEl = document.getElementById('console');

        // Supprimer le message de bienvenue s'il existe
        const welcome = consoleEl.querySelector('.welcome');
        if (welcome) welcome.remove();

        const div = document.createElement('div');
        div.className = 'line ' + type;

        const timestamp = document.createElement('span');
        timestamp.className = 'timestamp';
        timestamp.textContent = getTimestamp();

        div.appendChild(timestamp);
        div.appendChild(document.createTextNode(text));
        consoleEl.appendChild(div);

        lineCounter++;
        document.getElementById('lineCount').textContent = lineCounter + ' lignes';

        // Auto-scroll
        if (autoScroll) {
            consoleEl.scrollTop = consoleEl.scrollHeight;
        }
    }

    // Détecter si l'utilisateur scrolle manuellement
    document.getElementById('console').addEventListener('scroll', function () {
        const el = this;
        autoScroll = (el.scrollTop + el.clientHeight >= el.scrollHeight - 50);
    });

    function setStatus(state, text) {
        const dot = document.getElementById('statusDot');
        const label = document.getElementById('statusText');
        dot.className = 'status-dot ' + state;
        label.textContent = text;
    }

    function runScript() {
        const scriptName = document.getElementById('scriptSelect').value;
        if (!scriptName) {
            appendLine('error', '✗ Aucun script sélectionné');
            return;
        }

        const argsRaw = document.getElementById('argsInput').value.trim();
        const args = argsRaw ? argsRaw.split(/\\s+/) : [];

        // Fermer toute connexion existante
        if (ws) {
            ws.close();
        }

        // UI
        document.getElementById('btnRun').disabled = true;
        document.getElementById('btnRun').style.display = 'none';
        document.getElementById('btnStop').style.display = '';
        setStatus('running', 'Exécution en cours...');

        appendLine('info', '━'.repeat(60));
        appendLine('info', '▶ ' + scriptName + ' ' + args.join(' '));
        appendLine('info', '━'.repeat(60));

        // Connexion WebSocket
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        ws = new WebSocket(protocol + '//' + window.location.host + '/scripts/ws/run');

        ws.onopen = function () {
            ws.send(JSON.stringify({
                script: scriptName,
                args: args
            }));
        };

        ws.onmessage = function (event) {
            const msg = JSON.parse(event.data);

            if (msg.type === 'done') {
                const cssClass = msg.code === 0 ? 'done' : 'done failed';
                appendLine(cssClass, msg.data);
                setStatus(msg.code === 0 ? 'success' : 'error',
                    msg.code === 0 ? 'Terminé avec succès' : 'Terminé avec erreur (code ' + msg.code + ')');
                resetButtons();
            } else {
                appendLine(msg.type, msg.data);
            }
        };

        ws.onerror = function () {
            appendLine('error', '✗ Erreur de connexion WebSocket');
            setStatus('error', 'Erreur de connexion');
            resetButtons();
        };

        ws.onclose = function () {
            resetButtons();
        };
    }

    function stopScript() {
        if (ws) {
            appendLine('error', '■ Arrêt demandé par l\\'utilisateur');
            ws.close();
            ws = null;
            setStatus('error', 'Arrêté');
        }
        resetButtons();
    }

    function resetButtons() {
        document.getElementById('btnRun').disabled = false;
        document.getElementById('btnRun').style.display = '';
        document.getElementById('btnStop').style.display = 'none';
    }

    function clearConsole() {
        const consoleEl = document.getElementById('console');
        consoleEl.innerHTML = '';
        lineCounter = 0;
        document.getElementById('lineCount').textContent = '0 lignes';
        setStatus('', 'Prêt');
    }

    // Init
    loadScripts();
</script>
<script src="/static/bootstrap.bundle.min.js"></script>

</body>
</html>
"""
