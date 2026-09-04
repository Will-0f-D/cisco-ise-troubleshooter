"""Entry point per l'eseguibile standalone (PyInstaller)."""
import threading
import webbrowser

import uvicorn

from main import app

if __name__ == "__main__":
    threading.Timer(1.5, lambda: webbrowser.open("http://127.0.0.1:8000")).start()
    uvicorn.run(app, host="127.0.0.1", port=8000)
