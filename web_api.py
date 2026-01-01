
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import logging

# Assuming other managers are in the same directory
# We will add API endpoints for them later
import process_manager
import network_manager
import dll_manager
import handle_manager
import dump_manager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# --- CORS Middleware ---
# This allows the frontend to communicate with the backend
# (In case we decide to serve them on different ports later)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# --- Static Files ---
# This serves the HTML, CSS, and JS files for our new GUI
app.mount("/modern_gui", StaticFiles(directory="modern_gui"), name="modern_gui")


# --- API Endpoints ---
@app.get("/api/processes")
async def get_processes():
    """
    API endpoint to get the list of running processes.
    """
    try:
        logger.info("Fetching process list.")
        # Reusing the existing logic from process_manager.py
        processes = process_manager.get_process_list()
        return {"success": True, "data": processes}
    except Exception as e:
        logger.error(f"Failed to fetch processes: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@app.get("/api/network")
async def get_network():
    """
    API endpoint to get network connections.
    """
    try:
        logger.info("Fetching network connections.")
        connections = network_manager.get_network_connections()
        return {"success": True, "data": connections}
    except Exception as e:
        logger.error(f"Failed to fetch network connections: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@app.get("/api/dlls/{pid}")
async def get_dlls(pid: int):
    """
    API endpoint to get loaded DLLs for a specific process.
    """
    try:
        logger.info(f"Fetching DLLs for PID: {pid}")
        dlls = dll_manager.find_dlls(pid)
        return {"success": True, "data": dlls}
    except Exception as e:
        logger.error(f"Failed to fetch DLLs for PID {pid}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@app.get("/api/handles/{pid}")
async def get_handles(pid: int):
    """
    API endpoint to get open handles for a specific process.
    """
    try:
        logger.info(f"Fetching handles for PID: {pid}")
        # Note: The underlying find_handles function might be slow
        handles = handle_manager.find_handles(pid)
        return {"success": True, "data": handles}
    except Exception as e:
        logger.error(f"Failed to fetch handles for PID {pid}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@app.post("/api/dump/{pid}")
async def dump_process_api(pid: int):
    """
    API endpoint to create a memory dump for a specific process.
    """
    try:
        logger.info(f"Dumping process for PID: {pid}")
        # This is a fire-and-forget action from the UI perspective
        dump_path = dump_manager.dump_process(pid)
        return {"success": True, "message": f"Process dumped successfully to {dump_path}"}
    except Exception as e:
        logger.error(f"Failed to dump process for PID {pid}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


# --- Root Endpoint ---
@app.get("/", include_in_schema=False)
async def root():
    """
    Serves the main index.html file.
    """
    return FileResponse('modern_gui/index.html')


# --- Main Entry Point ---
if __name__ == "__main__":
    logger.info("Starting Sysmon Modern GUI backend server.")
    # Runs the FastAPI application
    # You can access the GUI at http://127.0.0.1:8008
    uvicorn.run(app, host="127.0.0.1", port=8008)
