from time import strftime
from fastapi import FastAPI, UploadFile , File
from fastapi_socketio import SocketManager
from pathlib import Path

from ..pcap_analyzer import *

app = FastAPI
socket_manager = SocketManager(app)

@app.post("/upload/")
async def handleUpload(file : UploadFile  = File(...)  ):
    file_path = str(Path.cwd())+"uploded_files/" + strftime("%Y%m%d_%H%M%S.pcapng")
    with open(file_path , 'wb') as wb:
        wb.write( await file.read() )
    
