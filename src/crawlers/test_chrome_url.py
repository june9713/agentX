import websocket
import json

try:
    # Try to connect to WebSocket
    ws = websocket.create_connection("ws://127.0.0.1:8000")
    print("WebSocket connection successful!")
    
    # Send default ping message
    ws.send(json.dumps({"type": "ping"}))
    result = ws.recv()
    print(f"Received response: {result}")
    
    ws.close()
except Exception as e:
    print(f"WebSocket connection failed: {e}")