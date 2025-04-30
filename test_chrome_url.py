import websocket
import json

try:
    # WebSocket 연결 시도
    ws = websocket.create_connection("ws://127.0.0.1:8000")
    print("WebSocket 연결 성공!")
    
    # 기본 핑 메시지 전송
    ws.send(json.dumps({"type": "ping"}))
    result = ws.recv()
    print(f"받은 응답: {result}")
    
    ws.close()
except Exception as e:
    print(f"WebSocket 연결 실패: {e}")