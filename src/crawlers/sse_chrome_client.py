import requests
import json
import uuid
import time
import threading
import asyncio
import websockets
from sseclient import SSEClient  # pip install sseclient-py

class ChromeMCPSession:
    def __init__(self, server_url="http://localhost:8000"):
        self.server_url = server_url
        self.session_id = str(uuid.uuid4())
        self.messages_endpoint = f"{server_url}/messages/"
        self.sse_endpoint = f"{server_url}/sse"
        self.sse_client = None
        self.sse_thread = None
        self.request_id = 0
    
    def _get_next_id(self):
        self.request_id += 1
        return self.request_id
    
    def _sse_listener(self):
        """SSE 연결을 유지하는 스레드 함수"""
        try:
            print(f"Opening SSE connection to {self.sse_endpoint}?session_id={self.session_id}")
            # SSE 연결 시작
            self.sse_client = SSEClient(f"{self.sse_endpoint}?session_id={self.session_id}")
            
            # 메시지 수신 (이 코드는 SSE 연결이 종료될 때까지 블록됨)
            for event in self.sse_client.events():
                if event.event == "message":
                    print(f"SSE message received: {event.data[:100]}...")
                elif event.event == "error":
                    print(f"SSE error: {event.data}")
                    break
        except Exception as e:
            print(f"SSE connection error: {e}")
    
    def connect(self):
        """서버에 SSE 연결 설정"""
        # SSE 연결을 위한 스레드 시작
        self.sse_thread = threading.Thread(target=self._sse_listener)
        self.sse_thread.daemon = True  # 메인 스레드가 종료되면 이 스레드도 종료
        self.sse_thread.start()
        
        # 연결이 설정될 시간을 잠시 기다림
        time.sleep(1)
        return True
    
    def send_request(self, method, params=None):
        """JSON-RPC 요청 전송"""
        if params is None:
            params = {}
        
        # 요청 페이로드 생성
        payload = {
            "jsonrpc": "2.0",
            "id": self._get_next_id(),
            "method": method,
            "params": params
        }
        
        # 헤더 설정
        headers = {"Content-Type": "application/json"}
        
        try:
            # 요청 전송 (세션 ID는 쿼리 매개변수로)
            url = f"{self.messages_endpoint}?session_id={self.session_id}"
            print(f"Sending request to: {url}")
            print(f"Payload: {json.dumps(payload)}")
            
            response = requests.post(url, json=payload, headers=headers)
            print(f"Response status: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                if "error" in result:
                    print(f"RPC error: {result['error']}")
                    return None
                return result.get("result")
            else:
                print(f"HTTP error: {response.status_code}, {response.text}")
                return None
        except Exception as e:
            print(f"Request error: {e}")
            return None
    
    def get_chrome_url(self):
        """크롬의 현재 URL 가져오기"""
        params = {
            "name": "chrome_evaluate",
            "arguments": {
                "expression": "window.location.href",
                "return_by_value": True
            }
        }
        return self.send_request("callTool", params)
    
    def disconnect(self):
        """SSE 연결 종료"""
        if self.sse_client:
            # SSEClient는 명시적 종료 메서드가 없으므로 스레드만 종료
            self.sse_thread = None
            print("SSE connection closed")

# 간단한 사용 예시
if __name__ == "__main__":
    session = ChromeMCPSession()
    
    print(f"세션 ID: {session.session_id}")
    
    # SSE 연결 설정
    print("SSE 연결 설정 중...")
    if session.connect():
        print("연결 성공!")
        
        # 현재 URL 가져오기
        print("\nCurrent Chrome URL 가져오는 중...")
        url = session.get_chrome_url()
        
        if url:
            print(f"현재 URL: {url}")
        else:
            print("URL을 가져오지 못했습니다.")
        
        # 연결 종료
        session.disconnect()
    else:
        print("연결 실패!") 