import requests
import json
import uuid
import time

def test_chrome_url():
    # 1. 기본 설정
    server_url = "http://localhost:8000"
    message_endpoint = f"{server_url}/messages/"
    sse_endpoint = f"{server_url}/sse"
    session_id = str(uuid.uuid4())
    
    print(f"Using session ID: {session_id}")
    
    # 2. 먼저 SSE 연결 시도 (비동기 연결이므로 timeout 발생 가능)
    try:
        print(f"Establishing SSE connection: {sse_endpoint}")
        sse_headers = {
            "Accept": "text/event-stream",
            "Cache-Control": "no-cache"
        }
        sse_response = requests.get(
            sse_endpoint, 
            headers=sse_headers, 
            params={"session_id": session_id},
            stream=True,
            timeout=1
        )
        print(f"SSE response status: {sse_response.status_code}")
    except requests.exceptions.Timeout:
        print("SSE connection timeout (expected for streaming connection)")
    except Exception as e:
        print(f"SSE connection error (non-critical): {e}")
    
    # 3. 잠시 대기 (서버가 세션을 등록할 시간 허용)
    time.sleep(1)
    
    # 4. JSON-RPC 메시지로 크롬 URL 요청
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "callTool",
        "params": {
            "name": "chrome_evaluate",
            "arguments": {
                "expression": "window.location.href",
                "return_by_value": True
            }
        },
        "session_id": session_id
    }
    
    headers = {"Content-Type": "application/json"}
    
    # 5. 요청 전송 (다양한 형식으로 시도)
    methods = [
        ("Standard", lambda: requests.post(message_endpoint, json=payload, headers=headers)),
        ("Query param", lambda: requests.post(f"{message_endpoint}?session_id={session_id}", json=payload, headers=headers)),
        ("Both", lambda: requests.post(
            f"{message_endpoint}?session_id={session_id}", 
            json=payload, 
            headers=headers
        ))
    ]
    
    for name, method in methods:
        print(f"\nTrying method: {name}")
        try:
            response = method()
            print(f"Status: {response.status_code}")
            print(f"Response: {response.text[:1000]}")  # 긴 응답은 잘라서 출력
            
            if response.status_code == 200:
                result = response.json()
                if "result" in result:
                    print(f"Success! URL: {result['result']}")
                    return result["result"]
        except Exception as e:
            print(f"Error: {str(e)}")
    
    return None

if __name__ == "__main__":
    print("Testing Chrome URL retrieval...")
    result = test_chrome_url()
    if result:
        print(f"\nFinal result: {result}")
    else:
        print("\nAll methods failed.") 