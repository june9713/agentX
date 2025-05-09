import requests
import json
import uuid

def get_chrome_url():
    """
    Get current Chrome URL using query parameter for session ID
    """
    # 기본 설정
    server_url = "http://localhost:8000"
    session_id = str(uuid.uuid4())
    message_endpoint = f"{server_url}/messages/"
    
    # JSON-RPC 요청 생성
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
        }
    }
    
    # 헤더 설정
    headers = {"Content-Type": "application/json"}
    
    # 요청 URL에 session_id 쿼리 매개변수 추가
    request_url = f"{message_endpoint}?session_id={session_id}"
    
    print(f"Session ID: {session_id}")
    print(f"Request URL: {request_url}")
    
    try:
        # 요청 전송
        response = requests.post(request_url, json=payload, headers=headers)
        
        # 응답 확인
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.text[:200]}")  # 응답의 첫 200자만 출력
        
        # 성공적인 응답 처리
        if response.status_code == 200:
            result = response.json()
            
            if "error" in result:
                print(f"Error: {result['error']}")
                return None
            
            if "result" in result:
                url = result["result"]
                print(f"Current Chrome URL: {url}")
                return url
            
        return None
    except Exception as e:
        print(f"Error: {str(e)}")
        return None

if __name__ == "__main__":
    print("Fetching current Chrome URL...")
    url = get_chrome_url() 