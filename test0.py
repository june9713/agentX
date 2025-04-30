import requests
import json
import time
import uuid

def main():
    # 고유 클라이언트 ID 생성
    client_id = str(uuid.uuid4())
    print(f"클라이언트 ID: {client_id}")
    
    # FastMCP 서버의 SSE 엔드포인트
    sse_url = 'http://127.0.0.1:8000/sse'
    
    try:
        # 1. SSE 연결 요청
        print(f"SSE 연결 시도: {sse_url}")
        # timeout을 길게 설정하지 않고 SSE 메시지만 가져오기
        sse_response = requests.get(
            sse_url, 
            headers={'Accept': 'text/event-stream'},
            stream=True,
            timeout=2  # 짧은 타임아웃으로 첫 이벤트만 가져옴
        )
        
        if sse_response.status_code != 200:
            print(f"SSE 연결 실패. 상태 코드: {sse_response.status_code}")
            return
            
        print("SSE 응답 수신 중...")
        
        # 메시지 URL 추출
        messages_url = None
        for i, line in enumerate(sse_response.iter_lines()):
            if line:
                decoded_line = line.decode('utf-8')
                print(f"라인 {i+1}: {decoded_line}")
                
                if "data: /messages/" in decoded_line:
                    messages_path = decoded_line.replace("data: ", "").strip()
                    messages_url = f"http://127.0.0.1:8000{messages_path}"
                    print(f"메시지 URL: {messages_url}")
                    break
            
            # 타임아웃으로 인해 연결이 끊어지기 전에 URL 가져오기 위한 안전장치
            if i > 5:  # 5줄까지만 확인
                break
        
        if not messages_url:
            print("메시지 URL을 찾을 수 없습니다.")
            return
        
        # 2. 새로운 요청으로 초기화 시도
        init_payload = {
            "jsonrpc": "2.0",
            "id": f"init-{client_id}",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {
                    "tools": True,
                    "resources": True,
                    "prompts": True,
                    "completion": True
                },
                "clientInfo": {
                    "name": "python-test-client",
                    "version": "1.0.0"
                }
            }
        }
        
        print("\n초기화 요청 전송 중...")
        init_response = requests.post(
            messages_url,
            headers={'Content-Type': 'application/json'},
            json=init_payload,
            timeout=5
        )
        
        print(f"초기화 응답 상태: {init_response.status_code}")
        
        # 3. 도구 호출
        # 초기화 후 잠시 대기
        time.sleep(1)
        
        tool_payload = {
            "jsonrpc": "2.0",
            "id": f"tool-{client_id}",
            "method": "tools/call",
            "params": {
                "name": "chrome_connect",
                "arguments": {
                    "port": 9222,
                    "host": "localhost"
                }
            }
        }
        
        print("\n도구 호출 요청 전송 중...")
        tool_response = requests.post(
            messages_url,
            headers={'Content-Type': 'application/json'},
            json=tool_payload,
            timeout=5
        )
        
        print(f"도구 호출 응답 상태: {tool_response.status_code}")
        
        # 콘텐츠 출력
        if tool_response.text:
            try:
                json_response = tool_response.json()
                print(f"JSON 응답: {json.dumps(json_response, indent=2)}")
            except:
                print(f"텍스트 응답: {tool_response.text}")
        
    except requests.exceptions.Timeout:
        print("타임아웃 발생 - 이는 SSE 연결에서는 정상적인 현상일 수 있습니다.")
    except Exception as e:
        print(f"오류 발생: {e}")

if __name__ == "__main__":
    main()