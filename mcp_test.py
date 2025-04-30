import asyncio
import json
import base64
from datetime import datetime
import websockets

class ClaudeMCPClient:
    """Claude MCP 클라이언트 구현"""
    
    def __init__(self, server_url="ws://localhost:8765"):
        self.server_url = server_url
        self.connection = None
        self.request_id = 0
        
    async def connect(self):
        """MCP 서버에 연결"""
        try:
            self.connection = await websockets.connect(self.server_url)
            print(f"서버에 연결됨: {self.server_url}")
            return True
        except Exception as e:
            print(f"서버 연결 실패: {str(e)}")
            return False
            
    async def disconnect(self):
        """MCP 서버 연결 종료"""
        if self.connection:
            await self.connection.close()
            print("서버 연결 종료")
            
    async def send_message(self, target, command, params=None):
        """MCP 메시지 전송"""
        if not self.connection:
            print("서버에 연결되어 있지 않습니다.")
            return None
            
        self.request_id += 1
        request_id = f"req_{self.request_id}"
        
        message = {
            "type": "request",
            "target": target,
            "command": command,
            "params": params or {},
            "id": request_id
        }
        
        try:
            await self.connection.send(json.dumps(message))
            response = await self.connection.recv()
            return json.loads(response)
        except Exception as e:
            print(f"메시지 전송 중 오류: {str(e)}")
            return None
            
    async def test_server_info(self):
        """서버 정보 테스트"""
        print("\n=== 서버 정보 테스트 ===")
        
        # 사용 가능한 핸들러 목록 가져오기
        response = await self.send_message("server", "list_handlers")
        if response and response.get("success"):
            handlers = response.get("result", {}).get("handlers", {})
            print(f"사용 가능한 핸들러:")
            for name, desc in handlers.items():
                print(f"  - {name}: {desc}")
        else:
            error = response.get("error") if response else "응답 없음"
            print(f"핸들러 목록 가져오기 실패: {error}")
            
    async def test_chrome_handler(self):
        """Chrome 핸들러 테스트"""
        print("\n=== Chrome 핸들러 테스트 ===")
        
        # Chrome 연결
        print("Chrome에 연결 중...")
        response = await self.send_message("chrome", "connect", {
            "url": "http://localhost:9222"
        })
        
        if not response or not response.get("success"):
            error = response.get("error") if response else "응답 없음"
            print(f"Chrome 연결 실패: {error}")
            return
            
        print("Chrome 연결 성공!")
        
        # 웹페이지 이동
        print("\nClaude.ai로 이동 중...")
        response = await self.send_message("chrome", "navigate", {
            "url": "https://claude.ai"
        })
        
        if response and response.get("success"):
            print("페이지 이동 성공")
        else:
            error = response.get("error") if response else "응답 없음"
            print(f"페이지 이동 실패: {error}")
        
        # 페이지 제목 가져오기
        print("\n페이지 제목 가져오는 중...")
        response = await self.send_message("chrome", "eval", {
            "expression": "document.title",
            "return_by_value": True
        })
        
        if response and response.get("success"):
            result = response.get("result", {})
            value = None
            
            if "result" in result:
                if "result" in result["result"] and "value" in result["result"]["result"]:
                    value = result["result"]["result"]["value"]
                    
            if value:
                print(f"페이지 제목: {value}")
            else:
                print("페이지 제목을 가져올 수 없음")
        else:
            error = response.get("error") if response else "응답 없음"
            print(f"JavaScript 실행 실패: {error}")
        
        # 스크린샷 촬영
        print("\n스크린샷 촬영 중...")
        response = await self.send_message("chrome", "screenshot", {
            "format": "png",
            "quality": 100
        })
        
        if response and response.get("success"):
            result = response.get("result", {})
            data = None
            
            if "result" in result and "data" in result["result"]:
                data = result["result"]["data"]
                
            if data:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"claude_screenshot_{timestamp}.png"
                
                try:
                    with open(filename, "wb") as f:
                        f.write(base64.b64decode(data))
                    print(f"스크린샷 저장 완료: {filename}")
                except Exception as e:
                    print(f"스크린샷 저장 실패: {str(e)}")
            else:
                print("스크린샷 데이터를 받지 못함")
        else:
            error = response.get("error") if response else "응답 없음"
            print(f"스크린샷 촬영 실패: {error}")
            
        # Chrome 연결 종료
        print("\nChrome 연결 종료...")
        response = await self.send_message("chrome", "disconnect")
        if response and response.get("success"):
            print("Chrome 연결 종료 성공")
        else:
            error = response.get("error") if response else "응답 없음"
            print(f"Chrome 연결 종료 실패: {error}")

async def main():
    """테스트 실행"""
    print("Claude MCP 테스트 시작")
    
    client = ClaudeMCPClient()
    try:
        # 서버 연결
        if await client.connect():
            # 서버 정보 테스트
            await client.test_server_info()
            
            # Chrome 핸들러 테스트
            await client.test_chrome_handler()
        
    finally:
        # 연결 종료
        await client.disconnect()
    
    print("\nClaude MCP 테스트 완료")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n테스트가 사용자에 의해 중단되었습니다.") 