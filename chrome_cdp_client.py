"""
Chrome DevTools Protocol (CDP) 클라이언트 구현.
이 모듈은 WebSocket을 통해 크롬 DevTools 프로토콜과 통신하는 기능을 제공합니다.
"""

import asyncio
import json
import logging
import requests
import websockets
from typing import Dict, List, Any, Optional, Union, Callable
from concurrent.futures import Future

# 로깅 설정
logger = logging.getLogger(__name__)

class ChromeCDPClient:
    """크롬 DevTools 프로토콜 클라이언트"""
    
    def __init__(self, host: str = "localhost", port: int = 9222):
        """
        ChromeCDPClient 초기화
        
        Args:
            host: 크롬 디버그 호스트 (기본값: localhost)
            port: 크롬 디버그 포트 (기본값: 9222)
        """
        self.host = host
        self.port = port
        self.ws = None
        self.msg_id = 0
        self.callbacks = {}
        self.connected = False
        self.ws_url = None
        self.loop = None
        self.task = None
    
    def get_tabs(self) -> List[Dict[str, Any]]:
        """
        사용 가능한 크롬 탭 목록을 가져옵니다.
        
        Returns:
            탭 정보 목록
        """
        response = requests.get(f"http://{self.host}:{self.port}/json")
        if response.status_code != 200:
            raise ConnectionError(f"Failed to get tabs: {response.status_code} {response.text}")
        return response.json()
    
    def get_version(self) -> Dict[str, Any]:
        """
        크롬 브라우저 버전 정보를 가져옵니다.
        
        Returns:
            버전 정보
        """
        response = requests.get(f"http://{self.host}:{self.port}/json/version")
        if response.status_code != 200:
            raise ConnectionError(f"Failed to get version: {response.status_code} {response.text}")
        return response.json()
    
    async def connect(self, tab_id: Optional[str] = None) -> None:
        """
        WebSocket을 통해 특정 탭에 연결합니다.
        
        Args:
            tab_id: 연결할 탭 ID (None인 경우 첫 번째 사용 가능한 탭에 연결)
        """
        if self.connected:
            return
        
        try:
            # 사용 가능한 탭 목록 가져오기
            tabs = self.get_tabs()
            
            if not tabs:
                raise ConnectionError("No available tabs")
            
            # 특정 탭 선택 또는 첫 번째 탭 선택
            tab = None
            if tab_id:
                tab = next((t for t in tabs if t.get("id") == tab_id), None)
                if not tab:
                    raise ValueError(f"Tab with id '{tab_id}' not found")
            else:
                # 첫 번째 페이지 탭 선택
                for t in tabs:
                    if t.get("type") == "page":
                        tab = t
                        break
                
                if not tab:
                    tab = tabs[0]  # 페이지 탭이 없으면 첫 번째 탭
            
            # WebSocket URL 추출
            self.ws_url = tab.get("webSocketDebuggerUrl")
            if not self.ws_url:
                raise ConnectionError(f"WebSocket URL not found in tab: {tab}")
            
            # WebSocket 연결
            self.ws = await websockets.connect(self.ws_url)
            self.connected = True
            
            # 메시지 수신 루프 시작
            self.loop = asyncio.get_event_loop()
            self.task = self.loop.create_task(self._message_loop())
            
            logger.info(f"Connected to Chrome DevTools WebSocket: {self.ws_url}")
        
        except Exception as e:
            logger.error(f"Connection failed: {str(e)}")
            raise
    
    async def disconnect(self) -> None:
        """WebSocket 연결을 종료합니다."""
        if not self.connected:
            return
        
        try:
            if self.task and not self.task.done():
                self.task.cancel()
                try:
                    await self.task
                except asyncio.CancelledError:
                    pass
            
            if self.ws:
                await self.ws.close()
            
            self.connected = False
            self.ws = None
            logger.info("Disconnected from Chrome DevTools WebSocket")
        
        except Exception as e:
            logger.error(f"Disconnection error: {str(e)}")
            raise
    
    async def _message_loop(self) -> None:
        """
        메시지 수신 루프.
        비동기적으로 메시지를 수신하고 적절한 콜백에 전달합니다.
        """
        try:
            while self.connected:
                if self.ws is None:
                    break
                
                # 메시지 수신
                message = await self.ws.recv()
                data = json.loads(message)
                
                # 메시지 처리
                if "id" in data:
                    msg_id = data["id"]
                    if msg_id in self.callbacks:
                        future = self.callbacks.pop(msg_id)
                        if "error" in data:
                            future.set_exception(Exception(f"CDP Error: {data['error']}"))
                        else:
                            future.set_result(data.get("result", {}))
                elif "method" in data:
                    # 이벤트 처리 로직 (필요한 경우 구현)
                    logger.debug(f"Event received: {data['method']}")
        
        except asyncio.CancelledError:
            # 정상적인 취소
            pass
        except Exception as e:
            logger.error(f"Message loop error: {str(e)}")
            self.connected = False
    
    async def send_command(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """
        CDP 명령을 전송하고 결과를 기다립니다.
        
        Args:
            method: CDP 메소드 이름 (예: "Runtime.evaluate")
            params: 메소드 파라미터 (기본값: None)
        
        Returns:
            명령 실행 결과
        """
        if not self.connected or self.ws is None:
            raise ConnectionError("Not connected to Chrome DevTools")
        
        self.msg_id += 1
        message = {
            "id": self.msg_id,
            "method": method,
        }
        
        if params:
            message["params"] = params
        
        # Future 객체 생성
        future = self.loop.create_future()
        self.callbacks[self.msg_id] = future
        
        # 메시지 전송
        await self.ws.send(json.dumps(message))
        
        # 응답 대기
        try:
            return await asyncio.wait_for(future, timeout=10.0)
        except asyncio.TimeoutError:
            self.callbacks.pop(self.msg_id, None)
            raise TimeoutError(f"Command timed out: {method}")
    
    async def evaluate(self, expression: str, return_by_value: bool = True, await_promise: bool = True) -> Any:
        """
        JavaScript 코드를 실행하고 결과를 반환합니다.
        
        Args:
            expression: 실행할 JavaScript 코드
            return_by_value: JavaScript 객체를 값으로 반환할지 여부 (기본값: True)
            await_promise: Promise가 해결될 때까지 기다릴지 여부 (기본값: True)
        
        Returns:
            코드 실행 결과
        """
        params = {
            "expression": expression,
            "returnByValue": return_by_value,
            "awaitPromise": await_promise,
        }
        
        result = await self.send_command("Runtime.evaluate", params)
        return result
    
    async def get_document(self) -> Dict[str, Any]:
        """
        현재 페이지의 DOM 문서를 가져옵니다.
        
        Returns:
            DOM 문서 노드
        """
        result = await self.send_command("DOM.getDocument")
        return result.get("root", {})
    
    async def query_selector(self, selector: str, node_id: Optional[int] = None) -> int:
        """
        특정 노드 내에서 CSS 선택자로 요소를 찾습니다.
        
        Args:
            selector: CSS 선택자
            node_id: 검색할 노드 ID (None인 경우 document에서 검색)
        
        Returns:
            찾은 요소의 노드 ID
        """
        if node_id is None:
            # document 노드 가져오기
            doc = await self.get_document()
            node_id = doc.get("nodeId", 0)
        
        params = {
            "nodeId": node_id,
            "selector": selector,
        }
        
        result = await self.send_command("DOM.querySelector", params)
        return result.get("nodeId", 0)
    
    async def get_outer_html(self, node_id: int) -> str:
        """
        특정 노드의 HTML을 가져옵니다.
        
        Args:
            node_id: 노드 ID
        
        Returns:
            노드의 outerHTML
        """
        params = {
            "nodeId": node_id,
        }
        
        result = await self.send_command("DOM.getOuterHTML", params)
        return result.get("outerHTML", "")
    
    async def navigate(self, url: str) -> Dict[str, Any]:
        """
        브라우저를 특정 URL로 이동시킵니다.
        
        Args:
            url: 이동할 URL
        
        Returns:
            탐색 결과
        """
        params = {
            "url": url,
        }
        
        result = await self.send_command("Page.navigate", params)
        return result
    
    async def capture_screenshot(self, format: str = "png", quality: Optional[int] = None) -> str:
        """
        현재 페이지의 스크린샷을 캡처합니다.
        
        Args:
            format: 이미지 형식 ("png" 또는 "jpeg")
            quality: JPEG 품질 (0-100, JPEG 형식에만 적용)
        
        Returns:
            Base64로 인코딩된 이미지 데이터
        """
        params = {
            "format": format,
        }
        
        if format == "jpeg" and quality is not None:
            params["quality"] = quality
        
        result = await self.send_command("Page.captureScreenshot", params)
        return result.get("data", "")


# 비동기 컨텍스트 관리자
class ChromeCDPSession:
    """WebSocket 연결을 관리하는 비동기 컨텍스트 관리자"""
    
    def __init__(self, host: str = "localhost", port: int = 9222, tab_id: Optional[str] = None):
        self.client = ChromeCDPClient(host, port)
        self.tab_id = tab_id
    
    async def __aenter__(self) -> ChromeCDPClient:
        await self.client.connect(self.tab_id)
        return self.client
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.disconnect() 