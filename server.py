# server.py
from mcp.server.fastmcp import FastMCP
import json
import subprocess
import sys
import os
import asyncio
import base64
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
import time
import traceback
import inspect
import logging
import requests
import asyncio
import concurrent.futures
import logging
import asyncio, concurrent.futures, logging
from x64dbg_automate import X64DbgClient
from x64dbg_automate.models import PageRightsConfiguration, StandardBreakpointType, HardwareBreakpointType, MemoryBreakpointType, MemPage
dbgClient = X64DbgClient("C:\\x64dbg\\release\\x64\\x64dbg.exe")

# 커스텀 모듈 임포트
from cmd_manager import get_cmd_manager

# 로깅 설정
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("mcp_error.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 크롬 CDP 클라이언트 임포트
from chrome_cdp_client import ChromeCDPClient, ChromeCDPSession

# Create an MCP server
mcp = FastMCP("Chrome Debug Console MCP")

# 전역 CDP 클라이언트 인스턴스
_cdp_client = None
_default_port = 9222
_default_host = "localhost"


def run_async(coro, *, timeout=60, request_id=None, function_name=None):
    """
    코루틴을 동기 방식으로 안전하게 실행하고 결과를 반환한다.
      • 현재 스레드에 이벤트 루프가 없으면  → asyncio.run()
      • 이미 루프가 돌고 있으면           → 워커 스레드에서 asyncio.run()
    """
    log = logging.getLogger(__name__)
    tag = f"[RUN_ASYNC][{request_id or '-'}:{function_name or '-'}] "

    # ── 메인 스레드에 이벤트 루프가 없는 경우 ───────────────────────
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        log.debug(tag + "메인 루프 없음 → asyncio.run 직접 호출")
        return asyncio.run(asyncio.wait_for(coro, timeout=timeout))

    # ── 메인 루프가 이미 돌고 있는 경우 (FastMCP 이벤트 루프) ───────
    log.debug(tag + "메인 루프 감지됨 → 워커 스레드로 오프로드")

    def _worker(inner_coro):
        return asyncio.run(inner_coro)

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        fut = pool.submit(_worker, coro)
        return fut.result(timeout)



# 에러 로깅 함수
def log_error(message):
    """
    에러 메시지와 함께 호출 스택, 파일명, 라인 번호, 함수명을 로깅합니다.
    
    Args:
        message: 로깅할 에러 메시지
    """
    # 현재 스택 프레임 정보 가져오기
    stack = inspect.stack()
    # 호출자 정보 가져오기 (0은 현재 함수, 1은 호출자)
    if len(stack) > 1:
        caller = stack[1]
        file_name = os.path.basename(caller.filename)
        line_number = caller.lineno
        function_name = caller.function
        
        error_info = f"{message} - 위치: {file_name}:{line_number}, 함수: {function_name}"
        logger.error(error_info)
        
        # 전체 스택 트레이스 로깅
        stack_trace = ''.join(traceback.format_stack()[:-1])
        logger.debug(f"스택 트레이스:\n{stack_trace}")
    else:
        logger.error(message)


# 크롬 CDP 클라이언트 초기화
def get_cdp_client():
    global _cdp_client
    try:
        if _cdp_client is None or not _cdp_client.connected:
            _cdp_client = ChromeCDPClient(_default_host, _default_port)
        return _cdp_client
    except Exception as e:
        log_error(f"Error initializing CDP client: {str(e)}")
        return None


# 에러 처리 헬퍼 함수
def handle_cdp_error(func_name):
    def decorator(f):
        async def wrapper(*args, **kwargs):
            try:
                return await f(*args, **kwargs)
            except Exception as e:
                error_msg = f"Error in {func_name}: {str(e)}"
                log_error(error_msg)
                return {"error": error_msg}
        return wrapper
    return decorator


# Add an addition tool
@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two numbers"""
    return a + b


# Add a dynamic greeting resource
@mcp.resource("greeting://{name}")
def get_greeting(name: str) -> str:
    """Get a personalized greeting"""
    return f"Hello, {name}!"


# 요청 ID 추적을 위한 유틸리티 함수 (미들웨어 대신 사용)
_current_request_id = None

def get_current_request_id():
    """현재 요청 ID를 반환합니다. 없으면 None을 반환합니다."""
    global _current_request_id
    return _current_request_id


# Chrome DevTools Protocol 제어 기능
@mcp.tool()
def chrome_evaluate(expression: str) -> str:
    """
    크롬 디버그 콘솔에서 JavaScript 코드를 실행합니다.

    Args:
        expression: 실행할 JavaScript 코드

    Returns:
        실행 결과를 JSON 문자열로 반환하거나, 오류 메시지를 반환합니다.
    """
    request_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    request_id = f"eval_{request_time}"
    start_time = time.time()
    logger.info(f"[CHROME_EVALUATE][{request_id}] Called at {request_time}")

    try:
        async def _evaluate():
            # 1) 연결 가능 여부 확인
            version_url = f"http://{_default_host}:{_default_port}/json/version"
            try:
                resp = requests.get(version_url, timeout=5)
                if resp.status_code != 200:
                    return f"Connection failed: status {resp.status_code}"
            except requests.RequestException as e:
                return f"Connection failed: {e}"

            # 2) 단일 CDP 세션에서 평가
            async with ChromeCDPSession(_default_host, _default_port) as client:
                try:
                    # return_by_value 대신 핸들만 받아옴으로 직렬화 오류 방지
                    result_obj = await client.evaluate(expression, return_by_value=False)
                    return json.dumps(result_obj, indent=2, ensure_ascii=False)
                except Exception as e:
                    return f"CDP Error: {e}"

        # 비동기 작업 실행 (15초 제한)
        result = run_async(_evaluate(), timeout=15, request_id=request_id, function_name="chrome_evaluate")
        return result

    except Exception as e:
        error_msg = f"Error executing JavaScript: {e}"
        logger.error(f"[CHROME_EVALUATE][{request_id}] {error_msg}")
        return error_msg


@mcp.tool()
def chrome_get_dom(selector: str) -> str:
    """
    크롬 브라우저에서 특정 DOM 요소를 선택하고 정보를 반환합니다.
    
    Args:
        selector: CSS 선택자
    
    Returns:
        선택된 요소의 HTML을 문자열로 반환합니다.
    """
    # 요청 ID 로깅
    request_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    request_id = f"dom_{request_time}"
    start_time = time.time()
    
    logger.info(f"[CHROME_GET_DOM][{request_id}] Function called at {request_time}, selector: {selector}")
    
    try:
        async def _get_dom():
            dom_start_time = time.time()
            logger.debug(f"[CHROME_GET_DOM][{request_id}] Starting DOM element search at {datetime.now().isoformat()}")
            logger.debug(f"[CHROME_GET_DOM][{request_id}] Using selector: {selector}")
            
            try:
                # 연결 확인
                try:
                    import requests
                    version_url = f"http://{_default_host}:{_default_port}/json/version"
                    logger.debug(f"[CHROME_GET_DOM][{request_id}] Checking Chrome availability: {version_url}")
                    
                    response = requests.get(version_url, timeout=5)
                    
                    if response.status_code == 200:
                        logger.debug(f"[CHROME_GET_DOM][{request_id}] Chrome is available: Status {response.status_code}")
                    else:
                        error_msg = f"Connection failed: Chrome debug port {_default_port} returned status {response.status_code}"
                        logger.error(f"[CHROME_GET_DOM][{request_id}] {error_msg}")
                        return error_msg
                except requests.exceptions.RequestException as e:
                    error_msg = f"Connection failed: Chrome debug port {_default_port} is not accessible on {_default_host}. Error: {str(e)}"
                    logger.error(f"[CHROME_GET_DOM][{request_id}] {error_msg}")
                    return error_msg
                
                # CDP 세션 생성 및 DOM 요소 가져오기
                logger.debug(f"[CHROME_GET_DOM][{request_id}] Creating CDP session for {_default_host}:{_default_port}")
                try:
                    async with ChromeCDPSession(_default_host, _default_port) as client:
                        logger.debug(f"[CHROME_GET_DOM][{request_id}] CDP session established")
                        
                        # DOM 노드 찾기
                        logger.debug(f"[CHROME_GET_DOM][{request_id}] Querying for selector: {selector}")
                        node_id = await client.query_selector(selector)
                        
                        if node_id == 0:
                            logger.warning(f"[CHROME_GET_DOM][{request_id}] Element not found with selector: {selector}")
                            return f"Element not found: {selector}"
                        
                        logger.debug(f"[CHROME_GET_DOM][{request_id}] Element found, node_id: {node_id}")
              
                        # 요소의 HTML 가져오기
                        logger.debug(f"[CHROME_GET_DOM][{request_id}] Getting outerHTML for node_id: {node_id}")
                        html = await client.get_outer_html(node_id)
                        
                        html_length = len(html)
                        html_preview = html[:100] + "..." if html_length > 100 else html
                        logger.debug(f"[CHROME_GET_DOM][{request_id}] Got HTML of length {html_length}, preview: {html_preview}")
                        
                        total_duration = time.time() - dom_start_time
                        logger.info(f"[CHROME_GET_DOM][{request_id}] DOM operation completed in {total_duration:.2f}s")
                        
                        return html
                except Exception as e:
                    error_msg = f"Error in CDP session: {str(e)}"
                    logger.error(f"[CHROME_GET_DOM][{request_id}] {error_msg}")
                    logger.debug(f"[CHROME_GET_DOM][{request_id}] Exception details: {traceback.format_exc()}")
                    return error_msg
            except Exception as e:
                total_duration = time.time() - dom_start_time
                error_msg = f"Error getting DOM element after {total_duration:.2f}s: {str(e)}"
                logger.error(f"[CHROME_GET_DOM][{request_id}] {error_msg}")
                logger.debug(f"[CHROME_GET_DOM][{request_id}] Exception details: {traceback.format_exc()}")
                return error_msg
        
        logger.debug(f"[CHROME_GET_DOM][{request_id}] About to run async function")
        result = run_async(_get_dom(), timeout=10, request_id=request_id, function_name="chrome_get_dom")
        
        if "Element not found" in result:
            logger.warning(f"[CHROME_GET_DOM][{request_id}] DOM element not found")
        elif "Error" in result:
            logger.warning(f"[CHROME_GET_DOM][{request_id}] Operation failed: {result[:100]}...")
        else:
            logger.info(f"[CHROME_GET_DOM][{request_id}] Successfully returned HTML for selector")
        
        end_time = time.time()
        total_time = end_time - start_time
        logger.debug(f"[CHROME_GET_DOM][{request_id}] Total function execution time: {total_time:.2f}s")
        
        return result
    except Exception as e:
        end_time = time.time()
        total_time = end_time - start_time
        error_msg = f"Error getting DOM element after {total_time:.2f}s: {str(e)}"
        logger.error(f"[CHROME_GET_DOM][{request_id}] Error in outer function: {str(e)}")
        logger.debug(f"[CHROME_GET_DOM][{request_id}] Stack trace: {traceback.format_exc()}")
        return error_msg


@mcp.tool()
def chrome_navigate(url: str) -> str:
    """
    크롬 브라우저를 특정 URL로 이동시킵니다.
    
    Args:
        url: 이동할 URL
    
    Returns:
        이동 결과를 문자열로 반환합니다.
    """
    # 요청 ID 로깅
    request_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    request_id = f"nav_{request_time}"
    start_time = time.time()
    
    logger.info(f"[CHROME_NAVIGATE][{request_id}] Function called at {request_time}, URL: {url}")
    
    try:
        async def _navigate():
            nav_start_time = time.time()
            logger.debug(f"[CHROME_NAVIGATE][{request_id}] Starting navigation at {datetime.now().isoformat()}")
            logger.debug(f"[CHROME_NAVIGATE][{request_id}] Destination URL: {url}")
            
            try:
                # 연결 확인
                try:
                    import requests
                    version_url = f"http://{_default_host}:{_default_port}/json/version"
                    logger.debug(f"[CHROME_NAVIGATE][{request_id}] Checking Chrome availability: {version_url}")
                    
                    response = requests.get(version_url, timeout=5)
                    
                    if response.status_code == 200:
                        logger.debug(f"[CHROME_NAVIGATE][{request_id}] Chrome is available: Status {response.status_code}")
                    else:
                        error_msg = f"Connection failed: Chrome debug port {_default_port} returned status {response.status_code}"
                        logger.error(f"[CHROME_NAVIGATE][{request_id}] {error_msg}")
                        return error_msg
                except requests.exceptions.RequestException as e:
                    error_msg = f"Connection failed: Chrome debug port {_default_port} is not accessible on {_default_host}. Error: {str(e)}"
                    logger.error(f"[CHROME_NAVIGATE][{request_id}] {error_msg}")
                    return error_msg
                
                # 탐색 수행
                logger.debug(f"[CHROME_NAVIGATE][{request_id}] Creating CDP session for {_default_host}:{_default_port}")
                try:
                    async with ChromeCDPSession(_default_host, _default_port) as client:
                        logger.debug(f"[CHROME_NAVIGATE][{request_id}] CDP session established")
                        
                        logger.debug(f"[CHROME_NAVIGATE][{request_id}] Navigating to URL: {url}")
                        result = await client.navigate(url)
                        
                        logger.debug(f"[CHROME_NAVIGATE][{request_id}] Navigation result: {json.dumps(result)}")
                        
                        total_duration = time.time() - nav_start_time
                        logger.info(f"[CHROME_NAVIGATE][{request_id}] Navigation completed in {total_duration:.2f}s")
                        
                        return f"Navigated to: {url}\nResult: {json.dumps(result, indent=2)}"
                except Exception as e:
                    error_msg = f"Error in CDP session: {str(e)}"
                    logger.error(f"[CHROME_NAVIGATE][{request_id}] {error_msg}")
                    logger.debug(f"[CHROME_NAVIGATE][{request_id}] Exception details: {traceback.format_exc()}")
                    return error_msg
            except Exception as e:
                total_duration = time.time() - nav_start_time
                error_msg = f"Error during navigation after {total_duration:.2f}s: {str(e)}"
                logger.error(f"[CHROME_NAVIGATE][{request_id}] {error_msg}")
                logger.debug(f"[CHROME_NAVIGATE][{request_id}] Exception details: {traceback.format_exc()}")
                return error_msg
        
        logger.debug(f"[CHROME_NAVIGATE][{request_id}] About to run async function")
        result = run_async(_navigate(), timeout=15, request_id=request_id, function_name="chrome_navigate")
        
        if "Navigated to:" in result:
            logger.info(f"[CHROME_NAVIGATE][{request_id}] Successfully navigated to URL")
        else:
            logger.warning(f"[CHROME_NAVIGATE][{request_id}] Navigation failed: {result[:100]}...")
        
        end_time = time.time()
        total_time = end_time - start_time
        logger.debug(f"[CHROME_NAVIGATE][{request_id}] Total function execution time: {total_time:.2f}s")
        
        return result
    except Exception as e:
        end_time = time.time()
        total_time = end_time - start_time
        error_msg = f"Error navigating to URL after {total_time:.2f}s: {str(e)}"
        logger.error(f"[CHROME_NAVIGATE][{request_id}] Error in outer function: {str(e)}")
        logger.debug(f"[CHROME_NAVIGATE][{request_id}] Stack trace: {traceback.format_exc()}")
        return error_msg


@mcp.tool()
def chrome_screenshot(save_path: Optional[str] = None) -> str:
    """
    현재 크롬 브라우저 화면의 스크린샷을 캡처합니다.
    
    Args:
        save_path: 스크린샷을 저장할 경로 (기본값: 현재 디렉토리)
    
    Returns:
        스크린샷 경로를 문자열로 반환합니다.
    """
    # 요청 ID 로깅
    request_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    request_id = f"screenshot_{request_time}"
    start_time = time.time()
    
    logger.info(f"[CHROME_SCREENSHOT][{request_id}] Function called at {request_time}, save_path: {save_path or 'default'}")
    
    try:
        async def _screenshot():
            ss_start_time = time.time()
            logger.debug(f"[CHROME_SCREENSHOT][{request_id}] Starting screenshot capture at {datetime.now().isoformat()}")
            
            try:
                # 연결 확인
                try:
                    import requests
                    version_url = f"http://{_default_host}:{_default_port}/json/version"
                    logger.debug(f"[CHROME_SCREENSHOT][{request_id}] Checking Chrome availability: {version_url}")
                    
                    response = requests.get(version_url, timeout=5)
                    
                    if response.status_code == 200:
                        logger.debug(f"[CHROME_SCREENSHOT][{request_id}] Chrome is available: Status {response.status_code}")
                    else:
                        error_msg = f"Connection failed: Chrome debug port {_default_port} returned status {response.status_code}"
                        logger.error(f"[CHROME_SCREENSHOT][{request_id}] {error_msg}")
                        return error_msg
                except requests.exceptions.RequestException as e:
                    error_msg = f"Connection failed: Chrome debug port {_default_port} is not accessible on {_default_host}. Error: {str(e)}"
                    logger.error(f"[CHROME_SCREENSHOT][{request_id}] {error_msg}")
                    return error_msg
                
                # 스크린샷 캡처 실행
                logger.debug(f"[CHROME_SCREENSHOT][{request_id}] Creating CDP session for {_default_host}:{_default_port}")
                try:
                    async with ChromeCDPSession(_default_host, _default_port) as client:
                        logger.debug(f"[CHROME_SCREENSHOT][{request_id}] CDP session established")
                        
                        # 스크린샷 캡처
                        logger.debug(f"[CHROME_SCREENSHOT][{request_id}] Capturing screenshot")
                        base64_data = await client.capture_screenshot()
                        logger.debug(f"[CHROME_SCREENSHOT][{request_id}] Screenshot captured, base64 data length: {len(base64_data) if base64_data else 'empty'}")
                        
                        # 저장 경로 지정
                        if save_path is None:
                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                            filename = f"screenshot_{timestamp}.png"
                            save_location = os.path.join(os.getcwd(), filename)
                            logger.debug(f"[CHROME_SCREENSHOT][{request_id}] Using default save location: {save_location}")
                        else:
                            save_location = save_path
                            logger.debug(f"[CHROME_SCREENSHOT][{request_id}] Using provided save location: {save_location}")
                        
                        # Base64 디코딩 및 파일 저장
                        try:
                            logger.debug(f"[CHROME_SCREENSHOT][{request_id}] Decoding base64 data")
                            img_data = base64.b64decode(base64_data)
                            logger.debug(f"[CHROME_SCREENSHOT][{request_id}] Writing {len(img_data)} bytes to file")
                            
                            with open(save_location, "wb") as f:
                                f.write(img_data)
                            
                            logger.debug(f"[CHROME_SCREENSHOT][{request_id}] File saved successfully")
                            
                            total_duration = time.time() - ss_start_time
                            logger.info(f"[CHROME_SCREENSHOT][{request_id}] Screenshot captured and saved in {total_duration:.2f}s")
                            
                            return f"Screenshot saved to: {save_location}"
                        except Exception as e:
                            error_msg = f"Error saving screenshot file: {str(e)}"
                            logger.error(f"[CHROME_SCREENSHOT][{request_id}] {error_msg}")
                            logger.debug(f"[CHROME_SCREENSHOT][{request_id}] Exception details: {traceback.format_exc()}")
                            return error_msg
                except Exception as e:
                    error_msg = f"Error in CDP session: {str(e)}"
                    logger.error(f"[CHROME_SCREENSHOT][{request_id}] {error_msg}")
                    logger.debug(f"[CHROME_SCREENSHOT][{request_id}] Exception details: {traceback.format_exc()}")
                    return error_msg
            except Exception as e:
                total_duration = time.time() - ss_start_time
                error_msg = f"Error capturing screenshot after {total_duration:.2f}s: {str(e)}"
                logger.error(f"[CHROME_SCREENSHOT][{request_id}] {error_msg}")
                logger.debug(f"[CHROME_SCREENSHOT][{request_id}] Exception details: {traceback.format_exc()}")
                return error_msg
        
        logger.debug(f"[CHROME_SCREENSHOT][{request_id}] About to run async function")
        result = run_async(_screenshot(), timeout=15, request_id=request_id, function_name="chrome_screenshot")
        
        if "Screenshot saved to:" in result:
            logger.info(f"[CHROME_SCREENSHOT][{request_id}] Screenshot operation succeeded")
        else:
            logger.warning(f"[CHROME_SCREENSHOT][{request_id}] Screenshot operation failed: {result[:100]}...")
        
        end_time = time.time()
        total_time = end_time - start_time
        logger.debug(f"[CHROME_SCREENSHOT][{request_id}] Total function execution time: {total_time:.2f}s")
        
        return result
    except Exception as e:
        end_time = time.time()
        total_time = end_time - start_time
        error_msg = f"Error capturing screenshot after {total_time:.2f}s: {str(e)}"
        logger.error(f"[CHROME_SCREENSHOT][{request_id}] Error in outer function: {str(e)}")
        logger.debug(f"[CHROME_SCREENSHOT][{request_id}] Stack trace: {traceback.format_exc()}")
        return error_msg


# 크롬 DevTools 연결 관리 툴
@mcp.tool()
def chrome_connect(port: int = 9222, host: str = "localhost") -> str:
    """
    특정 포트에서 실행 중인 크롬 디버그 인스턴스에 연결합니다.
    
    Args:
        port: 크롬 디버그 포트 (기본값: 9222)
        host: 크롬 디버그 호스트 (기본값: localhost)
    
    Returns:
        연결 결과를 문자열로 반환합니다.
    """
    global _default_port, _default_host
    
    # 요청 ID 로깅
    request_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    request_id = f"connect_request_{request_time}"
    
    try:
        start_time = time.time()
        logger.debug(f"[CHROME_CONNECT][{request_id}] Function called with parameters: port={port}, host={host}")
        
        # 이전 설정 기록
        logger.debug(f"[CHROME_CONNECT][{request_id}] Previous connection settings: host={_default_host}, port={_default_port}")
        
        _default_port = port
        _default_host = host
        
        logger.debug(f"[CHROME_CONNECT][{request_id}] Updated global connection settings: host={_default_host}, port={_default_port}")
        logger.info(f"[CHROME_CONNECT][{request_id}] Attempting to connect to Chrome on {host}:{port}")
        
        async def _connect():
            connect_start_time = time.time()
            logger.debug(f"[CHROME_CONNECT][{request_id}] Starting async connection procedure at {datetime.now().isoformat()}")
            
            try:
                # 소켓 대신 HTTP 요청으로 연결 확인
                logger.debug(f"[CHROME_CONNECT][{request_id}] Checking Chrome availability with HTTP request to http://{host}:{port}/json/version")
                
                try:
                    # Chrome DevTools Protocol는 /json/version 엔드포인트를 제공함
                    version_url = f"http://{host}:{port}/json/version"
                    logger.debug(f"[CHROME_CONNECT][{request_id}] Sending HTTP request to {version_url}")
                    
                    # 짧은 타임아웃 설정으로 빠른 응답 확인
                    response = requests.get(version_url, timeout=5)
                    
                    if response.status_code == 200:
                        logger.debug(f"[CHROME_CONNECT][{request_id}] HTTP request successful: Status code {response.status_code}")
                        logger.debug(f"[CHROME_CONNECT][{request_id}] Response: {response.text[:200]}...")
                    else:
                        error_msg = f"Connection failed: Chrome debug port {port} returned unexpected status code {response.status_code}"
                        logger.debug(f"[CHROME_CONNECT][{request_id}] HTTP request failed: Status code {response.status_code}")
                        log_error(error_msg)
                        return error_msg
                        
                except requests.exceptions.RequestException as e:
                    error_msg = f"Connection failed: Cannot connect to Chrome debug port {port} on {host}. Make sure Chrome is running with --remote-debugging-port={port}. Error: {str(e)}"
                    logger.debug(f"[CHROME_CONNECT][{request_id}] HTTP request exception: {str(e)}")
                    log_error(error_msg)
                    return error_msg
                
                logger.debug(f"[CHROME_CONNECT][{request_id}] Chrome debug port is accessible")
                
                # 연결 시도 (최대 2번으로 감소)
                max_attempts = 2
                last_error = None
                
                logger.debug(f"[CHROME_CONNECT][{request_id}] Will try CDP connection up to {max_attempts} times")
                
                for attempt in range(1, max_attempts + 1):
                    attempt_start_time = time.time()
                    logger.debug(f"[CHROME_CONNECT][{request_id}] Starting connection attempt {attempt}/{max_attempts}")
                    
                    try:
                        # CDP 클라이언트 생성
                        logger.debug(f"[CHROME_CONNECT][{request_id}] Creating CDP client for {host}:{port}")
                        client = ChromeCDPClient(host, port)
                        logger.debug(f"[CHROME_CONNECT][{request_id}] CDP client created successfully")
                        
                        # 버전 정보 확인 (CDP 세션이 아닌 클라이언트에서 직접 호출)
                        logger.debug(f"[CHROME_CONNECT][{request_id}] Requesting Chrome version information")
                        version_info = client.get_version()
                        logger.debug(f"[CHROME_CONNECT][{request_id}] Version info retrieved: {json.dumps(version_info)}")
                        
                        # 탭 목록 가져오기
                        logger.debug(f"[CHROME_CONNECT][{request_id}] Requesting Chrome tabs list")
                        tabs = client.get_tabs()
                        logger.debug(f"[CHROME_CONNECT][{request_id}] Retrieved {len(tabs)} tabs")
                        
                        # 탭 세부 정보 로깅 (타이틀, URL)
                        for i, tab in enumerate(tabs):
                            if i < 5:  # 처음 5개 탭만 로깅하여 로그 크기 제한
                                logger.debug(f"[CHROME_CONNECT][{request_id}] Tab {i+1}: {tab.get('title', 'No title')} - {tab.get('url', 'No URL')}")
                        
                        # 결과 포맷팅
                        result = {
                            "connected": True,
                            "host": host,
                            "port": port,
                            "version": version_info,
                            "tabs": tabs
                        }
                        
                        attempt_duration = time.time() - attempt_start_time
                        logger.debug(f"[CHROME_CONNECT][{request_id}] Connection attempt {attempt} succeeded in {attempt_duration:.2f} seconds")
                        
                        total_duration = time.time() - connect_start_time
                        logger.info(f"[CHROME_CONNECT][{request_id}] Successfully connected to Chrome on {host}:{port} in {total_duration:.2f} seconds")
                        
                        return json.dumps(result, indent=2, ensure_ascii=False)
                    except Exception as e:
                        attempt_duration = time.time() - attempt_start_time
                        last_error = str(e)
                        logger.warning(f"[CHROME_CONNECT][{request_id}] Connection attempt {attempt}/{max_attempts} failed after {attempt_duration:.2f} seconds: {last_error}")
                        logger.debug(f"[CHROME_CONNECT][{request_id}] Exception details: {traceback.format_exc()}")
                        
                        if attempt < max_attempts:
                            logger.debug(f"[CHROME_CONNECT][{request_id}] Waiting 1 second before retry {attempt+1}")
                            await asyncio.sleep(1)  # 재시도 전 1초 대기
                
                total_duration = time.time() - connect_start_time
                error_msg = f"Failed to connect to Chrome after {max_attempts} attempts in {total_duration:.2f} seconds. Last error: {last_error}"
                log_error(error_msg)
                logger.debug(f"[CHROME_CONNECT][{request_id}] All {max_attempts} connection attempts failed")
                return error_msg
            except Exception as e:
                total_duration = time.time() - connect_start_time
                error_msg = f"CDP connection error after {total_duration:.2f} seconds: {str(e)}"
                logger.debug(f"[CHROME_CONNECT][{request_id}] Unexpected exception in _connect function: {traceback.format_exc()}")
                log_error(error_msg)
                return f"Error connecting to Chrome: {str(e)}\nMake sure Chrome is running with --remote-debugging-port={port}"
        
        logger.debug(f"[CHROME_CONNECT][{request_id}] Running async _connect function with timeout of 20 seconds")
        # 타임아웃 감소 (30초 -> 20초)
        result = run_async(_connect(), timeout=20, request_id=request_id, function_name="chrome_connect")
        
        end_time = time.time()
        total_function_time = end_time - start_time
        logger.debug(f"[CHROME_CONNECT][{request_id}] Function completed in {total_function_time:.2f} seconds")
        
        # 성공/실패 여부 로깅
        if "connected\": true" in result:
            logger.info(f"[CHROME_CONNECT][{request_id}] Connection successful to {host}:{port}")
        else:
            logger.warning(f"[CHROME_CONNECT][{request_id}] Connection unsuccessful to {host}:{port}")
        
        return result
    except Exception as e:
        end_time = time.time()
        total_function_time = end_time - start_time
        error_msg = f"Error in chrome_connect after {total_function_time:.2f} seconds: {str(e)}"
        logger.debug(f"[CHROME_CONNECT][{request_id}] Exception in outer function: {traceback.format_exc()}")
        log_error(error_msg)
        return error_msg


@mcp.tool()
def chrome_list_tabs() -> str:
    """
    크롬 브라우저의 열린 탭 목록을 가져옵니다.
    
    Returns:
        탭 목록을 문자열로 반환합니다.
    """
    # 요청 ID 로깅
    request_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    request_id = f"tabs_{request_time}"
    start_time = time.time()
    
    logger.info(f"[CHROME_LIST_TABS][{request_id}] Function called at {request_time}")
    
    try:
        async def _list_tabs():
            tabs_start_time = time.time()
            logger.debug(f"[CHROME_LIST_TABS][{request_id}] Starting async tabs listing at {datetime.now().isoformat()}")
            
            try:
                logger.debug(f"[CHROME_LIST_TABS][{request_id}] Attempting to create CDP client for {_default_host}:{_default_port}")
                
                # 먼저 HTTP 요청으로 연결 확인
                try:
                    import requests
                    version_url = f"http://{_default_host}:{_default_port}/json/version"
                    logger.debug(f"[CHROME_LIST_TABS][{request_id}] Sending HTTP request to {version_url}")
                    
                    # 짧은 타임아웃 설정으로 빠른 응답 확인
                    response = requests.get(version_url, timeout=5)
                    
                    if response.status_code == 200:
                        logger.debug(f"[CHROME_LIST_TABS][{request_id}] Chrome DevTools is available: Status {response.status_code}")
                    else:
                        error_msg = f"Chrome DevTools returned unexpected status code {response.status_code}"
                        logger.error(f"[CHROME_LIST_TABS][{request_id}] {error_msg}")
                        return error_msg
                        
                except requests.exceptions.RequestException as e:
                    error_msg = f"Cannot connect to Chrome DevTools at {_default_host}:{_default_port}. Error: {str(e)}"
                    logger.error(f"[CHROME_LIST_TABS][{request_id}] HTTP request failed: {str(e)}")
                    return error_msg
                
                # CDP 클라이언트 생성
                client = None
                try:
                    client = ChromeCDPClient(_default_host, _default_port)
                    logger.debug(f"[CHROME_LIST_TABS][{request_id}] CDP client created successfully")
                except Exception as e:
                    error_msg = f"Failed to create CDP client: {str(e)}"
                    logger.error(f"[CHROME_LIST_TABS][{request_id}] {error_msg}")
                    return error_msg
                
                # 탭 목록 가져오기
                try:
                    logger.debug(f"[CHROME_LIST_TABS][{request_id}] Requesting tabs from CDP client")
                    tabs = client.get_tabs()
                    logger.debug(f"[CHROME_LIST_TABS][{request_id}] Successfully retrieved {len(tabs)} tabs")
                except Exception as e:
                    error_msg = f"Failed to get tabs: {str(e)}"
                    logger.error(f"[CHROME_LIST_TABS][{request_id}] {error_msg}")
                    return error_msg
                
                # 각 탭에 대한 정보 로깅
                for i, tab in enumerate(tabs):
                    logger.debug(f"[CHROME_LIST_TABS][{request_id}] Tab {i+1}/{len(tabs)}: {tab.get('title', 'No title')}")
                
                # 간결한 탭 정보만 추출
                simplified_tabs = []
                for tab in tabs:
                    simplified_tabs.append({
                        "id": tab.get("id"),
                        "title": tab.get("title"),
                        "url": tab.get("url"),
                        "type": tab.get("type")
                    })
                
                total_time = time.time() - tabs_start_time
                logger.info(f"[CHROME_LIST_TABS][{request_id}] Successfully listed {len(tabs)} tabs in {total_time:.2f}s")
                return json.dumps(simplified_tabs, indent=2, ensure_ascii=False)
            except Exception as e:
                total_time = time.time() - tabs_start_time
                error_msg = f"Error listing tabs after {total_time:.2f}s: {str(e)}"
                logger.error(f"[CHROME_LIST_TABS][{request_id}] Unexpected error: {str(e)}")
                logger.debug(f"[CHROME_LIST_TABS][{request_id}] Stack trace: {traceback.format_exc()}")
                return error_msg
        
        logger.debug(f"[CHROME_LIST_TABS][{request_id}] About to run async function with request tag: {request_id}")
        # 짧은 타임아웃으로 수정 (15초)
        result = run_async(_list_tabs(), timeout=15, request_id=request_id, function_name="chrome_list_tabs")
        
        # 응답 타입 분석
        if result.startswith("[") and result.endswith("]"):
            logger.info(f"[CHROME_LIST_TABS][{request_id}] Successfully returned tabs list")
        else:
            logger.warning(f"[CHROME_LIST_TABS][{request_id}] Failed to list tabs: {result[:100]}...")
        
        end_time = time.time()
        total_time = end_time - start_time
        logger.debug(f"[CHROME_LIST_TABS][{request_id}] Total function execution time: {total_time:.2f}s")
        
        return result
    except Exception as e:
        end_time = time.time()
        total_time = end_time - start_time
        error_msg = f"Error listing Chrome tabs after {total_time:.2f}s: {str(e)}"
        logger.error(f"[CHROME_LIST_TABS][{request_id}] Error in outer function: {str(e)}")
        logger.debug(f"[CHROME_LIST_TABS][{request_id}] Stack trace: {traceback.format_exc()}")
        return error_msg


@mcp.tool()
def chrome_launch() -> str:
    """
    크롬 브라우저를 디버깅 모드로 실행합니다.
    
    Returns:
        실행 결과를 문자열로 반환합니다.
    """
    # 요청 ID 로깅
    request_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    request_id = f"launch_{request_time}"
    start_time = time.time()
    
    logger.info(f"[CHROME_LAUNCH][{request_id}] Function called at {request_time}")
    
    try:
        chrome_path = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        cmd = [chrome_path, f"--remote-debugging-port={_default_port}"]
        
        logger.info(f"[CHROME_LAUNCH][{request_id}] Attempting to launch Chrome with debug port {_default_port}")
        logger.debug(f"[CHROME_LAUNCH][{request_id}] Chrome executable path: {chrome_path}")
        logger.debug(f"[CHROME_LAUNCH][{request_id}] Launch command: {' '.join(cmd)}")
        
        # 이미 연결이 되어있는지 확인
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        logger.debug(f"[CHROME_LAUNCH][{request_id}] Checking if port {_default_port} is already in use")
        
        result = sock.connect_ex((_default_host, _default_port))
        sock.close()
        
        if result == 0:
            logger.info(f"[CHROME_LAUNCH][{request_id}] Chrome debug port {_default_port} is already open on {_default_host}")
            return f"Chrome debug port {_default_port} is already open on {_default_host}."
        else:
            logger.debug(f"[CHROME_LAUNCH][{request_id}] Port {_default_port} is available, proceeding with launch")
        
        # 크롬 실행
        try:
            logger.debug(f"[CHROME_LAUNCH][{request_id}] Starting Chrome process")
            subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            logger.info(f"[CHROME_LAUNCH][{request_id}] Chrome process started with command: {' '.join(cmd)}")
        except Exception as e:
            error_msg = f"Failed to start Chrome process: {str(e)}"
            logger.error(f"[CHROME_LAUNCH][{request_id}] {error_msg}")
            logger.debug(f"[CHROME_LAUNCH][{request_id}] Exception details: {traceback.format_exc()}")
            return error_msg
        
        # 연결 대기
        max_attempts = 5
        logger.debug(f"[CHROME_LAUNCH][{request_id}] Waiting for Chrome to start, will check port {max_attempts} times")
        
        for attempt in range(max_attempts):
            logger.debug(f"[CHROME_LAUNCH][{request_id}] Checking port availability (attempt {attempt+1}/{max_attempts})")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((_default_host, _default_port))
            sock.close()
            
            if result == 0:
                end_time = time.time()
                total_time = end_time - start_time
                logger.info(f"[CHROME_LAUNCH][{request_id}] Chrome launched successfully with debugging port {_default_port} in {total_time:.2f}s")
                return f"Chrome launched successfully with debugging port {_default_port}."
            
            logger.debug(f"[CHROME_LAUNCH][{request_id}] Waiting for Chrome to start (attempt {attempt+1}/{max_attempts})...")
            time.sleep(1)
        
        end_time = time.time()
        total_time = end_time - start_time
        error_msg = f"Chrome was launched but could not confirm debug port {_default_port} is open after {total_time:.2f}s. Try connecting manually."
        logger.warning(f"[CHROME_LAUNCH][{request_id}] {error_msg}")
        return error_msg
    except Exception as e:
        end_time = time.time()
        total_time = end_time - start_time
        error_msg = f"Error launching Chrome after {total_time:.2f}s: {str(e)}"
        logger.error(f"[CHROME_LAUNCH][{request_id}] Error in function: {str(e)}")
        logger.debug(f"[CHROME_LAUNCH][{request_id}] Stack trace: {traceback.format_exc()}")
        return error_msg


# CMD 명령어 실행 툴
@mcp.tool()
def cmd_execute(command: str, timeout: int = 30, working_dir: Optional[str] = None) -> str:
    """
    서버 PC에서 CMD 명령어를 실행하고 결과를 반환합니다.
    
    Args:
        command: 실행할 CMD 명령어
        timeout: 명령어 실행 제한 시간(초, 기본값: 30초)
        working_dir: 명령어를 실행할 작업 디렉토리 (기본값: 현재 디렉토리)
    
    Returns:
        명령어 실행 결과를 JSON 문자열로 반환합니다.
    """
    # 요청 ID 생성
    request_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    request_id = f"cmd_execute_{request_time}"
    start_time = time.time()
    
    logger.info(f"[CMD_EXECUTE][{request_id}] Function called with command: {command}")
    logger.debug(f"[CMD_EXECUTE][{request_id}] Parameters: timeout={timeout}, working_dir={working_dir or 'default'}")
    
    try:
        # CMD 매니저 인스턴스 가져오기
        cmd_manager = get_cmd_manager()
        
        # 명령어 실행
        result = cmd_manager.execute_command(
            command=command,
            timeout=timeout,
            working_dir=working_dir,
            request_id=request_id
        )
        
        # JSON 형식으로 반환
        end_time = time.time()
        total_time = end_time - start_time
        logger.info(f"[CMD_EXECUTE][{request_id}] Command execution completed in {total_time:.2f}s")
        
        return json.dumps(result, indent=2, ensure_ascii=False)
        
    except Exception as e:
        end_time = time.time()
        total_time = end_time - start_time
        error_msg = f"Error executing command after {total_time:.2f}s: {str(e)}"
        
        logger.error(f"[CMD_EXECUTE][{request_id}] {error_msg}")
        logger.debug(f"[CMD_EXECUTE][{request_id}] Exception details: {traceback.format_exc()}")
        
        result = {
            "command": command,
            "success": False,
            "error": error_msg,
            "execution_time": round(total_time, 2)
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False)

# 마지막 CMD 실행 결과 가져오기
@mcp.tool()
def cmd_get_last_result() -> str:
    """
    마지막으로 실행한 CMD 명령어의 결과를 가져옵니다.
    
    Returns:
        마지막 명령어 실행 결과를 JSON 문자열로 반환합니다.
    """
    request_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    request_id = f"cmd_last_{request_time}"
    
    logger.info(f"[CMD_GET_LAST_RESULT][{request_id}] Function called")
    
    try:
        cmd_manager = get_cmd_manager()
        last_result = cmd_manager.get_last_result()
        
        if last_result is None:
            logger.info(f"[CMD_GET_LAST_RESULT][{request_id}] No previous command execution found")
            return json.dumps({"error": "No previous command execution found"})
        
        logger.info(f"[CMD_GET_LAST_RESULT][{request_id}] Last command: {cmd_manager.get_last_command()}")
        return json.dumps(last_result, indent=2, ensure_ascii=False)
        
    except Exception as e:
        error_msg = f"Error getting last command result: {str(e)}"
        logger.error(f"[CMD_GET_LAST_RESULT][{request_id}] {error_msg}")
        logger.debug(f"[CMD_GET_LAST_RESULT][{request_id}] Exception details: {traceback.format_exc()}")
        
        return json.dumps({"error": error_msg})

if __name__ == "__main__":
    # MCP 서버 실행
    mcp.run() 