import win32ui
import win32gui
import win32con
import numpy as np
import cv2
import time
import pyautogui
import os
import subprocess
import win32api
import pychrome
import psutil
import traceback
import base64
import logging
# JSON에서 cmd 필드 추출
import json
import re
from cmdman.cmd_manager import *
import websocket
import threading
import inspect

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("myagent.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

print("chatgpt.py file loading completed", PersistentCmdManager)

class ChromeCDPClient:
    """
    Chrome DevTools Protocol 클라이언트 클래스
    ChatGPT와의 상호작용 및 브라우저 제어를 위한 클래스
    """
    
    def __init__(self):
        """
        ChromeCDPClient 클래스 초기화
        """
        self.browser = None
        self.tab = None
        self.tab2 = None
        self.pythonpath = None
        
        # 디버그용 로깅 설정
        self.setup_debug_logging()
        
        self.start_browser()
        
    def setup_debug_logging(self):
        """
        웹소켓 디버깅을 위한 추가 로깅 설정
        """
        # Fixing try-except structure
        # Import pychrome tab
        import pychrome.tab
        from pychrome.tab import Tab
        
        try:
            # Patch the WebSocket receive loop to handle empty messages
            if hasattr(Tab, '_recv_loop'):
                original_recv_loop = Tab._recv_loop
                
                def patched_recv_loop(self):
                    import json
                    import inspect
                    
                    try:
                        # Ensure websocket module is available
                        try:
                            import websocket
                            WebSocketConnectionClosedException = websocket.WebSocketConnectionClosedException
                            WebSocketException = websocket.WebSocketException
                        except ImportError:
                            # Define dummy exception classes if module not available
                            class WebSocketConnectionClosedException(Exception): pass
                            class WebSocketException(Exception): pass
                            
                        # Check if _ws attribute is a proper websocket connection
                        if hasattr(self, '_ws'):
                            ws_type = type(self._ws).__name__
                            logger.debug(f"WebSocket connection type: {ws_type}")
                            
                            # Check if it has necessary methods
                            if not hasattr(self._ws, 'recv') or not callable(getattr(self._ws, 'recv', None)):
                                logger.error(f"WebSocket object missing recv method or recv is not callable: {ws_type}")
                                
                        # Log all relevant attributes for debugging
                        self_attrs = {name: (type(val).__name__, callable(val) if hasattr(val, '__call__') else "not callable") 
                                     for name, val in inspect.getmembers(self) 
                                     if not name.startswith('__')}
                        logger.debug(f"Tab object attributes: {self_attrs}")
                        
                        while getattr(self, '_started', False):
                            try:
                                if not hasattr(self, '_ws') or self._ws is None:
                                    logger.debug("WebSocket connection is None, exiting loop")
                                    break
                                    
                                # Use standard attribute access instead of callable
                                try:
                                    # Create a safe wrapper for the recv method
                                    ws_recv = getattr(self._ws, 'recv', None)
                                    
                                    # Validate it's actually callable
                                    if not callable(ws_recv):
                                        logger.error(f"WebSocket recv is not callable: {type(ws_recv).__name__}")
                                        # Try an alternative approach
                                        if hasattr(self._ws, '_recv'):
                                            ws_recv = getattr(self._ws, '_recv', None)
                                            if callable(ws_recv):
                                                message_json = ws_recv()
                                            else:
                                                logger.error("Both recv and _recv are not callable")
                                                break
                                        else:
                                            logger.error("No valid recv method found, exiting loop")
                                            break
                                    else:
                                        # Call the recv method
                                        message_json = ws_recv()
                                except (WebSocketConnectionClosedException, WebSocketException) as e:
                                    logger.debug(f"WebSocket connection closed or exception: {e}")
                                    break
                                except Exception as e:
                                    logger.debug(f"Error receiving from WebSocket: {e}")
                                    # Only break if connection is actually closed
                                    if "connection is already closed" in str(e).lower():
                                        break
                                    continue
                                
                                # Handle empty messages gracefully
                                if not message_json or message_json.strip() == '':
                                    logger.debug("Received empty WebSocket message, ignoring")
                                    continue
                                    
                                try:
                                    message = json.loads(message_json)
                                    # Use safe method call
                                    handle_message = getattr(self, '_handle_message', None)
                                    if callable(handle_message):
                                        handle_message(message)
                                    else:
                                        logger.debug("_handle_message not callable, skipping")
                                except json.JSONDecodeError:
                                    # Silently ignore JSON decode errors from WebSocket
                                    logger.debug("JSONDecodeError in WebSocket message, ignoring")
                                    continue
                                except Exception as e:
                                    # Log but try to continue
                                    logger.error(f"Error handling message: {e}")
                                    continue
                            except (WebSocketConnectionClosedException, WebSocketException) as e:
                                # WebSocket is closed, exit the loop
                                logger.debug(f"WebSocket connection closed (outer): {e}")
                                break
                            except Exception as e:
                                # Log but try to continue
                                logger.error(f"Error in WebSocket receive loop: {e}")
                                if not getattr(self, '_started', False):
                                    break
                    except Exception as e:
                        logger.error(f"Fatal error in WebSocket loop: {e}")
                    finally:
                        setattr(self, '_started', False)
                        logger.debug("WebSocket receive loop exited")
                
                # Apply the patched function
                Tab._recv_loop = patched_recv_loop
                logger.info("Applied WebSocket receive loop patch to pychrome Tab._recv_loop")
            
            # We'll skip the other parts of the debug logging that might cause problems
            # since our main focus is to fix the websocket loop
            
        except Exception as e:
            logger.warning(f"Error setting up debug logging: {e}")
            logger.info("Continuing without WebSocket debugging")

    def capture_window(self, hwnd):
        """
        윈도우 핸들로부터 스크린샷을 캡처합니다.
        성능 최적화 버전
        """
        try:
            # 윈도우 핸들로부터 윈도우 크기 정보 획득
            left, top, right, bottom = win32gui.GetWindowRect(hwnd)
            width = right - left
            height = bottom - top
            
            # 윈도우 크기가 너무 크면 축소 (메모리 사용 최적화)
            scale_factor = 1.0
            max_dimension = 1920  # 최대 치수 제한
            
            if width > max_dimension or height > max_dimension:
                scale_factor = min(max_dimension / width, max_dimension / height)
                target_width = int(width * scale_factor)
                target_height = int(height * scale_factor)
            else:
                target_width = width
                target_height = height

            # 윈도우 DC 생성
            window_dc = win32gui.GetWindowDC(hwnd)
            dc_obj = win32ui.CreateDCFromHandle(window_dc)
            compatible_dc = dc_obj.CreateCompatibleDC()

            # 비트맵 생성
            dataBitMap = win32ui.CreateBitmap()
            dataBitMap.CreateCompatibleBitmap(dc_obj, width, height)
            compatible_dc.SelectObject(dataBitMap)

            # BitBlt로 화면 캡처
            compatible_dc.BitBlt((0, 0), (width, height), dc_obj, (0, 0), win32con.SRCCOPY)

            # 비트맵 정보를 numpy 배열로 변환
            signedIntsArray = dataBitMap.GetBitmapBits(True)
            img = np.frombuffer(signedIntsArray, dtype='uint8')
            img.shape = (height, width, 4)

            # BGR 형식의 CV2 이미지로 변환
            img = cv2.cvtColor(img, cv2.COLOR_BGRA2BGR)
            
            # 필요한 경우 이미지 크기 조정 (메모리 및 처리 시간 최적화)
            if scale_factor < 1.0:
                img = cv2.resize(img, (target_width, target_height), interpolation=cv2.INTER_AREA)

            # 메모리 해제
            dc_obj.DeleteDC()
            compatible_dc.DeleteDC()
            win32gui.ReleaseDC(hwnd, window_dc)
            win32gui.DeleteObject(dataBitMap.GetHandle())

            return img
        except Exception as e:
            logger.error(f"Error capturing window: {e}")
            logger.error(traceback.format_exc())
            return None

    def bring_to_foreground(self, hwnd):
        """
        창을 전면으로 가져옵니다.
        """
        try:
            # 현재 윈도우가 최소화되어 있는지 확인
            if win32gui.IsIconic(hwnd):
                # 최소화되어 있다면 복원
                win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
            
            # Alt 키 시뮬레이션으로 포커스 변경 문제 방지
            pyautogui.keyDown('alt')
            pyautogui.keyUp('alt')
            
            # 윈도우를 최상단으로 가져오기
            win32gui.SetForegroundWindow(hwnd)
            win32gui.BringWindowToTop(hwnd)
            win32gui.SetActiveWindow(hwnd)
            
            return True
        except Exception as e:
            logger.error(f"Error bringing window to foreground: {e}")
            return False

    def resize_window(self, hwnd, width, height, x=None, y=None):
        """
        윈도우 크기를 변경합니다.
        """
        try:
            # 현재 윈도우의 위치와 크기 정보 가져오기
            left, top, right, bottom = win32gui.GetWindowRect(hwnd)
            
            # x, y 위치가 지정되지 않은 경우 현재 위치 사용
            if x is None:
                x = left
            if y is None:
                y = top
            
            # 윈도우 이동 및 크기 조절
            win32gui.SetWindowPos(
                hwnd,
                win32con.HWND_TOP,
                x,
                y,
                width,
                height,
                win32con.SWP_SHOWWINDOW
            )
            return True
        except Exception as e:
            logger.error(f"Error resizing window: {e}")
            return False

        
    def analisys_crawl_page(self, browser, url, purpose, test_string):
        """
        크롤링 페이지를 분석하고 필요한 정보를 추출합니다.
        tab 을 새로 생성하고 url 로 접속하여 html 소스를 확인하고
        각 엘리먼트와 js 소스를 분석하여 purpose 에 맞는 Crawling method을 확인합니다.
        만약 온라인 js,css 소스를 다운로드 해야 한다면 requests 모듈을 사용하여 다운로드 합니다.
        다운받은 소스파일들은 ./tmp/crawl 에 저장한뒤에
        크롤링 페이지의 Crawling method을 확인하고 결과를 추후에 다시 웹자동화에 사용할수있도록
        파일로 정리하여 ./crawls 폴더에 {날짜}{특수문자를 제거한 url}{purpose} 파일로 저장합니다.
        
        순서는 다음과 같습니다.
        1. 새로운 탭 생성
        2. 해당 웹페이지 접속
        3. 페이지 로드가 완료되면 html 파일을 tmp/crawl 폴더에 저장
        4. 해당 파일을 chatgpt 에 전달하여 Crawling method을 확인
        5. 챗지피티는 추가 필요 소스파일이 필요할 경우 온라인에서 다운로드
        6. 챗지피티는 Crawling method을 확인하고 결과를 추후에 다시 웹자동화에 사용할수있도록
        파일로 정리하여 ./crawls 폴더에 {날짜}{특수문자를 제거한 url}{purpose} 파일로 저장
        7. 필요한 경우 다양한 반복 분석을 통해 원하는 결과가 나올 때까지 진행합니다.
        """
        try:
            import os
            import re
            import time
            import datetime
            import requests
            import json
            from urllib.parse import urljoin, urlparse
            
            # 필요한 디렉토리 생성
            tmp_dir = "./tmp/crawl"
            crawls_dir = "./crawls"
            os.makedirs(tmp_dir, exist_ok=True)
            os.makedirs(crawls_dir, exist_ok=True)
            
            # 현재 날짜 가져오기
            current_date = datetime.datetime.now().strftime("%Y%m%d")
            
            # URL에서 특수문자 제거하여 파일 이름 만들기
            url_filename = re.sub(r'[^\w]', '_', url)
            if len(url_filename) > 50:  # 파일명 길이 제한
                url_filename = url_filename[:50]
            
            # 결과 파일 경로 생성
            result_filename = f"{current_date}_{url_filename}_{purpose}.json"
            result_path = os.path.join(crawls_dir, result_filename)
            
            logger.info(f"Starting crawl analysis for URL: {url}")
            logger.info(f"Purpose: {purpose}")
            
            # 1. 새로운 탭 생성
            logger.info("1. Creating new tab")
            crawl_tab = browser.new_tab()
            crawl_tab_id = crawl_tab.id  # 나중에 탭 닫을 때 필요
            logger.info(f"Created new tab with ID: {crawl_tab_id}")
            
            crawl_tab.start()
            logger.info("Tab WebSocket connection started")
            
            # 네트워크 및 페이지 활성화
            crawl_tab.Network.enable()
            crawl_tab.Page.enable()
            crawl_tab.Runtime.enable()  # JavaScript 실행을 위해 활성화
            browser.activate_tab(crawl_tab_id)
            logger.info("Network and Page domains enabled and tab activated")
            
            # 2. 해당 웹페이지 접속
            logger.info(f"2. Navigating to URL: {url}")
            crawl_tab.Page.navigate(url=url)
            
            # 페이지 로드 완료 기다리기
            logger.info("Waiting for page load to complete")
            
            # DOM 완료 이벤트 대기
            page_loaded = False
            
            def on_page_load_event(**kwargs):
                nonlocal page_loaded
                page_loaded = True
                logger.info("Page load event fired")
                
            # 이벤트 리스너 등록
            crawl_tab.Page.loadEventFired = on_page_load_event
            
            # 타임아웃 설정
            load_timeout = 30
            start_time = time.time()
            
            # 페이지 로드 대기
            while not page_loaded and time.time() - start_time < load_timeout:
                time.sleep(0.5)
                
            if not page_loaded:
                logger.warning(f"Page load timeout after {load_timeout} seconds")
                
            # 추가 시간 대기 (JavaScript 실행 완료를 위해)
            time.sleep(5)
            
            # 3. 페이지 로드가 완료되면 html 파일을 tmp/crawl 폴더에 저장
            logger.info("3. Saving HTML content")
            
            # 현재 HTML 내용 가져오기
            result = crawl_tab.Runtime.evaluate(expression="document.documentElement.outerHTML")
            html_content = result.get('result', {}).get('value', '')
            
            # HTML 파일 저장
            html_filename = os.path.join(tmp_dir, f"{current_date}_{url_filename}_source.html")
            with open(html_filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"HTML saved to: {html_filename}")
            
            # DOM 구조 및 렌더링된 상태 분석
            logger.info("Analyzing DOM structure and rendered state")
            
            # 렌더링된 전체 페이지 스크린샷 캡처
            screenshot_result = crawl_tab.Page.captureScreenshot()
            screenshot_data = screenshot_result.get('data', '')
            if screenshot_data:
                screenshot_filename = os.path.join(tmp_dir, f"{current_date}_{url_filename}_screenshot.png")
                with open(screenshot_filename, 'wb') as f:
                    f.write(base64.b64decode(screenshot_data))
                logger.info(f"Screenshot saved to: {screenshot_filename}")
            
            # 페이지 기본 정보 수집
            page_info = crawl_tab.Runtime.evaluate(
                expression="""
                (function() {
                    return {
                        title: document.title,
                        url: window.location.href,
                        size: {
                            width: window.innerWidth,
                            height: window.innerHeight
                        },
                        documentReady: document.readyState
                    };
                })()
                """
            )
            page_info = page_info.get('result', {}).get('value', {})
            
            # 4. 대화형 JavaScript 크롤링 세션 Start
            logger.info("4. Starting interactive JavaScript crawling session with ChatGPT")
            
            # 먼저 HTML 파일을 ChatGPT로 업로드
            logger.info(f"Uploading HTML file: {html_filename}")
            self.simulate_paste_local_file(html_filename, self.tab)
            time.sleep(1)  # 업로드 완료 기다리기
            
            # 스크린샷도 업로드
            if os.path.exists(screenshot_filename):
                logger.info(f"Uploading screenshot: {screenshot_filename}")
                self.simulate_paste_local_file(screenshot_filename, self.tab)
                time.sleep(1)
            
            # 대화형 크롤링 세션 초기화
            max_iterations = 10  # 최대 반복 횟수
            iteration = 0
            final_result = {"steps": []}
            crawling_complete = False
            
            # 초기 프롬프트 작성 - JavaScript 크롤링 코드 요청
            initial_prompt = f"""
Purpose: {purpose}에 관한 웹페이지 크롤링

이 웹페이지({url})를 크롤링하기 위해 JavaScript 코드를 작성해 주세요.
개발자 도구 콘솔에서 바로 실행할 수 있는 JavaScript 코드로 작성해야 합니다.

다음 단계로 진행하겠습니다:
1. 먼저 당신이 첫 번째 JavaScript 코드 조각을 작성해주세요. 이 코드는 페이지를 분석하고 {purpose}와 관련된 데이터를 찾아내는 데 사용됩니다.
2. 나는 그 코드를 브라우저에서 실행하고 결과를 알려드리겠습니다.
3. 그 결과를 바탕으로 후속 작업을 위한 다음 JavaScript 코드를 작성해주세요.
4. 이 과정을 원하는 데이터를 완전히 추출할 때까지 반복하겠습니다.

JavaScript 코드를 작성할 때 다음 가이드라인을 따라주세요:
- 코드는 ```javascript 와 ``` 사이에 작성해야 합니다.
- 코드는 비동기(async/await) 형태로 작성하고 Promise를 사용하여 결과를 반환하세요.
- 코드는 즉시 실행 함수 표현식(IIFE) 형태로 작성하세요. 예: (async function() { ... })()
- JSON 형식으로 결과를 반환하세요.
- 코드가 오류 처리를 포함하도록 해주세요.
- 코드는 한 번에 하나의 작업만 수행하도록 집중하세요.

첫 번째 JavaScript 크롤링 코드를 작성해주세요. Page structure 분석과 크롤링 Target elements 식별에 집중하세요.
"""

            logger.info("Sending initial prompt to ChatGPT")
            self.send_query(browser, self.tab, initial_prompt)
            
            # 응답 대기
            if not self.wait_for_response_complete(self.tab, timeout=300):
                logger.warning("Initial response waiting timed out")
                return "오류: ChatGPT 응답 대기 시간 초과"
            
            # 반복 크롤링 세션 Start
            while iteration < max_iterations and not crawling_complete:
                iteration += 1
                logger.info(f"JavaScript crawling iteration {iteration}/{max_iterations}")
                
                # ChatGPT 응답에서 JavaScript 코드 추출
                js_code = self.extract_javascript_code(self.tab)
                if not js_code:
                    logger.warning("No JavaScript code found in response")
                    
                    # JavaScript 코드 요청 재시도
                    retry_prompt = """
죄송합니다만, 응답에서 JavaScript 코드를 찾을 수 없습니다.
다음 형식으로 JavaScript 코드를 작성해주세요:

```javascript
(async function() {
    try {
        // 페이지 분석 및 데이터 추출 코드
        
        return {
            success: true,
            data: 추출된_데이터,
            message: "분석 결과 메시지"
        };
    } catch (error) {
        return {
            success: false,
            error: error.message,
            message: "오류 발생"
        };
    }
})();
```

코드 블록은 반드시 ```javascript로 Start하고 ```로 끝나야 합니다.
"""
                    self.send_query(browser, self.tab, retry_prompt)
                    
                    if not self.wait_for_response_complete(self.tab, timeout=180):
                        logger.warning("Retry response waiting timed out")
                    
                    js_code = self.extract_javascript_code(self.tab)
                    if not js_code:
                        logger.error("Failed to get JavaScript code after retry")
                        break
                
                # JavaScript 코드 실행
                logger.info(f"Executing JavaScript code (iteration {iteration})")
                try:
                    # 크롤 탭에서 JavaScript 코드 실행
                    js_result = crawl_tab.Runtime.evaluate(
                        expression=js_code,
                        awaitPromise=True,
                        returnByValue=True,
                        timeout=30000  # 30초 타임아웃
                    )
                    
                    # 실행 결과 확인
                    js_error = js_result.get('exceptionDetails')
                    if js_error:
                        error_msg = js_error.get('exception', {}).get('description', 'Unknown JS error')
                        logger.error(f"JavaScript execution error: {error_msg}")
                        
                        # 오류 정보를 포함한 결과 객체 생성
                        execution_result = {
                            "success": False,
                            "error": error_msg,
                            "message": "JavaScript 실행 중 오류 발생"
                        }
                    else:
                        # 성공적으로 실행된 경우 결과 추출
                        result_value = js_result.get('result', {}).get('value')
                        logger.info(f"JavaScript execution result: {str(result_value)[:200]}...")
                        
                        # 결과가 딕셔너리가 아니면 딕셔너리로 변환
                        if not isinstance(result_value, dict):
                            execution_result = {
                                "success": True,
                                "data": result_value,
                                "message": "JavaScript가 실행되었지만 예상된 형식이 아닙니다."
                            }
                        else:
                            execution_result = result_value
                    
                    # 단계 결과 저장
                    step_result = {
                        "iteration": iteration,
                        "js_code": js_code,
                        "result": execution_result
                    }
                    final_result["steps"].append(step_result)
                    
                    # 완료 여부 확인 - 다양한 완료 신호 패턴 검사
                    is_complete = False
                    
                    # 1. complete 플래그 확인
                    if execution_result.get('complete', False):
                        logger.info("Crawling process marked as complete via 'complete' flag")
                        is_complete = True
                        
                    # 2. message 내용 확인
                    if not is_complete:
                        complete_messages = ["크롤링 완료", "crawling complete", "crawl complete", "extraction complete", "완료되었습니다"]
                        msg = str(execution_result.get('message', '')).lower()
                        for complete_msg in complete_messages:
                            if complete_msg.lower() in msg:
                                logger.info(f"Crawling process marked as complete via message: '{msg}'")
                                is_complete = True
                                break
                    
                    # 3. data 검사 (원하는 데이터가 포함되어 있는지)
                    if not is_complete and test_string and execution_result.get('success', False):
                        data_str = json.dumps(execution_result.get('data', {}), ensure_ascii=False).lower()
                        if test_string.lower() in data_str:
                            logger.info(f"Crawling process potentially complete - test string '{test_string}' found in data")
                            # 추가 확인: 메시지나 플래그가 없어도 명시적인 데이터 완료로 간주할 수 있는지
                            if isinstance(execution_result.get('data', {}), dict) and len(execution_result.get('data', {})) > 0:
                                logger.info("Data is complete dictionary, marking as complete")
                                is_complete = True
                    
                    if is_complete:
                        logger.info("Crawling process marked as complete")
                        crawling_complete = True
                        final_result["success"] = True
                        final_result["message"] = "크롤링이 성공적으로 완료되었습니다."
                        break
                        
                    # 다음 JavaScript 코드 요청 프롬프트 구성
                    next_prompt = f"""
JavaScript 코드 실행 결과:
```json
{json.dumps(execution_result, ensure_ascii=False, indent=2)}
```

위 결과를 바탕으로 다음 단계의 크롤링을 위한 JavaScript 코드를 작성해주세요.

{f'목표 데이터에 "{test_string}"이 포함되어 있는지 확인해주세요.' if test_string else ''}

아직 목표한 데이터를 완전히 추출하지 못했다면, 다음 작업을 위한 JavaScript 코드를 작성해주세요.
이전 코드의 문제점이 있다면 수정하고, 다음 단계로 진행하세요.

만약 크롤링이 완료되었다면, 최종 결과를 정리하는 JavaScript 코드를 작성하고 결과 객체에 `complete: true`를 포함시켜주세요.

코드는 다음 형식으로 작성해주세요:
```
(async function() {{
    try {{
        // 이전 결과를 바탕으로 다음 작업 수행
        
        return {{
            success: true,
            data: 추출된_데이터,
            message: "작업 상태 메시지"
            // 필요시 complete: true 추가
        }};
    }} catch (error) {{
        return {{
            success: false,
            error: error.message,
            message: "오류 발생"
        }};
    }}
}})();
```
"""
                    
                    # 다음 프롬프트 전송
                    logger.info("Sending next prompt with execution results")
                    self.send_query(browser, self.tab, next_prompt)
                    
                    if not self.wait_for_response_complete(self.tab, timeout=300):
                        logger.warning("Next response waiting timed out")
                        break
                
                except Exception as js_exec_error:
                    logger.error(f"Error during JavaScript execution: {js_exec_error}")
                    
                    # 오류 정보를 포함한 프롬프트 구성
                    error_prompt = f"""
JavaScript 코드 실행 중 오류가 발생했습니다:
```
{str(js_exec_error)}
```

이 오류를 해결할 수 있는 새로운 JavaScript 코드를 작성해주세요.
코드는 다음 형식으로 작성해주세요:

```
(async function() {{
    try {{
        // 오류를 수정한 코드
        
        return {{
            success: true,
            data: 추출된_데이터,
            message: "오류 수정 후 실행 결과"
        }};
    }} catch (error) {{
        return {{
            success: false,
            error: error.message,
            message: "오류 발생"
        }};
    }}
}})();
```
"""
                    
                    # 오류 프롬프트 전송
                    logger.info("Sending error prompt for JavaScript fix")
                    self.send_query(browser, self.tab, error_prompt)
                    
                    if not self.wait_for_response_complete(self.tab, timeout=180):
                        logger.warning("Error response waiting timed out")
                        break
            
            # 최종 결과 정리
            if iteration >= max_iterations and not crawling_complete:
                logger.warning(f"Maximum iterations ({max_iterations}) reached without completing crawling")
                final_result["success"] = False
                final_result["message"] = f"최대 반복 횟수({max_iterations})에 도달했지만 크롤링이 완료되지 않았습니다."
            
            # 크롤링된 데이터 추출
            crawled_data = []
            for step in final_result["steps"]:
                if step["result"].get("success", False) and step["result"].get("data"):
                    data = step["result"]["data"]
                    if isinstance(data, list):
                        crawled_data.extend(data)
                    elif isinstance(data, dict) and "items" in data:
                        crawled_data.extend(data["items"])
                    elif isinstance(data, dict):
                        crawled_data.append(data)
            
            # 중복 제거 (가능한 경우)
            try:
                unique_data = []
                seen_items = set()
                
                for item in crawled_data:
                    item_str = json.dumps(item, sort_keys=True) if isinstance(item, dict) else str(item)
                    if item_str not in seen_items:
                        seen_items.add(item_str)
                        unique_data.append(item)
                
                final_result["data"] = unique_data
            except:
                final_result["data"] = crawled_data
            
            # test_string 확인
            if test_string:
                data_str = json.dumps(final_result["data"], ensure_ascii=False)
                final_result["test_string_found"] = test_string.lower() in data_str.lower()
                logger.info(f"Test string '{test_string}' found: {final_result['test_string_found']}")
            
            # 결과 파일 저장
            with open(result_path, 'w', encoding='utf-8') as f:
                json.dump(final_result, f, ensure_ascii=False, indent=2)
            
            logger.info(f"Final crawling result saved to: {result_path}")
            
            # 안전하게 탭 닫기
            try:
                logger.info(f"Attempting to safely close tab with ID: {crawl_tab_id}")
                self.complete_tab_cleanup(browser, crawl_tab)
            except Exception as e:
                logger.error(f"Error during tab cleanup: {e}")
                logger.error(traceback.format_exc())
                # 변수 정리
                crawl_tab = None
            
            # 결과 객체 반환
            result_obj = {
                'success': final_result["success"],
                'result_file': result_path,
                'html_file': html_filename,
                'iterations': iteration,
                'crawling_complete': crawling_complete,
                'data': final_result["data"],
                'message': final_result["message"] if "message" in final_result else ""
            }
            
            return result_obj
            
        except Exception as e:
            logger.error(f"Error in analisys_crawl_page: {e}")
            logger.error(traceback.format_exc())
            
            # 에러가 발생해도 크롤링 결과 파일 생성 시도
            try:
                error_result = {
                    'error': str(e),
                    'target_url': url,
                    'purpose': purpose,
                    'date': datetime.datetime.now().strftime("%Y%m%d"),
                    'traceback': traceback.format_exc()
                }
                
                with open(result_path, 'w', encoding='utf-8') as f:
                    json.dump(error_result, f, ensure_ascii=False, indent=2)
                
                logger.info(f"Error information saved to: {result_path}")
            except:
                pass
                
            return {
                'success': False,
                'error': str(e)
            }

    
    def extract_javascript_code(self, tab):
        """
        ChatGPT 응답에서 JavaScript 코드를 추출합니다.
        """
        try:
            js_code = """
            (function() {
                try {
                    // JavaScript 코드 블록 찾기
                    const jsBlocks = [];
                    
                    // 코드 블록 찾기 (```javascript ... ``` 형식)
                    const codeElements = document.querySelectorAll('pre code.language-javascript');
                    if (codeElements.length > 0) {
                        // 마지막 JavaScript 코드 블록 사용
                        return codeElements[codeElements.length - 1].textContent;
                    }
                    
                    // 일반 코드 블록 확인
                    const preElements = document.querySelectorAll('pre');
                    for (const pre of preElements) {
                        // pre 요소 내부 텍스트 확인
                        const text = pre.textContent || '';
                        if (text.includes('async function') || 
                            text.includes('function(') || 
                            text.includes('return {') ||
                            text.includes('document.querySelector')) {
                            jsBlocks.push(text);
                        }
                    }
                    
                    // JavaScript 코드 블록이 있다면 마지막 것 반환
                    if (jsBlocks.length > 0) {
                        return jsBlocks[jsBlocks.length - 1];
                    }
                    
                    // Markdown 텍스트에서 코드 블록 찾기
                    const markdownElements = document.querySelectorAll('.markdown');
                    if (markdownElements.length > 0) {
                        const lastMarkdown = markdownElements[markdownElements.length - 1];
                        const text = lastMarkdown.textContent || '';
                        
                        // ```javascript ... ``` 패턴 찾기
                        const jsRegex = /```(?:javascript|js)([\\s\\S]*?)```/g;
                        const matches = [];
                        let match;
                        
                        while ((match = jsRegex.exec(text)) !== null) {
                            matches.push(match[1].trim());
                        }
                        
                        if (matches.length > 0) {
                            return matches[matches.length - 1];
                        }
                        
                        // 일반 코드 블록 찾기
                        const codeRegex = /```([\\s\\S]*?)```/g;
                        const codeMatches = [];
                        
                        while ((match = codeRegex.exec(text)) !== null) {
                            const code = match[1].trim();
                            if (code.includes('async function') || 
                                code.includes('function(') || 
                                code.includes('return {') ||
                                code.includes('document.querySelector')) {
                                codeMatches.push(code);
                            }
                        }
                        
                        if (codeMatches.length > 0) {
                            return codeMatches[codeMatches.length - 1];
                        }
                    }
                    
                    return '';
                } catch (error) {
                    console.error('JavaScript 코드 추출 오류:', error);
                    return '';
                }
            })();
            """
            
            result = tab.Runtime.evaluate(expression=js_code)
            code = result.get('result', {}).get('value', "")
            
            if code:
                # JavaScript 코드 유효성 검증
                if code.startswith('```javascript') and code.endswith('```'):
                    code = code[13:-3].strip()  # ```javascript와 ``` 제거
                elif code.startswith('```js') and code.endswith('```'):
                    code = code[5:-3].strip()  # ```js와 ``` 제거
                elif code.startswith('```') and code.endswith('```'):
                    code = code[3:-3].strip()  # ```와 ``` 제거
                
                logger.info(f"Found JavaScript code ({len(code)} characters)")
                return code
            else:
                logger.warning("No JavaScript code found")
                return ""
            
        except Exception as e:
            logger.error(f"Error extracting JavaScript code: {e}")
            return ""

    def start_browser(self, profile_name="Default", position=(0, 0), size=(1024, 768), pythonpath="./Scripts/python.exe"):
        """
        Brave 브라우저를 Start하고 디버깅 포트를 연결합니다.
        성능 최적화된 옵션 적용
        """
        try:
            # 실행 중인 Brave 브라우저 종료
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] == "slimjet.exe":
                    logger.info("Closing existing Brave browser...")
                    try:
                        proc.kill()
                    except Exception as e:
                        logger.warning(f"Failed to kill process: {e}")
            
            time.sleep(1)  # 대기 시간 감소 (2초 → 1초)
            
            # 화면 해상도 확인
            screen_width, screen_height = pyautogui.size()
            
            # 기본 위치와 크기 값 사용, 화면 범위 초과 시 조정
            x, y = position
            width, height = size
            
            if x + width > screen_width:
                x = max(0, screen_width - width)
            if y + height > screen_height:
                y = max(0, screen_height - height)
            
            # 브라우저 Start 명령 - 성능 최적화 옵션 추가
            cmd = r'"C:\Program Files\Slimjet\slimjet.exe" ' \
                f'--remote-debugging-port=9333 ' \
                f'--window-size={width},{height} ' \
                f'--window-position={x},{y} ' \
                f'--profile-directory="{profile_name}" ' \
                f'--disable-extensions ' \
                f'--disable-gpu ' \
                f'--no-sandbox ' \
                f'--disable-dev-shm-usage ' \
                f'--disable-software-rasterizer'
            
            logger.info(f"Starting browser with command: {cmd}")
            ps = subprocess.Popen(cmd)
            
            cmd2 = r'"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"' \
                f'--remote-debugging-port=9444' \
                f'--window-size={width},{height} ' \
                f'--window-position={x},{y} ' \
                f'--profile-directory="Profile 1" ' \
                f'--disable-extensions ' \
                f'--disable-gpu ' \
                f'--no-sandbox ' \
                f'--disable-dev-shm-usage ' \
                f'--disable-software-rasterizer'
            
            logger.info(f"Starting browser with command: {cmd}")
            #ps2 = subprocess.Popen(cmd2)
            
            # 브라우저가 Start되고 디버깅 포트가 준비될 때까지 기다림
            max_attempts = 10
            attempts = 0
            self.browser = None
            self.tab = None
            self.tab2 = None
            
            # 이전에 생성된 탭 정리
            try:
                # 이전 브라우저 인스턴스가 있으면 탭 정리
                if self.browser:
                    logger.info("Cleaning up previous browser tabs")
                    tabs = self.browser.list_tab()
                    for tab in tabs:
                        try:
                            tab_id = tab.get('id')
                            if tab_id:
                                logger.info(f"Closing previous tab: {tab_id}")
                                self.browser.close_tab(tab_id)
                        except Exception as e:
                            logger.warning(f"Error closing previous tab: {e}")
            except Exception as e:
                logger.warning(f"Error during previous tabs cleanup: {e}")
                
            while attempts < max_attempts:
                try:
                    time.sleep(0.5)  # 대기 시간 감소 (1초 → 0.5초)
                    self.browser = pychrome.Browser(url="http://127.0.0.1:9333")
                    logger.info("Connected to Chrome DevTools Protocol")
                    break
                except Exception as e:
                    logger.warning(f"Browser not ready yet, retrying... ({attempts+1}/{max_attempts})")
                    attempts += 1
                    if attempts >= max_attempts:
                        logger.error(f"Failed to connect to browser: {e}")
                        return False
                
                # 열려 있는 모든 탭 확인
                try:
                    existing_tabs = self.browser.list_tab()
                    logger.info(f"Found {len(existing_tabs)} existing tabs")
                    
                    # 기존 탭이 있으면 모두 닫기
                    for tab in existing_tabs:
                        try:
                            tab_id = tab.get('id')
                            if tab_id:
                                logger.info(f"Closing existing tab: {tab_id}")
                                self.browser.close_tab(tab_id)
                        except Exception as e:
                            logger.warning(f"Error closing existing tab: {e}")
                except Exception as e:
                    logger.warning(f"Error listing or closing existing tabs: {e}")
                
                # 새 탭 생성
                attempts = 0
            while attempts < max_attempts:
                try:
                    time.sleep(0.5)  # 대기 시간 감소 (1초 → 0.5)
                    self.tab = self.browser.new_tab()
                    logger.info(f"Created main tab with ID: {self.tab.id}")
                    self.tab.start()
                    logger.info("Started main tab WebSocket connection")
                    break
                except Exception as e:
                    logger.warning(f"tab1 not ready yet, retrying... ({attempts+1}/{max_attempts})")
                    attempts += 1
                    if attempts >= max_attempts:
                        logger.error(f"Failed to connect to browser: {e}")
                        return False
            
                attempts = 0
            while attempts < max_attempts:
                try:
                    time.sleep(0.5)  # 대기 시간 감소 (1초 → 0.5초)
                    self.tab2 = self.browser.new_tab()
                    logger.info(f"Created secondary tab with ID: {self.tab2.id}")
                    self.tab2.start()
                    logger.info("Started secondary tab WebSocket connection")
                    break
                except Exception as e:
                    logger.warning(f"tab2 not ready yet, retrying... ({attempts+1}/{max_attempts})")
                    attempts += 1
                    if attempts >= max_attempts:
                        logger.error(f"Failed to connect to tab2: {e}")
                        return False
            
                # 네트워크 활성화 및 페이지 이동
            try:
                self.tab.Network.enable()
                self.tab2.Network.enable()
                logger.info("Enabled Network domain for both tabs")
            
                # ChatGPT 페이지로 직접 이동
                url = "https://chatgpt.com/?model=gpt-4o-mini&temporary-chat=false"
                logger.info(f"Navigating to {url}")
                self.tab.Page.navigate(url=url, _timeout=5)  # 타임아웃 감소 (10초 → 5초)
                # 페이지 로딩 기다리기
                self.tab.wait(5)  # 대기 시간 감소 (10초 → 5초)
            
                if self.tab2:
                    url = "https://chatgpt.com/?model=gpt-4o-mini&temporary-chat=false"
                    logger.info(f"Navigating secondary tab to {url}")
                    self.tab2.Page.navigate(url=url, _timeout=5)  # 타임아웃 감소 (10초 → 5초)
                    self.tab2.wait(5)  # 대기 시간 감소 (10초 → 5초)
            except Exception as e:
                logger.error(f"Error during tab initialization: {e}")
                logger.error(traceback.format_exc())
            
            self.pythonpath = pythonpath
            return True
        
        except Exception as e:
            logger.error(f"Error starting browser: {e}")
            logger.error(traceback.format_exc())
            return False

    def check_page_loaded(self, tab, timeout=15):  # 타임아웃 감소 (30초 → 15초)
        """
        페이지가 완전히 로드되었는지 확인합니다.
        더 효율적인 로딩 체크 방식 적용
        """
        try:
            start_time = time.time()
            polling_interval = 0.3  # 초기 폴링 간격 0.3초
            
            while time.time() - start_time < timeout:
                # 페이지 로드 상태 확인 - 더 효율적인 셀렉터 사용
                js_code = '''
                    (function() {
                        if (document.readyState !== 'complete') return 0;
                        const textarea = document.querySelector('#prompt-textarea');
                        return textarea ? 1 : 0;
                    })()
                '''
                result = tab.Runtime.evaluate(expression=js_code)
                
                if result.get('result', {}).get('value', 0) == 1:
                    logger.info("Page fully loaded")
                    return True
                
                # 동적 폴링 간격 적용 (시간이 지날수록 간격 증가)
                elapsed = time.time() - start_time
                polling_interval = min(1.0, 0.3 + (elapsed / 10))  # 최대 1초
                time.sleep(polling_interval)
            
            logger.warning("Timeout waiting for page to load")
            return False
        
        except Exception as e:
            logger.error(f"Error checking page load: {e}")
            return False

    def simulate_paste_local_file(self, filename, tab):
        """
        로컬 파일을 브라우저에 붙여넣기 시뮬레이션합니다.
        """
        try:
            full_path = os.path.abspath(filename)
            if not os.path.exists(full_path):
                logger.error(f"File not found: {full_path}")
                return False
                
            # 파일 읽기
            with open(full_path, "rb") as f:
                image_data = f.read()
            
            # Base64로 인코딩
            image_base64 = base64.b64encode(image_data).decode('utf-8')
            
            # 파일 타입 결정
            file_ext = os.path.splitext(filename)[1].lower()
            mime_type = 'image/png'  # 기본값
            
            if file_ext == '.jpg' or file_ext == '.jpeg':
                mime_type = 'image/jpeg'
            elif file_ext == '.png':
                mime_type = 'image/png'
            elif file_ext == '.pdf':
                mime_type = 'application/pdf'
            elif file_ext == '.txt':
                mime_type = 'text/plain'
            elif file_ext == '.js':
                mime_type = 'text/javascript'
            elif file_ext == '.css':
                mime_type = 'text/css'
            elif file_ext == '.html':
                mime_type = 'text/html'
            elif file_ext == '.json':
                mime_type = 'application/json'
            elif file_ext == '.xml':
                mime_type = 'application/xml'
            elif file_ext == '.csv':
                mime_type = 'text/csv'
            elif file_ext == '.md':
                mime_type = 'text/markdown'
            elif file_ext == '.yaml' or file_ext == '.yml':
                mime_type = 'text/yaml'
            elif file_ext == '.toml':
                mime_type = 'text/toml'
            elif file_ext == '.ini':
                mime_type = 'text/ini'
            elif file_ext == '.bat':
                mime_type = 'text/plain'
            elif file_ext == '.sh':
                mime_type = 'text/x-shellscript'
            elif file_ext == '.ps1':
                mime_type = 'text/x-powershell'
            elif file_ext == '.psm1':
                mime_type = 'text/x-powershell'
            elif file_ext == '.ps1xml':
                mime_type = 'text/x-powershell'
                    
                    
                    
            
            script = """
            (async function() {
                try {
                    const editor = document.querySelector('#prompt-textarea');
                    if (!editor) {
                        console.log("Editor not found");
                        return false;
                    }
                    
                    // Base64 데이터를 Blob으로 변환
                    const base64Data = '%s';
                    const byteCharacters = atob(base64Data);
                    const byteArrays = [];
                    
                    for (let offset = 0; offset < byteCharacters.length; offset += 512) {
                        const slice = byteCharacters.slice(offset, offset + 512);
                        const byteNumbers = new Array(slice.length);
                        for (let i = 0; i < slice.length; i++) {
                            byteNumbers[i] = slice.charCodeAt(i);
                        }
                        const byteArray = new Uint8Array(byteNumbers);
                        byteArrays.push(byteArray);
                    }
                    
                    const blob = new Blob(byteArrays, {type: '%s'});
                    const file = new File([blob], '%s', {type: '%s'});
                    
                    const dataTransfer = new DataTransfer();
                    dataTransfer.items.add(file);
                    
                    // 요소에 포커스
                    editor.focus();
                    
                    // Paste 이벤트 생성
                    const pasteEvent = new ClipboardEvent('paste', {
                        bubbles: true,
                        cancelable: true,
                        composed: true,
                        clipboardData: dataTransfer
                    });
                    
                    editor.dispatchEvent(pasteEvent);
                    
                    return true;
                } catch (error) {
                    console.error('Error:', error);
                    return false;
                }
            })();
            """ % (image_base64, mime_type, os.path.basename(filename), mime_type)
            
            result = tab.Runtime.evaluate(expression=script, awaitPromise=True)
            success = result.get('result', {}).get('value', False)
            
            if success:
                logger.info(f"Successfully pasted file: {filename}")
            else:
                logger.warning(f"Failed to paste file: {filename}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error pasting file: {e}")
            logger.error(traceback.format_exc())
            return False

    def send_query(self, browser, tab, text):
        """
        텍스트 쿼리를 ChatGPT에 전송합니다.
        """
        try:
            browser.activate_tab(tab.id)
            time.sleep(0.5)
            if not text.strip():
                logger.warning("Empty query text")
                return False
                
            # 업데이트된 셀렉터를 사용하여 텍스트 영역 찾기
            js_code = r"""
            (function() {
                // 최신 ChatGPT 인터페이스에서는 ProseMirror 에디터를 사용함
                const editor = document.querySelector('.ProseMirror');
                if (!editor) return false;
                
                // 에디터에 포커스
                editor.focus();
                
                // ChatGPT ProseMirror 에디터는 contenteditable 속성 사용
                // 내용 삽입을 위한 방법
                editor.innerHTML = `<p>${`%s`.replace('\\', '\\\\').replace('`', '\\`').replace("'", "\\'").replace('"', '\\"')}</p>`;
                
                // 입력 이벤트 발생시키기
                const event = new Event('input', { bubbles: true });
                editor.dispatchEvent(event);
                
                return true;
            })();
            """ % text.replace('\\', '\\\\').replace('`', '\\`').replace("'", "\\'").replace('"', '\\"')
            
            result = tab.Runtime.evaluate(expression=js_code)
            success = result.get('result', {}).get('value', False)
            
            if not success:
                logger.warning("Failed to set text in editor")
                return False
                
            # 파일 업로드 상태 확인 및 대기
            max_wait_time = 30  # 최대 30초 대기
            wait_interval = 0.5  # 0.5초 간격으로 확인
            start_time = time.time()
            
            while time.time() - start_time < max_wait_time:
                # 파일 업로드 상태 확인
                js_code = """
                (function() {
                    // 파일 업로드 진행 중 표시 확인
                    const uploadIndicator = document.querySelector('.upload-progress-indicator');
                    if (uploadIndicator) {
                        return false; // 업로드 진행 중
                    }
                    
                    // 파일 처리 중 메시지 확인
                    const processingElement = document.querySelector('.file-processing-message');
                    if (processingElement) {
                        return false; // 파일 처리 중
                    }
                    
                    // 파일 썸네일 또는 미리보기가 완전히 로드되었는지 확인
                    const fileAttachments = document.querySelectorAll('.file-attachment');
                    if (fileAttachments.length > 0) {
                        // 각 파일 첨부가 완전히 로드되었는지 확인
                        for (const attachment of fileAttachments) {
                            if (attachment.classList.contains('uploading') || 
                                attachment.classList.contains('processing')) {
                                return false; // 아직 업로드/처리 중
                            }
                        }
                    }
                    
                    // 전송 버튼이 활성화되었는지 확인 - 비활성화되어 있으면 아직 업로드 중일 수 있음
                    const sendButton = document.querySelector('button[data-testid="send-button"]');
                    if (sendButton && sendButton.disabled) {
                        return false; // 버튼 비활성화 = 업로드 중
                    }
                    
                    // 모든 확인 통과 = 업로드 완료
                    return true;
                })();
                """
                
                result = tab.Runtime.evaluate(expression=js_code)
                upload_complete = result.get('result', {}).get('value', False)
                
                if upload_complete:
                    logger.info("File uploads completed, proceeding to send message")
                    break
                
                # 아직 업로드 중이면 대기
                time.sleep(wait_interval)
                
                # 중간 로그 (5초마다)
                if (time.time() - start_time) % 5 < wait_interval:
                    logger.info("Waiting for file uploads to complete...")
            
            # 추가 안전 대기 시간 (업로드 완료 후 서버 처리 시간)
            time.sleep(1)
            
            # 전송 버튼 셀렉터 업데이트
            js_code = """
            (function() {
                // 현재 UI에 맞는 전송 버튼 셀렉터
                const sendButton = document.querySelector('button[data-testid="send-button"]');
                if (!sendButton) {
                    // 대체 셀렉터 시도
                    const alternativeButton = document.querySelector('button.absolute.bottom-0');
                    if (!alternativeButton) return false;
                    if (alternativeButton.disabled) return false;
                    alternativeButton.click();
                    return true;
                }
                
                if (sendButton.disabled) return false;
                sendButton.click();
                return true;
            })();
            """
            
            result = tab.Runtime.evaluate(expression=js_code)
            success = result.get('result', {}).get('value', False)
            
            if success:
                logger.info(f"Query sent successfully: {text[:50]}...")
            else:
                logger.warning("Failed to click send button")
                
                # 전송 실패 시 재시도 (1회)
                logger.info("Retrying send button click after short delay...")
                time.sleep(2)  # 추가 대기
                
                # 재시도 전에 버튼 상태 확인
                js_check = """
                (function() {
                    const sendButton = document.querySelector('button[data-testid="send-button"]');
                    if (!sendButton) return "button not found";
                    return sendButton.disabled ? "button disabled" : "button ready";
                })();
                """
                check_result = tab.Runtime.evaluate(expression=js_check)
                button_status = check_result.get('result', {}).get('value', "unknown")
                logger.info(f"Send button status: {button_status}")
                
                # 재시도
                result = tab.Runtime.evaluate(expression=js_code)
                success = result.get('result', {}).get('value', False)
                
                if success:
                    logger.info("Send button click successful on retry")
                else:
                    logger.warning("Send button click failed even after retry")
                
            return success
                
        except Exception as e:
            logger.error(f"Error sending query: {e}")
            logger.error(traceback.format_exc())
            return False

    def is_send_button_available(self, tab):
        """
        전송 버튼이 활성화되어 있는지 확인합니다.
        """
        try:
            js_code = """
            (function() {
                const sendButton = document.querySelector('button[data-testid="send-button"]');
                if (!sendButton) return false;
                return !sendButton.disabled;
            })();
            """
            
            result = tab.Runtime.evaluate(expression=js_code)
            return result.get('result', {}).get('value', False)
            
        except Exception as e:
            logger.error(f"Error checking send button: {e}")
            return False

    def is_model_responding(self, tab):
        """
        모델이 현재 응답 중인지 확인합니다.
        더 효율적인 DOM 검사 구현
        """
        try:
            js_code = """
            (function() {
                // 가장 빠른 검사 먼저 수행 - 중지 버튼 확인
                const stopButton = document.querySelector('button[data-testid="stop-button"]');
                if (stopButton) return true;
                
                // 더 효율적인 Selectors로 진행 중 인디케이터 확인
                return document.querySelector('.text-token-text-streaming') !== null;
            })();
            """
            
            result = tab.Runtime.evaluate(expression=js_code)
            return result.get('result', {}).get('value', False)
            
        except Exception as e:
            logger.error(f"Error checking if model is responding: {e}")
            return False

    def wait_for_response_complete(self, tab, timeout=180):  # 타임아웃 감소 (300초 → 180초)
        """
        모델 응답이 완료될 때까지 기다립니다.
        응답 대기 로직 최적화
        """
        try:
            start_time = time.time()
            last_log_time = start_time
            polling_interval = 0.2  # 초기 폴링 간격
            consecutive_inactive = 0  # 연속적으로 응답이 없는 횟수
            
            # 먼저 모델이 응답하기 Start하는지 확인 - 타임아웃 감소
            response_started = False
            response_start_timeout = 15  # 15초 동안 응답 Start 대기 (30초 → 15초)
            
            while time.time() - start_time < response_start_timeout and not response_started:
                if self.is_model_responding(tab):
                    response_started = True
                    logger.info("Model started responding")
                    break
                
                time.sleep(0.3)  # 폴링 간격 감소 (0.5초 → 0.3초)
            
            if not response_started:
                logger.warning("Model did not start responding within timeout")
                return False
            
            # 이제 응답이 완료될 때까지 대기 - 더 효율적인 동적 폴링 적용
            while time.time() - start_time < timeout:
                is_responding = self.is_model_responding(tab)
                
                if not is_responding:
                    consecutive_inactive += 1
                    # 연속 3회 이상 응답 없음 확인 시 완료로 판단 (안정성 확보)
                    if consecutive_inactive >= 3:
                        logger.info("Response completed")
                        return True
                else:
                    consecutive_inactive = 0
                
                # 30초마다 진행 상황 로그
                current_time = time.time()
                if current_time - last_log_time > 30:
                    elapsed = int(current_time - start_time)
                    logger.info(f"Still waiting for response... ({elapsed}s elapsed)")
                    last_log_time = current_time
                
                # 동적 폴링 간격 (응답 중이면 더 자주 체크, 아니면 간격 늘림)
                polling_interval = 0.2 if is_responding else min(1.0, polling_interval * 1.5)
                time.sleep(polling_interval)
            
            logger.warning(f"Timeout waiting for response completion after {timeout}s")
            return False
            
        except Exception as e:
            logger.error(f"Error waiting for response: {e}")
            logger.error(traceback.format_exc())
            return False

    def get_last_python_code(self, tab):
        """
        마지막 Python 코드 블록을 가져옵니다.
        HTML 구조가 변경되어도 작동하도록 개선되었습니다.
        """
        try:
            js_code = """
            (function() {
                // 여러 셀렉터를 시도하여 코드 블록 찾기
                let codeBlocks = document.querySelectorAll('code.hljs.language-python');
                
                // 첫 번째 셀렉터로 찾지 못하면 다른 셀렉터 시도
                if (codeBlocks.length === 0) {
                    codeBlocks = document.querySelectorAll('pre code.language-python');
                }
                
                if (codeBlocks.length === 0) {
                    // 일반적인 code 태그 찾기
                    const allCodeBlocks = document.querySelectorAll('pre code');
                    // Python 코드로 보이는 블록만 필터링
                    codeBlocks = Array.from(allCodeBlocks).filter(block => {
                        const text = block.textContent;
                        return text.includes('import') || text.includes('def ') || 
                            text.includes('class ') || text.includes('if __name__');
                    });
                }
                
                if (codeBlocks.length === 0) return '';
                
                // 마지막 코드 블록 반환
                return codeBlocks[codeBlocks.length - 1].textContent;
            })();
            """
            
            result = tab.Runtime.evaluate(expression=js_code)
            code = result.get('result', {}).get('value', "")
            
            if code:
                logger.info(f"Found Python code ({len(code)} characters)")
            else:
                logger.warning("No Python code found")
                
            return code
            
        except Exception as e:
            logger.error(f"Error getting Python code: {e}")
            return ""

    def summery_answer(self, browser, tab, rsltstrpost, comment_of_this_cmd, simplify_command):
        """
        사용자의 명령어 실행 결과를 ChatGPT-4o-mini에게 전송하여 요약 정보를 얻습니다.
        
        Args:
            browser2: 브라우저 객체 (ChatGPT-4o-mini 탭)
            tab2: 브라우저 탭 객체 (ChatGPT-4o-mini 탭)
            rsltstrpost: 명령어 실행 결과 문자열
        
        Returns:
            구조화된 결과 요약 문자열
        """
        try:
            # 명령어 결과를 요약할 수 있는 프롬프트 작성
            prompt = f"""

    Remove excessively repeated sentences and delete unnecessary content. If successful, clearly indicate that the task has succeeded according to the goal.
    In case of failure, clearly provide the cause of failure.
    ```
    Purpose of this command:
    {comment_of_this_cmd}

    Result of this command:
    {rsltstrpost}

    Summary command for this command:
    {simplify_command}
    ```

    Please respond exactly in the following format:
    purpose of command: [명령어의 목적]
    success : "success" | "failed"
    error: False | true
    error status: [오류가 있다면 오류 내용 설명, 없으면 'no error']
    summary of output: [전체 결과의 핵심 요약]


    The response must contain exactly only the above format. Do not include other explanations or text."""

            # ChatGPT-4o-mini에 프롬프트 전송
            logger.info("Sending command results to ChatGPT-4o-mini for summarization")
            self.send_query(browser, tab, prompt)
            
            # 응답 대기 - 요약은 비교적 빠르게 생성 가능하므로 타임아웃 감소
            if not self.wait_for_response_complete(tab, timeout=90):
                logger.warning("Summary response waiting timed out")
                return "요약 생성 시간 초과"
                
            # ChatGPT 응답 추출
            js_code = """
    (function() {
        try {
            // 다양한 셀렉터로 응답 메시지 찾기
            const selectors = [
                '.markdown.prose', 
                '.text-message .markdown',
                '[data-message-author-role="assistant"] .markdown',
                '.agent-turn .markdown',
                'article .prose',
                '.text-message'
            ];
            
            let lastMessage = null;
            for (const selector of selectors) {
                const elements = document.querySelectorAll(selector);
                if (elements.length > 0) {
                    lastMessage = elements[elements.length - 1];
                    break;
                }
            }
            
            if (!lastMessage) return '응답 메시지를 찾을 수 없음';
            
            // 1. 코드 블록 추출 시도 (hljs 클래스가 있는 code 태그)
            const codeBlocks = lastMessage.querySelectorAll('code.hljs');
            if (codeBlocks && codeBlocks.length > 0) {
                return codeBlocks[codeBlocks.length - 1].textContent;
            }
            
            // 2. 일반 code 태그 확인
            const codeElements = lastMessage.querySelectorAll('code');
            if (codeElements && codeElements.length > 0) {
                return codeElements[codeElements.length - 1].textContent;
            }
            
            // 3. pre 태그 내부 확인
            const preElements = lastMessage.querySelectorAll('pre');
            if (preElements && preElements.length > 0) {
                // pre 태그 내부의 code 확인
                const preCodeElements = preElements[preElements.length - 1].querySelectorAll('code');
                if (preCodeElements && preCodeElements.length > 0) {
                    return preCodeElements[0].textContent;
                }
                return preElements[preElements.length - 1].textContent;
            }
            
            // 4. 일반 텍스트 추출 (위의 모든 방법이 실패한 경우)
            return lastMessage.textContent;
        } catch (error) {
            console.error('요약 추출 오류:', error);
            return '오류: ' + error.toString();
        }
    })();
    """
            
            result = tab.Runtime.evaluate(expression=js_code)
            response_text = result.get('result', {}).get('value', "")
            
            if not response_text or response_text.startswith('오류:') or response_text == '응답 메시지를 찾을 수 없음':
                logger.warning(f"No valid summary response found: {response_text}")
                return "요약 응답을 찾을 수 없습니다"
                
            logger.info(f"Summary generated ({len(response_text)} characters)")
            return response_text
            
        except Exception as e:
            logger.error(f"Error in summery_answer: {e}")
            logger.error(traceback.format_exc())
            return f"요약 생성 중 Error occurred: {str(e)}"

    def execute_chatgpt_cmd_session(self, browser, tab, tab2, query):
        """
        사용자의 쿼리를 ChatGPT에 전달하고, CMD 명령을 실행한 후 결과를 주고받는 세션을 관리합니다.

        Args:
            tab: 브라우저 탭 객체
            query: 사용자의 초기 쿼리

        Returns:
            최종 결과 문자열
        """
        try:
            logger.info(f"Starting ChatGPT CMD session with query: {query}")

            # 이미 import된 cmd_manager 모듈에서 CmdManager 인스턴스 가져오기
            cmd_manager = get_cmd_manager()
            print("cmd_manager", cmd_manager.uid)

            # 작업 완료 플래그 파일 초기화 (이미 존재한다면 삭제)
            if os.path.exists("task_complete.flag"):
                os.remove("task_complete.flag")

            # 초기 쿼리 전송
            cmd_result = cmd_manager.execute_command("echo %CD%", timeout=60)
            rsltstr = cmd_result['stdout'].strip()
            
            initial_prompt = f"""사용자 요청: Current directory path is {rsltstr} 입니다. 
    주의: 항상 작업을 위한 디렉토리로 먼저 이동을 한 뒤에 본격적인 작업을 Start합니다.
    {query}

    이 작업을 수행하기 위한 윈도우즈 CMD 명령어 시퀀스를 단계적으로 제공해주세요.
    첫번째째 명령어 실행 결과를 확인한 후 다음 명령어를 제시하겠습니다.
    rsltstr_summried 에 success 이면 We consider the previous task to be successful.
    cmd 명령어는 다음과 같은 json형식으로 출력합니다.

    {{ "aim": aim of this command,
    "cmd" : cmd code for aim , 
    "simplify_command": ask query for making answer for result of this command
    }}

    예를 들어 d: 의 파일목록을 조회 한다면
    {{ "aim": "search list of files in D:",
    "cmd" : "dir d:",
    "simplify_command": "d:디렉토리의 파일목록을 조회한 결과를 제공하오니 Please summarize to best match the purpose."
    }}

    이전 명령을 확인한 결과 완료된 것으로 판단되어 다음 명령어가 필요 없다면 다음의 형태로로 명확하게 종료를 표시해주세요:
    {{ "aim": "terminated",
    "cmd" : "terminated",
    "simplify_command": conclusion of result of this commands sequence
    }}

    불필요한 설명을 절대 하지 않습니다."""

            logger.info("Sending initial prompt to ChatGPT")
            self.send_query(browser, tab, initial_prompt)

            # 응답 대기
            if not self.wait_for_response_complete(tab, timeout=300):
                logger.warning("Initial response waiting timed out")
                return "오류: ChatGPT 응답 대기 시간 초과"
            time.sleep(1)
            
            # 명령어 실행 및 결과 전송 루프
            max_iterations = 15  # 안전을 위한 최대 반복 횟수
            iteration = 0
            final_result = ""
            answerFailed = False

            try:
                while iteration < max_iterations:
                    time.sleep(5)
                    iteration += 1
                    logger.info(f"Command iteration {iteration}/{max_iterations}")
                    
                    # 작업 완료 플래그 파일 확인
                    if os.path.exists("task_complete.flag"):
                        logger.info("Task completion flag file found")
                        with open("task_complete.flag", "r") as f:
                            flag_content = f.read().strip()
                        if "##TASK_COMPLETE##" in flag_content:
                            logger.info("Task completed with completion flag")
                            final_result = "Task has been completed. Completion flag file has been created."
                            # JSON 상태 파일의 내용 읽기
                            cmd_result = cmd_manager.execute_command('type task_complete.flag', timeout=60)
                            if cmd_result["success"]:
                                final_result += f"\n\nCompletion information: {cmd_result['stdout']}"
                            break
                    
                    # ChatGPT 응답에서 명령어 추출
                    js_code = """
        (function() {
            // 셀렉터를 통해 응답 메시지 찾기
            const selectors = [
                '.markdown.prose', 
                '.text-message .markdown',
                '[data-message-author-role="assistant"] .markdown',
                '.agent-turn .markdown',
                'article .prose'
            ];
            
            let lastMessage = null;
            
            // 각 셀렉터로 시도
            for (const selector of selectors) {
                const elements = document.querySelectorAll(selector);
                if (elements.length > 0) {
                    lastMessage = elements[elements.length - 1];
                    break;
                }
            }
            
            // 메시지를 찾지 못한 경우
            if (!lastMessage) {
                return '';
            }
            
            // 메시지 텍스트 추출
            const fullText = lastMessage.textContent || '';
            
            // JSON 형식 명령어 추출 시도
            try {
                // JSON 포맷 추출 (다양한 형태 지원)
                // 1. {로 Start하고 }로 끝나는 텍스트 추출
                const jsonRegex = /\\{[^\\{\\}]*"aim"\\s*:\\s*"[^"]*"[^\\{\\}]*"cmd"\\s*:\\s*"[^"]*"[^\\{\\}]*\\}/g;
                const jsonMatches = fullText.match(jsonRegex);
                
                if (jsonMatches && jsonMatches.length > 0) {
                    // 가장 마지막 JSON 포맷 반환
                    return jsonMatches[jsonMatches.length - 1];
                }
                
                // 2. 코드 블록에서 JSON 추출 시도 - pre 및 code 태그 내용 확인
                const codeElements = lastMessage.querySelectorAll('code');
                if (codeElements && codeElements.length > 0) {
                    // 마지막 코드 블록의 텍스트 내용
                    const codeText = codeElements[codeElements.length - 1].textContent;
                    // 코드 블록 내에서 JSON 찾기
                    const codeJsonMatches = codeText.match(jsonRegex);
                    if (codeJsonMatches && codeJsonMatches.length > 0) {
                        return codeJsonMatches[codeJsonMatches.length - 1];
                    }
                }
                
                // 3. 텍스트에서 정규식을 사용한 코드 블록 추출
                const codeBlockRegex = /```(?:json)?([^`]+)```/g;
                const codeMatches = [];
                let match;
                while ((match = codeBlockRegex.exec(fullText)) !== null) {
                    codeMatches.push(match[1].trim());
                }
                
                if (codeMatches.length > 0) {
                    const lastCodeBlock = codeMatches[codeMatches.length - 1];
                    // 코드 블록 내용에서 JSON 형식 찾기
                    const jsonInCodeRegex = /\\{[^\\{\\}]*"aim"\\s*:\\s*"[^"]*"[^\\{\\}]*"cmd"\\s*:\\s*"[^"]*"[^\\{\\}]*\\}/g;
                    const jsonInCodeMatches = lastCodeBlock.match(jsonInCodeRegex);
                    
                    if (jsonInCodeMatches && jsonInCodeMatches.length > 0) {
                        return jsonInCodeMatches[jsonInCodeMatches.length - 1];
                    }
                    
                    // JSON 형식이 아닌 일반 코드 블록 반환
                    return lastCodeBlock;
                }
                
                // 4. 기존 완료 패턴 확인
                const hasResult = 
                    fullText.includes('##TASK_COMPLETE##') || 
                    fullText.includes('{"status":"complete"') || 
                    fullText.includes('에이전트작업완료') ||
                    (fullText.includes('task_complete.flag') && fullText.includes('작업완료')) ||
                    fullText.includes('"aim": "terminated"');
                
                if (hasResult) {
                    // 종료 메시지인 경우 전체 텍스트 반환
                    return fullText;
                }
                
                // JSON 형식이 없고 코드 블록도 없는 경우 빈 문자열 반환
                return '';
                
            } catch (error) {
                // 오류 발생 시 원본 텍스트 반환
                console.error('JSON 추출 오류:', error);
                return fullText;
            }
        })();
        """
                    
                    result = tab.Runtime.evaluate(expression=js_code)
                    response_text = result.get('result', {}).get('value', "")
                    print("Command response:", response_text[:100])
                    
                    # 응답 텍스트에서 명령어 추출 또는 완료 여부 확인
                    if any(marker in response_text for marker in [
                        "##TASK_COMPLETE##", 
                        "\"status\":\"complete\"", 
                        "에이전트작업완료", 
                        "\"aim\": \"terminated\""
                    ]):
                        logger.info("Task completion detected in response")
                        final_result = response_text
                        break
                        
                    # 코드 블록에서 추출한 명령어가 있으면 실행
                    cmd_to_execute = response_text.strip() if response_text else None
                    comment_of_this_cmd = ''
                    
                    
                    # JSON에서 cmd 필드 추출
                    simplify_command = None
                    if answerFailed == False:
                        try:
                            # JSON 형식 추출 시도
                            json_pattern = r'\{.*"aim"\s*:\s*"[^"]*".*"cmd"\s*:\s*"[^"]*".*\}'
                            json_match = re.search(json_pattern, cmd_to_execute, re.DOTALL)
                            
                            if json_match:
                                json_str = json_match.group(0)
                                # JSON 문자열 정규화 - 따옴표 확인 및 백슬래시 이스케이프 처리
                                json_str = json_str.replace("'", '"')
                                
                                # 백슬래시 문제 해결
                                # 1. 모든 백슬래시를 임시 토큰으로 변환
                                json_str = json_str.replace('\\', '___BACKSLASH___')
                                # 2. 임시 토큰을 이스케이프된 백슬래시로 변환
                                json_str = json_str.replace('___BACKSLASH___', '\\\\')
                                
                                # JSON 유효성 확인 및 정규화
                                try:
                                    # 정규화된 JSON 문자열 파싱
                                    json_data = json.loads(json_str)
                                    
                                    if "aim" in json_data and "cmd" in json_data:
                                        comment_of_this_cmd = json_data["aim"]
                                        cmd_to_execute = json_data["cmd"]
                                        simplify_command = json_data["simplify_command"]
                                        
                                        # 종료 명령 확인
                                        if cmd_to_execute == "terminated":
                                            logger.info("Termination command detected")
                                            final_result = f"작업이 완료되었습니다.\n\n목표: {comment_of_this_cmd}"
                                            break
                                except json.JSONDecodeError as je:
                                    # JSON 파싱 실패 시 직접 추출 시도
                                    logger.warning(f"JSON parsing failed: {je}, trying direct extraction")
                                    
                                    # 정규식으로 aim과 cmd 직접 추출
                                    aim_match = re.search(r'"aim"\s*:\s*"([^"]*)"', json_str)
                                    cmd_match = re.search(r'"cmd"\s*:\s*"([^"]*)"', json_str)
                                    simplify_command_match = re.search(r'"simplify_command"\s*:\s*"([^"]*)"', json_str)
                                    
                                    if aim_match and cmd_match:
                                        comment_of_this_cmd = aim_match.group(1)
                                        cmd_to_execute = cmd_match.group(1)
                                        cc = simplify_command_match.group(1)
                                        # 종료 명령 확인
                                        if cmd_to_execute == "terminated":
                                            logger.info("Termination command detected")
                                            final_result = f"작업이 완료되었습니다.\n\n목표: {comment_of_this_cmd}"
                                            break
                        except Exception as e:
                            print(traceback.format_exc())
                            logger.warning(f"Error parsing JSON command: {e}")
                            # JSON 파싱 오류 시 원본 사용
                        
                        print("cmd_to_execute", cmd_to_execute)
                        
                        if not cmd_to_execute:
                            logger.warning("No command found in response")
                            self.send_query(browser, tab, "명령어를 찾을 수 없습니다. JSON 형식으로 명확하게 제시해주세요.")
                            
                            if not self.wait_for_response_complete(tab, timeout=300):
                                logger.warning("Response waiting timed out")
                            continue
                    
                        # 명령어 실행
                        cmd_result = cmd_manager.execute_command("dir", timeout=60)
                        rsltstrpre = '---dir result before operation---\n'
                        rsltstrpre += cmd_result['stdout'].strip()
                        rsltstrpre += cmd_result['stderr'].strip()
                        
                        logger.info(f"Executing command: {cmd_to_execute}")
                        cmd_result = cmd_manager.execute_command(cmd_to_execute, timeout=300)
                        
                        cmd_resultpost = cmd_manager.execute_command("dir", timeout=60)
                        rsltstrpost = '\n\n---dir result after operation---\n'
                        rsltstrpost += cmd_resultpost['stdout'].strip()
                        rsltstrpost += cmd_resultpost['stderr'].strip()
                        
                        rsltstr_summried = self.summery_answer(browser, tab2, rsltstrpost, comment_of_this_cmd, simplify_command)
                        print("rsltstr_summried", rsltstr_summried)
                            
                        # 실행 결과 준비
                        if True:  # cmd_result["success"]:
                            # 지정된 형식으로 결과 구성
                            formatted_output = cmd_result.get('formatted_output', '')
                            
                            # 형식이 없는 경우 이전 방식으로 구성
                            if not formatted_output:
                                rsltstr = "----stdout---\n" + cmd_result['stdout'] + "\n\n---stderr---\n" + cmd_result['stderr']
                                result_message = f"""
            ----Agent's final goal----
            {query}
            ----Current command execution result----
            {rsltstr}

            ----Result summary----
            {rsltstr_summried}
            
            rsltstr_summried 에 success : "success" 이면 We consider the previous task to be successful.
            현재의 결과요약을 통해 원하는 작업이 실행이 되었는지 확인 후, 
            
            Please suggest the next command considering the next task.
            
            If you did not get the desired content through the result summary, clearly present how and why to modify the simplify_command to reduce the logs

            cmd 명령어는 다음과 같은 json형식으로 출력합니다.

            {{ "aim": aim of this command,
            "cmd" : cmd code for aim , 
            "simplify_command": additional query for making "a truncate not necessary logs for rsltstr of this command, explain how to remove not necessary logs and why 
            }}

            예를 들어 d: 의 파일목록을 조회 한다면
            {{ "aim": "search list of files in D:",
            "cmd" : "dir d:",
            "simplify_command": "d:디렉토리의 파일목록을 조회한 결과를 제공하오니 Please summarize to best match the purpose.The summary includes the following content....(설명)"
            }}

            이전 명령을 확인한 결과 완료된 것으로 판단되어 다음 명령어가 필요 없다면 다음의 형태로로 명확하게 종료를 표시해주세요:
            {{ "aim": "terminated",
            "cmd" : "terminated",
            "simplify_command": "terminated"
            }}
            """
                            else:
                                # 새로운 형식 사용
                                result_message = f"""
            ----Agent's final goal----
            {query}

            ----Current command execution result----
            {formatted_output}

            ----Result summary----
            {rsltstr_summried}

            rsltstr_summried 에 success : "success" 이면 We consider the previous task to be successful.
            현재의 결과요약을 통해 원하는 작업이 실행이 되었는지 확인 후, 
            
            Please suggest the next command considering the next task.
            
            If you did not get the desired content through the result summary, clearly present how and why to modify the simplify_command to reduce the logs

            cmd 명령어는 다음과 같은 json형식으로 출력합니다.

            {{ "aim": aim of this command,
            "cmd" : cmd code for aim , 
            "simplify_command": additional query for making "a truncate not necessary logs for rsltstr of this command, explain how to remove not necessary logs and why 
            }}

            예를 들어 d: 의 파일목록을 조회 한다면
            {{ "aim": "search list of files in D:",
            "cmd" : "dir d:",
            "simplify_command": "d:디렉토리의 파일목록을 조회한 결과를 제공하오니 Please summarize to best match the purpose.The summary includes the following content....(설명)"
            }}

            이전 명령을 확인한 결과 완료된 것으로 판단되어 다음 명령어가 필요 없다면 다음의 형태로로 명확하게 종료를 표시해주세요:
            {{ "aim": "terminated",
            "cmd" : "terminated",
            "simplify_command": "terminated"
            }}
            """
                        else:
                                result_message = """명령어를 찾을 수 없습니다. JSON 형식으로 명확하게 다시 제시해주세요.
                
                            rsltstr_summried 에 success : "success" 이면 We consider the previous task to be successful.
                            현재의 결과요약을 통해 원하는 작업이 실행이 되었는지 확인 후, 
                            
                            Please suggest the next command considering the next task.
                            
                            If you did not get the desired content through the result summary, clearly present how and why to modify the simplify_command to reduce the logs

                            cmd 명령어는 다음과 같은 json형식으로 출력합니다.

                            {{ "aim": aim of this command,
                            "cmd" : cmd code for aim , 
                            "simplify_command": additional query for making "a truncate not necessary logs for rsltstr of this command, explain how to remove not necessary logs and why 
                            }}

                            예를 들어 d: 의 파일목록을 조회 한다면
                            {{ "aim": "search list of files in D:",
                            "cmd" : "dir d:",
                            "simplify_command": "d:디렉토리의 파일목록을 조회한 결과를 제공하오니 Please summarize to best match the purpose.The summary includes the following content....(설명)"
                            }}

                            이전 명령을 확인한 결과 완료된 것으로 판단되어 다음 명령어가 필요 없다면 다음의 형태로로 명확하게 종료를 표시해주세요:
                            {{ "aim": "terminated",
                            "cmd" : "terminated",
                            "simplify_command": "terminated"
                            }}
                        """
                    # 결과 전송
                    self.send_query(browser, tab, result_message)
                    
                    # 응답 대기
                    if not self.wait_for_response_complete(tab, timeout=300):
                        logger.warning("Response waiting timed out")
                        continue

                    # 작업 완료 플래그 파일 다시 확인
                    if os.path.exists("task_complete.flag"):
                        logger.info("Task completion flag file found after response")
                        with open("task_complete.flag", "r") as f:
                            flag_content = f.read().strip()
                        if "##TASK_COMPLETE##" in flag_content:
                            logger.info("Task completed with completion flag")
                            final_result = "Task has been completed. Completion flag file has been created."
                            # JSON 상태 파일의 내용 읽기
                            cmd_result = cmd_manager.execute_command('type task_complete.flag', timeout=60)
                            if cmd_result["success"]:
                                final_result += f"\n\nCompletion information: {cmd_result['stdout']}"
                            break

                if not final_result and iteration >= max_iterations:
                    logger.warning("Maximum iterations reached without completion")
                    final_result = "Maximum number of iterations reached. The task may not have been completed."
                    
                # 최종 결과 출력 시 시각적 구분 추가
                logger.info("=" * 50)
                logger.info("Task status: Completed" if "작업이 완료되었습니다" in final_result else "Task status: Incomplete")
                logger.info("=" * 50)
                
                # Task result summary 생성
                summary = "== Task result summary ==\n"
                if os.path.exists("task_complete.flag"):
                    with open("task_complete.flag", "r") as f:
                        flag_content = f.read().strip()
                    summary += f"Completion status: Success\nCompletion tag: {flag_content}\n"
                else:
                    summary += "Completion status: Incomplete or failed\n"
                
                # 최종 디렉토리 상태
                cmd_result = cmd_manager.execute_command("dir", timeout=60)
                summary += f"\nFinal directory status:\n{cmd_result['stdout'][:500]}...\n"
                
                logger.info(summary)
                return final_result + "\n\n" + summary
                
            except Exception as e:
                answerFailed = True
                logger.error(f"Error in command execution loop: {e}")
                logger.error(traceback.format_exc())
                return f"Error occurred during command execution: {str(e)}"
            
        except Exception as e:
            logger.error(f"Error in execute_chatgpt_cmd_session: {str(e)}")
            logger.error(traceback.format_exc())
            return f"Error occurred: {str(e)}"

    def extract_command_from_response(self, response_text):
        """
        ChatGPT 응답에서 실행할 CMD 명령어를 추출합니다.
        
        Args:
            response_text: ChatGPT 응답 텍스트
            
        Returns:
            추출된 명령어 문자열 또는 빈 문자열
        """
        try:
            # 코드 블록에서 명령어 추출 시도
            import re
            print("response_text", response_text)
            # 코드 블록 패턴 (```로 둘러싸인 모든 형태의 코드)
            code_block_pattern = r'```(?:cmd|bat|bash|shell|powershell|)?\s*(.*?)\s*```'
            code_blocks = re.findall(code_block_pattern, response_text, re.DOTALL)
            
            if code_blocks:
                # 가장 마지막 코드 블록 사용
                cmd = code_blocks[-1].strip()
                logger.info(f"Found command in code block: {cmd}")
                return cmd
            
            # 코드 블록이 없는 경우, 일반 텍스트에서 명령어 찾기
            lines = response_text.split('\n')
            
            # Windows CMD 명령어 목록
            common_cmd_prefixes = [
                'dir', 'cd', 'copy', 'del', 'echo', 'type', 'mkdir', 'rmdir', 
                'ping', 'ipconfig', 'netstat', 'tasklist', 'findstr', 'systeminfo',
                'ver', 'chdir', 'cls', 'date', 'time', 'rd', 'md', 'ren', 'move'
            ]
            
            # 명령어 인식 방법 1: 명령어 지시자로 Start하는 라인
            cmd_indicators = ["명령어:", "실행:", "CMD:", "명령:", "커맨드:", "command:", "다음 명령어:"]
            for line in lines:
                for indicator in cmd_indicators:
                    if indicator.lower() in line.lower():
                        cmd = line.split(indicator, 1)[1].strip()
                        logger.info(f"Found command with indicator: {cmd}")
                        return cmd
            
            # 명령어 인식 방법 2: 흔한 CMD 명령어로 Start하는 라인
            for line in lines:
                line_stripped = line.strip()
                for prefix in common_cmd_prefixes:
                    # 명령어 형태: 'dir', 'dir C:\', 'cd /d C:\' 등
                    if re.match(f"^{prefix}\\b", line_stripped, re.IGNORECASE):
                        logger.info(f"Found command by prefix: {line_stripped}")
                        return line_stripped
            
            # 명령어 인식 방법 3: 따옴표로 둘러싸인 명령어
            quoted_cmd_pattern = r'["\']([^"\']+?)["\']'
            for line in lines:
                line_stripped = line.strip()
                quoted_matches = re.findall(quoted_cmd_pattern, line_stripped)
                for match in quoted_matches:
                    for prefix in common_cmd_prefixes:
                        if re.match(f"^{prefix}\\b", match, re.IGNORECASE):
                            logger.info(f"Found command in quotes: {match}")
                            return match
            
            logger.warning("No command found in response")
            logger.debug(f"Response content: {response_text[:500]}...")
            return ""
            
        except Exception as e:
            logger.error(f"Error extracting command: {e}")
            logger.error(traceback.format_exc())
            return ""

    def cmd_session_main(self):
        """
        CMD 세션 메인 함수
        """
        try:
            # 사용자 입력 받기
            print("Input query?")
            user_query = input("Enter a query for CMD task: ")
            
            # 브라우저가 이미 Start되었으므로 페이지 로드만 확인
            if not self.tab:
                logger.error("No main tab available")
                return
                
            # 페이지 로드 확인
            if not self.check_page_loaded(self.tab, timeout=15):
                logger.error("Page load check failed")
                return
                
            # CMD 세션 실행
            result = self.execute_chatgpt_cmd_session(self.browser, self.tab, self.tab2, user_query)
            
            # 결과 출력
            print("\n--- Task result ---")
            print(result)
            
        except Exception as e:
            logger.error(f"Unexpected error in CMD session: {e}")
            logger.error(traceback.format_exc())
        finally:
                # 안전하게 탭 정리 (브라우저는 종료하지 않음)
                logger.info("CMD session completed, cleaning up tabs")

    def newmain(self):
        try:
            # 작업 모드 선택 (기존 기능 유지하면서 CMD 세션 기능 추가)
            print("Select operation mode:")
            print("1. Code analysis and modification (existing feature)")
            print("2. CMD command execution session")
            
            mode = "2"
            if mode == "2":
                self.cmd_session_main()
            else:
                # 기존 main 함수 내용 (코드 분석 및 수정 기능)
                # 브라우저가 이미 Start되었으므로 페이지 로드만 확인
                if not self.tab:
                    logger.error("No main tab available")
                    return
                
                # 페이지 로드 확인 - 더 짧은 타임아웃
                if not self.check_page_loaded(self.tab, timeout=15):  # 타임아웃 감소 (기본값 30초 → 15초)
                    logger.error("Page load check failed")
                    return
                    
                # 테스트 쿼리 전송
                logger.info("Sending test query...")
                self.send_query(self.browser, self.tab, "Please tell me about today's weather:")
                
                # 응답 대기 - 더 짧은 타임아웃
                if not self.wait_for_response_complete(self.tab, timeout=180):  # 타임아웃 감소 (기본값 300초 → 180초)
                    logger.warning("Response waiting timed out")
                
                # 코드 가져오기
                python_code = self.get_last_python_code(self.tab)
                if python_code:
                    # 결과 코드 저장
                    with open("fixed_code.py", "w", encoding="utf-8") as f:
                        f.write(python_code)
                    logger.info("Code saved to fixed_code.py")
            
        except Exception as e:
            logger.error(f"Unexpected error in main: {e}")
            logger.error(traceback.format_exc())
        finally:
                logger.info("Exiting program")

    def safely_close_tab(self, browser, tab):
        """
        탭을 안전하게 닫습니다.
        """
        try:
            if tab and hasattr(tab, 'id') and tab.id:
                return self.complete_tab_cleanup(browser, tab)
            else:
                logger.warning("Cannot safely close invalid tab")
                return False
        except Exception as e:
            logger.error(f"Error in safely_close_tab: {e}")
            return False

    def extract_useful_content_from_text(self, text):
        """
        텍스트 응답에서 유용한 정보를 추출하여 구조화합니다.
        JSON 형식이 아닌 일반 텍스트에서도 정보를 추출할 수 있도록 합니다.
        """
        result = {
            "page_structure": "",
            "target_elements": [],
            "selectors": {},
            "crawling_method": "",
            "python_code": "",
            "javascript_handling": "",
            "dynamic_content": "",
            "analysis_complete": True,
            "additional_instructions": ""
        }
        
        # 파이썬 코드 블록 추출
        python_code_pattern = r'```python\s*([\s\S]*?)\s*```'
        python_matches = re.findall(python_code_pattern, text, re.MULTILINE)
        if python_matches:
            result["python_code"] = python_matches[0].strip()
        
        # 코드 블록이 없는 경우 일반 코드 블록에서 찾기
        if not result["python_code"]:
            code_pattern = r'```\s*([\s\S]*?)\s*```'
            code_matches = re.findall(code_pattern, text, re.MULTILINE)
            if code_matches:
                for code in code_matches:
                    # 파이썬 코드로 보이는 내용 확인
                    if "import" in code or "def " in code or "class " in code:
                        result["python_code"] = code.strip()
                        break
        
        # 섹션 기반 추출 (Page structure, Target elements 등)
        sections = {
            "Page structure": "page_structure",
            "웹Page structure": "page_structure", 
            "Target elements": "target_elements",
            "Target elements": "target_elements",
            "Selectors": "selectors",
            "Crawling method": "crawling_method",
            "JavaScript handling": "javascript_handling",
            "Dynamic content": "dynamic_content"
        }
        
        for section_name, result_key in sections.items():
            pattern = rf"{section_name}[:\s]+(.*?)(?:\n\n|\n[A-Z가-힣])"
            matches = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
            if matches:
                content = matches.group(1).strip()
                if result_key == "target_elements":
                    # 리스트 항목 추출
                    elements = re.findall(r'[-*]\s*(.*?)(?:\n|$)', content)
                    if elements:
                        result[result_key] = elements
                    else:
                        result[result_key] = [content]
                elif result_key == "selectors":
                    # 셀렉터 추출 (name: selector 형식)
                    selector_pairs = re.findall(r'([^:]+):\s*([^\n]+)', content)
                    if selector_pairs:
                        result[result_key] = {k.strip(): v.strip() for k, v in selector_pairs}
                else:
                    result[result_key] = content
        
        # 결과가 비어있는 필드 확인
        if not result["page_structure"]:
            # 일반 텍스트에서 첫 몇 문단 추출
            paragraphs = text.split('\n\n')
            if paragraphs:
                result["page_structure"] = paragraphs[0].strip()
        
        # 필수 정보가 모두 있는지 확인
        has_minimum_info = result["python_code"] and result["page_structure"]
        result["analysis_complete"] = has_minimum_info
        
        # 응답 일부 저장
        result["raw_response"] = text[:1000]
        
        return result

    def test_crawl_functionality(self, analysis_result, url, test_string):
        """
        분석 결과를 바탕으로 실제 크롤링을 테스트합니다.
        Chrome DevTools Protocol을 통해 브라우저 환경에서 직접 실행합니다.
        
        Args:
            analysis_result: 크롤링 분석 결과 딕셔너리
            url: 테스트할 URL
            test_string: 크롤링 결과에서 찾을 테스트 문자열
            
        Returns:
            테스트 결과를 담은 딕셔너리
        """
        test_tab = None
        try:
            logger.info(f"Starting test crawl for URL: {url}")
            logger.info(f"Test string to verify: {test_string}")
            
            # 테스트 결과 초기화
            test_result = {
                "success": False,
                "time_taken": 0,
                "error": None,
                "data_sample": None,
                "test_string_found": False,
                "executed_code": None,
                "output": None,
                "stderr": None
            }
            
            # 크롤링 코드 추출 - Python에서 JavaScript로 변환이 필요
            python_code = analysis_result.get('python_code', '')
            if not python_code:
                test_result["error"] = "No Python code found in analysis results"
                logger.error(test_result["error"])
                return test_result
            
            # 새 탭 열기
            logger.info("Opening new tab for crawl testing")
            try:
                test_tab = self.browser.new_tab()
                test_tab_id = test_tab.id
                logger.info(f"Created test tab with ID: {test_tab_id}")
                
                test_tab.start()
                test_tab.Network.enable()
                test_tab.Page.enable()
                test_tab.Runtime.enable()
                
                # 페이지 이동
                logger.info(f"Navigating to test URL: {url}")
                test_tab.Page.navigate(url=url)
                
                # 페이지 로드 완료 대기
                logger.info("Waiting for page load to complete")
                
                def on_page_load_event(**kwargs):
                    logger.info("Page load event fired")
                
                test_tab.Page.loadEventFired = on_page_load_event
                
                # 페이지 로드 대기 (타임아웃 30초)
                start_time = time.time()
                load_timeout = 30
                page_loaded = False
                
                while time.time() - start_time < load_timeout:
                    # 페이지 로드 상태 확인
                    try:
                        self.browser.activate_tab(test_tab.id)
                        result = test_tab.Runtime.evaluate(expression="document.readyState")
                        ready_state = result.get('result', {}).get('value', '')
                        
                        if ready_state == 'complete':
                            logger.info("Page load complete")
                            page_loaded = True
                            break
                    except Exception as load_error:
                        logger.warning(f"Error checking page load state: {load_error}")
                    
                    time.sleep(1)
                
                if not page_loaded:
                    logger.warning(f"Page load timeout after {load_timeout} seconds")
                    test_result["error"] = f"Page load timeout after {load_timeout} seconds"
                    return test_result
                
                # 추가 대기 시간 (JavaScript 실행 완료를 위해)
                time.sleep(3)
                
                # 테스트 코드 실행 시간 측정 Start
                start_time = time.time()
                
                # JavaScript 실행 코드 생성
                js_crawl_code = self._generate_js_crawler_code(python_code, test_string)
                test_result["executed_code"] = js_crawl_code
                
                logger.info("Executing JavaScript crawler code")
                
                # JavaScript 코드 실행
                try:
                    # 디버깅 정보 로깅
                    js_lines = js_crawl_code.split("\n")
                    logger.debug(f"JavaScript code to execute ({len(js_lines)} lines):")
                    for i, line in enumerate(js_lines[:10]):
                        logger.debug(f"[{i+1}] {line}")
                    if len(js_lines) > 10:
                        logger.debug(f"... (and {len(js_lines) - 10} more lines)")
                    self.browser.activate_tab(test_tab.id)
                    js_result = test_tab.Runtime.evaluate(
                        expression=js_crawl_code,
                        awaitPromise=True,
                        timeout=60000  # 60초 타임아웃
                    )
                    
                    # 실행 결과 확인
                    js_error = js_result.get('exceptionDetails')
                    if js_error:
                        error_msg = js_error.get('exception', {}).get('description', 'Unknown JS error')
                        line_number = js_error.get('lineNumber', -1)
                        column_number = js_error.get('columnNumber', -1)
                        
                        error_detail = f"JavaScript execution error: {error_msg} at line {line_number}:{column_number}"
                        
                        # 에러가 발생한 라인 주변 코드 출력
                        if line_number >= 0 and line_number < len(js_lines):
                            error_context = "\nError context:\n"
                            start_line = max(0, line_number - 2)
                            end_line = min(len(js_lines), line_number + 3)
                            
                            for i in range(start_line, end_line):
                                prefix = ">> " if i == line_number else "   "
                                error_context += f"{prefix}[{i+1}] {js_lines[i]}\n"
                            
                            error_detail += error_context
                        
                        test_result["error"] = error_detail
                        test_result["stderr"] = error_msg
                        logger.error(error_detail)
                    else:
                        # 성공한 경우 결과 추출
                        result_value = js_result.get('result', {}).get('value')
                        
                        if isinstance(result_value, dict):
                            # 가져온 결과 저장
                            data = result_value.get('data')
                            log_messages = result_value.get('log', [])
                            js_error = result_value.get('error')
                            
                            # 로그 출력
                            for log_msg in log_messages:
                                logger.info(f"JS Crawler: {log_msg}")
                            
                            test_result["data_sample"] = data
                            test_result["output"] = "\n".join(log_messages) if log_messages else ""
                            test_result["error"] = js_error
                            test_result["test_string_found"] = result_value.get('testStringFound', False)
                            test_result["success"] = not js_error and result_value.get('success', False)
                            
                            logger.info(f"JavaScript crawler execution completed with success: {test_result['success']}")
                            
                            if test_result["test_string_found"]:
                                logger.info(f"Test string '{test_string}' was found")
                            elif test_string:
                                logger.warning(f"Test string '{test_string}' was NOT found")
                        else:
                            # 결과가 예상 형식이 아닌 경우
                            test_result["data_sample"] = result_value
                            test_result["success"] = result_value is not None
                            
                            # 테스트 문자열 확인
                            if test_string and result_value:
                                result_str = str(result_value)
                                test_result["test_string_found"] = test_string.lower() in result_str.lower()
                                logger.info(f"Test string found: {test_result['test_string_found']}")
                            
                            logger.warning("JavaScript crawler returned unexpected format")
                
                except Exception as js_exec_error:
                    error_msg = str(js_exec_error)
                    logger.error(f"Error executing JavaScript: {error_msg}")
                    
                    test_result["error"] = f"Error executing JavaScript: {error_msg}"
                    test_result["stderr"] = traceback.format_exc()
                
                # 실행 시간 계산
                execution_time = time.time() - start_time
                test_result["time_taken"] = execution_time
                
                # 탭 정리
                try:
                    if test_tab:
                        logger.info(f"Closing test tab: {test_tab_id}")
                        self.complete_tab_cleanup(self.browser, test_tab)
                        test_tab = None
                except Exception as close_error:
                    logger.warning(f"Error during test tab cleanup: {close_error}")
                    # 강제로 객체 정리
                    test_tab = None
            except Exception as tab_error:
                error_msg = str(tab_error)
                logger.error(f"Browser tab error: {error_msg}")
                logger.error(traceback.format_exc())
                
                test_result["error"] = f"Browser tab error: {error_msg}"
                test_result["stderr"] = traceback.format_exc()
            
            # 결과 로깅
            if test_result["success"]:
                logger.info(f"Test crawl completed successfully in {test_result['time_taken']:.2f} seconds")
                if isinstance(test_result["data_sample"], (list, dict)):
                    logger.info(f"Sample data: {str(test_result['data_sample'][:3]) if isinstance(test_result['data_sample'], list) else str(test_result['data_sample'])[:200]}...")
            else:
                logger.warning(f"Test crawl failed: {test_result.get('error', 'Unknown error')}")
            
            return test_result
        
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in test_crawl_functionality: {error_msg}")
            logger.error(traceback.format_exc())
            
            # 탭 정리 (예외 발생 시에도)
            if test_tab:
                try:
                    # 순차적으로 정리하여 오류 최소화
                    logger.info(f"Emergency cleanup of tab in exception handler")
                    self.complete_tab_cleanup(self.browser, test_tab)
                except Exception as e:
                    logger.warning(f"Complete cleanup failure: {e}")
                
                # 강제로 참조 제거
                test_tab = None
            
            return {
                "success": False,
                "time_taken": 0,
                "error": error_msg,
                "data_sample": None,
                "test_string_found": False,
                "executed_code": None,
                "output": None,
                "stderr": traceback.format_exc()
            }
    
    def _convert_python_to_js_crawler(self, python_code, url, test_string):
        """
        Python 크롤링 코드를 JavaScript로 변환합니다.
        
        Args:
            python_code: 변환할 Python 코드
            url: 크롤링할 URL
            test_string: 테스트할 문자열
            
        Returns:
            JavaScript 크롤링 코드
        """
        logger.info("Converting Python crawler code to JavaScript")
        
        # BeautifulSoup 관련 코드가 있는지 확인
        has_bs4 = "BeautifulSoup" in python_code
        has_requests = "requests." in python_code or "requests.get" in python_code
        has_selenium = "selenium" in python_code or "webdriver" in python_code
        
        # Python 코드에서 주요 패턴 추출
        selectors = []
        # CSS Selectors 추출
        selector_pattern = r'\.(?:find|select|find_all|select_one)\([\'"]([^\'"]+)[\'"]\)'
        selector_matches = re.findall(selector_pattern, python_code)
        selectors.extend(selector_matches)
        
        # XPath 추출
        xpath_pattern = r'\.xpath\([\'"]([^\'"]+)[\'"]\)'
        xpath_matches = re.findall(xpath_pattern, python_code)
        
        # 데이터 추출 패턴
        data_extraction = []
        # .text 패턴
        text_pattern = r'\.(?:text|get_text\(\))'
        if re.search(text_pattern, python_code):
            data_extraction.append("text")
            
        # .get('attribute') 패턴
        attr_pattern = r'\.get\([\'"]([^\'"]+)[\'"]\)'
        attr_matches = re.findall(attr_pattern, python_code)
        for attr in attr_matches:
            if attr not in ['text', 'content']:
                data_extraction.append(f"attribute: {attr}")
        
        # 페이지 탐색/다음 페이지 패턴
        has_pagination = "next_page" in python_code or "pagination" in python_code
        
        # 특수 처리 패턴 (인피니트 스크롤, 버튼 클릭 등)
        special_patterns = {
            "infinite_scroll": "scroll" in python_code,
            "button_click": "click" in python_code,
            "wait": "wait" in python_code or "sleep" in python_code,
            "iframe": "iframe" in python_code,
            "ajax": "ajax" in python_code or "xhr" in python_code,
            "json": "json" in python_code,
        }
        
        # 기본 JavaScript 크롤링 코드 생성
        js_code = f"""
        (async function() {{
            try {{
                console.log("Starting JavaScript crawler test for: {url}");
                
                // 테스트 결과 객체
                const result = {{
                    success: false,
                    error: null,
                    data: null,
                    log: [],
                    testStringFound: false
                }};
                
                // 로그 헬퍼 함수
                function log(message) {{
                    console.log(message);
                    result.log.push(message);
                }}
                
                // 현재 URL 기록
                const currentUrl = window.location.href;
                log(`Current URL: ${{currentUrl}}`);
                
                // 페이지 확인
                if (!document || !document.body) {{
                    result.error = "Document or body is not available";
                    return result;
                }}
                
                // Helper: 요소 대기 함수
                async function waitForElement(selector, timeout = 5000) {{
                    const startTime = Date.now();
                    
                    while (Date.now() - startTime < timeout) {{
                        const element = document.querySelector(selector);
                        if (element) return element;
                        await new Promise(resolve => setTimeout(resolve, 100));
                    }}
                    
                    return null;
                }}
                
                // Helper: 스크롤 함수
                async function scrollToBottom() {{
                    return new Promise(resolve => {{
                        let lastScrollTop = document.documentElement.scrollTop;
                        
                        function scroll() {{
                            window.scrollTo(0, document.documentElement.scrollHeight);
                            
                            setTimeout(() => {{
                                const newScrollTop = document.documentElement.scrollTop;
                                if (newScrollTop === lastScrollTop) {{
                                    // 더 이상 스크롤 되지 않음
                                    resolve();
                                }} else {{
                                    lastScrollTop = newScrollTop;
                                    scroll();
                                }}
                            }}, 1000);
                        }}
                        
                        scroll();
                    }});
                }}
                
                // 데이터 추출 헬퍼
                function extractData(element, extractionType = "text") {{
                    if (!element) return null;
                    
                    if (extractionType === "text") {{
                        return element.textContent.trim();
                    }}
                    
                    if (extractionType.startsWith("attribute:")) {{
                        const attr = extractionType.split(":")[1].trim();
                        return element.getAttribute(attr);
                    }}
                    
                    return element.textContent.trim();
                }}
        """
        
        # Selectors 기반 크롤링 코드
        if selectors:
            js_code += f"""
                // Selectors를 사용한 데이터 추출
                let extractedData = [];
                log("Starting data extraction with selectors");
                
                try {{
            """
            
            # 각 Selectors에 대한 코드 추가
            for i, selector in enumerate(selectors):
                js_code += f"""
                    // Selectors {i+1}: "{selector}"
                    const elements{i} = document.querySelectorAll("{selector}");
                    log(`Selectors "{selector}"로 ${{elements{i}.length}}개 요소 발견`);
                    
                    if (elements{i}.length > 0) {{
                        const items{i} = [];
                        elements{i}.forEach(el => {{
                            items{i}.push(extractData(el, "text"));
                        }});
                        extractedData.push(...items{i});
                        log(`Selectors {i+1}에서 ${{items{i}.length}}개 데이터 추출`);
                    }}
                """
            
            js_code += """
                } catch (extractError) {
                    log(`데이터 추출 중 오류: ${extractError.message}`);
                }
            """
        
        # XPath Selectors 처리
        if xpath_matches:
            js_code += """
                // XPath 평가 헬퍼 함수
                function getElementByXpath(path) {
                    return document.evaluate(
                        path, 
                        document, 
                        null, 
                        XPathResult.FIRST_ORDERED_NODE_TYPE, 
                        null
                    ).singleNodeValue;
                }
                
                function getElementsByXpath(path) {
                    const result = document.evaluate(
                        path, 
                        document, 
                        null, 
                        XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, 
                        null
                    );
                    
                    const elements = [];
                    for (let i = 0; i < result.snapshotLength; i++) {
                        elements.push(result.snapshotItem(i));
                    }
                    return elements;
                }
            """
            
            # 각 XPath에 대한 코드 추가
            for i, xpath in enumerate(xpath_matches):
                js_code += f"""
                    // XPath {i+1}: "{xpath}"
                    try {{
                        const xpathElements{i} = getElementsByXpath("{xpath}");
                        log(`XPath "{xpath}"로 ${{xpathElements{i}.length}}개 요소 발견`);
                        
                        if (xpathElements{i}.length > 0) {{
                            const xpathItems{i} = [];
                            xpathElements{i}.forEach(el => {{
                                xpathItems{i}.push(extractData(el, "text"));
                            }});
                            extractedData.push(...xpathItems{i});
                            log(`XPath {i+1}에서 ${{xpathItems{i}.length}}개 데이터 추출`);
                        }}
                    }} catch (xpathError) {{
                        log(`XPath 처리 중 오류: ${{xpathError.message}}`);
                    }}
                """
        
        # 특수 패턴 처리
        if special_patterns["infinite_scroll"]:
            js_code += """
                // 무한 스크롤 처리
                log("스크롤 수행 Start");
                try {
                    await scrollToBottom();
                    log("페이지 끝까지 스크롤 완료");
                    
                    // 스크롤 후 데이터 다시 추출
                    const scrollElements = document.querySelectorAll("SELECTOR_PLACEHOLDER");
                    if (scrollElements.length > extractedData.length) {
                        log(`스크롤 후 요소 수 증가: ${scrollElements.length}`);
                        
                        extractedData = [];
                        scrollElements.forEach(el => {
                            extractedData.push(extractData(el, "text"));
                        });
                    }
                } catch (scrollError) {
                    log(`스크롤 처리 중 오류: ${scrollError.message}`);
                }
            """.replace("SELECTOR_PLACEHOLDER", selectors[0] if selectors else "a")
        
        if special_patterns["button_click"]:
            js_code += """
                // 버튼 클릭 처리
                log("버튼 클릭 처리 시도");
                try {
                    // "더 보기" 버튼 검색
                    const loadMoreButton = await waitForElement("button:contains('더 보기'), a:contains('더 보기'), button:contains('more'), a:contains('more'), button:contains('load more'), a:contains('load more')");
                    
                    if (loadMoreButton) {
                        log(`버튼 발견: ${loadMoreButton.textContent.trim()}`);
                        loadMoreButton.click();
                        log("버튼 클릭 완료");
                        
                        // 클릭 후 새 컨텐츠 로딩 대기
                        await new Promise(resolve => setTimeout(resolve, 2000));
                        
                        // 데이터 다시 추출
                        const clickElements = document.querySelectorAll("SELECTOR_PLACEHOLDER");
                        log(`클릭 후 요소 수: ${clickElements.length}`);
                        
                        if (clickElements.length > extractedData.length) {
                            extractedData = [];
                            clickElements.forEach(el => {
                                extractedData.push(extractData(el, "text"));
                            });
                        }
                    } else {
                        log("추가 로드 버튼을 찾지 못함");
                    }
                } catch (clickError) {
                    log(`버튼 클릭 처리 중 오류: ${clickError.message}`);
                }
            """.replace("SELECTOR_PLACEHOLDER", selectors[0] if selectors else "a")
        
        # 테스트 문자열 검증
        if test_string:
            js_code += f"""
                // 테스트 문자열 확인: "{test_string}"
                try {{
                    const pageContent = document.body.textContent;
                    result.testStringFound = pageContent.toLowerCase().includes("{test_string.lower()}");
                    log(`테스트 문자열 발견: ${{result.testStringFound}}`);
                    
                    // 추출된 데이터에서도 확인
                    if (!result.testStringFound && extractedData.length > 0) {{
                        const dataContent = JSON.stringify(extractedData);
                        result.testStringFound = dataContent.toLowerCase().includes("{test_string.lower()}");
                        log(`추출 데이터에서 테스트 문자열 발견: ${{result.testStringFound}}`);
                    }}
                }} catch (testStringError) {{
                    log(`테스트 문자열 확인 중 오류: ${{testStringError.message}}`);
                }}
            """
        
        # 결과 마무리
        js_code += """
                // 결과 설정
                result.data = extractedData;
                result.success = extractedData && extractedData.length > 0;
                log(`추출 완료: ${extractedData ? extractedData.length : 0}개 데이터`);
                
                return result;
            } catch (error) {
                return {
                    success: false,
                    error: `JavaScript crawler error: ${error.message}`,
                    data: null,
                    log: [`Fatal error: ${error.message}`],
                    testStringFound: false
                };
            }
        })();
        """
        
        return js_code

    def _generate_js_crawler_code(self, python_code, test_string):
        """
        Python 크롤링 코드를 분석하여 브라우저 환경에서 실행할 JavaScript 코드를 생성합니다.
        
        Args:
            python_code: 파이썬 크롤링 코드
            test_string: 테스트할 문자열
            
        Returns:
            JavaScript 코드
        """
        logger.info("Generating JavaScript crawler code from Python code")
        
        # Python 코드 분석하여 중요 패턴 찾기
        selectors = []
        data_targets = []
        
        # BeautifulSoup Selectors 패턴 추출
        bs4_patterns = {
            'find': r'\.find\([\'"]([^\'"]+)[\'"]',
            'find_all': r'\.find_all\([\'"]([^\'"]+)[\'"]',
            'select': r'\.select\([\'"]([^\'"]+)[\'"]',
            'select_one': r'\.select_one\([\'"]([^\'"]+)[\'"]'
        }
        
        for pattern_name, pattern in bs4_patterns.items():
            matches = re.findall(pattern, python_code)
            for match in matches:
                selectors.append(match)
                logger.info(f"Found {pattern_name} selector: {match}")
        
        # Selenium Selectors 패턴
        selenium_patterns = {
            'find_element_by_css': r'\.find_element_by_css_selector\([\'"]([^\'"]+)[\'"]',
            'find_elements_by_css': r'\.find_elements_by_css_selector\([\'"]([^\'"]+)[\'"]',
            'css_selector': r'\.find_element\(By\.CSS_SELECTOR,\s*[\'"]([^\'"]+)[\'"]',
            'css_selectors': r'\.find_elements\(By\.CSS_SELECTOR,\s*[\'"]([^\'"]+)[\'"]'
        }
        
        for pattern_name, pattern in selenium_patterns.items():
            matches = re.findall(pattern, python_code)
            for match in matches:
                selectors.append(match)
                logger.info(f"Found {pattern_name} selector: {match}")
        
        # XPath 패턴
        xpath_patterns = {
            'find_element_by_xpath': r'\.find_element_by_xpath\([\'"]([^\'"]+)[\'"]',
            'find_elements_by_xpath': r'\.find_elements_by_xpath\([\'"]([^\'"]+)[\'"]',
            'xpath': r'\.find_element\(By\.XPATH,\s*[\'"]([^\'"]+)[\'"]',
            'xpaths': r'\.find_elements\(By\.XPATH,\s*[\'"]([^\'"]+)[\'"]',
            'bs4_xpath': r'\.xpath\([\'"]([^\'"]+)[\'"]'
        }
        
        xpath_selectors = []
        for pattern_name, pattern in xpath_patterns.items():
            matches = re.findall(pattern, python_code)
            for match in matches:
                xpath_selectors.append(match)
                logger.info(f"Found {pattern_name} selector: {match}")
        
        # 데이터 추출 패턴
        data_patterns = {
            'text': r'\.text',
            'get_text': r'\.get_text\(\)',
            'string': r'\.string',
            'inner_text': r'\.get_attribute\([\'"]innerText[\'"]\)',
            'inner_html': r'\.get_attribute\([\'"]innerHTML[\'"]\)',
            'attribute': r'\.get_attribute\([\'"]([^\'"]+)[\'"]\)',
            'attr': r'\.attr\([\'"]([^\'"]+)[\'"]\)',
            'href': r'\.get\([\'"]href[\'"]\)'
        }
        
        for pattern_name, pattern in data_patterns.items():
            if re.search(pattern, python_code):
                if pattern_name in ['attribute', 'attr']:
                    matches = re.findall(pattern, python_code)
                    for match in matches:
                        data_targets.append(f'attribute:{match}')
                        logger.info(f"Found data target: attribute {match}")
                else:
                    data_targets.append(pattern_name)
                    logger.info(f"Found data target: {pattern_name}")
        
        # 특별 처리 패턴 확인
        special_actions = {
            'scroll': 'scroll' in python_code or 'SCROLL' in python_code,
            'infinite_scroll': 'infinite_scroll' in python_code or 'scroll_down' in python_code,
            'click': 'click()' in python_code or '.click(' in python_code,
            'load_more': 'load_more' in python_code or 'show_more' in python_code,
            'pagination': 'pagination' in python_code or 'next_page' in python_code,
            'wait': 'wait' in python_code or 'sleep' in python_code or 'time.sleep' in python_code,
            'iframe': 'iframe' in python_code or 'switch_to.frame' in python_code,
            'json': 'json' in python_code or 'JSON' in python_code
        }
        
        # 셀렉터 없거나 제한된 경우 기본 셀렉터 추가
        if not selectors and not xpath_selectors:
            # HTML에서 의미 있는 요소 선택
            default_selectors = [
                'div.content', 'article', 'section', 'main', 'table', 
                'ul li', '.item', '.product', '.article', '.post',
                '.content', '.result', 'div[id*="content"]', 'div[class*="content"]'
            ]
            selectors = default_selectors
            logger.info("No explicit selectors found, using default selectors")
        
        # 데이터 타겟이 없는 경우 기본값 설정
        if not data_targets:
            data_targets = ['text']
            logger.info("No explicit data targets found, using 'text' as default")
        
        # JavaScript 크롤링 코드 생성
        js_code = f"""
        (async function() {{
            try {{
                console.log("Starting JavaScript crawler test");
                
                // 테스트 결과
                const result = {{
                    success: false,
                    error: null,
                    data: null,
                    log: [],
                    testStringFound: false
                }};
                
                // 로그 헬퍼 함수
                function log(message) {{
                    console.log(message);
                    result.log.push(message);
                }}
                
                log("Current URL: " + window.location.href);
                
                // Helper 함수: 요소에서 데이터 추출
                function extractData(element, method = "text") {{
                    if (!element) return null;
                    
                    if (method === "text" || method === "get_text" || method === "string") {{
                        return element.textContent.trim();
                    }}
                    else if (method === "inner_text") {{
                        return element.innerText.trim();
                    }}
                    else if (method === "inner_html") {{
                        return element.innerHTML.trim();
                    }}
                    else if (method.startsWith("attribute:")) {{
                        const attr = method.split(":")[1];
                        return element.getAttribute(attr);
                    }}
                    else if (method === "href") {{
                        return element.href || element.getAttribute("href");
                    }}
                    
                    // 기본적으로 텍스트 반환
                    return element.textContent.trim();
                }}
                
                // XPath Selectors 도우미 함수
                function getElementByXpath(xpath) {{
                    return document.evaluate(
                        xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null
                    ).singleNodeValue;
                }}
                
                function getElementsByXpath(xpath) {{
                    const result = document.evaluate(
                        xpath, document, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null
                    );
                    
                    const elements = [];
                    for (let i = 0; i < result.snapshotLength; i++) {{
                        elements.push(result.snapshotItem(i));
                    }}
                    return elements;
                }}
                
                // 스크롤 도우미 함수
                async function scrollDown(scrollCount = 3) {{
                    log("Scrolling down the page...");
                    
                    for (let i = 0; i < scrollCount; i++) {{
                        window.scrollTo(0, document.body.scrollHeight);
                        log(`Scroll ${i+1}/${scrollCount}`);
                        
                        // 스크롤 후 대기
                        await new Promise(resolve => setTimeout(resolve, 1000));
                    }}
                    
                    // 페이지 맨 위로 다시 스크롤
                    window.scrollTo(0, 0);
                    log("Scrolled back to top");
                }}
                
                // 무한 스크롤 처리
                async function handleInfiniteScroll() {{
                    log("Handling potential infinite scroll...");
                    
                    const initialHeight = document.body.scrollHeight;
                    let lastHeight = initialHeight;
                    let scrollCount = 0;
                    const maxScrolls = 5;  // 최대 스크롤 횟수 제한
                    
                    while (scrollCount < maxScrolls) {{
                        // 페이지 끝까지 스크롤
                        window.scrollTo(0, document.body.scrollHeight);
                        await new Promise(resolve => setTimeout(resolve, 1500));
                        
                        const currentHeight = document.body.scrollHeight;
                        scrollCount++;
                        
                        log(`Scroll ${scrollCount}/${maxScrolls}: Height changed from ${lastHeight} to ${currentHeight}`);
                        
                        // 더 이상 높이가 변하지 않으면 종료
                        if (currentHeight === lastHeight) {{
                            log("Page height didn't change, stopping scroll");
                            break;
                        }}
                        
                        lastHeight = currentHeight;
                    }}
                    
                    // 결과 리포트
                    const heightDiff = lastHeight - initialHeight;
                    log(`Total height change: ${heightDiff}px after ${scrollCount} scrolls`);
                    
                    // 페이지 맨 위로 다시 스크롤
                    window.scrollTo(0, 0);
                    log("Scrolled back to top after infinite scroll");
                    
                    return heightDiff > 0;  // 높이가 변했으면 true
                }}
                
                // 버튼 클릭 처리
                async function handleButtonClick() {{
                    log("Looking for 'load more' buttons...");
                    
                    // 다양한 "더 보기" 유형의 버튼 찾기
                    const buttonSelectors = [
                        'button:contains("더 보기")', 'a:contains("더 보기")',
                        'button:contains("더보기")', 'a:contains("더보기")',
                        'button:contains("load more")', 'a:contains("load more")',
                        'button:contains("Load More")', 'a:contains("Load More")',
                        'button:contains("show more")', 'a:contains("show more")',
                        'button:contains("View More")', 'a:contains("View More")',
                        'button.more', 'a.more', '.btn-more', '.more-btn',
                        'button[class*="more"]', 'a[class*="more"]'
                    ];
                    
                    // 가시적인 모든 버튼 요소 가져오기
                    const allButtons = Array.from(document.querySelectorAll('button, a.btn, a[role="button"], .button, [class*="btn"]'));
                    
                    // 텍스트로 "더 보기" 유형 버튼 필터링
                    const moreButtons = allButtons.filter(btn => {{
                        const text = btn.textContent.toLowerCase().trim();
                        return text.includes('more') || text.includes('load') || text.includes('show') || 
                               text.includes('보기') || text.includes('더보기') || text.includes('더 보기');
                    }});
                    
                    let clickedAny = false;
                    
                    // 발견된 버튼 클릭
                    if (moreButtons.length > 0) {{
                        log(`Found ${moreButtons.length} 'load more' type buttons`);
                        
                        for (let btnIndex = 0; btnIndex < Math.min(moreButtons.length, 2); btnIndex++) {{
                            const btn = moreButtons[btnIndex];
                            log(`Clicking button ${btnIndex+1}: "${btn.textContent.trim()}"`);
                            
                            try {{
                                btn.click();
                                clickedAny = true;
                                
                                // 컨텐츠 로딩 대기
                                await new Promise(resolve => setTimeout(resolve, 2000));
                                log(`Waited after button ${btnIndex+1} click`);
                            }} catch (clickError) {{
                                log(`Error clicking button ${btnIndex+1}: ${clickError.message}`);
                            }}
                        }}
                    }} else {{
                        log("No 'load more' buttons found");
                    }}
                    
                    return clickedAny;
                }}
                
                // 메인 크롤링 수행
                let extractedData = [];
                
                // 특수 작업 먼저 처리 (스크롤, 클릭 등)
        """
        
        # 특별 처리 코드 추가
        if special_actions['scroll'] or special_actions['infinite_scroll']:
            if special_actions['infinite_scroll']:
                js_code += """
                // 무한 스크롤 처리
                log("Processing infinite scroll");
                const scrollResult = await handleInfiniteScroll();
                log(`Infinite scroll processed: ${scrollResult ? "content loaded" : "no changes"}`);
                """
            else:
                js_code += """
                // 기본 스크롤 처리
                log("Processing basic scroll");
                await scrollDown(3);
                log("Basic scroll completed");
                """
        
        if special_actions['click'] or special_actions['load_more']:
            js_code += """
                // 더보기 버튼 클릭 처리
                log("Processing button clicks");
                const clickResult = await handleButtonClick();
                log(`Button click processed: ${clickResult ? "buttons clicked" : "no buttons clicked"}`);
                """
        
        if special_actions['wait']:
            js_code += """
                // 페이지 안정화를 위한 추가 대기
                log("Waiting for page to stabilize");
                await new Promise(resolve => setTimeout(resolve, 2000));
                log("Wait completed");
                """
        
        # 셀렉터 기반 크롤링 코드 추가
        js_code += """
                // CSS 셀렉터 기반 크롤링
                log("Starting data extraction with CSS selectors");
                """
        
        # 각 CSS 셀렉터에 대한 코드 추가
        for i, selector in enumerate(selectors):
            js_code += f"""
                try {{
                    const elements_{i} = document.querySelectorAll("{selector}");
                    log(`Selector {i+1} "{selector}": found ${{elements_{i}.length}} elements`);
                    
                    if (elements_{i}.length > 0) {{
                        // 데이터 추출
                        Array.from(elements_{i}).forEach(element => {{
                            """
            
            # 데이터 추출 코드
            for j, data_target in enumerate(data_targets):
                js_code += f"""
                        const data_{i}_{j} = extractData(element, "{data_target}");
                        if (data_{i}_{j} && data_{i}_{j}.trim() !== "") {{
                            extractedData.push(data_{i}_{j});
                        }}
                        """
            
            js_code += """
                    });
                } catch (err) {
                    log(`Error processing selector: ${err.message}`);
                }
                """
        
        # XPath 셀렉터 처리
        if xpath_selectors:
            js_code += """
                // XPath 기반 크롤링
                log("Starting data extraction with XPath");
                """
            
            for i, xpath in enumerate(xpath_selectors):
                js_code += f"""
                try {{
                    const xpathElements_{i} = getElementsByXpath("{xpath}");
                    log(`XPath {i+1} "{xpath}": found ${{xpathElements_{i}.length}} elements`);
                    
                    if (xpathElements_{i}.length > 0) {{
                        xpathElements_{i}.forEach(element => {{
                            """
                
                # 데이터 추출 코드
                for j, data_target in enumerate(data_targets):
                    js_code += f"""
                            const xpathData_{i}_{j} = extractData(element, "{data_target}");
                            if (xpathData_{i}_{j} && xpathData_{i}_{j}.trim() !== "") {{
                                extractedData.push(xpathData_{i}_{j});
                            }}
                            """
                
                js_code += """
                        });
                    }
                } catch (err) {
                    log(`Error processing XPath: ${err.message}`);
                }
                """
        
        # 테스트 문자열 확인 코드
        if test_string:
            js_code += f"""
                // 테스트 문자열 확인
                log("Checking for test string: '{test_string}'");
                
                // 1. 페이지 전체 텍스트에서 확인
                const pageContent = document.body.textContent || "";
                const testStringInPage = pageContent.toLowerCase().includes("{test_string.lower()}");
                log(`Test string in page content: ${{testStringInPage}}`);
                
                // 2. 추출된 데이터에서 확인
                let testStringInData = false;
                if (extractedData.length > 0) {{
                    const dataString = JSON.stringify(extractedData).toLowerCase();
                    testStringInData = dataString.includes("{test_string.lower()}");
                    log(`Test string in extracted data: ${{testStringInData}}`);
                }}
                
                result.testStringFound = testStringInPage || testStringInData;
            """
        
        # 결과 마무리
        js_code += """
                // 최종 결과 준비
                result.data = extractedData;
                result.success = extractedData.length > 0;
                log(`Crawling completed with ${extractedData.length} items extracted`);
                
                return result;
            } catch (error) {
                console.error("JavaScript crawler error:", error);
                return {
                    success: false,
                    error: `JavaScript crawler error: ${error.message}`,
                    data: null,
                    log: [`Fatal error: ${error.message}`],
                    testStringFound: false
                };
            }
        })();
        """
        
        return js_code

    def complete_tab_cleanup(self, browser, tab):
        """
        탭을 완전히 정리합니다. 모든 관련 리소스 해제 및 WebSocket 연결 정리.
        
        Args:
            browser: 브라우저 객체
            tab: 정리할 탭 객체
            
        Returns:
            성공 여부
        """
        if not tab or not hasattr(tab, 'id'):
            logger.warning("Cannot cleanup a null tab or tab without ID")
            return False
            
        tab_id = tab.id
        logger.info(f"Starting complete cleanup for tab: {tab_id}")
        
        # 1. WebSocket 연결 직접 정리
        try:
            # 우선적으로 _started 플래그 비활성화
            if hasattr(tab, '_started'):
                tab._started = False
                
            # WebSocket 직접 종료
            if hasattr(tab, '_ws') and tab._ws is not None:
                try:
                    logger.debug(f"Closing WebSocket for tab {tab_id}")
                    tab._ws.close()
                    # 명시적 None 할당
                    tab._ws = None
                except Exception as e:
                    logger.debug(f"Error closing WebSocket (non-critical): {e}")
        except Exception as e:
            logger.warning(f"Error accessing WebSocket attributes: {e}")
        
        # 2. 명시적으로 stop 호출 시도
        try:
            if hasattr(tab, 'stop') and callable(tab.stop):
                try:
                    logger.debug(f"Calling stop() on tab {tab_id}")
                    tab.stop()
                except Exception as e:
                    logger.debug(f"Error stopping tab (expected, non-critical): {e}")
        except Exception as e:
            logger.warning(f"Error calling stop method: {e}")
            
        # 3. 잠시 대기 (정리 작업이 완료될 시간 부여)
        import time
        time.sleep(0.5)
                
        # 4. 브라우저에서 탭 닫기
        try:
            logger.info(f"Closing tab {tab_id} in browser")
            browser.close_tab(tab_id)
        except Exception as e:
            logger.warning(f"Error closing tab in browser: {e}")
            return False
            
        # 5. 추가적인 참조 정리
        try:
            # 탭 객체의 주요 속성들 정리
            for attr in ['_started', '_ws', '_recv_callbacks', '_handlers']:
                if hasattr(tab, attr):
                    setattr(tab, attr, None)
        except Exception as e:
            logger.debug(f"Error during additional cleanup: {e}")
        
        logger.info(f"Tab {tab_id} safely closed")
        return True
        
    def safely_close_all_tabs(self):
        """
        열려 있는 모든 탭을 안전하게 닫습니다.
        """
        if not hasattr(self, 'browser') or self.browser is None:
            logger.warning("Browser is not initialized")
            return
            
        try:
            # 모든 탭 목록 가져오기
            tabs = self.browser.list_tab()
            if not tabs:
                logger.info("No tabs to close")
                return
                
            logger.info(f"Closing {len(tabs)} tabs")
            
            # 각 탭 안전하게 닫기
            for tab in tabs:
                try:
                    self.complete_tab_cleanup(self.browser, tab)
                except Exception as e:
                    logger.warning(f"Error closing tab {tab.id if hasattr(tab, 'id') else 'unknown'}: {e}")
            
            logger.info("All tabs closed")
        except Exception as e:
            logger.error(f"Error closing all tabs: {e}")


if __name__ == "__main__":
    import sys
    
    # Set up test mode
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("Running in test mode - testing WebSocket handling")
        try:
            client = ChromeCDPClient()
            print("ChromeCDPClient initialization successful")
            print("WebSocket patching was applied successfully")
            sys.exit(0)
        except Exception as e:
            logger.error(f"Test failed: {e}")
            logger.error(traceback.format_exc())
            sys.exit(1)
    
    # Regular mode    
    os.chdir("d:")
    client = ChromeCDPClient()
    try:
        client.newmain()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        logger.error(traceback.format_exc())
    finally:
        # 프로그램 종료 전 안전하게 모든 탭 닫기
        try:
            if hasattr(client, 'safely_close_all_tabs'):
                client.safely_close_all_tabs()
        except Exception as e:
            logger.error(f"Error during final tab cleanup: {e}")
        logger.info("Program terminated")