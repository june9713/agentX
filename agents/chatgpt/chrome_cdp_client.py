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

print("chatgpt.py 파일 로드 완료", PersistentCmdManager)

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
            # Check if Tab class has the expected behavior for websocket
            # Instead of directly accessing _recv attribute which may not exist in newer versions
            if hasattr(Tab, 'recv'):
                # If there's a recv method, we can monkey patch that
                original_recv = Tab.recv
                
                def debug_recv(self, *args, **kwargs):
                    try:
                        message = original_recv(self, *args, **kwargs)
                        logger.debug(f"WebSocket received (len={len(str(message))}): {str(message)[:100]}...")
                        return message
                    except Exception as e:
                        logger.error(f"Error in WebSocket receive: {e}")
                        return None
                
                Tab.recv = debug_recv
                logger.info("Applied WebSocket debug patch to pychrome.tab.Tab.recv")
            elif hasattr(Tab, '_recv'):
                # Original approach for older versions
                original_recv = Tab._recv
                
                def debug_recv(self):
                    try:
                        message_json = self._ws.recv()
                        logger.debug(f"WebSocket received (len={len(message_json)}): {message_json[:100]}...")
                        
                        if not message_json:
                            logger.warning("Received empty message from WebSocket")
                            return None
                        
                        try:
                            message = json.loads(message_json)
                            return message
                        except json.JSONDecodeError as e:
                            logger.error(f"JSON decode error: {e}")
                            logger.error(f"Raw message content (first 200 chars): {message_json[:200]}")
                            if len(message_json) < 10:
                                logger.error(f"Very short message, hex: {' '.join(hex(ord(c)) for c in message_json)}")
                            return None
                    except Exception as e:
                        logger.error(f"Error in WebSocket receive: {e}")
                        return None
                
                Tab._recv = debug_recv
                logger.info("Applied WebSocket debug patch to pychrome.tab.Tab._recv")
            else:
                # If we can't find either method, log a warning but continue
                logger.warning("Could not apply WebSocket debug patch to pychrome - neither Tab._recv nor Tab.recv found")
                logger.info("Continuing without WebSocket debugging")
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
        각 엘리먼트와 js 소스를 분석하여 purpose 에 맞는 크롤링 방법을 확인합니다.
        만약 온라인 js,css 소스를 다운로드 해야 한다면 requests 모듈을 사용하여 다운로드 합니다.
        다운받은 소스파일들은 ./tmp/crawl 에 저장한뒤에
        크롤링 페이지의 크롤링 방법을 확인하고 결과를 추후에 다시 웹자동화에 사용할수있도록
        파일로 정리하여 ./crawls 폴더에 {날짜}{특수문자를 제거한 url}{purpose} 파일로 저장합니다.
        
        순서는 다음과 같습니다.
        1. 새로운 탭 생성
        2. 해당 웹페이지 접속
        3. 페이지 로드가 완료되면 html 파일을 tmp/crawl 폴더에 저장
        4. 해당 파일을 chatgpt 에 전달하여 크롤링 방법을 확인
        5. 챗지피티는 추가 필요 소스파일이 필요할 경우 온라인에서 다운로드
        6. 챗지피티는 크롤링 방법을 확인하고 결과를 추후에 다시 웹자동화에 사용할수있도록
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
            browser.activate_tab(crawl_tab_id)
            logger.info("Network and Page domains enabled and tab activated")
            
            # 네트워크 요청 및 응답 저장을 위한 리스트
            resources = []
            
            # 네트워크 요청 이벤트 리스너 설정
            def network_request_will_be_sent(request, **kwargs):
                resources.append({
                    'url': request.get('url'),
                    'type': request.get('resourceType', ''),
                    'downloaded': False
                })
            
            crawl_tab.Network.requestWillBeSent = network_request_will_be_sent
            logger.info("Network request listener registered")
            
            # 2. 해당 웹페이지 접속
            logger.info(f"2. Navigating to URL: {url}")
            crawl_tab.Page.navigate(url=url)
            
            # 페이지 로드 완료 기다리기
            logger.info("Waiting for page load to complete")
            
            # DOM 완료 이벤트 대기 - wait_event는 직접 호출이 아닌 이벤트 리스너로 설정
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
            
            # 필요한 리소스 다운로드 (JS, CSS)
            resource_files = []
            
            for resource in resources:
                # JS와 CSS 파일만 다운로드
                resource_type = resource.get('type', '').lower()
                resource_url = resource.get('url', '')
                
                if (resource_type in ['script', 'stylesheet'] or 
                    resource_url.endswith('.js') or resource_url.endswith('.css')):
                    try:
                        # 상대 URL을 절대 URL로 변환
                        if not resource_url.startswith(('http://', 'https://')):
                            resource_url = urljoin(url, resource_url)
                        
                        # 파일명 추출
                        parsed_url = urlparse(resource_url)
                        filename = os.path.basename(parsed_url.path)
                        if not filename:
                            # 파일 이름이 없는 경우 URL 해시 사용
                            filename = f"resource_{hash(resource_url) % 10000}"
                        
                        if resource_url.endswith('.js'):
                            filename = f"{filename}.js" if not filename.endswith('.js') else filename
                        elif resource_url.endswith('.css'):
                            filename = f"{filename}.css" if not filename.endswith('.css') else filename
                        
                        # 리소스 다운로드
                        logger.info(f"Downloading resource: {resource_url}")
                        response = requests.get(resource_url, timeout=10)
                        
                        if response.status_code == 200:
                            file_path = os.path.join(tmp_dir, filename)
                            with open(file_path, 'wb') as f:
                                f.write(response.content)
                            
                            resource['downloaded'] = True
                            resource['local_path'] = file_path
                            resource_files.append({
                                'url': resource_url,
                                'local_path': file_path,
                                'type': 'js' if resource_url.endswith('.js') else 'css',
                                'filename': filename,
                                'size': len(response.content)
                            })
                            
                            logger.info(f"Resource saved to: {file_path}")
                    except Exception as e:
                        logger.error(f"Error downloading resource {resource_url}: {e}")
            
            # 4. 분석 세션 시작 - 반복 대화를 통한 크롤링 방법 분석
            logger.info("4. Starting interactive analysis session with ChatGPT")
            
            # 먼저 HTML 파일을 ChatGPT로 업로드
            logger.info(f"Uploading HTML file: {html_filename}")
            self.simulate_paste_local_file(html_filename, self.tab)
            time.sleep(1)  # 업로드 완료 기다리기
            
            # 중요도 순서로 리소스 정렬 (CSS, JS 순으로, 크기가 작은 순)
            # CSS가 더 중요하므로 CSS 파일을 먼저 정렬
            sorted_resources = sorted(resource_files, 
                                  key=lambda x: (0 if x['type'] == 'css' else 1, x['size']))
            
            # 최대 9개의 중요 리소스 파일 업로드 (HTML 파일 1개 + 리소스 9개 = 총 10개)
            uploaded_resources = []
            for i, resource in enumerate(sorted_resources[:9]):  # 최대 9개 리소스
                try:
                    resource_path = resource['local_path']
                    logger.info(f"Uploading resource {i+1}/9: {resource['filename']}")
                    self.simulate_paste_local_file(resource_path, self.tab)
                    uploaded_resources.append(resource)
                    time.sleep(1)  # 업로드 사이에 약간의 지연 시간
                except Exception as e:
                    logger.error(f"Error uploading resource {resource['filename']}: {e}")
            
            # 반복 분석 세션 초기화
            max_iterations = 10  # 최대 반복 횟수
            iteration = 0
            analysis_complete = False
            final_result = {}
            
            # 초기 프롬프트 작성
            initial_prompt = f"""
웹 페이지 크롤링 분석 요청:
목적: {purpose}

방금 업로드한 파일들:
1. HTML 소스 파일: {os.path.basename(html_filename)}
"""

            # 업로드된 리소스 파일 목록 추가
            for i, resource in enumerate(uploaded_resources):
                initial_prompt += f"{i+2}. {resource['type'].upper()} 파일: {resource['filename']} (URL: {resource['url']})\n"

            initial_prompt += f"""
추가로 다운로드된 파일 수: {len(resource_files) - len(uploaded_resources)}

다음 단계에 따라 크롤링 방법을 분석해주세요:
1. 이 웹페이지의 구조를 분석하고 주요 요소들을 식별해주세요.
2. 목적({purpose})에 맞는 데이터를 추출하기 위한 최적의 방법을 제안해주세요.
3. 필요한 셀렉터(CSS/XPath)와 크롤링 로직을 Python 코드로 제공해주세요.
4. JavaScript가 필요한 부분이 있다면 어떻게 처리해야 하는지 설명해주세요.
5. 페이지 내 동적 콘텐츠 로딩 처리 방법도 포함해주세요.
6. pythnonpath 는 {os.path.abspath(self.pythonpath)} 입니다.

응답 형식(필수):
```json
{{
  "page_structure": "웹페이지 구조 설명",
  "target_elements": ["목적에 맞는 데이터 요소들"],
  "selectors": {{
    "element_name1": "selector1",
    "element_name2": "selector2"
  }},
  "crawling_method": "크롤링 방법 설명",
  "python_code": "크롤링을 위한 파이썬 코드",
  "javascript_handling": "필요한 경우 JavaScript 처리 방법",
  "dynamic_content": "동적 콘텐츠 처리 방법",
  "analysis_complete": true/false,
  "additional_instructions": "분석을 계속하기 위해 필요한 추가 정보나 지시사항"
}}
```

JSON 응답의 "analysis_complete" 필드가 true인 경우 분석이 완료된 것으로 간주합니다.
분석이 불완전하거나 추가 정보가 필요한 경우 "analysis_complete": false로 설정하고 "additional_instructions" 필드에 필요한 내용을 명시해주세요.
"""
            
            # 반복 분석 세션 시작
            logger.info("Starting interactive analysis loop")
            current_prompt = initial_prompt
            
            while iteration < max_iterations and not analysis_complete:
                iteration += 1
                logger.info(f"Analysis iteration {iteration}/{max_iterations}")
                
                # ChatGPT에 프롬프트 전송
                logger.info(f"Sending prompt for iteration {iteration}")
                self.send_query(browser, self.tab, current_prompt)
                
                # 응답 대기
                logger.info("Waiting for ChatGPT response")
                if not self.wait_for_response_complete(self.tab, timeout=300):
                    logger.warning("ChatGPT response timeout")
                    break
                
                # ChatGPT 응답 추출
                logger.info("Extracting response from ChatGPT")
                response_text = self.extract_chatgpt_response(self.tab)
                logger.info(f"Received response: {response_text}")
                
                # 응답에서 JSON 부분 추출
                json_pattern = r'''(\{(?:[^{}]|(?:\{(?:[^{}]|(?:\{[^{}]*\}))*\}))*\})'''
                json_matches = re.findall(json_pattern, response_text, re.MULTILINE)
                logger.info(f"JSON matches: {json_matches}")
                # 포맷 오류 카운터 추가 (연속으로 JSON 형식을 찾지 못한 횟수)
                if not hasattr(self, '_json_format_error_count'):
                    self._json_format_error_count = 0
                
                if json_matches:
                    # JSON 응답을 찾았으므로 카운터 초기화
                    self._json_format_error_count = 0
                    
                    try:
                        # JSON 파싱
                        logger.info(f"Found JSON match of length: {len(json_matches[0])}")
                        result_data = json.loads(json_matches[0].strip())
                        logger.info("Successfully parsed JSON response")
                        
                        # 분석 완료 여부 확인
                        analysis_complete = result_data.get('analysis_complete', False)
                        if analysis_complete:
                            logger.info("Analysis marked as complete in response")
                            final_result = result_data
                            
                            # 크롤링 테스트 실행
                            logger.info(f"Running test crawl to verify functionality with test string: {test_string}")
                            test_result = self.test_crawl_functionality(result_data, url, test_string)
                            
                            # 테스트 결과를 최종 결과에 추가
                            final_result['test_crawl_result'] = test_result
                            
                            # 테스트 결과에 따른 추가 메시지 구성
                            if test_result['success']:
                                logger.info("Test crawl successful!")
                                if test_string and test_result['test_string_found']:
                                    logger.info(f"The test string '{test_string}' was found in the crawled data")
                                    final_result['test_string_validation'] = "Test string found successfully"
                                elif test_string:
                                    logger.warning(f"The test string '{test_string}' was NOT found in the crawled data")
                                    final_result['test_string_validation'] = "Test string not found in crawled data"
                            else:
                                # 테스트 실패 원인 상세 분석
                                error_msg = test_result.get('error', 'Unknown error')
                                error_details = []
                                
                                # 오류 유형 분석
                                if "ModuleNotFoundError" in error_msg or "ImportError" in error_msg:
                                    # 패키지 설치 관련 오류
                                    error_details.append("필요한 패키지가 설치되지 않았습니다.")
                                    
                                    # 누락된 패키지 식별
                                    missing_package_match = re.search(r"ModuleNotFoundError: No module named '([^']+)'", error_msg)
                                    if missing_package_match:
                                        package_name = missing_package_match.group(1)
                                        error_details.append(f"누락된 패키지: {package_name}")
                                        error_details.append(f"설치 방법: pip install {package_name}")
                                
                                elif "ConnectionError" in error_msg or "ConnectionRefusedError" in error_msg:
                                    # 연결 관련 오류
                                    error_details.append("웹 사이트 연결에 실패했습니다.")
                                    error_details.append("가능한 원인: 인터넷 연결 문제, 서버 접근 제한, URL 오류")
                                
                                elif "HTTPError" in error_msg or "status code" in error_msg.lower():
                                    # HTTP 오류
                                    status_code_match = re.search(r"(\d{3})", error_msg)
                                    if status_code_match:
                                        status_code = status_code_match.group(1)
                                        error_details.append(f"HTTP 오류 코드: {status_code}")
                                        
                                        if status_code.startswith('4'):
                                            error_details.append("클라이언트 오류: 요청이 올바르지 않거나 접근 권한이 없습니다.")
                                        elif status_code.startswith('5'):
                                            error_details.append("서버 오류: 웹사이트 서버에 문제가 있습니다.")
                                    else:
                                        error_details.append("HTTP 요청 오류가 발생했습니다.")
                                
                                elif "IndexError" in error_msg or "KeyError" in error_msg:
                                    # 데이터 접근 오류
                                    error_details.append("웹 페이지 구조에서 필요한 데이터를 찾지 못했습니다.")
                                    error_details.append("가능한 원인: 웹 페이지 구조 변경, 선택자(selector) 오류")
                                
                                elif "SyntaxError" in error_msg:
                                    # 문법 오류
                                    error_details.append("생성된 크롤링 코드에 문법 오류가 있습니다.")
                                    syntax_line_match = re.search(r"line (\d+)", error_msg)
                                    if syntax_line_match:
                                        line_num = syntax_line_match.group(1)
                                        error_details.append(f"오류 발생 위치: {line_num}번 줄")
                                
                                elif "AttributeError" in error_msg:
                                    # 속성 접근 오류
                                    error_details.append("존재하지 않는 객체 속성에 접근을 시도했습니다.")
                                    attr_match = re.search(r"has no attribute '([^']+)'", error_msg)
                                    if attr_match:
                                        attr_name = attr_match.group(1)
                                        error_details.append(f"존재하지 않는 속성: {attr_name}")
                                
                                elif "TimeoutError" in error_msg or "timeout" in error_msg.lower():
                                    # 시간 초과 오류
                                    error_details.append("실행 시간이 초과되었습니다.")
                                    error_details.append("가능한 원인: 웹사이트 응답 지연, 복잡한 처리로 인한 실행 지연")
                                
                                elif "JSONDecodeError" in error_msg:
                                    # JSON 파싱 오류
                                    error_details.append("응답을 JSON으로 파싱하는 데 실패했습니다.")
                                    error_details.append("가능한 원인: 웹사이트가 예상된 JSON 형식으로 응답하지 않음")
                                
                                # 기본 오류 메시지 추가
                                error_summary = f"테스트 실패: {error_msg}"
                                if error_details:
                                    error_summary += "\n\n원인 분석:\n- " + "\n- ".join(error_details)
                                
                                # stderr 내용이 있으면 추가
                                stderr_content = test_result.get('stderr', '')
                                if stderr_content and len(stderr_content.strip()) > 0:
                                    error_summary += f"\n\n오류 로그:\n{stderr_content[:500]}"
                                
                                logger.warning(f"Test crawl failed: {error_msg}")
                                final_result['test_string_validation'] = error_summary
                                final_result['test_error_details'] = error_details
                                
                                # 수정 제안 추가
                                fix_suggestions = []
                                if "ModuleNotFoundError" in error_msg:
                                    missing_pkg = re.search(r"No module named '([^']+)'", error_msg)
                                    if missing_pkg:
                                        pkg_name = missing_pkg.group(1)
                                        fix_suggestions.append(f"패키지 설치: pip install {pkg_name}")
                                
                                if fix_suggestions:
                                    final_result['fix_suggestions'] = fix_suggestions
                            
                            # 데이터 샘플 추가
                            if test_result.get('data_sample'):
                                if isinstance(test_result['data_sample'], list):
                                    sample_size = min(3, len(test_result['data_sample']))
                                    final_result['data_preview'] = test_result['data_sample'][:sample_size]
                                elif isinstance(test_result['data_sample'], dict):
                                    final_result['data_preview'] = test_result['data_sample']
                                else:
                                    sample_data = str(test_result['data_sample'])
                                    if len(sample_data) > 500:
                                        final_result['data_preview'] = sample_data[:500] + "..."
                                    else:
                                        final_result['data_preview'] = sample_data
                            
                            break
                        else:
                            # 추가 지시사항이 있으면 다음 프롬프트 구성
                            additional_instructions = result_data.get('additional_instructions', '')
                            logger.info(f"Analysis not complete, additional instructions: {additional_instructions[:100]}...")
                            
                            # 다음 프롬프트 구성
                            current_prompt = f"""
이전 분석에 대한 피드백:

{additional_instructions}

이전 분석과 피드백을 기반으로 크롤링 방법을 다시 분석해주세요. 웹페이지 구조와 목적({purpose})에 맞는 최적의 크롤링 방법을 제시해주세요.

반드시 다음 형식의 JSON으로 응답해주세요:
```json
{{
  "page_structure": "웹페이지 구조 설명",
  "target_elements": ["목적에 맞는 데이터 요소들"],
  "selectors": {{
    "element_name1": "selector1",
    "element_name2": "selector2"
  }},
  "crawling_method": "크롤링 방법 설명",
  "python_code": "크롤링을 위한 파이썬 코드",
  "javascript_handling": "필요한 경우 JavaScript 처리 방법",
  "dynamic_content": "동적 콘텐츠 처리 방법",
  "analysis_complete": true/false,
  "additional_instructions": "분석을 계속하기 위해 필요한 추가 정보나 지시사항"
}}
```

"analysis_complete" 필드가 true면 분석이 완료된 것으로 간주합니다. 만약 분석이 불완전하거나 추가 정보가 필요하면 false로 설정하고 "additional_instructions" 필드에 필요한 내용을 명시해주세요.
"""
                            
                            # 중간 결과 저장
                            intermediate_result_path = os.path.join(tmp_dir, f"{current_date}_{url_filename}_iteration_{iteration}.json")
                            with open(intermediate_result_path, 'w', encoding='utf-8') as f:
                                json.dump(result_data, f, ensure_ascii=False, indent=2)
                            logger.info(f"Intermediate analysis saved to: {intermediate_result_path}")
                            
                    except json.JSONDecodeError as e:
                        logger.error(f"Error parsing JSON from response: {e}")
                        # 오류 발생 시 사용자에게 오류 안내 프롬프트
                        self._json_format_error_count += 1
                        current_prompt = f"""
이전 응답에서 JSON 형식을 정확히 파싱할 수 없었습니다. 다음 형식으로 정확하게 응답해주세요:

```json
{{
  "page_structure": "웹페이지 구조 설명",
  "target_elements": ["목적에 맞는 데이터 요소들"],
  "selectors": {{
    "element_name1": "selector1",
    "element_name2": "selector2"
  }},
  "crawling_method": "크롤링 방법 설명",
  "python_code": "크롤링을 위한 파이썬 코드",
  "javascript_handling": "필요한 경우 JavaScript 처리 방법",
  "dynamic_content": "동적 콘텐츠 처리 방법",
  "analysis_complete": true/false,
  "additional_instructions": "분석을 계속하기 위해 필요한 추가 정보나 지시사항"
}}
```

JSON 형식에 오류가 없도록 주의하세요. 특히 중괄호, 따옴표, 콤마 등의 구문을 정확히 사용해야 합니다.
"""
                else:
                    # JSON 형식이 없는 경우 형식 요청 프롬프트
                    logger.warning("No JSON format found in response")
                    self._json_format_error_count += 1
                    
                    # 연속으로 3회 이상 JSON 형식을 찾지 못한 경우, 분석을 강제 종료하고 수동으로 결과 생성
                    if self._json_format_error_count >= 3:
                        logger.warning(f"Failed to get JSON format after {self._json_format_error_count} consecutive attempts, forcing analysis completion")
                        
                        # 원본 응답에서 유용한 정보 추출
                        logger.info("Attempting to extract useful information from unstructured response")
                        extracted_data = self.extract_useful_content_from_text(response_text)
                        
                        if extracted_data["python_code"] or extracted_data["page_structure"]:
                            logger.info("Successfully extracted useful content from unstructured text")
                            final_result = extracted_data
                        else:
                            # 추출에 실패한 경우 기본 결과 생성
                            logger.warning("Failed to extract useful content, using default result")
                            text_content = response_text.strip()
                            final_result = {
                                "page_structure": "웹페이지 구조 자동 추출 실패",
                                "target_elements": ["자동 추출 실패"],
                                "selectors": {},
                                "crawling_method": "원본 응답에서 형식화된 JSON을 찾지 못했습니다.",
                                "python_code": "# 원본 응답에서 파이썬 코드를 추출하지 못했습니다",
                                "javascript_handling": "없음",
                                "dynamic_content": "없음",
                                "analysis_complete": True,
                                "raw_response": text_content[:1000]  # 원본 응답 일부 저장
                            }
                        break
                    
                    # 최종 시도: 이전 프롬프트가 성공하지 않았다면, 극단적으로 단순화된 프롬프트 사용
                    if self._json_format_error_count == 2:
                        current_prompt = """
중요: JSON 형식으로만 응답하세요. 다른 텍스트 없이 오직 아래 형식의 JSON만 반환하세요:

```json
{
  "page_structure": "웹페이지 구조 설명",
  "target_elements": ["목적에 맞는 데이터 요소들"],
  "selectors": {
    "element_name1": "selector1",
    "element_name2": "selector2"
  },
  "crawling_method": "크롤링 방법 설명",
  "python_code": "크롤링을 위한 파이썬 코드",
  "javascript_handling": "필요한 경우 JavaScript 처리 방법",
  "dynamic_content": "동적 콘텐츠 처리 방법",
  "analysis_complete": true,
  "additional_instructions": ""
}
```

JSON 형식만 응답하세요. 다른 텍스트는 모두 제외하세요.
"""
                    else:
                        # 더 명확한 지시사항으로 JSON 형식 응답 요청
                        current_prompt = f"""
중요: 응답에서 JSON 형식을 찾을 수 없습니다. 

다음 JSON 형식으로만 응답해주세요. 설명이나 추가 텍스트 없이 정확히 다음 형식의 JSON만 응답하세요:

```json
{{
  "page_structure": "웹페이지 구조 설명",
  "target_elements": ["목적에 맞는 데이터 요소들"],
  "selectors": {{
    "element_name1": "selector1",
    "element_name2": "selector2"
  }},
  "crawling_method": "크롤링 방법 설명",
  "python_code": "크롤링을 위한 파이썬 코드",
  "javascript_handling": "필요한 경우 JavaScript 처리 방법",
  "dynamic_content": "동적 콘텐츠 처리 방법",
  "analysis_complete": false,
  "additional_instructions": "분석을 계속하기 위해 필요한 추가 정보나 지시사항"
}}
```

반드시 위 JSON 형식으로만 응답해주세요. JSON 코드 블록을 백틱(```) 안에 정확히 포함시켜야 합니다.
어떤 설명이나 추가 텍스트를 포함하지 마세요. JSON 만 응답하세요.
"""
            
            # 반복 분석 완료 또는 최대 반복 횟수 도달
            if analysis_complete:
                logger.info(f"Analysis completed successfully after {iteration} iterations")
            else:
                logger.warning(f"Maximum iterations ({max_iterations}) reached without completing analysis")
                if not final_result:
                    # 마지막 응답에서 최선의 결과 추출 시도
                    try:
                        if json_matches and json_matches[0]:
                            final_result = json.loads(json_matches[0].strip())
                        else:
                            final_result = {"error": "분석 완료되지 않음", "raw_response": response_text[:1000]}
                    except:
                        final_result = {"error": "분석 완료되지 않음", "raw_response": response_text[:1000]}
            
            # 최종 결과 저장
            final_result['downloaded_resources'] = resource_files
            final_result['uploaded_resources'] = uploaded_resources
            final_result['target_url'] = url
            final_result['purpose'] = purpose
            final_result['date'] = current_date
            final_result['html_file'] = html_filename
            final_result['iterations_count'] = iteration
            
            # 결과 저장
            with open(result_path, 'w', encoding='utf-8') as f:
                json.dump(final_result, f, ensure_ascii=False, indent=2)
            
            logger.info(f"Final crawling method saved to: {result_path}")
            
            # 안전하게 탭 닫기
            try:
                logger.info(f"Attempting to safely close tab with ID: {crawl_tab_id}")
                self.safely_close_tab(browser, crawl_tab)
                logger.info(f"Tab {crawl_tab_id} safely closed")
            except Exception as e:
                logger.error(f"Error during tab cleanup: {e}")
                logger.error(traceback.format_exc())
            
            # 결과 객체 반환
            result_obj = {
                'success': True,
                'result_file': result_path,
                'html_file': html_filename,
                'resources': resource_files,
                'uploaded_resources': uploaded_resources,
                'iterations': iteration,
                'analysis_complete': analysis_complete
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

    def extract_chatgpt_response(self, tab):
        """
        ChatGPT 응답을 추출합니다.
        """
        try:
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
                        '.text-message',
                        '[data-message-author-role="assistant"]'
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
                    
                    // 응답에서 코드 블록과 텍스트 모두 추출
                    let fullContent = '';
                    
                    // 코드 블록 처리
                    const codeBlocks = lastMessage.querySelectorAll('pre code');
                    if (codeBlocks && codeBlocks.length > 0) {
                        for (let i = 0; i < codeBlocks.length; i++) {
                            const codeType = codeBlocks[i].className.includes('language-') ? 
                                codeBlocks[i].className.replace('language-', '') : '';
                            fullContent += '```' + codeType + '\\n';
                            fullContent += codeBlocks[i].textContent + '\\n```\\n\\n';
                        }
                    }
                    
                    // 전체 텍스트 추가
                    fullContent += lastMessage.textContent;
                    
                    return fullContent;
                } catch (error) {
                    console.error('응답 추출 오류:', error);
                    return '오류: ' + error.toString();
                }
            })();
            """
            
            result = tab.Runtime.evaluate(expression=js_code)
            response_text = result.get('result', {}).get('value', "")
            return response_text
        except Exception as e:
            logger.error(f"Error extracting ChatGPT response: {e}")
            return ""

    def start_browser(self, profile_name="Default", position=(0, 0), size=(1024, 768), pythonpath="./Scripts/python.exe"):
        """
        Brave 브라우저를 시작하고 디버깅 포트를 연결합니다.
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
            
            # 브라우저 시작 명령 - 성능 최적화 옵션 추가
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
            
            # 브라우저가 시작되고 디버깅 포트가 준비될 때까지 기다림
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
                url = "https://chatgpt.com/?model=gpt-4o&temporary-chat=false"
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
                
                // 더 효율적인 선택자로 진행 중 인디케이터 확인
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
            
            # 먼저 모델이 응답하기 시작하는지 확인 - 타임아웃 감소
            response_started = False
            response_start_timeout = 15  # 15초 동안 응답 시작 대기 (30초 → 15초)
            
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

    과도하게 반복되는 문장을 제거하고, 불필요한 내용을 삭제합니다. 만약 성공이라면 분명하게 작업이 목표에 맞게 성공했음을 표시합니다.
    실패한 경우 분명히 실패한 원인을 제공합니다.
    ```
    이번 명령의 목적:
    {comment_of_this_cmd}

    이번 명령의 결과:
    {rsltstrpost}

    이번 명령의 요약 명령:
    {simplify_command}
    ```

    다음 형식으로 정확히 응답해주세요:
    purpose of command: [명령어의 목적]
    success : "success" | "failed"
    error: False | true
    error status: [오류가 있다면 오류 내용 설명, 없으면 'no error']
    summary of output: [전체 결과의 핵심 요약]


    응답은 위 형식만 정확히 포함해야 합니다. 다른 설명이나 텍스트는 포함하지 마세요."""

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
            return f"요약 생성 중 오류 발생: {str(e)}"

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
            
            initial_prompt = f"""사용자 요청: 현재의 디렉토리 패스는 {rsltstr} 입니다. 
    주의: 항상 작업을 위한 디렉토리로 먼저 이동을 한 뒤에 본격적인 작업을 시작합니다.
    {query}

    이 작업을 수행하기 위한 윈도우즈 CMD 명령어 시퀀스를 단계적으로 제공해주세요.
    첫번째째 명령어 실행 결과를 확인한 후 다음 명령어를 제시하겠습니다.
    rsltstr_summried 에 success 이면 이전 작업이 성공 한 것으로 간주합니다.
    cmd 명령어는 다음과 같은 json형식으로 출력합니다.

    {{ "aim": aim of this command,
    "cmd" : cmd code for aim , 
    "simplify_command": ask query for making answer for result of this command
    }}

    예를 들어 d: 의 파일목록을 조회 한다면
    {{ "aim": "search list of files in D:",
    "cmd" : "dir d:",
    "simplify_command": "d:디렉토리의 파일목록을 조회한 결과를 제공하오니 목적에 가장 부합하도록 요약해주세요."
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
                            final_result = "작업이 완료되었습니다. 완료 플래그 파일이 생성되었습니다."
                            # JSON 상태 파일의 내용 읽기
                            cmd_result = cmd_manager.execute_command('type task_complete.flag', timeout=60)
                            if cmd_result["success"]:
                                final_result += f"\n\n완료 정보: {cmd_result['stdout']}"
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
                // 1. {로 시작하고 }로 끝나는 텍스트 추출
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
                        rsltstrpre = '---작업 전의 dir 결과 ---\n'
                        rsltstrpre += cmd_result['stdout'].strip()
                        rsltstrpre += cmd_result['stderr'].strip()
                        
                        logger.info(f"Executing command: {cmd_to_execute}")
                        cmd_result = cmd_manager.execute_command(cmd_to_execute, timeout=300)
                        
                        cmd_resultpost = cmd_manager.execute_command("dir", timeout=60)
                        rsltstrpost = '\n\n---작업 후의 dir 결과 ---\n'
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
            ----에이전트의 최종목표----
            {query}
            ----현재의 명령어 실행 결과----
            {rsltstr}

            ----결과 요약----
            {rsltstr_summried}
            
            rsltstr_summried 에 success : "success" 이면 이전 작업이 성공 한 것으로 간주합니다.
            현재의 결과요약을 통해 원하는 작업이 실행이 되었는지 확인 후, 
            
            다음 작업을 상정하여 다음 명령어를 제시하세요.
            
            만약 결과 요약 을 통해 원하는 내용을 얻지 못했다면 simplify_command 를 수정하여 로그를 줄이는 방법과 이유를 명확히 제시합니다

            cmd 명령어는 다음과 같은 json형식으로 출력합니다.

            {{ "aim": aim of this command,
            "cmd" : cmd code for aim , 
            "simplify_command": additional query for making "a truncate not nessacery logs for rsltstr of this command, explain how to remove not nessacery logs and why 
            }}

            예를 들어 d: 의 파일목록을 조회 한다면
            {{ "aim": "search list of files in D:",
            "cmd" : "dir d:",
            "simplify_command": "d:디렉토리의 파일목록을 조회한 결과를 제공하오니 목적에 가장 부합하도록 요약해주세요.요약은 다음의 내용을 포함합니다....(설명)"
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
            ----에이전트의 최종목표----
            {query}

            ----현재의 명령어 실행 결과----
            {formatted_output}

            ----결과 요약----
            {rsltstr_summried}

            rsltstr_summried 에 success : "success" 이면 이전 작업이 성공 한 것으로 간주합니다.
            현재의 결과요약을 통해 원하는 작업이 실행이 되었는지 확인 후, 
            
            다음 작업을 상정하여 다음 명령어를 제시하세요.
            
            만약 결과 요약 을 통해 원하는 내용을 얻지 못했다면 simplify_command 를 수정하여 로그를 줄이는 방법과 이유를 명확히 제시합니다

            cmd 명령어는 다음과 같은 json형식으로 출력합니다.

            {{ "aim": aim of this command,
            "cmd" : cmd code for aim , 
            "simplify_command": additional query for making "a truncate not nessacery logs for rsltstr of this command, explain how to remove not nessacery logs and why 
            }}

            예를 들어 d: 의 파일목록을 조회 한다면
            {{ "aim": "search list of files in D:",
            "cmd" : "dir d:",
            "simplify_command": "d:디렉토리의 파일목록을 조회한 결과를 제공하오니 목적에 가장 부합하도록 요약해주세요.요약은 다음의 내용을 포함합니다....(설명)"
            }}

            이전 명령을 확인한 결과 완료된 것으로 판단되어 다음 명령어가 필요 없다면 다음의 형태로로 명확하게 종료를 표시해주세요:
            {{ "aim": "terminated",
            "cmd" : "terminated",
            "simplify_command": "terminated"
            }}
            """
                        else:
                                result_message = """명령어를 찾을 수 없습니다. JSON 형식으로 명확하게 다시 제시해주세요.
                
                            rsltstr_summried 에 success : "success" 이면 이전 작업이 성공 한 것으로 간주합니다.
                            현재의 결과요약을 통해 원하는 작업이 실행이 되었는지 확인 후, 
                            
                            다음 작업을 상정하여 다음 명령어를 제시하세요.
                            
                            만약 결과 요약 을 통해 원하는 내용을 얻지 못했다면 simplify_command 를 수정하여 로그를 줄이는 방법과 이유를 명확히 제시합니다

                            cmd 명령어는 다음과 같은 json형식으로 출력합니다.

                            {{ "aim": aim of this command,
                            "cmd" : cmd code for aim , 
                            "simplify_command": additional query for making "a truncate not nessacery logs for rsltstr of this command, explain how to remove not nessacery logs and why 
                            }}

                            예를 들어 d: 의 파일목록을 조회 한다면
                            {{ "aim": "search list of files in D:",
                            "cmd" : "dir d:",
                            "simplify_command": "d:디렉토리의 파일목록을 조회한 결과를 제공하오니 목적에 가장 부합하도록 요약해주세요.요약은 다음의 내용을 포함합니다....(설명)"
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
                            final_result = "작업이 완료되었습니다. 완료 플래그 파일이 생성되었습니다."
                            # JSON 상태 파일의 내용 읽기
                            cmd_result = cmd_manager.execute_command('type task_complete.flag', timeout=60)
                            if cmd_result["success"]:
                                final_result += f"\n\n완료 정보: {cmd_result['stdout']}"
                            break

                if not final_result and iteration >= max_iterations:
                    logger.warning("Maximum iterations reached without completion")
                    final_result = "최대 반복 횟수에 도달했습니다. 작업이 완료되지 않았을 수 있습니다."
                    
                # 최종 결과 출력 시 시각적 구분 추가
                logger.info("=" * 50)
                logger.info("작업 상태: 완료됨" if "작업이 완료되었습니다" in final_result else "작업 상태: 미완료")
                logger.info("=" * 50)
                
                # 작업 결과 요약 생성
                summary = "== 작업 결과 요약 ==\n"
                if os.path.exists("task_complete.flag"):
                    with open("task_complete.flag", "r") as f:
                        flag_content = f.read().strip()
                    summary += f"완료 상태: 성공\n완료 태그: {flag_content}\n"
                else:
                    summary += "완료 상태: 미완료 또는 실패\n"
                
                # 최종 디렉토리 상태
                cmd_result = cmd_manager.execute_command("dir", timeout=60)
                summary += f"\n최종 디렉토리 상태:\n{cmd_result['stdout'][:500]}...\n"
                
                logger.info(summary)
                return final_result + "\n\n" + summary
                
            except Exception as e:
                answerFailed = True
                logger.error(f"Error in command execution loop: {e}")
                logger.error(traceback.format_exc())
                return f"명령 실행 중 오류 발생: {str(e)}"
            
        except Exception as e:
            logger.error(f"Error in execute_chatgpt_cmd_session: {str(e)}")
            logger.error(traceback.format_exc())
            return f"오류 발생: {str(e)}"

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
            
            # 명령어 인식 방법 1: 명령어 지시자로 시작하는 라인
            cmd_indicators = ["명령어:", "실행:", "CMD:", "명령:", "커맨드:", "command:", "다음 명령어:"]
            for line in lines:
                for indicator in cmd_indicators:
                    if indicator.lower() in line.lower():
                        cmd = line.split(indicator, 1)[1].strip()
                        logger.info(f"Found command with indicator: {cmd}")
                        return cmd
            
            # 명령어 인식 방법 2: 흔한 CMD 명령어로 시작하는 라인
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
            print("input query?")
            user_query = input("CMD 작업을 위한 쿼리를 입력하세요: ")
            
            # 브라우저가 이미 시작되었으므로 페이지 로드만 확인
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
            print("\n--- 작업 결과 ---")
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
            print("작업 모드를 선택하세요:")
            print("1. 코드 분석 및 수정 (기존 기능)")
            print("2. CMD 명령어 실행 세션")
            
            mode = "2"
            if mode == "2":
                self.cmd_session_main()
            else:
                # 기존 main 함수 내용 (코드 분석 및 수정 기능)
                # 브라우저가 이미 시작되었으므로 페이지 로드만 확인
                if not self.tab:
                    logger.error("No main tab available")
                    return
                
                # 페이지 로드 확인 - 더 짧은 타임아웃
                if not self.check_page_loaded(self.tab, timeout=15):  # 타임아웃 감소 (기본값 30초 → 15초)
                    logger.error("Page load check failed")
                    return
                    
                # 테스트 쿼리 전송
                logger.info("Sending test query...")
                self.send_query(self.browser, self.tab, "오늘의 날씨에 대해서 알려주세요:")
                
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
                logger.info(f"Closing tab with ID: {tab.id}")
                browser.close_tab(tab)
                return True
        except Exception as e:
            logger.error(f"Error closing tab: {e}")
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
        
        # 섹션 기반 추출 (페이지 구조, 타겟 요소 등)
        sections = {
            "페이지 구조": "page_structure",
            "웹페이지 구조": "page_structure", 
            "대상 요소": "target_elements",
            "타겟 요소": "target_elements",
            "선택자": "selectors",
            "크롤링 방법": "crawling_method",
            "자바스크립트 처리": "javascript_handling",
            "동적 콘텐츠": "dynamic_content"
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
        
        Args:
            analysis_result: 크롤링 분석 결과 딕셔너리
            url: 테스트할 URL
            test_string: 크롤링 결과에서 찾을 테스트 문자열
            
        Returns:
            테스트 결과를 담은 딕셔너리
        """
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
            
            # 파이썬 코드 추출
            python_code = analysis_result.get('python_code', '')
            if not python_code:
                test_result["error"] = "No Python code found in analysis results"
                logger.error(test_result["error"])
                return test_result
            
            # 파이썬 코드 준비 - 필요한 import 구문 추가
            imports_added = []
            
            # 1. requests와 BeautifulSoup 임포트 확인 및 추가
            if "import requests" not in python_code:
                python_code = "import requests\n" + python_code
                imports_added.append("requests")
                
            if "from bs4 import BeautifulSoup" not in python_code and "BeautifulSoup" in python_code:
                python_code = "from bs4 import BeautifulSoup\n" + python_code
                imports_added.append("BeautifulSoup")
            
            # 2. 필요한 경우 selenium 임포트 추가
            if "selenium" in python_code:
                if "from selenium import webdriver" not in python_code:
                    python_code = "from selenium import webdriver\n" + python_code
                    imports_added.append("selenium.webdriver")
                if "from selenium.webdriver.common.by import By" not in python_code and "By." in python_code:
                    python_code = "from selenium.webdriver.common.by import By\n" + python_code
                    imports_added.append("selenium.webdriver.common.by")
                if "from selenium.webdriver.chrome.options import Options" not in python_code and "Options" in python_code:
                    python_code = "from selenium.webdriver.chrome.options import Options\n" + python_code
                    imports_added.append("selenium.webdriver.chrome.options")
                if "from selenium.webdriver.chrome.service import Service" not in python_code and "Service" in python_code:
                    python_code = "from selenium.webdriver.chrome.service import Service\n" + python_code
                    imports_added.append("selenium.webdriver.chrome.service")
                if "from selenium.webdriver.support.ui import WebDriverWait" not in python_code and "WebDriverWait" in python_code:
                    python_code = "from selenium.webdriver.support.ui import WebDriverWait\n" + python_code
                    imports_added.append("selenium.webdriver.support.ui")
                if "from selenium.webdriver.support import expected_conditions as EC" not in python_code and "expected_conditions" in python_code:
                    python_code = "from selenium.webdriver.support import expected_conditions as EC\n" + python_code
                    imports_added.append("selenium.webdriver.support.expected_conditions")
            
            # 3. 기타 필요한 라이브러리 추가
            if ("time.sleep" in python_code or "time." in python_code) and "import time" not in python_code:
                python_code = "import time\n" + python_code
                imports_added.append("time")
                
            if "json.loads" in python_code and "import json" not in python_code:
                python_code = "import json\n" + python_code
                imports_added.append("json")
                
            if "re.search" in python_code and "import re" not in python_code:
                python_code = "import re\n" + python_code
                imports_added.append("re")
                
            if "os.path" in python_code and "import os" not in python_code:
                python_code = "import os\n" + python_code
                imports_added.append("os")
                
            logger.info(f"Added imports: {', '.join(imports_added)}")
            
            # URL 변수가 없으면 추가하거나 수정
            if "url = " not in python_code:
                python_code = f"url = '{url}'\n" + python_code
                logger.info(f"Added URL variable: url = '{url}'")
            else:
                # 기존 URL 변수 재정의
                url_pattern = r"url\s*=\s*['\"].*?['\"]"
                new_url = f"url = '{url}'"
                if re.search(url_pattern, python_code):
                    python_code = re.sub(url_pattern, new_url, python_code)
                    logger.info(f"Updated URL variable: {new_url}")
            
            # 결과 출력 및 저장 코드 추가
            result_output_code = """
# 크롤링 결과 저장 코드
def save_crawl_result(result_data):
    import json
    import os
    
    # 결과를 문자열로 변환
    if isinstance(result_data, (list, dict)):
        try:
            result_str = json.dumps(result_data, ensure_ascii=False, indent=2)
        except:
            result_str = str(result_data)
    else:
        result_str = str(result_data)
    
    # 결과 저장
    with open('./tmp/crawl/crawl_result_data.txt', 'w', encoding='utf-8') as f:
        f.write(result_str)
    
    # 성공 여부 반환
    return True

"""
            
            # 메인 함수가 있으면 메인 함수에 결과 저장 코드 추가
            if "def main" in python_code:
                # 메인 함수 내에서 결과를 저장하는 코드 추가
                main_pattern = r"def\s+main\s*\([^)]*\)\s*:"
                main_match = re.search(main_pattern, python_code)
                
                if main_match:
                    # 메인 함수의 끝을 찾기
                    main_start = main_match.start()
                    main_code = python_code[main_start:]
                    
                    # 메인 함수 내에서 반환값 확인
                    return_pattern = r"return\s+([^\n]+)"
                    return_match = re.search(return_pattern, main_code)
                    
                    if return_match:
                        # 반환문 전에 결과 저장 코드 추가
                        return_var = return_match.group(1).strip()
                        save_code = f"\n    # 크롤링 결과 저장\n    save_crawl_result({return_var})\n"
                        
                        # 반환문 앞에 코드 삽입
                        return_pos = main_start + return_match.start()
                        python_code = python_code[:return_pos] + save_code + python_code[return_pos:]
                    else:
                        # 반환문이 없는 경우 함수 끝에 저장 코드 추가
                        # 함수 끝 찾기 - 들여쓰기가 변경되는 지점
                        indent_pattern = r"\n(?=\S)"
                        indent_matches = list(re.finditer(indent_pattern, main_code))
                        
                        if indent_matches and len(indent_matches) > 1:
                            # 함수 끝 위치
                            func_end = main_start + indent_matches[1].start()
                            save_code = "\n    # 크롤링 결과 저장\n    save_crawl_result(locals())\n"
                            python_code = python_code[:func_end] + save_code + python_code[func_end:]
                        else:
                            # 함수 끝을 찾을 수 없는 경우 전체 코드 끝에 추가
                            python_code += "\n    # 크롤링 결과 저장\n    save_crawl_result(locals())\n"
                
                # 메인 함수 호출 코드 수정 - 크롤링 결과를 저장하는 부분 추가
                if "if __name__ == '__main__':" in python_code:
                    # 기존 __main__ 블록이 있는 경우 수정
                    main_call_pattern = r"if\s+__name__\s*==\s*['\"]__main__['\"]\s*:(.*?)(?:\n\S|\Z)"
                    main_call_match = re.search(main_call_pattern, python_code, re.DOTALL)
                    
                    if main_call_match:
                        # __main__ 블록 전체 내용
                        main_call_code = main_call_match.group(1)
                        
                        # main() 호출이 있는지 확인
                        if "main()" in main_call_code:
                            # 기존 호출을 결과 저장 코드로 대체
                            new_main_call = main_call_code.replace("main()", "result = main()\nsave_crawl_result(result)")
                            python_code = python_code.replace(main_call_code, new_main_call)
                        else:
                            # main() 호출이 없는 경우 추가
                            new_main_call = main_call_code + "\n    result = main()\n    save_crawl_result(result)"
                            python_code = python_code.replace(main_call_code, new_main_call)
                else:
                    # __main__ 블록이 없는 경우 추가
                    python_code += "\n\nif __name__ == '__main__':\n    result = main()\n    save_crawl_result(result)"
            else:
                # 메인 함수가 없는 경우 - 크롤링 결과를 직접 저장하는 코드 추가
                python_code += "\n\n# 크롤링 결과 저장\nsave_crawl_result(locals().get('result', locals()))"
            
            # 결과 저장 함수 추가
            python_code = result_output_code + python_code
            
            # 테스트 코드 파일 저장
            test_file_path = os.path.join("./tmp/crawl", "test_crawl.py")
            with open(test_file_path, 'w', encoding='utf-8') as f:
                f.write(python_code)
            
            # 테스트 코드 실행 시간 측정 시작
            start_time = time.time()
            
            # 파이썬 실행 환경 설정
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"
            
            # 크롤링 코드 실행
            pythonpath = self.pythonpath if self.pythonpath else "python"
            logger.info(f"Executing test crawl with Python: {pythonpath}")
            
            # 임시 디렉터리 생성 확인
            if not os.path.exists("./tmp/crawl"):
                os.makedirs("./tmp/crawl")
            
            # 크롤링 코드 실행
            process = subprocess.Popen(
                [pythonpath, test_file_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                env=env,
                cwd="./tmp/crawl"  # 작업 디렉터리 설정
            )
            
            # 타임아웃 설정 (기본 120초)
            timeout = 120
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                test_result["output"] = stdout
                test_result["stderr"] = stderr
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                test_result["output"] = stdout
                test_result["stderr"] = stderr
                test_result["error"] = f"Crawl execution timed out after {timeout} seconds"
                logger.error(test_result["error"])
                test_result["executed_code"] = python_code
                return test_result
            
            # 실행 시간 계산
            execution_time = time.time() - start_time
            test_result["time_taken"] = execution_time
            
            # 오류 확인
            if process.returncode != 0:
                test_result["error"] = f"Crawl execution failed with exit code {process.returncode}"
                if stderr:
                    test_result["error"] += f": {stderr}"
                logger.error(test_result["error"])
                test_result["executed_code"] = python_code
                return test_result
            
            # 결과 파일 확인
            result_file_path = os.path.join("./tmp/crawl", "crawl_result_data.txt")
            crawl_result = None
            
            if os.path.exists(result_file_path):
                logger.info(f"Found crawl result file: {result_file_path}")
                try:
                    with open(result_file_path, 'r', encoding='utf-8') as f:
                        result_str = f.read()
                        
                    # JSON 형식으로 파싱 시도
                    try:
                        crawl_result = json.loads(result_str)
                        logger.info("Successfully parsed crawl result as JSON")
                    except json.JSONDecodeError:
                        # JSON으로 파싱할 수 없는 경우 원본 문자열 사용
                        crawl_result = result_str
                        logger.info("Using raw string as crawl result (not valid JSON)")
                except Exception as e:
                    logger.error(f"Error reading result file: {e}")
                    test_result["error"] = f"Error reading result file: {e}"
                    crawl_result = None
            else:
                logger.warning(f"No crawl result file found at {result_file_path}")
                # 결과 파일이 없는 경우 stdout 사용
                crawl_result = stdout
                logger.info("Using stdout as crawl result")
            
            # 결과 샘플 저장
            if crawl_result is not None:
                if isinstance(crawl_result, list) and len(crawl_result) > 0:
                    test_result["data_sample"] = crawl_result[:5] if len(crawl_result) > 5 else crawl_result
                    logger.info(f"Crawl result is a list with {len(crawl_result)} items")
                elif isinstance(crawl_result, dict):
                    test_result["data_sample"] = crawl_result
                    logger.info(f"Crawl result is a dictionary with {len(crawl_result)} keys")
                else:
                    # 문자열인 경우 처리
                    result_str = str(crawl_result)
                    test_result["data_sample"] = result_str[:1000] if len(result_str) > 1000 else result_str
                    logger.info(f"Crawl result is a string of length {len(result_str)}")
            else:
                # 결과가 없는 경우 stdout 사용
                logger.warning("No crawl result found, using stdout")
                test_result["data_sample"] = stdout[:1000] if stdout and len(stdout) > 1000 else stdout
            
            # 테스트 문자열 확인
            if test_string and crawl_result is not None:
                result_str = str(crawl_result)
                test_result["test_string_found"] = test_string.lower() in result_str.lower()
                logger.info(f"Test string '{test_string}' found: {test_result['test_string_found']}")
            
            # 테스트 성공 여부 판단
            test_result["success"] = (
                test_result["error"] is None and 
                test_result["data_sample"] is not None and 
                (not test_string or test_result["test_string_found"])
            )
            
            # 실행한 코드 저장
            test_result["executed_code"] = python_code
            
            logger.info(f"Test crawl completed in {execution_time:.2f} seconds")
            logger.info(f"Test result: {'Success' if test_result['success'] else 'Failed'}")
            
            # 성공한 경우 데이터 샘플 로깅
            if test_result["success"]:
                logger.info(f"Sample data: {str(test_result['data_sample'])[:200]}...")
            
            return test_result
            
        except Exception as e:
            logger.error(f"Error in test_crawl_functionality: {e}")
            logger.error(traceback.format_exc())
            return {
                "success": False,
                "time_taken": 0,
                "error": str(e),
                "data_sample": None,
                "test_string_found": False,
                "executed_code": python_code if 'python_code' in locals() else None,
                "output": None,
                "stderr": traceback.format_exc()
            }

if __name__ == "__main__":
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
            client.safely_close_all_tabs()
        except Exception as e:
            logger.error(f"Error during final tab cleanup: {e}")
        logger.info("Program terminated")