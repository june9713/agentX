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
import sys
import re
try:
    from cmdman.cmd_manager import *
    print("chatgpt.py 파일 로드 완료",PersistentCmdManager)
except:
    print(os.getcwd()   )
    from cmdman.cmd_manager import *
    print("cmdman 모듈을 찾을 수 없습니다.")



# 로깅 설정을 개선하여 불필요한 로그는 제외하고 중요한 정보와 오류만 표시
logging.basicConfig(
    level=logging.WARNING,  # 기본 로깅 레벨을 WARNING으로 설정
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
    handlers=[
        logging.FileHandler("myagent.log"),  # 파일에는 모든 로그 기록
        logging.StreamHandler(sys.stdout)    # 콘솔에는 중요한 메시지만 표시
    ]
)

# 메인 로거 설정
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)  # 이 모듈의 로거는 INFO 레벨 유지

# 라이브러리 로깅 레벨 조정 (불필요한 로그 제거)
logging.getLogger("pychrome").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("pyautogui").setLevel(logging.WARNING)

# 핵심 함수들에 대한 로그 필터 설정
class ErrorInfoFilter(logging.Filter):
    def filter(self, record):
        # 오류 메시지 또는 중요한 상태 메시지 허용
        if record.levelno >= logging.ERROR:
            return True
        # 특정 중요 메시지 패턴 허용
        important_patterns = [
            "Task complete", "Error in", "Failed to", "Starting", "Complete",
            "Timeout", "Exception", "작업 상태"
        ]
        for pattern in important_patterns:
            if pattern in record.getMessage():
                return True
        return False

# 콘솔 출력에만 필터 적용
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
console_handler.addFilter(ErrorInfoFilter())

# 로거에 핸들러 추가
logger.handlers = []  # 기존 핸들러 제거
logger.addHandler(console_handler)
logger.addHandler(logging.FileHandler("myagent_detail.log"))  # 상세 로그는 별도 파일에 저장

def capture_window(hwnd):
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
        error_msg = f"화면 캡처 실패: {str(e)}"
        logger.error(error_msg)
        
        # 디버깅에 유용한 상세 정보는 상세 로그에만 기록
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(traceback.format_exc())
        
        # 명확한 오류 원인 식별을 위한 추가 정보
        try:
            # 윈도우가 유효한지 확인
            if not win32gui.IsWindow(hwnd):
                logger.error(f"유효하지 않은 윈도우 핸들: {hwnd}")
            # 윈도우 제목 확인 시도
            title = win32gui.GetWindowText(hwnd)
            logger.error(f"문제가 발생한 윈도우: '{title}' (핸들: {hwnd})")
        except:
            pass
            
        return None

def bring_to_foreground(hwnd):
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

def resize_window(hwnd, width, height, x=None, y=None):
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

def start_browser(profile_name="Profile 1", position=(0, 0), size=(1024, 768)):
    """
    slimjet 브라우저를 시작하고 디버깅 포트를 연결합니다.
    성능 최적화된 옵션 적용
    """
    try:
        # 실행 중인 slimjet 브라우저 종료
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] == "slimjet.exe":
                logger.info("기존 slimjet 브라우저 종료 중...")
                try:
                    proc.kill()
                except Exception as e:
                    logger.warning(f"브라우저 프로세스 종료 실패: {e}")
        
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
        cmd = f'"C:\\Program Files\\Slimjet\\slimjet.exe"' \
              f'--remote-debugging-port=9333 ' \
              f'--window-size={width},{height} ' \
              f'--window-position={x},{y} ' \
              f'--profile-directory="{profile_name}" ' \
              f'--disable-extensions ' \
              f'--disable-gpu ' \
              f'--no-sandbox ' \
              f'--disable-dev-shm-usage ' \
              f'--disable-software-rasterizer'
        
        logger.info(f"브라우저 시작 중...")
        ps = subprocess.Popen(cmd)
        
        # 브라우저가 시작되고 디버깅 포트가 준비될 때까지 기다림
        max_attempts = 10
        attempts = 0
        browser = None
        
        while attempts < max_attempts:
            try:
                time.sleep(0.5)  # 대기 시간 감소 (1초 → 0.5초)
                browser = pychrome.Browser(url="http://127.0.0.1:9333")
                tab = browser.new_tab()
                tab.start()
                break
            except Exception as e:
                attempts += 1
                if attempts >= max_attempts:
                    error_msg = f"브라우저 연결 실패 (최대 시도 횟수 초과): {e}"
                    logger.error(error_msg)
                    
                    # 추가 디버깅 정보
                    logger.error("브라우저 연결 문제 해결 방법:")
                    logger.error("1. slimjet 브라우저가 설치되어 있는지 확인하세요")
                    logger.error("2. 방화벽이 디버깅 포트(9333)를 차단하고 있는지 확인하세요")
                    logger.error("3. 다른 프로세스가 포트 9333을 사용 중인지 확인하세요")
                    
                    # 디버깅에 유용한 상세 정보는 DEBUG 레벨에 기록
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug(traceback.format_exc())
                    return None, None
        
        # 네트워크 활성화 및 페이지 이동
        tab.Network.enable()
        
        # ChatGPT 페이지로 직접 이동
        url = "https://chatgpt.com/?model=gpt-4o&temporary-chat=true"
        logger.info(f"ChatGPT 페이지로 이동 중...")
        tab.Page.navigate(url=url, _timeout=5)  # 타임아웃 감소 (10초 → 5초)
        
        # 페이지 로딩 기다리기
        tab.wait(5)  # 대기 시간 감소 (10초 → 5초)
        
        logger.info("브라우저 시작 및 페이지 로드 완료")
        return browser, tab
    
    except Exception as e:
        error_msg = f"브라우저 시작 오류: {str(e)}"
        logger.error(error_msg)
        
        # 디버깅에 유용한 상세 정보는 상세 로그에만 기록
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(traceback.format_exc())
            
        # 오류 진단을 위한 추가 정보
        try:
            # Slimjet 설치 확인
            slimjet_path = "C:\\Program Files\\Slimjet\\slimjet.exe"
            if not os.path.exists(slimjet_path):
                logger.error(f"Slimjet 브라우저가 설치되어 있지 않거나 경로가 다릅니다: {slimjet_path}")
                
            # 프로세스 확인
            for proc in psutil.process_iter(['name', 'pid']):
                if proc.info['name'] == "slimjet.exe":
                    logger.error(f"Slimjet 프로세스가 여전히 실행 중입니다: PID {proc.info['pid']}")
        except:
            pass
            
        return None, None

def check_page_loaded(tab, timeout=15):  # 타임아웃 감소 (30초 → 15초)
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

def simulate_paste_local_file(filename, tab):
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

def send_query(tab, text):
    """
    ChatGPT 에디터에 텍스트를 입력하고 전송 버튼을 클릭합니다.
    개선된 버전: 긴 텍스트를 안정적으로 전송하고 코드 블록 포맷을 보존합니다.
    
    Args:
        tab: 브라우저 탭 객체
        text: 전송할 텍스트
        
    Returns:
        성공 여부를 나타내는 불리언 값
    """
    try:
        if not text.strip():
            logger.warning("전송할 텍스트가 비어 있습니다")
            return False
        
        # 텍스트 내용에 줄바꿈이 있는지 확인
        has_newlines = '\n' in text
        has_code_blocks = '```' in text
        
        logger.debug(f"텍스트 전송 시작 - 길이: {len(text)}, 줄바꿈: {has_newlines}, 코드블록: {has_code_blocks}")
        
        # 텍스트의 특수 문자 이스케이프
        escaped_text = text.replace('\\', '\\\\').replace('`', '\\`').replace("'", "\\'").replace('"', '\\"')
        
        # 텍스트 에디터에 텍스트 삽입 - 개선된 방식
        if has_code_blocks or has_newlines:
            # 코드 블록이 있거나 줄바꿈이 있는 경우의 고급 삽입 방식
            js_code = r"""
            (function() {
                try {
                    // 1. 최신 ChatGPT 에디터 찾기
                    const editor = document.querySelector('[contenteditable="true"]') || 
                                  document.querySelector('.ProseMirror');
                    if (!editor) {
                        console.error('에디터를 찾을 수 없습니다');
                        return {success: false, error: '에디터를 찾을 수 없습니다'};
                    }
                    
                    // 2. 에디터에 포커스 설정
                    editor.focus();
                    
                    // 3. 클립보드를 통한 붙여넣기 방식 (가장 안정적)
                    const textToPaste = `%s`;
                    
                    // 클립보드 API 사용
                    const pasteEvent = new ClipboardEvent('paste', {
                        bubbles: true,
                        clipboardData: new DataTransfer()
                    });
                    
                    // 클립보드 데이터 설정
                    pasteEvent.clipboardData.setData('text/plain', textToPaste);
                    
                    // 붙여넣기 이벤트 발생
                    editor.dispatchEvent(pasteEvent);
                    
                    // 4. 입력 이벤트 시뮬레이션으로 ChatGPT에 변경 알림
                    const inputEvent = new Event('input', {bubbles: true});
                    editor.dispatchEvent(inputEvent);
                    
                    return {success: true};
                } catch(err) {
                    console.error('텍스트 입력 중 오류:', err);
                    return {success: false, error: err.toString()};
                }
            })();
            """ % escaped_text
        else:
            # 일반 텍스트 삽입 (단순한 경우)
            js_code = r"""
            (function() {
                try {
                    // 에디터 찾기
                    const editor = document.querySelector('[contenteditable="true"]') || 
                                  document.querySelector('.ProseMirror');
                    if (!editor) return {success: false, error: '에디터를 찾을 수 없습니다'};
                    
                    // 에디터에 포커스
                    editor.focus();
                    
                    // innerHTML로 직접 설정 (단순 텍스트의 경우 더 안정적)
                    editor.innerHTML = `<p>${`%s`}</p>`;
                    
                    // 입력 이벤트 발생
                    editor.dispatchEvent(new Event('input', {bubbles: true}));
                    
                    return {success: true};
                } catch(err) {
                    return {success: false, error: err.toString()};
                }
            })();
            """ % escaped_text
            
        # 자바스크립트 실행
        result = tab.Runtime.evaluate(expression=js_code)
        response = result.get('result', {}).get('value', {})
        
        # 결과 확인
        if isinstance(response, dict):
            success = response.get('success', False)
            if not success and 'error' in response:
                logger.warning(f"텍스트 입력 실패: {response.get('error')}")
                return False
        else:
            success = bool(response)
            
        if not success:
            logger.warning("에디터에 텍스트를 설정하지 못했습니다")
            return False
            
        # 텍스트 입력 후 잠시 대기 (긴 텍스트의 경우 더 오래 대기)
        wait_time = 0.5 + (min(len(text) / 5000, 2.0))
        time.sleep(wait_time)
        
        # 전송 버튼 클릭 - 개선된 선택자
        js_code = """
        (function() {
            try {
                // 1. 표준 전송 버튼 시도
                let sendButton = document.querySelector('button[data-testid="send-button"]');
                
                // 2. 대체 선택자 시도
                if (!sendButton) {
                    sendButton = document.querySelector('button.absolute.bottom-0') ||
                                document.querySelector('form button:last-child') ||
                                Array.from(document.querySelectorAll('button')).find(b => 
                                    b.textContent.includes('Send') || 
                                    b.getAttribute('aria-label')?.includes('Send'));
                }
                
                // 3. 버튼 상태 확인
                if (!sendButton) {
                    return {success: false, error: '전송 버튼을 찾을 수 없습니다'};
                }
                
                if (sendButton.disabled) {
                    return {success: false, error: '전송 버튼이 비활성화되어 있습니다'};
                }
                
                // 4. 버튼 클릭
                sendButton.click();
                return {success: true};
            } catch(err) {
                return {success: false, error: err.toString()};
            }
        })();
        """
        
        result = tab.Runtime.evaluate(expression=js_code)
        response = result.get('result', {}).get('value', {})
        
        # 결과 확인
        if isinstance(response, dict):
            success = response.get('success', False)
            if not success and 'error' in response:
                logger.warning(f"전송 버튼 클릭 실패: {response.get('error')}")
                return False
        else:
            success = bool(response)
            
        if success:
            logger.info(f"쿼리 전송 성공: {text[:50]}...")
        else:
            logger.warning("전송 버튼 클릭 실패")
            
        return success
            
    except Exception as e:
        logger.error(f"쿼리 전송 중 오류 발생: {e}")
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(traceback.format_exc())
        return False

def is_send_button_available(tab):
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

def is_model_responding(tab):
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

def wait_for_response_complete(tab, timeout=180):  # 타임아웃 감소 (300초 → 180초)
    """
    ChatGPT의 응답이 완료될 때까지 대기합니다.
    효율적인 폴링 방식 적용
    """
    try:
        start_time = time.time()
        is_responding_prev = None
        reported_waiting = False
        
        # 응답 상태 변화를 감지하는 폴링 루프
        while True:
            # 실행 시간 체크
            elapsed = time.time() - start_time
            if elapsed > timeout:
                logger.warning(f"응답 대기 시간 초과: {int(elapsed)}초 경과 (제한: {timeout}초)")
                return False
            
            # 현재 응답 상태 확인
            is_responding = is_model_responding(tab)
            
            # 에러 상태인 경우
            if is_responding is None:
                if not reported_waiting:
                    logger.info("응답 상태 확인 중...")
                    reported_waiting = True
                time.sleep(0.5)
                continue
                
            # 응답 상태 변화 감지 및 로깅
            if is_responding_prev is not None and is_responding_prev != is_responding:
                if is_responding:
                    logger.info("모델이 응답 생성 중...")
                else:
                    logger.info("응답 생성 완료")
            
            is_responding_prev = is_responding
            
            # 응답이 완료된 경우
            if not is_responding:
                # 응답 완료 확인을 위한 추가 대기 (버퍼링 완료 대기)
                time.sleep(0.5)
                
                # 한 번 더 확인하여 정말 완료되었는지 검증
                is_still_responding = is_model_responding(tab)
                if is_still_responding is False:
                    elapsed = time.time() - start_time
                    logger.info(f"응답 완료 (소요 시간: {int(elapsed)}초)")
                    return True
            
            # 적응형 폴링 간격 설정 (응답 생성 중일 때 간격 늘림)
            if is_responding:
                time.sleep(0.8)  # 응답 생성 중이면 더 긴 간격
            else:
                time.sleep(0.3)  # 그 외에는 짧은 간격
    
    except Exception as e:
        error_msg = f"응답 대기 중 오류 발생: {str(e)}"
        logger.error(error_msg)
        
        # 디버깅 정보는 상세 로그에만 기록
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(traceback.format_exc())
            
        # 가능하면 현재 상태 확인
        try:
            js_code = '''
                (function() {
                    return {
                        responseElements: document.querySelectorAll('div[data-message-author-role="assistant"]').length,
                        pageState: document.readyState
                    };
                })()
            '''
            result = tab.Runtime.evaluate(expression=js_code)
            state_info = result.get('result', {}).get('value', {})
            if state_info:
                logger.error(f"현재 페이지 상태: {state_info}")
        except:
            pass
            
        return False


def summery_result(tab, browser, mini_tab, cmd_prompt, result_text):
    """
    먼저 현재 열려있는 탭 중에  chatgpt 4o-mini 가 열려있는지 확인합니다.
    만약 열려있지 않다면 새로운 탭을 열어서 chatgpt 4o-mini 모델에게 result_text 를 요약해달라고 요청한 뒤에 반환합니다.
    만약 열려있다면 현재 열려있는 탭에게 result_text 를 요약해달라고 요청한 뒤에 반환합니다.
    결과를 반환하기 전에 다시 원래의 모델이 있던 탭으로 탭을 변경합니다. chatgpt 4o-mini 탭은 닫지 않고 유지합니다다.
    """
    logger.info("=" * 50)
    logger.info("Starting summery_result function")
    logger.info(f"Input text length: {len(result_text)} characters")
    logger.debug(f"First 100 chars of input text: {result_text[:100]}...")
    
    # 실행 완료 플래그 설정
    execution_done = False
    
    try:
        # 원래 탭 객체 저장 (나중에 돌아오기 위함)
        original_tab = tab
        logger.info("Original tab saved")
        
        # 현재 열려있는 탭 중에 chatgpt o-mini 가 열려있는지 확인
        logger.info("Checking if current tab is a ChatGPT tab")
        js_code = """
        (function() {
            const chatgptTabs = document.querySelectorAll('div[data-testid="chat-message-container"]');
            return chatgptTabs.length > 0;
        })();
        """
        result = tab.Runtime.evaluate(expression=js_code)
        is_chatgpt_open = result.get('result', {}).get('value', False)
        logger.info(f"Is current tab a ChatGPT tab? {is_chatgpt_open}")
        
        if is_chatgpt_open:
            # 현재 열려있는 탭이 ChatGPT 탭이면 그대로 사용
            mini_tab = tab
            url = "https://chatgpt.com/?model=gpt-4o-mini&temporary-chat=true"
            logger.info(f"Navigating to {url}")
            mini_tab.Page.navigate(url=url, _timeout=5)
            logger.info("Using existing ChatGPT tab for summarization")
        else:
            # 새로운 탭을 직접 열기 위해 새 브라우저 시작
            logger.info("Opening new browser instance for ChatGPT 4o-mini summarization")
            logger.debug("Starting new browser with start_browser()")
            mini_tab = browser.new_tab()
            mini_tab.start()
            url = "https://chatgpt.com/?model=gpt-4o-mini&temporary-chat=true"
            logger.info(f"Navigating to {url}")
            mini_tab.Page.navigate(url=url, _timeout=5)
            
            if not browser or not mini_tab:
                logger.error("Failed to start browser or open tab for summarization")
                return result_text, mini_tab # 원본 텍스트 반환
            
            logger.info("New browser instance created successfully")    
            # 페이지 로드 확인
            logger.info("Checking if page is loaded in the new tab")
            if not check_page_loaded(mini_tab, timeout=15):
                logger.error("Failed to load ChatGPT 4o-mini page")
                return result_text, mini_tab  # 원본 텍스트 반환
            logger.info("Page loaded successfully in the new tab")
        
        # 요약 요청 프롬프트 구성
        logger.info("Preparing summary prompt")
        summary_prompt = f"다음 내용을 간결하게 요약해주세요 (중요한 정보는 유지하고, 불필요한 세부사항은 제외). 반드시 500단어 이내로 요약해주세요:\n\n'cmd 의 목적 : {cmd_prompt} \n\n 결과 : {result_text}"
        logger.debug(f"Summary prompt length: {len(summary_prompt)} characters")
        
        # 요약 요청
        logger.info("Sending summary request to ChatGPT")
        send_result = send_query(mini_tab, summary_prompt)
        logger.info(f"Send query result: {send_result}")
        
        # 응답 대기
        logger.info("Waiting for response from ChatGPT")
        wait_result = wait_for_response_complete(mini_tab, timeout=180)
        logger.info(f"Wait for response result: {wait_result}")
        
        if not wait_result:
            logger.warning("Summary response waiting timed out")
            if mini_tab != original_tab:
                # 새로 열었던 탭을 닫기
                logger.info("Closing the new tab due to timeout")
                try:
                    pass
                    #browser.close_tab(mini_tab)
                    #logger.info("New tab closed successfully")
                except Exception as e:
                    logger.error(f"Error closing mini tab: {e}")
                    logger.error(traceback.format_exc())
                return result_text, mini_tab  # 원본 텍스트 반환
        
        # 요약 결과 가져오기
        logger.info("Extracting summary from ChatGPT response")
        js_code = """
        (function() {
            // 마지막 응답 메시지 가져오기
            const responseElements = document.querySelectorAll('div[data-testid="conversation-turn-2"] div[data-message-author-role="assistant"] div[data-message-text="true"], div[data-message-author-role="assistant"] div[data-message-text="true"]');
            if (responseElements.length > 0) {
                return responseElements[responseElements.length - 1].textContent;
            }
            return "";
        })();
        """
        
        logger.debug("Executing JavaScript to extract summary")
        result = mini_tab.Runtime.evaluate(expression=js_code)
        summarized_text = result.get('result', {}).get('value', "")
        logger.info(f"Extracted summary text length: {len(summarized_text)} characters")
        logger.debug(f"First 100 chars of summary: {summarized_text[:100]}...")
        
        # 새로 열었던 탭이면 닫기
        if mini_tab != original_tab:
            logger.info("Closing the new browser tab")
            try:
                browser.close_tab(mini_tab)
                logger.info("New tab closed successfully")
            except Exception as e:
                logger.error(f"Error closing mini tab: {e}")
                logger.error(traceback.format_exc())
        
        if not summarized_text:
            logger.warning("Failed to extract summary from ChatGPT response")
            return result_text, mini_tab # 원본 텍스트 반환
        
        logger.info(f"Successfully summarized text ({len(summarized_text)} characters)")
        logger.info("=" * 50)
        
        # 실행 완료 플래그 설정
        execution_done = True
        
        # 잠시 대기하여 실행 프로세스가 정리되도록 함
        time.sleep(1)
        
        return summarized_text, mini_tab
        
    except Exception as e:
        logger.error(f"Error summery_result: {e}")
        logger.error(traceback.format_exc())
        logger.info("=" * 50)
        return result_text, mini_tab # 오류 발생 시 원본 텍스트 반환
    finally:
        # 모든 경우에 실행 완료 표시
        execution_done = True
        logger.info("summery_result execution finished")


def execute_chatgpt_cmd_session(tab, browser, mini_tab, query):
    """
    ChatGPT를 이용한 CMD 명령어 실행 세션
    
    Args:
        tab: 브라우저 탭 객체
        browser: 브라우저 객체
        mini_tab: 요약용 미니 탭 (현재 미사용)
        query: 실행할 작업 쿼리
        
    Returns:
        실행 결과 문자열
    """
    try:
        # 쿼리 전송 프롬프트 작성
        logger.info("=" * 50)
        logger.info(f"CMD 세션 시작: {query}")
        logger.info("=" * 50)
        
        # CMD 관리자 준비
        cmd_manager = PersistentCmdManager()
        
        # CMD 결과 초기화
        cmd_result = None
        
        # 첫 번째 프롬프트 구성 - 초기 지시사항
        initial_prompt = f"""당신은 시스템 명령어 실행 도우미입니다. 다음 작업을 수행하기 위한 명령어를 제공해주세요:

작업: {query}

현재 환경:
- 운영체제: Windows 10
- 명령 프롬프트(CMD)를 사용할 수 있습니다
- 작업을 단계별로 명령어를 생성해주세요
- 한 번에 하나의 명령어만 제공해주세요 (복잡한 파이프라인이나 && 연산자 사용 자제)
- 각 명령어의 결과를 확인 후 다음 명령어를 제시할 것입니다

첫 번째로 실행할 명령어를 추천해주세요. 코드 블록으로 명령어 하나만 작성해 주세요.
```cmd
(이곳에 명령어를 작성)
```"""

        # 첫 번째 프롬프트 전송
        logger.info("초기 프롬프트 전송 중...")
        send_query(tab, initial_prompt)
        
        # 응답 대기
        if not wait_for_response_complete(tab, timeout=120):
            logger.warning("ChatGPT 초기 응답 대기 시간 초과")
            return "ChatGPT가 응답하지 않습니다. 나중에 다시 시도해주세요."
        
        logger.info("-" * 50)
        logger.info("CMD 명령어 실행 세션 시작")
        logger.info("-" * 50)
        
        # 명령어 처리 반복
        max_iterations = 5  # 최대 반복 횟수 (무한 루프 방지)
        iteration = 0
        final_result = ""
        
        while iteration < max_iterations:
            iteration += 1
            logger.info(f"명령어 처리 반복 {iteration}/{max_iterations}")
            
            # 응답 텍스트 가져오기 (페이지로부터 JavaScript 실행)
            response_script = """
                (function() {
                    try {
                        // 명령어와 코드 블록을 우선적으로 추출하는 향상된 스크립트
                        // 1. 마지막 응답 메시지 찾기 (가장 최근 응답)
                        const assistantMessages = Array.from(document.querySelectorAll('div[data-message-author-role="assistant"]'));
                        if (!assistantMessages || assistantMessages.length === 0) {
                            return { error: "응답 메시지를 찾을 수 없습니다", text: "" };
                        }
                        
                        const lastMessage = assistantMessages[assistantMessages.length - 1];
                        
                        // 2. 코드 블록 추출 시도 (pre 태그)
                        let commandBlocks = [];
                        const preElements = lastMessage.querySelectorAll('pre');
                        
                        if (preElements && preElements.length > 0) {
                            // 모든 코드 블록 추출
                            for (const pre of preElements) {
                                const code = pre.querySelector('code') || pre;
                                const content = code.textContent.trim();
                                
                                // 콘텐츠가 유효하고 CMD 명령어 패턴과 일치하는지 확인
                                const isCmdPattern = /^(dir|cd|copy|del|echo|type|mkdir|rmdir|ping|for|if|findstr)/i.test(content);
                                
                                commandBlocks.push({
                                    text: content,
                                    isCmdPattern: isCmdPattern
                                });
                            }
                            
                            // CMD 패턴과 일치하는 마지막 코드 블록 찾기
                            const cmdBlocks = commandBlocks.filter(block => block.isCmdPattern);
                            if (cmdBlocks.length > 0) {
                                // 마지막 CMD 블록 사용
                                const lastCmdBlock = cmdBlocks[cmdBlocks.length - 1];
                                return {
                                    type: "cmd_block",
                                    text: lastCmdBlock.text,
                                    allBlocks: commandBlocks.map(b => b.text)
                                };
                            } 
                            else if (commandBlocks.length > 0) {
                                // CMD 패턴이 없으면 마지막 코드 블록 사용
                                const lastBlock = commandBlocks[commandBlocks.length - 1];
                                return {
                                    type: "code_block",
                                    text: lastBlock.text,
                                    allBlocks: commandBlocks.map(b => b.text)
                                };
                            }
                        }
                        
                        // 3. 코드 블록이 없으면 텍스트 내용에서 명령어 줄 찾기
                        // 버튼 요소 임시 제거 (텍스트 추출 후 복원)
                        const buttons = lastMessage.querySelectorAll('button');
                        for (const btn of buttons) {
                            btn.style.display = 'none';
                        }
                        
                        // 전체 텍스트 추출
                        let messageText = lastMessage.textContent || "";
                        
                        // 버튼 복원
                        for (const btn of buttons) {
                            btn.style.display = '';
                        }
                        
                        // 추출된 텍스트 정리
                        messageText = messageText.replace(/\\s*복사\\s*|\\s*편집\\s*|\\s*cmd\\s*/gi, "");
                        
                        // 텍스트를 줄 단위로 분석
                        const lines = messageText.split("\\n").map(line => line.trim()).filter(line => line);
                        
                        // CMD 명령어 패턴 찾기
                        const cmdPattern = /^(dir|cd|copy|del|echo|type|mkdir|rmdir|ping|powershell|for|if|findstr)\\b/i;
                        const cmdLines = lines.filter(line => cmdPattern.test(line));
                        
                        if (cmdLines.length > 0) {
                            // 마지막 CMD 패턴 라인 사용
                            return {
                                type: "cmd_line",
                                text: cmdLines[cmdLines.length - 1],
                                allLines: cmdLines
                            };
                        }
                        
                        // 4. 아무것도 찾지 못한 경우 전체 텍스트 반환
                        return {
                            type: "full_text",
                            text: messageText
                        };
                    } catch (error) {
                        return {
                            error: error.toString(),
                            text: "오류 발생: " + error.toString()
                        };
                    }
                })()
            """
            response_result = tab.Runtime.evaluate(expression=response_script)
            response_value = response_result.get('result', {}).get('value', {})

            if isinstance(response_value, dict):
                # 새로운 형식 응답 처리
                if 'error' in response_value and response_value['error']:
                    logger.warning(f"응답 추출 중 오류: {response_value['error']}")
                response_text = response_value.get('text', '')
            else:
                # 이전 형식 응답 처리 (호환성 유지)
                response_text = response_value if isinstance(response_value, str) else ''

            logger.debug(f"추출된 응답: {response_text[:100]}...")
            
            # 응답 텍스트로부터 명령어 추출
            command = extract_command_from_response(response_text)

            # 응답 값을 분석하여 직접 명령어 추출 시도 - 개선된 버전
            response_result = tab.Runtime.evaluate(expression=response_script)
            response_value = response_result.get('result', {}).get('value', {})

            # 명령어를 담을 변수
            command = ""
            
            # 응답 값이 딕셔너리인 경우 (새 형식)
            if isinstance(response_value, dict):
                # 오류 발생 시 처리
                if 'error' in response_value and response_value['error']:
                    logger.warning(f"응답 추출 중 오류: {response_value['error']}")
                
                # 응답 타입별 처리
                response_type = response_value.get('type', '')
                
                if response_type == 'cmd_block' or response_type == 'code_block':
                    # 명령어 직접 추출 성공
                    command = response_value.get('text', '').strip()
                    logger.info(f"코드 블록에서 명령어 직접 추출: {command}")
                    
                    # 혹시 다른 후보들이 있는지 확인 (디버깅용)
                    if 'allBlocks' in response_value and logger.isEnabledFor(logging.DEBUG):
                        all_blocks = response_value.get('allBlocks', [])
                        if len(all_blocks) > 1:
                            logger.debug(f"다른 코드 블록 후보들: {all_blocks}")
                
                elif response_type == 'cmd_line':
                    # 텍스트 라인에서 명령어 찾음
                    command = response_value.get('text', '').strip()
                    logger.info(f"텍스트 라인에서 명령어 추출: {command}")
                    
                    # 다른 명령어 라인 후보들
                    if 'allLines' in response_value and logger.isEnabledFor(logging.DEBUG):
                        all_lines = response_value.get('allLines', [])
                        if len(all_lines) > 1:
                            logger.debug(f"다른 명령어 라인 후보들: {all_lines}")
                
                else:
                    # 전체 텍스트에서 명령어 추출 시도
                    full_text = response_value.get('text', '')
                    logger.debug(f"전체 텍스트에서 명령어 추출 시도 (첫 50자): {full_text[:50]}...")
                    command = extract_command_from_response(full_text)
            
            # 기존 방식으로 폴백 (응답이 문자열인 경우)
            else:
                full_text = response_value if isinstance(response_value, str) else ''
                logger.debug(f"기존 방식으로 명령어 추출 시도 (응답 길이: {len(full_text)})")
                command = extract_command_from_response(full_text)
            
            # 명령어가 없는 경우
            if not command:
                logger.warning("응답에서 명령어를 찾을 수 없습니다.")
                # 피드백 전송 - 향상된 명령어 제공 요청
                feedback_message = """
다음 형식으로 정확히 하나의 CMD 명령어를 제공해주세요:

```cmd
명령어
```

명령어는 별도의 코드 블록 안에 작성해주시고, 다른 설명없이 명령어만 포함해주세요.
예시:
```cmd
dir /s /a:-d d:\ > d:\filelist.txt
```
                """
                send_query(tab, feedback_message)
                
                # 응답 대기
                if not wait_for_response_complete(tab):
                    logger.warning("피드백 응답 대기 시간 초과")
                    continue
                
                # 다음 반복 진행
                continue
            
            # 명령어 완료 플래그 확인
            if "##TASK_COMPLETE##" in command or "task_complete.flag" in command:
                logger.info("작업 완료 플래그 감지됨")
                
                # 완료 플래그 파일이 존재하는지 확인
                if os.path.exists("task_complete.flag"):
                    with open("task_complete.flag", "r") as f:
                        flag_content = f.read().strip()
                    if "##TASK_COMPLETE##" in flag_content:
                        logger.info("작업 완료: 완료 플래그 파일 존재")
                        final_result = "작업이 완료되었습니다. 완료 플래그 파일이 생성되었습니다."
                        cmd_result = cmd_manager.execute_command('type task_complete.flag', timeout=60)
                        if cmd_result["success"]:
                            final_result += f"\n\n완료 정보: {cmd_result['stdout']}"
                        break
                
                # 실제로 완료 명령어 실행
                logger.info(f"완료 명령어 실행: {command}")
            
            # 실행할 명령어 표시
            logger.info("-" * 30)
            logger.info(f"실행할 명령어: {command}")
            
            # 명령어 실행 - 개선된 버전
            logger.info(f"명령어 실행 시작: {command}")
            try:
                # 복잡하거나 시간이 오래 걸릴 수 있는 명령어인지 확인
                is_complex_command = any(pattern in command.lower() for pattern in [
                    'dir /s', 'findstr /s', 'find /s', 'robocopy', 'xcopy', 'for /r'
                ])
                
                # 복잡한 명령어는 타임아웃 연장
                cmd_timeout = 300 if is_complex_command else 120
                
                # 안전한 실행 경로 확인 (현재 디렉토리가 올바른지)
                if command.startswith('cd ') or command.startswith('pushd '):
                    # 디렉토리 변경 명령은 안전하게 실행
                    cmd_result = cmd_manager.execute_command(command, timeout=60)
                else:
                    cmd_result = cmd_manager.execute_command(command, timeout=cmd_timeout)
                
                # 실행 결과 확인
                if cmd_result["success"]:
                    stdout = cmd_result["stdout"].strip()
                    # 불필요하게 긴 출력은 요약
                    if len(stdout) > 2000:
                        stdout_summary = stdout[:1000] + f"\n...(출력 길이: {len(stdout)}자)...\n" + stdout[-500:]
                        logger.info(f"명령어 실행 결과: (요약됨, 전체 길이: {len(stdout)}자)")
                        if logger.isEnabledFor(logging.DEBUG):
                            logger.debug(f"전체 명령어 출력:\n{stdout}")
                    else:
                        stdout_summary = stdout
                        logger.info(f"명령어 실행 결과:")
                    
                    # ChatGPT로 결과 전송
                    result_message = f"""### 명령어 실행 결과

실행한 명령어: `{command}`

출력 결과:
```
{stdout_summary}
```

------

### 다음 단계 안내
작업 목표: '{query}'

다음 명령어를 제안해주세요. 정확히 다음 형식으로 하나의 명령어만 제공해주세요:

```cmd
[여기에 명령어 작성]
```

만약 작업이 완료되었다고 판단되면 다음 명령어를 실행하세요:
```cmd
echo ##TASK_COMPLETE##[%random%] > task_complete.flag && echo {{"status":"complete","timestamp":"%date% %time%","message":"에이전트작업완료"}}
```"""
                else:
                    error_output = cmd_result["stderr"] if cmd_result["stderr"] else "알 수 없는 오류"
                    logger.error(f"명령어 실행 실패: {error_output}")
                    
                    # ChatGPT로 오류 결과 전송
                    result_message = f"""### 명령어 실행 결과 - 오류 발생

실행한 명령어: `{command}`

오류 내용:
```
{error_output}
```

------

### 다음 단계 안내
작업 목표: '{query}'

오류를 해결하고 작업을 진행하기 위한 다음 명령어를 제안해주세요. 정확히 다음 형식으로 하나의 명령어만 제공해주세요:

```cmd
[여기에 명령어 작성]
```

만약 작업이 완료되었다고 판단되면 다음 명령어를 실행하세요:
```cmd
echo ##TASK_COMPLETE##[%random%] > task_complete.flag && echo {{"status":"complete","timestamp":"%date% %time%","message":"에이전트작업완료"}}
```"""
            
            # 결과 전송
            logger.info("결과 메시지 전송 중...")
            send_query(tab, result_message)
            
            # 응답 대기
            logger.info("ChatGPT 응답 대기 중...")
            if not wait_for_response_complete(tab, timeout=180):
                logger.warning("응답 대기 시간 초과")
                continue

            # 작업 완료 플래그 파일 다시 확인
            if os.path.exists("task_complete.flag"):
                logger.info("작업 완료 플래그 파일 발견")
                with open("task_complete.flag", "r") as f:
                    flag_content = f.read().strip()
                if "##TASK_COMPLETE##" in flag_content:
                    logger.info("작업 완료 플래그 확인됨")
                    final_result = "작업이 완료되었습니다. 완료 플래그 파일이 생성되었습니다."
                    # JSON 상태 파일의 내용 읽기
                    cmd_result = cmd_manager.execute_command('type task_complete.flag', timeout=60)
                    if cmd_result["success"]:
                        final_result += f"\n\n완료 정보: {cmd_result['stdout']}"
                    break

        # 최대 반복 횟수 초과 확인
        if not final_result and iteration >= max_iterations:
            logger.warning(f"최대 반복 횟수({max_iterations}회) 도달")
            final_result = "최대 반복 횟수에 도달했습니다. 작업이 완료되지 않았을 수 있습니다."
            
        # 최종 결과 출력 시 시각적 구분 추가
        logger.info("=" * 50)
        completion_status = "작업 상태: 완료됨" if "작업이 완료되었습니다" in final_result else "작업 상태: 미완료"
        logger.info(completion_status)
        logger.info("=" * 50)
        
        # 작업 결과 요약 생성
        summary = "== 작업 결과 요약 ==\n"
        if os.path.exists("task_complete.flag"):
            with open("task_complete.flag", "r") as f:
                flag_content = f.read().strip()
            summary += f"완료 상태: 성공\n완료 태그: {flag_content}\n"
        else:
            summary += "완료 상태: 미완료 또는 실패\n"
        
        # 최종 디렉토리 상태 로깅 (상세 로그에만 기록)
        if logger.isEnabledFor(logging.DEBUG):
            cmd_result = cmd_manager.execute_command("dir", timeout=60)
            if cmd_result["success"]:
                logger.debug(f"최종 디렉토리 상태:\n{cmd_result['stdout'][:500]}...\n")
        
        logger.info(summary)
        return final_result + "\n\n" + summary
        
    except Exception as e:
        error_msg = f"CMD 세션 실행 중 오류 발생: {str(e)}"
        logger.error(error_msg)
        
        # 상세 로그에만 기록
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(traceback.format_exc())
            
        # 상세 오류 진단
        try:
            tab_info = "알 수 없음"
            if tab:
                tab_info = f"탭 ID: {tab.id}"
            browser_info = "알 수 없음"
            if browser:
                browser_info = f"연결 상태: {browser.url}"
                
            logger.error(f"브라우저 정보: {browser_info}, {tab_info}")
            
            # 명령어 관리자 상태 확인
            if 'cmd_manager' in locals():
                last_cmd = cmd_manager.last_command if hasattr(cmd_manager, 'last_command') else "없음"
                logger.error(f"마지막 실행 명령어: {last_cmd}")
        except:
            pass
            
        return f"오류 발생: {str(e)}\n\n문제 해결 제안:\n1. 브라우저 연결 상태를 확인하세요.\n2. 네트워크 연결을 확인하세요.\n3. ChatGPT 서비스 접근 가능 여부를 확인하세요."

def extract_command_from_response(response_text):
    """
    ChatGPT 응답에서 실행할 CMD 명령어를 추출합니다.
    매우 단순화된 버전: UI 요소 제거 및 응답 형식에 맞춰 최적화
    
    Args:
        response_text: ChatGPT 응답 텍스트
        
    Returns:
        추출된 명령어 문자열 또는 빈 문자열
    """
    try:
        # 디버깅 목적으로만 로깅
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"응답 첫 100자: {response_text[:100]}...")
        
        # 불필요한 UI 텍스트 제거
        cleaned_text = re.sub(r'(?:복사|편집|cmd)\s*', '', response_text, flags=re.IGNORECASE)
        
        # 행 단위로 분할
        lines = cleaned_text.split('\n')
        
        # 모든 줄 중에서 가장 가능성 높은 명령어 찾기
        # Windows 명령어 목록 (가장 흔한 것들)
        common_cmd_prefixes = [
            'dir', 'cd', 'copy', 'del', 'echo', 'type', 'mkdir', 'rmdir', 
            'ping', 'ipconfig', 'netstat', 'findstr', 'find',
            'for', 'sort', 'fc', 'comp', 'powershell', 'cmd'
        ]
        
        # 각 줄 평가
        for line in lines:
            # 빈 줄 건너뛰기
            line = line.strip()
            if not line or len(line) < 3:
                continue
                
            # 명령어 시작 패턴 확인
            for prefix in common_cmd_prefixes:
                # 명령어로 시작하는지 확인 (공백이나 슬래시가 뒤따라야 함)
                pattern = f"^{prefix}\\s|^{prefix}/"
                if re.search(pattern, line, re.IGNORECASE):
                    logger.info(f"명령어 찾음: {line}")
                    return line
            
            # 파워셸 명령어 확인
            if re.search(r'^powershell', line, re.IGNORECASE):
                logger.info(f"파워셸 명령어 찾음: {line}")
                return line
                
            # 기타 파일 경로나 특수 패턴 확인
            if ">" in line or re.search(r'[a-zA-Z]:\\', line):
                logger.info(f"파일 작업 명령어 찾음: {line}")
                return line
        
        # 두 번째 시도: 전체 응답에서 코드 블록 패턴 찾기
        code_block_pattern = r'```(?:cmd|bat|bash|shell|powershell|)?\s*(.*?)\s*```'
        matches = re.findall(code_block_pattern, cleaned_text, re.DOTALL)
        
        if matches:
            for match in matches:
                cmd = match.strip()
                if cmd:
                    logger.info(f"코드 블록에서 명령어 찾음: {cmd}")
                    return cmd
        
        # 마지막 시도: 응답에서 명령어 직접 추출
        # 일반적으로 '이 명령어가 ...' 라는 형식으로 표현됨
        for line in lines:
            line = line.strip().lower()
            for cmd_word in ["명령어", "command", "cmd", "실행"]:
                if cmd_word in line:
                    # 명령어 단어 이후의 텍스트에서 첫 번째 줄만 사용
                    parts = line.split(cmd_word, 1)
                    if len(parts) > 1 and parts[1]:
                        cmd_text = parts[1].strip()
                        # 특수 문자 제거
                        cmd_text = re.sub(r'^[:\s"\'`]+', '', cmd_text)
                        if cmd_text:
                            logger.info(f"설명 텍스트에서 명령어 찾음: {cmd_text}")
                            return cmd_text
        
        # 명령어를 찾지 못한 경우
        logger.warning("응답에서 명령어를 찾지 못했습니다")
        # 디버깅용 출력
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"정제된 응답(첫 200자): {cleaned_text[:200]}...")
        return ""
    
    except Exception as e:
        logger.error(f"명령어 추출 중 오류 발생: {e}")
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(traceback.format_exc())
        return ""

def cmd_session_main(testcmd = ''):
    """
    CMD 세션 메인 함수
    """
    try:
        # 사용자 입력 받기
        if testcmd == '':
            user_query = input("CMD 작업을 위한 쿼리를 입력하세요: ")
        else:
            user_query = testcmd
        
        # 브라우저 시작 및 페이지 로드
        logger.info("Starting browser for CMD session")
        browser, tab = start_browser(
            profile_name="Default", 
            position=(10, 10), 
            size=(900, 700)
        )
        mini_tab = None
        
        if not browser or not tab:
            logger.error("Failed to start browser or open tab")
            return
            
        # 페이지 로드 확인
        if not check_page_loaded(tab, timeout=15):
            logger.error("Page load check failed")
            return
            
        # CMD 세션 실행
        result = execute_chatgpt_cmd_session(tab, browser, mini_tab, user_query)
        
        # 결과 출력
        print("\n--- 작업 결과 ---")
        print(result)
        
        # 브라우저 정리
        print("Press Enter to finish...")
        logger.info("Closing browser")
        browser.close_tab(tab)
        
    except Exception as e:
        logger.error(f"Unexpected error in CMD session: {e}")
        logger.error(traceback.format_exc())
    finally:
        # 종료 시 브라우저 프로세스 정리
        try:
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] == "slimjet.exe":
                    logger.info("남은 브라우저 프로세스 정리 중...")
                    proc.kill()
        except:
            pass
            
        logger.info("=" * 50)
        logger.info("프로그램 종료")
        logger.info("=" * 50)

# 메인 함수 수정
def newmain(testcmd = 'd: 의 가장 작은 파일의 이름을 출력해주세요요'):
    """
    메인 실행 함수
    
    Args:
        testcmd: 테스트할 명령어 (기본값: 'd: 의 가장 작은 파일의 이름을 출력해주세요요')
    """
    logger.info("=" * 50)
    logger.info("ChatGPT 에이전트 실행 시작")
    logger.info("=" * 50)
    
    try:
        cmd_session_main(testcmd = testcmd)
        logger.info("에이전트 실행 완료")
        
    except Exception as e:
        error_msg = f"에이전트 실행 중 예기치 않은 오류: {str(e)}"
        logger.error(error_msg)
        logger.error("=" * 50)
        logger.error("오류 세부 정보:")
        
        # 오류 세부 정보 출력 (중요한 오류이므로 INFO 레벨로도 기록)
        err_traceback = traceback.format_exc()
        logger.error(err_traceback)
        
        # 시스템 정보 수집
        system_info = []
        try:
            system_info.append(f"Python 버전: {sys.version}")
            system_info.append(f"운영체제: {os.name}, {sys.platform}")
            
            # 관련 프로세스 확인
            processes = []
            for proc in psutil.process_iter(['name', 'pid']):
                if proc.info['name'] in ["slimjet.exe", "chrome.exe", "python.exe"]:
                    processes.append(f"{proc.info['name']} (PID: {proc.info['pid']})")
            
            if processes:
                system_info.append("관련 프로세스: " + ", ".join(processes))
                
            # 메모리 사용량
            memory_info = psutil.virtual_memory()
            system_info.append(f"메모리 사용량: {memory_info.percent}% (사용/전체: {memory_info.used//1024//1024}MB/{memory_info.total//1024//1024}MB)")
            
            logger.error("시스템 정보:")
            for info in system_info:
                logger.error(f"- {info}")
                
        except:
            logger.error("시스템 정보 수집 중 오류 발생")
            
        logger.error("=" * 50)
        logger.error("해결 방법 제안:")
        logger.error("1. Slimjet 브라우저가 설치되어 있는지 확인하세요")
        logger.error("2. cmdman 모듈이 올바르게 설치되어 있는지 확인하세요")
        logger.error("3. 로그 파일(myagent.log, myagent_detail.log)을 확인하여 자세한 오류 내용을 확인하세요")
        logger.error("=" * 50)
    
    finally:
        # 정리 작업
        try:
            # 브라우저 프로세스 정리
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] == "slimjet.exe":
                    logger.info("남은 브라우저 프로세스 정리 중...")
                    proc.kill()
        except:
            pass
            
        logger.info("=" * 50)
        logger.info("프로그램 종료")
        logger.info("=" * 50)

if __name__ == "__main__":
    os.chdir("d:")
    newmain()