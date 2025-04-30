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
from cmd_manager import *


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
        logger.error(f"Error capturing window: {e}")
        logger.error(traceback.format_exc())
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
    Brave 브라우저를 시작하고 디버깅 포트를 연결합니다.
    성능 최적화된 옵션 적용
    """
    try:
        # 실행 중인 Brave 브라우저 종료
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] == "brave.exe":
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
        cmd = f'"C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe" ' \
              f'--remote-debugging-port=9222 ' \
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
        
        # 브라우저가 시작되고 디버깅 포트가 준비될 때까지 기다림
        max_attempts = 10
        attempts = 0
        browser = None
        
        while attempts < max_attempts:
            try:
                time.sleep(0.5)  # 대기 시간 감소 (1초 → 0.5초)
                browser = pychrome.Browser(url="http://127.0.0.1:9222")
                tab = browser.new_tab()
                tab.start()
                break
            except Exception as e:
                logger.warning(f"Browser not ready yet, retrying... ({attempts+1}/{max_attempts})")
                attempts += 1
                if attempts >= max_attempts:
                    logger.error(f"Failed to connect to browser: {e}")
                    return None, None
        
        # 네트워크 활성화 및 페이지 이동
        tab.Network.enable()
        
        # ChatGPT 페이지로 직접 이동
        url = "https://chatgpt.com/?model=o4-mini-high"#
        logger.info(f"Navigating to {url}")
        tab.Page.navigate(url=url, _timeout=5)  # 타임아웃 감소 (10초 → 5초)
        
        # 페이지 로딩 기다리기
        tab.wait(5)  # 대기 시간 감소 (10초 → 5초)
        
        return browser, tab
    
    except Exception as e:
        logger.error(f"Error starting browser: {e}")
        logger.error(traceback.format_exc())
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
    try:
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
            
        # 잠시 기다림
        time.sleep(0.5)
        
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
            
        return success
            
    except Exception as e:
        logger.error(f"Error sending query: {e}")
        logger.error(traceback.format_exc())
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
            if is_model_responding(tab):
                response_started = True
                logger.info("Model started responding")
                break
            
            time.sleep(0.3)  # 폴링 간격 감소 (0.5초 → 0.3초)
        
        if not response_started:
            logger.warning("Model did not start responding within timeout")
            return False
        
        # 이제 응답이 완료될 때까지 대기 - 더 효율적인 동적 폴링 적용
        while time.time() - start_time < timeout:
            is_responding = is_model_responding(tab)
            
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

def get_last_python_code(tab):
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

def main():
    try:
        # 브라우저 시작 및 페이지 로드 - 더 작은 사이즈로 시작 (메모리 사용 최적화)
        browser, tab = start_browser(
            profile_name="Profile 1", 
            position=(10, 10), 
            size=(900, 700)  # 사이즈 감소 (1024x800 → 900x700)
        )
        
        if not browser or not tab:
            logger.error("Failed to start browser or open tab")
            return
            
        # 페이지 로드 확인 - 더 짧은 타임아웃
        if not check_page_loaded(tab, timeout=15):  # 타임아웃 감소 (기본값 30초 → 15초)
            logger.error("Page load check failed")
            return
            
        # 테스트 쿼리 전송
        logger.info("Sending test query...")
        send_query(tab, "오늘의 날씨에 대해서 알려주세요:")
        
        # 이미지 파일 첨부 테스트 - 대기 시간 감소
        time.sleep(0.5)  # 대기 시간 감소 (1초 → 0.5초)
        #file_path = "capture.png"  # 파일 경로 설정
        #if os.path.exists(file_path):
        #    logger.info(f"Attaching file: {file_path}")
        #    simulate_paste_local_file(file_path, tab)
        #    time.sleep(1)  # 대기 시간 감소 (2초 → 1초)
        
        # 쿼리 전송
        #send_query(tab, "")  # 이미 텍스트 영역에 내용이 있으므로 빈 텍스트로 전송
        
        # 응답 대기 - 더 짧은 타임아웃
        if not wait_for_response_complete(tab, timeout=180):  # 타임아웃 감소 (기본값 300초 → 180초)
            logger.warning("Response waiting timed out")
        
        # 코드 가져오기
        python_code = get_last_python_code(tab)
        if python_code:
            # 결과 코드 저장
            with open("fixed_code.py", "w", encoding="utf-8") as f:
                f.write(python_code)
            logger.info("Code saved to fixed_code.py")
        
        # 브라우저 정리
        logger.info("Closing browser")
        browser.close_tab(tab)
        
    except Exception as e:
        logger.error(f"Unexpected error in main: {e}")
        logger.error(traceback.format_exc())
    finally:
        # 종료 시 브라우저 프로세스 정리
        try:
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] == "brave.exe":
                    logger.info("Cleaning up browser process")
                    proc.kill()
        except:
            pass

def execute_chatgpt_cmd_session(tab, query):
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

이 작업을 수행하기 위한 윈도우즈 CMD 명령어 시퀀스를 하나씩 제공해주세요. 각 명령어 실행 결과를 확인한 후 다음 명령어를 제시하겠습니다.

작업이 완료되면 반드시 다음의 명령어로 명확하게 종료를 표시해주세요:
echo ##TASK_COMPLETE##[%random%] > task_complete.flag && echo {{"status":"complete","timestamp":"%date% %time%","message":"에이전트작업완료"}}

불필요한 설명은 절대 하지 않고 모두 코드로만 대화 합니다"""

        logger.info("Sending initial prompt to ChatGPT")
        send_query(tab, initial_prompt)

        # 응답 대기
        if not wait_for_response_complete(tab, timeout=300):
            logger.warning("Initial response waiting timed out")
            return "오류: ChatGPT 응답 대기 시간 초과"
        time.sleep(1)
        
        # 명령어 실행 및 결과 전송 루프
        max_iterations = 10  # 안전을 위한 최대 반복 횟수
        iteration = 0
        final_result = ""

        while iteration < max_iterations:
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
   // 코드 블록만 추출 (일반 텍스트 제외)
   const codeBlockCommands = [];
   
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
   
   // 2. whitespace-pre 및 language 클래스를 가진 요소 추출
   const whitespacePreElements = document.querySelectorAll('[class*="whitespace-pre"]');
   if(whitespacePreElements.length > 0){
       codeBlockCommands.push(whitespacePreElements[whitespacePreElements.length - 1].textContent);
   }
   
   // 완료 확인 - 개선된 패턴 확인
   const fullText = lastMessage ? lastMessage.textContent : '';
   const hasResult = 
       fullText.includes('##TASK_COMPLETE##') || 
       fullText.includes('{"status":"complete"') || 
       fullText.includes('에이전트작업완료') ||
       (fullText.includes('task_complete.flag') && fullText.includes('작업완료'));
   
   // 코드 블록이 없고 결과 메시지도 없으면 빈 문자열 반환
   if (codeBlockCommands.length === 0 && !hasResult) {
       return '';
   }
   
   // 코드 블록이 있으면 코드 블록만 반환, 없으면서 결과 메시지가 있으면 결과 메시지 반환
   if (codeBlockCommands.length > 0) {
       return codeBlockCommands.join('\\n\\n');
   } else if (hasResult) {
       return fullText;
   }
   
   return '';
})();
"""
           
            result = tab.Runtime.evaluate(expression=js_code)
            response_text = result.get('result', {}).get('value', "")
            print("response_text", result)
            
            # 응답 텍스트에서 명령어 추출 또는 완료 여부 확인
            if any(marker in response_text for marker in [
                "##TASK_COMPLETE##", 
                "\"status\":\"complete\"", 
                "에이전트작업완료"
            ]):
                logger.info("Task completion detected in response")
                final_result = response_text
                break
                
            # 코드 블록에서 추출한 명령어가 있으면 실행
            cmd_to_execute = response_text.strip() if response_text else None
            print("cmd_to_execute", cmd_to_execute)
            
            if not cmd_to_execute:
                logger.warning("No command found in response")
                send_query(tab, "명령어를 찾을 수 없습니다. CMD 명령어를 코드 블록으로 명확하게 제시해주세요.")
                
                if not wait_for_response_complete(tab, timeout=300):
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
            
            # 실행 결과 준비
            if cmd_result["success"]:
                # 지정된 형식으로 결과 구성
                formatted_output = cmd_result.get('formatted_output', '')
                
                # 형식이 없는 경우 이전 방식으로 구성
                if not formatted_output:
                    rsltstr = "----stdout---\n" + cmd_result['stdout'] + "\n\n---stderr---\n" + cmd_result['stderr']
                    result_message = f"""명령어 실행 결과:\n{rsltstrpre}\n----명령어 실행 결과----\n{rsltstr}\n{rsltstrpost}\n현재의 로그 콘솔을 통해 원하는 작업이 실행이 되었는지 확인 후, 아니라고 생각한다면 계획을 수정하여 다음 명령어를 제시하거나, 모든 작업이 완료되었다고 판단되는 경우에는 다음의 명령어를 실행하세요:

echo ##TASK_COMPLETE##[%random%] > task_complete.flag && echo {{"status":"complete","timestamp":"%date% %time%","message":"에이전트작업완료"}}"""
                else:
                    # 새로운 형식 사용
                    result_message = f"""명령어 실행 결과:\n{rsltstrpre}----명령어 실행 결과----\n{formatted_output}\n{rsltstrpost}\n현재의 로그 콘솔을 통해 원하는 작업이 실행이 되었는지 확인 후, 아니라고 생각한다면 계획을 수정하여 다음 명령어를 제시하거나, 모든 작업이 완료되었다고 판단되는 경우에는 다음의 명령어를 실행하세요:

echo ##TASK_COMPLETE##[%random%] > task_complete.flag && echo {{"status":"complete","timestamp":"%date% %time%","message":"에이전트작업완료"}}"""
            else:
                error_output = cmd_result["stderr"] if cmd_result["stderr"] else "알 수 없는 오류"
                result_message = f"""명령어 실행 중 오류 발생:\n{rsltstrpre}\n----명령어 실행 오류----\n{error_output}\n{rsltstrpost}\n현재의 로그 콘솔을 통해 원하는 작업이 실행이 되었는지 확인 후, 아니라고 생각한다면 계획을 수정하여 다음 명령어를 제시하거나, 모든 작업이 완료되었다고 판단되는 경우에는 다음의 명령어를 실행하세요:

echo ##TASK_COMPLETE##[%random%] > task_complete.flag && echo {{"status":"complete","timestamp":"%date% %time%","message":"에이전트작업완료"}}"""
           
            # 결과 전송
            send_query(tab, result_message)
            
            # 응답 대기
            if not wait_for_response_complete(tab, timeout=300):
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
        logger.error(f"Error in execute_chatgpt_cmd_session: {str(e)}")
        logger.error(traceback.format_exc())
        return f"오류 발생: {str(e)}"

def extract_command_from_response(response_text):
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
        print("response_text"  ,response_text)
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

def cmd_session_main():
    """
    CMD 세션 메인 함수
    """
    try:
        # 사용자 입력 받기
        user_query = input("CMD 작업을 위한 쿼리를 입력하세요: ")
        
        # 브라우저 시작 및 페이지 로드
        logger.info("Starting browser for CMD session")
        browser, tab = start_browser(
            profile_name="Profile 1", 
            position=(10, 10), 
            size=(900, 700)
        )
        
        if not browser or not tab:
            logger.error("Failed to start browser or open tab")
            return
            
        # 페이지 로드 확인
        if not check_page_loaded(tab, timeout=15):
            logger.error("Page load check failed")
            return
            
        # CMD 세션 실행
        result = execute_chatgpt_cmd_session(tab, user_query)
        
        # 결과 출력
        print("\n--- 작업 결과 ---")
        print(result)
        
        # 브라우저 정리
        logger.info("Closing browser")
        browser.close_tab(tab)
        
    except Exception as e:
        logger.error(f"Unexpected error in CMD session: {e}")
        logger.error(traceback.format_exc())
    finally:
        # 종료 시 브라우저 프로세스 정리
        try:
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] == "brave.exe":
                    logger.info("Cleaning up browser process")
                    proc.kill()
        except:
            pass

# 메인 함수 수정
def newmain():
    try:
        # 작업 모드 선택 (기존 기능 유지하면서 CMD 세션 기능 추가)
        print("작업 모드를 선택하세요:")
        print("1. 코드 분석 및 수정 (기존 기능)")
        print("2. CMD 명령어 실행 세션")
        
        #mode = input("선택 (1 또는 2): ")
        mode = "2"
        if mode == "2":
            cmd_session_main()
        else:
            # 기존 main 함수 내용 (코드 분석 및 수정 기능)
            # 브라우저 시작 및 페이지 로드 - 더 작은 사이즈로 시작 (메모리 사용 최적화)
            browser, tab = start_browser(
                profile_name="Profile 1", 
                position=(10, 10), 
                size=(900, 700)  # 사이즈 감소 (1024x800 → 900x700)
            )
            
            if not browser or not tab:
                logger.error("Failed to start browser or open tab")
                return
                
            # 페이지 로드 확인 - 더 짧은 타임아웃
            if not check_page_loaded(tab, timeout=15):  # 타임아웃 감소 (기본값 30초 → 15초)
                logger.error("Page load check failed")
                return
                
            # 테스트 쿼리 전송
            logger.info("Sending test query...")
            send_query(tab, "오늘의 날씨에 대해서 알려주세요:")
            
            # 응답 대기 - 더 짧은 타임아웃
            if not wait_for_response_complete(tab, timeout=180):  # 타임아웃 감소 (기본값 300초 → 180초)
                logger.warning("Response waiting timed out")
            
            # 코드 가져오기
            python_code = get_last_python_code(tab)
            if python_code:
                # 결과 코드 저장
                with open("fixed_code.py", "w", encoding="utf-8") as f:
                    f.write(python_code)
                logger.info("Code saved to fixed_code.py")
            
            # 브라우저 정리
            logger.info("Closing browser")
            browser.close_tab(tab)
        
    except Exception as e:
        logger.error(f"Unexpected error in main: {e}")
        logger.error(traceback.format_exc())
    finally:
        # 종료 시 브라우저 프로세스 정리
        try:
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] == "brave.exe":
                    logger.info("Cleaning up browser process")
                    proc.kill()
        except:
            pass

if __name__ == "__main__":
    newmain()