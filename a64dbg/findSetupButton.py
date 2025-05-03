#!/usr/bin/env python3
# a64dbg/findSetupButton.py - Find setup button event handlers

import sys
import os
import time
import frida
import argparse
import logging
import traceback
from tabulate import tabulate

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("findSetupButton_debug.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Add current directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from controller import FridaController
from gui_utils import GuiElementUtils

class SetupButtonFinder:
    def __init__(self, target, timeout=60, setup_keywords=None):
        """
        Setup 버튼을 찾기 위한 클래스 초기화
        
        Args:
            target: 대상 프로세스 (이름 또는 PID)
            timeout: 버튼 핸들러 감지 제한 시간 (초)
            setup_keywords: Setup 관련 검색할 키워드 리스트
        """
        self.target = target
        self.timeout = timeout
        self.controller = None
        self.gui_utils = None
        
        # Setup 관련 키워드 (기본값 + 사용자 지정 키워드)
        self.setup_keywords = ['setup', 'install', 'configure', '설정', '설치', '구성']
        if setup_keywords:
            self.setup_keywords.extend(setup_keywords)
        
        # 대소문자 구분 없이 검색하기 위해 모두 소문자로 변환
        self.setup_keywords = [keyword.lower() for keyword in self.setup_keywords]
        
        # 발견된 Setup 버튼 목록
        self.setup_buttons = {}
        
        logger.info(f"SetupButtonFinder initialized with target: {target}, timeout: {timeout}")
        
    def run(self):
        """메인 실행 함수"""
        try:
            # 프로세스에 연결
            logger.info(f"Connecting to process: {self.target}")
            print(f"[*] 프로세스에 연결 중: {self.target}")
            self.controller = FridaController(self.target)
            
            # GUI 유틸리티 초기화 및 커스텀 핸들러 설정
            logger.info("Initializing GUI utilities")
            self.gui_utils = GuiElementUtils(None)
            if not self._setup_custom_handler():
                print("[!] 프로세스 연결 실패")
                return False
            
            # 모든 윈도우 스캔
            print("[*] 윈도우 스캔 중...")
            logger.info("Starting window scanning")
            try:
                self.gui_utils.scan_all_windows()
                logger.info("Window scanning completed")
            except Exception as e:
                logger.error(f"Error during window scanning: {e}")
                logger.error(f"Exception type: {type(e)}")
                logger.error(f"Traceback: {traceback.format_exc()}")
                print(f"[!] 윈도우 스캔 중 오류 발생: {e}")
            
            time.sleep(1)  # 스캔 완료 대기
            
            # 발견된 윈도우 목록 출력
            logger.info("Printing window information")
            try:
                self.gui_utils.print_windows()
            except Exception as e:
                logger.error(f"Error while printing windows: {e}")
                logger.error(f"Traceback: {traceback.format_exc()}")
            
            # 모든 윈도우에 대해 상세 정보 가져오기
            logger.info("Getting detailed window information")
            for hwnd in self.gui_utils.windows.keys():
                try:
                    logger.debug(f"Getting information for window with HWND: {hwnd}")
                    self.gui_utils.get_window_info(hwnd)
                except Exception as e:
                    logger.error(f"Error getting info for window {hwnd}: {e}")
                    logger.error(f"Traceback: {traceback.format_exc()}")
                time.sleep(0.2)  # 요청 간격
            
            # 발견된 setup 관련 컨트롤 검색
            logger.info("Searching for setup controls")
            self._find_setup_controls()
            
            if not self.setup_buttons:
                print("[!] Setup 관련 버튼을 찾지 못했습니다.")
                logger.info("No setup buttons found. Scanning all controls.")
                self._scan_all_controls()
                
                # 사용자에게 모든 윈도우 모니터링 제안
                print("\n[*] 모든 윈도우를 모니터링하고 직접 Setup 버튼을 클릭하시겠습니까?")
                response = input("  모니터링 시작 (y/n)? ")
                
                if response.lower() == 'y':
                    logger.info("Starting monitoring of all windows")
                    self._monitor_all_windows()
                else:
                    print("[*] 프로그램을 종료합니다.")
                    logger.info("User chose not to monitor windows. Exiting.")
                    return False
            else:
                # Setup 버튼이 발견된 경우
                logger.info(f"Found {len(self.setup_buttons)} setup buttons")
                self._print_setup_buttons()
                
                # 발견된 버튼이 있는 윈도우 모니터링
                logger.info("Monitoring windows with setup buttons")
                for hwnd in set([info['window_hwnd'] for info in self.setup_buttons.values()]):
                    try:
                        logger.debug(f"Monitoring window with HWND: {hwnd}")
                        self.gui_utils.monitor_window(hwnd)
                    except Exception as e:
                        logger.error(f"Error monitoring window {hwnd}: {e}")
                        logger.error(f"Traceback: {traceback.format_exc()}")
            
            # 사용자에게 버튼 클릭 요청
            print("\n[*] 이제 프로그램의 Setup 버튼을 클릭하세요.")
            print(f"[*] {self.timeout}초 동안 버튼 클릭 이벤트를 감지합니다...")
            
            # 핸들러 감지 대기
            logger.info(f"Waiting for setup handlers for {self.timeout} seconds")
            setup_handlers = self._wait_for_setup_handlers()
            
            # 결과 출력
            if setup_handlers:
                logger.info(f"Found {len(setup_handlers)} setup button handlers")
                print(f"\n[+] {len(setup_handlers)}개의 Setup 버튼 핸들러를 발견했습니다:")
                self._print_setup_handlers(setup_handlers)
                
                # 보고서 저장
                report_file = "setup_button_handlers.txt"
                logger.info(f"Generating report to {report_file}")
                self._generate_report(setup_handlers, report_file)
                print(f"[+] 보고서가 {report_file}에 저장되었습니다.")
            else:
                logger.info("No setup button handlers detected")
                print("\n[!] Setup 버튼 클릭 이벤트를 감지하지 못했습니다.")
            
            return True
            
        except KeyboardInterrupt:
            logger.info("Interrupted by user")
            print("\n[!] 사용자에 의해 중단되었습니다.")
            return False
        except Exception as e:
            logger.error(f"Error in run method: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            print(f"[!] 오류 발생: {e}")
            return False
        finally:
            # Frida 세션 정리
            if self.controller and hasattr(self.controller, 'session') and self.controller.session:
                logger.info("Detaching Frida session")
                print("[*] Frida 세션 종료 중...")
                self.controller.session.detach()
    
    def _setup_custom_handler(self):
        """
        커스텀 메시지 핸들러 설정
        
        Returns:
            bool: 설정 성공 여부
        """
        try:
            # 메시지 핸들러 정의
            def message_handler(message, data):
                try:
                    logger.debug(f"Received message: {type(message)}")
                    logger.debug(f"Message content: {message}")
                    logger.debug(f"Data type: {type(data)}")
                    if data:
                        logger.debug(f"Data length: {len(data)}")
                    
                    if message['type'] == 'send':
                        payload = message.get('payload', {})
                        logger.debug(f"Payload type: {type(payload)}")
                        logger.debug(f"Payload content: {payload}")
                        
                        if isinstance(payload, dict) and payload.get('hook') == 'GuiElement':
                            logger.debug("Sending to GUI event handler")
                            self.gui_utils.event_handler(message, data)
                        else:
                            # 다른 메시지는 기본 핸들러로 전달
                            logger.debug("Sending to default controller handler")
                            self.controller._on_message(message, data)
                except Exception as e:
                    logger.error(f"Error in message handler: {e}")
                    logger.error(f"Traceback: {traceback.format_exc()}")
            
            # 로컬 장치의 Frida 인스턴스 사용
            logger.info("Getting local Frida device")
            device = self.controller.device = frida.get_local_device()
            
            # 프로세스 연결
            if self.controller.spawn:
                logger.info(f"Spawning process: {self.controller.target}")
                pid = device.spawn([self.controller.target])
                self.controller.session = device.attach(pid)
                logger.info(f"Process spawned and attached (PID: {pid})")
                print(f"[+] 프로세스 생성 및 연결 완료 (PID: {pid})")
            else:
                try:
                    pid = int(self.controller.target)
                    logger.info(f"Attaching to PID: {pid}")
                    self.controller.session = device.attach(pid)
                except ValueError:
                    logger.info(f"Attaching to process name: {self.controller.target}")
                    self.controller.session = device.attach(self.controller.target)
                logger.info(f"Process attached: {self.controller.target}")
                print(f"[+] 프로세스 연결 완료: {self.controller.target}")
            
            # 후킹 스크립트 로드
            logger.info("Building script")
            script_code = self.controller._build_script()
            logger.debug(f"Script code length: {len(script_code)}")
            
            logger.info("Creating script")
            self.controller.script = self.controller.session.create_script(script_code)
            
            # GUI 유틸리티에 스크립트 설정
            logger.info("Setting script for GUI utilities")
            self.gui_utils.script = self.controller.script
            
            # 커스텀 메시지 핸들러 설정
            logger.info("Setting custom message handler")
            self.controller.script.on('message', message_handler)
            
            logger.info("Loading script")
            self.controller.script.load()
            
            if self.controller.spawn:
                logger.info(f"Resuming process: {pid}")
                device.resume(pid)
            
            logger.info("Script loaded successfully")
            print("[+] 스크립트 로드 완료")
            return True
        except Exception as e:
            logger.error(f"Error in setup_custom_handler: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            print(f"[!] 핸들러 설정 오류: {e}")
            return False
    
    def _find_setup_controls(self):
        """
        Setup 키워드를 포함하는 컨트롤 찾기
        """
        logger.info("Finding setup controls")
        self.setup_buttons = {}
        button_idx = 0
        
        # 모든 컨트롤에서 Setup 관련 버튼 찾기
        logger.info(f"Total controls: {len(self.gui_utils.controls)}")
        for control_id, info in self.gui_utils.controls.items():
            # 컨트롤 정보에서 버튼 텍스트 추출
            control_text = info.get('text', '').lower()
            class_name = info.get('className', '').lower()
            
            # 버튼 찾기 - 클래스명이 Button을 포함하거나 버튼 유형
            is_button = ('button' in class_name) or (info.get('controlType') == 'Button')
            
            if is_button:
                logger.debug(f"Found button: {control_text} (ID: {control_id})")
                # 텍스트에 setup 키워드가 포함되어 있는지 확인
                contains_setup = any(keyword in control_text for keyword in self.setup_keywords)
                
                if contains_setup:
                    logger.info(f"Found setup button: {control_text} (ID: {control_id})")
                    window_hwnd = info.get('parentHwnd', '')
                    window_title = ""
                    if window_hwnd in self.gui_utils.windows:
                        window_title = self.gui_utils.windows[window_hwnd].get('title', '')
                    
                    button_idx += 1
                    self.setup_buttons[button_idx] = {
                        'control_id': control_id,
                        'text': info.get('text', ''),
                        'hwnd': info.get('hwnd', ''),
                        'window_hwnd': window_hwnd,
                        'window_title': window_title
                    }
        
        logger.info(f"Total setup buttons found: {len(self.setup_buttons)}")
    
    def _scan_all_controls(self):
        """
        모든 컨트롤 정보 출력 (특별히 Setup 버튼을 찾지 못한 경우)
        """
        logger.info("Scanning all controls")
        # 버튼 타입의 컨트롤만 추출
        buttons = {}
        button_idx = 0
        
        for control_id, info in self.gui_utils.controls.items():
            class_name = info.get('className', '').lower()
            if 'button' in class_name or info.get('controlType') == 'Button':
                button_idx += 1
                window_hwnd = info.get('parentHwnd', '')
                window_title = ""
                if window_hwnd in self.gui_utils.windows:
                    window_title = self.gui_utils.windows[window_hwnd].get('title', '')
                
                buttons[button_idx] = {
                    'control_id': control_id,
                    'text': info.get('text', ''),
                    'hwnd': info.get('hwnd', ''),
                    'window_hwnd': window_hwnd,
                    'window_title': window_title
                }
        
        logger.info(f"Total buttons found: {len(buttons)}")
        if buttons:
            print("\n[*] 발견된 모든 버튼 목록:")
            data = []
            for idx, info in buttons.items():
                data.append([
                    idx,
                    info['text'],
                    info['control_id'],
                    info['window_title']
                ])
            
            print(tabulate(data, headers=["번호", "버튼 텍스트", "컨트롤 ID", "윈도우 제목"], tablefmt="grid"))
    
    def _print_setup_buttons(self):
        """
        발견된 Setup 버튼 목록 출력
        """
        logger.info("Printing setup buttons")
        print("\n[+] 발견된 Setup 관련 버튼:")
        data = []
        for idx, info in self.setup_buttons.items():
            data.append([
                idx,
                info['text'],
                info['control_id'],
                info['window_title']
            ])
        
        print(tabulate(data, headers=["번호", "버튼 텍스트", "컨트롤 ID", "윈도우 제목"], tablefmt="grid"))
    
    def _monitor_all_windows(self):
        """
        모든 윈도우 모니터링 시작
        """
        logger.info("Monitoring all windows")
        print("[*] 모든 윈도우를 모니터링합니다...")
        for hwnd in self.gui_utils.windows.keys():
            try:
                logger.debug(f"Monitoring window with HWND: {hwnd}")
                self.gui_utils.monitor_window(hwnd)
            except Exception as e:
                logger.error(f"Error monitoring window {hwnd}: {e}")
                logger.error(f"Traceback: {traceback.format_exc()}")
    
    def _wait_for_setup_handlers(self):
        """
        Setup 버튼 핸들러 감지 대기
        
        Returns:
            dict: 탐지된 Setup 버튼 핸들러 정보
        """
        logger.info("Waiting for setup handlers")
        # 기존 핸들러 수 기록
        handler_count_before = len(self.gui_utils.handlers)
        logger.info(f"Handlers before waiting: {handler_count_before}")
        
        # 타임아웃 동안 대기
        start_time = time.time()
        while time.time() - start_time < self.timeout:
            # 새로운 핸들러가 발견됐는지 확인
            current_handlers = len(self.gui_utils.handlers)
            if current_handlers > handler_count_before:
                logger.info(f"New handlers detected: {current_handlers} > {handler_count_before}")
                break
            time.sleep(0.1)
        
        # 새로 감지된 핸들러 필터링
        new_handlers = {}
        setup_handlers = {}
        
        # 대기 시간 내에 감지된 모든 새 핸들러
        for addr, info in self.gui_utils.handlers.items():
            timestamp = info.get('timestamp', '')
            if timestamp and time.strptime(timestamp, '%Y-%m-%d %H:%M:%S') > time.localtime(start_time):
                new_handlers[addr] = info
        
        logger.info(f"New handlers detected during wait: {len(new_handlers)}")
        
        # Setup 관련 핸들러만 필터링
        for addr, info in new_handlers.items():
            control_text = info.get('controlText', '').lower()
            # Setup 키워드 포함 여부 확인
            if any(keyword in control_text for keyword in self.setup_keywords):
                setup_handlers[addr] = info
        
        logger.info(f"Setup related handlers: {len(setup_handlers)}")
        return setup_handlers
    
    def _print_setup_handlers(self, handlers):
        """
        탐지된 Setup 버튼 핸들러 출력
        
        Args:
            handlers: 핸들러 정보 딕셔너리
        """
        logger.info("Printing setup handlers")
        data = []
        for addr, info in handlers.items():
            # 콜스택 추출 (최상위 3개 프레임만)
            callstack = info.get('callStack', [])
            callstack_str = "\n".join(callstack[:3]) if callstack else "N/A"
            
            data.append([
                addr,
                info.get('controlText', ''),
                info.get('controlId', ''),
                callstack_str
            ])
        
        print(tabulate(data, headers=["핸들러 주소", "버튼 텍스트", "컨트롤 ID", "콜스택(상위 3개)"], tablefmt="grid"))
    
    def _generate_report(self, handlers, output_file):
        """
        Setup 버튼 핸들러 보고서 생성
        
        Args:
            handlers: 핸들러 정보 딕셔너리
            output_file: 출력 파일 경로
        """
        logger.info(f"Generating report to {output_file}")
        report = []
        report.append("=== Setup 버튼 핸들러 분석 보고서 ===")
        report.append(f"생성 시간: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"대상 프로세스: {self.target}")
        report.append(f"검색 키워드: {', '.join(self.setup_keywords)}")
        report.append(f"총 발견된 핸들러 수: {len(handlers)}")
        report.append("")
        
        # 발견된 Setup 버튼 정보
        if self.setup_buttons:
            report.append("--- 발견된 Setup 버튼 ---")
            button_data = []
            for idx, info in self.setup_buttons.items():
                button_data.append([
                    idx,
                    info['text'],
                    info['control_id'],
                    info['window_title']
                ])
            
            button_table = tabulate(button_data, headers=["번호", "버튼 텍스트", "컨트롤 ID", "윈도우 제목"], tablefmt="grid")
            report.append(button_table)
            report.append("")
        
        # 핸들러 정보
        report.append("--- 탐지된 Setup 버튼 핸들러 ---")
        if handlers:
            handler_data = []
            for addr, info in handlers.items():
                # 콜스택 전체 포함
                callstack = info.get('callStack', [])
                callstack_str = "\n  ".join(callstack) if callstack else "N/A"
                
                handler_data.append([
                    addr,
                    info.get('controlText', ''),
                    info.get('controlId', ''),
                    callstack_str
                ])
                
            handler_table = tabulate(handler_data, headers=["핸들러 주소", "버튼 텍스트", "컨트롤 ID", "콜스택"], tablefmt="grid")
            report.append(handler_table)
        else:
            report.append("탐지된 Setup 버튼 핸들러가 없습니다.")
            
        report_str = '\n'.join(report)
        
        # 파일 출력
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_str)
            logger.info(f"Report written to {output_file}")
        except Exception as e:
            logger.error(f"Error writing report to {output_file}: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")


def main():
    """메인 함수"""
    parser = argparse.ArgumentParser(description='GUI 애플리케이션에서 Setup 버튼 핸들러 탐지')
    parser.add_argument('--target', type=int , default=45840 , help='대상 프로세스 이름 또는 PID')
    parser.add_argument('--timeout', type=int, default=60, help='핸들러 탐지 제한 시간 (초)')
    parser.add_argument('--keywords', type=str, default='' , help='추가 검색 키워드 (쉼표로 구분)')
    args = parser.parse_args()
    
    # 추가 키워드 처리
    additional_keywords = []
    if args.keywords:
        additional_keywords = [k.strip() for k in args.keywords.split(',')]
    
    logger.info(f"Starting SetupButtonFinder with target={args.target}, timeout={args.timeout}")
    # Setup 버튼 탐지기 실행
    finder = SetupButtonFinder(args.target, args.timeout, additional_keywords)
    finder.run()


if __name__ == "__main__":
    main() 