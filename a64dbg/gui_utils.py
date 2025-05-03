#!/usr/bin/env python3
# a64dbg/gui_utils.py - GUI element detection utilities

import time
import json
from tabulate import tabulate

class GuiElementUtils:
    def __init__(self, script):
        """
        초기화 함수
        
        Args:
            script: Frida 스크립트 객체 (controller에서 생성된 script)
        """
        self.script = script
        self.windows = {}  # 윈도우 핸들 -> 정보 매핑
        self.controls = {}  # 컨트롤 ID -> 정보 매핑
        self.handlers = {}  # 핸들러 주소 -> 정보 매핑
        
        self._setup_handlers()
        
    def _setup_handlers(self):
        """GUI 요소 관련 이벤트 핸들러 설정"""
        # 여기서 필요한 추가 처리 로직 구현 가능
        pass
        
    def scan_all_windows(self):
        """시스템의 모든 최상위 윈도우 스캔"""
        print("[*] 모든 최상위 윈도우를 스캔합니다...")
        message = json.dumps({'cmd': 'scan_all_windows'})
        self.script.post('gui_request', message)
        
    def get_window_info(self, hwnd):
        """
        특정 윈도우 핸들의 자세한 정보 조회
        
        Args:
            hwnd: 윈도우 핸들 (문자열 또는 정수)
        """
        if isinstance(hwnd, int):
            hwnd = str(hwnd)
            
        print(f"[*] 윈도우 핸들 0x{hwnd} 정보 조회 중...")
        message = json.dumps({
            'cmd': 'get_window_info',
            'hwnd': hwnd
        })
        self.script.post('gui_request', message)
        
    def monitor_window(self, hwnd):
        """
        특정 윈도우를 모니터링 대상으로 등록
        
        Args:
            hwnd: 윈도우 핸들 (문자열 또는 정수)
        """
        if isinstance(hwnd, int):
            hwnd = str(hwnd)
            
        print(f"[*] 윈도우 핸들 0x{hwnd} 모니터링 시작...")
        message = json.dumps({
            'cmd': 'monitor_window',
            'hwnd': hwnd
        })
        self.script.post('gui_request', message)
        
    def stop_monitor_window(self, hwnd):
        """
        특정 윈도우 모니터링 중지
        
        Args:
            hwnd: 윈도우 핸들 (문자열 또는 정수)
        """
        if isinstance(hwnd, int):
            hwnd = str(hwnd)
            
        print(f"[*] 윈도우 핸들 0x{hwnd} 모니터링 중지...")
        message = json.dumps({
            'cmd': 'stop_monitor_window',
            'hwnd': hwnd
        })
        self.script.post('gui_request', message)
        
    def print_windows(self):
        """수집된 윈도우 정보 출력"""
        if not self.windows:
            print("[!] 수집된 윈도우 정보가 없습니다. scan_all_windows()를 먼저 실행하세요.")
            return
            
        data = []
        for hwnd, info in self.windows.items():
            data.append([
                hwnd,
                info.get('title', ''),
                info.get('className', ''),
                info.get('childCount', 0)
            ])
            
        print("\n=== 탐지된 윈도우 목록 ===")
        print(tabulate(data, headers=["핸들", "제목", "클래스명", "자식 수"], tablefmt="grid"))
        
    def print_controls(self, hwnd=None):
        """
        수집된 컨트롤 정보 출력
        
        Args:
            hwnd: 특정 윈도우의 컨트롤만 출력할 경우 지정 (선택 사항)
        """
        if not self.controls:
            print("[!] 수집된 컨트롤 정보가 없습니다.")
            return
            
        data = []
        for control_id, info in self.controls.items():
            parent_hwnd = info.get('parentHwnd', '')
            
            # 특정 윈도우의 컨트롤만 출력하는 경우 필터링
            if hwnd and parent_hwnd != hwnd:
                continue
                
            data.append([
                control_id,
                info.get('hwnd', ''),
                parent_hwnd,
                info.get('controlType', ''),
                info.get('text', '')
            ])
            
        if not data:
            print(f"[!] 윈도우 핸들 0x{hwnd}의 컨트롤 정보가 없습니다.")
            return
            
        print("\n=== 탐지된 컨트롤 목록 ===")
        print(tabulate(data, headers=["ID", "핸들", "부모 핸들", "종류", "텍스트"], tablefmt="grid"))
        
    def print_handlers(self):
        """수집된 핸들러 함수 정보 출력"""
        if not self.handlers:
            print("[!] 수집된 핸들러 정보가 없습니다.")
            return
            
        data = []
        for addr, info in self.handlers.items():
            data.append([
                addr,
                info.get('controlId', ''),
                info.get('controlText', ''),
                info.get('type', ''),
                info.get('timestamp', '')
            ])
            
        print("\n=== 탐지된 핸들러 함수 목록 ===")
        print(tabulate(data, headers=["주소", "컨트롤 ID", "컨트롤 텍스트", "종류", "탐지 시간"], tablefmt="grid"))
        
    def event_handler(self, message, data=None):
        """
        GUI 요소 후킹에서 발생한 이벤트 처리
        
        이 함수는 controller에서 호출하도록 설정해야 합니다:
        ```
        # 컨트롤러에서 구성 예시
        gui_utils = GuiElementUtils(script)
        def on_message(message, data):
            if message['type'] == 'send':
                payload = message.get('payload', {})
                if isinstance(payload, dict) and payload.get('hook') == 'GuiElement':
                    gui_utils.event_handler(message, data)
                else:
                    # 다른 메시지 처리...
        ```
        """
        if message['type'] != 'send':
            return
            
        payload = message.get('payload', {})
        if not isinstance(payload, dict) or payload.get('hook') != 'GuiElement':
            return
            
        event_type = payload.get('type', '')
        
        # 최상위 윈도우 정보 수집
        if event_type == 'TopLevelWindow':
            hwnd = payload.get('hwnd', '')
            self.windows[hwnd] = {
                'title': payload.get('title', ''),
                'className': payload.get('className', ''),
                'visible': payload.get('visible', False)
            }
            print(f"[+] 윈도우 발견: {payload.get('title', '')} (핸들: 0x{hwnd})")
            
        # 윈도우 스캔 완료 알림
        elif event_type == 'WindowScanComplete':
            print(f"[+] 윈도우 스캔 완료: {payload.get('count', 0)}개 발견")
            
        # 윈도우 상세 정보
        elif event_type == 'WindowInfo':
            hwnd = payload.get('hwnd', '')
            child_count = payload.get('childCount', 0)
            
            if hwnd in self.windows:
                self.windows[hwnd].update({
                    'title': payload.get('title', ''),
                    'className': payload.get('className', ''),
                    'wndProc': payload.get('wndProc', 0),
                    'childCount': child_count
                })
            else:
                self.windows[hwnd] = {
                    'title': payload.get('title', ''),
                    'className': payload.get('className', ''),
                    'wndProc': payload.get('wndProc', 0),
                    'childCount': child_count
                }
                
            # 자식 윈도우 정보 저장
            children = payload.get('children', [])
            for child in children:
                child_hwnd = child.get('hwnd', '')
                control_id = child.get('controlId', 0)
                
                key = f"{hwnd}_{control_id}"
                self.controls[key] = {
                    'hwnd': child_hwnd,
                    'parentHwnd': hwnd,
                    'controlId': control_id,
                    'text': child.get('title', ''),
                    'className': child.get('className', '')
                }
                
                # 컨트롤 종류 추론
                class_name = child.get('className', '')
                control_type = 'Unknown'
                
                if 'Button' in class_name:
                    control_type = 'Button'
                elif 'Edit' in class_name:
                    control_type = 'Edit'
                elif 'Static' in class_name:
                    control_type = 'Label'
                elif 'ComboBox' in class_name:
                    control_type = 'ComboBox'
                elif 'ListBox' in class_name:
                    control_type = 'ListBox'
                else:
                    control_type = class_name
                    
                self.controls[key]['controlType'] = control_type
                
            print(f"[+] 윈도우 정보 수집 완료: {payload.get('title', '')} (자식: {child_count}개)")
            
        # 컨트롤 생성 정보
        elif event_type == 'CreateWindow':
            control_type = payload.get('controlType', '')
            window_name = payload.get('windowName', '')
            parent_hwnd = payload.get('parentHwnd', '')
            control_id = payload.get('controlId', 0)
            
            if parent_hwnd and control_id:
                key = f"{parent_hwnd}_{control_id}"
                self.controls[key] = {
                    'parentHwnd': parent_hwnd,
                    'controlId': control_id,
                    'controlType': control_type,
                    'text': window_name,
                    'className': payload.get('className', '')
                }
                
        # 버튼 클릭 핸들러 감지
        elif event_type == 'ButtonClick':
            handler_addr = payload.get('handler', '')
            control_id = payload.get('controlId', 0)
            control_text = payload.get('controlText', '')
            control_hwnd = payload.get('controlHwnd', '')
            call_stack = payload.get('callStack', [])
            
            # 핸들러 정보 저장
            if handler_addr:
                self.handlers[handler_addr] = {
                    'controlId': control_id,
                    'controlText': control_text,
                    'controlHwnd': control_hwnd,
                    'type': 'ButtonClick',
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'callStack': call_stack
                }
                
                print(f"[+] 버튼 클릭 핸들러 감지: {control_text} (ID: {control_id}) -> 함수 주소: {handler_addr}")
                
                # 콜 스택 정보 출력 (디버깅용)
                if call_stack:
                    print(f"[+] 콜 스택:")
                    for i, frame in enumerate(call_stack[:5]):  # 상위 5개 프레임만 출력
                        print(f"    {i}: {frame}")
                        
        # 윈도우 프로시저 변경 감지
        elif event_type == 'WindowProcChange_ret':
            hwnd = payload.get('hwnd', '')
            old_proc = payload.get('oldProc', '')
            new_proc = payload.get('newProc', '')
            
            print(f"[+] 윈도우 프로시저 변경 감지: 0x{hwnd}")
            print(f"    이전: {old_proc}")
            print(f"    신규: {new_proc}")
            
    def wait_for_handler(self, timeout=30, print_result=True):
        """
        핸들러 감지를 기다립니다 (상호작용용)
        
        Args:
            timeout: 대기 시간 (초)
            print_result: 결과 출력 여부
            
        Returns:
            탐지된 핸들러 정보 목록
        """
        handler_count_before = len(self.handlers)
        print(f"[*] GUI 요소의 동작 함수를 탐지합니다. {timeout}초 동안 버튼을 클릭하거나 UI 요소와 상호작용하세요...")
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            # 새로운 핸들러가 발견되었는지 확인
            if len(self.handlers) > handler_count_before:
                break
                
            time.sleep(0.1)
            
        # 타임아웃 또는 핸들러 발견
        new_handlers = {}
        for addr, info in self.handlers.items():
            timestamp = info.get('timestamp', '')
            # 대기 시간 내에 발견된 핸들러만 추출
            if timestamp and time.strptime(timestamp, '%Y-%m-%d %H:%M:%S') > time.localtime(start_time):
                new_handlers[addr] = info
                
        if print_result:
            if new_handlers:
                print(f"[+] {len(new_handlers)}개의 새로운 동작 함수를 탐지했습니다.")
                
                data = []
                for addr, info in new_handlers.items():
                    data.append([
                        addr,
                        info.get('controlId', ''),
                        info.get('controlText', ''),
                        info.get('type', ''),
                        info.get('timestamp', '')
                    ])
                    
                print(tabulate(data, headers=["주소", "컨트롤 ID", "컨트롤 텍스트", "종류", "탐지 시간"], tablefmt="grid"))
            else:
                print("[!] 대기 시간 내에 동작 함수를 탐지하지 못했습니다.")
                
        return new_handlers
        
    def find_handler_by_text(self, text, partial_match=True):
        """
        텍스트로 핸들러 찾기
        
        Args:
            text: 찾을 텍스트
            partial_match: 부분 일치 허용 여부
            
        Returns:
            일치하는 핸들러 목록
        """
        result = {}
        
        for addr, info in self.handlers.items():
            control_text = info.get('controlText', '')
            
            if (partial_match and text in control_text) or (not partial_match and text == control_text):
                result[addr] = info
                
        return result
        
    def generate_handler_report(self, output_file=None):
        """
        탐지된 핸들러 보고서 생성
        
        Args:
            output_file: 출력 파일 경로 (없으면 콘솔에 출력)
            
        Returns:
            보고서 문자열
        """
        report = []
        report.append("=== GUI 요소 동작 함수 분석 보고서 ===")
        report.append(f"생성 시간: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"총 윈도우 수: {len(self.windows)}")
        report.append(f"총 컨트롤 수: {len(self.controls)}")
        report.append(f"총 핸들러 수: {len(self.handlers)}")
        report.append("")
        
        # 핸들러 정보
        report.append("--- 탐지된 핸들러 함수 ---")
        if self.handlers:
            handler_data = []
            for addr, info in self.handlers.items():
                handler_data.append([
                    addr,
                    info.get('controlId', ''),
                    info.get('controlText', ''),
                    info.get('type', ''),
                    info.get('timestamp', '')
                ])
                
            handler_table = tabulate(handler_data, headers=["주소", "컨트롤 ID", "컨트롤 텍스트", "종류", "탐지 시간"], tablefmt="grid")
            report.append(handler_table)
        else:
            report.append("탐지된 핸들러가 없습니다.")
            
        report_str = '\n'.join(report)
        
        # 파일 출력
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_str)
            print(f"[+] 보고서가 {output_file}에 저장되었습니다.")
            
        return report_str

# 사용 예:
"""
from controller import FridaController
from gui_utils import GuiElementUtils

# Frida 세션 생성
controller = FridaController("notepad.exe")

# GUI 유틸리티 초기화
gui_utils = GuiElementUtils(controller.script)

# 모든 윈도우 스캔
gui_utils.scan_all_windows()

# 윈도우 정보 출력
gui_utils.print_windows()

# 특정 윈도우 상세 정보 조회
gui_utils.get_window_info("0x00010A28")

# 특정 윈도우 모니터링 시작
gui_utils.monitor_window("0x00010A28")

# 사용자에게 버튼 클릭 등 상호작용 요청
handlers = gui_utils.wait_for_handler(timeout=20)

# 탐지된 핸들러 출력
gui_utils.print_handlers()

# 보고서 생성
report = gui_utils.generate_handler_report("handlers.txt")
""" 