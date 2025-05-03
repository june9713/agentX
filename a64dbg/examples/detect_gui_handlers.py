#!/usr/bin/env python3
# a64dbg/examples/detect_gui_handlers.py - Example for GUI element handler detection

import sys
import os
import time

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from controller import FridaController
from gui_utils import GuiElementUtils

def print_usage():
    print(f"Usage: python {sys.argv[0]} <process name | PID>")
    print("Example:")
    print(f"  python {sys.argv[0]} notepad.exe")
    print(f"  python {sys.argv[0]} 1234")
    sys.exit(1)

def main():
    if len(sys.argv) < 2:
        print_usage()
        
    target = sys.argv[1]
    
    try:
        print(f"[*] 프로세스에 연결 중: {target}")
        controller = FridaController(target)
        
        # 콜백 함수 정의
        gui_utils = GuiElementUtils(None)  # 임시로 초기화
        
        def message_handler(message, data):
            if message['type'] == 'send':
                payload = message.get('payload', {})
                if isinstance(payload, dict) and payload.get('hook') == 'GuiElement':
                    gui_utils.event_handler(message, data)
                else:
                    # 다른 메시지는 기본 핸들러로 전달
                    controller._on_message(message, data)
        
        # 스크립트에 메시지 핸들러 설정
        def run_with_custom_handler():
            # 로컬 장치의 Frida 인스턴스 사용
            device = controller.device = frida.get_local_device()
            
            try:
                # 프로세스 연결
                if controller.spawn:
                    pid = device.spawn([controller.target])
                    controller.session = device.attach(pid)
                    print(f"[+] 프로세스 생성 및 연결 완료 (PID: {pid})")
                else:
                    try:
                        pid = int(controller.target)
                        controller.session = device.attach(pid)
                    except ValueError:
                        controller.session = device.attach(controller.target)
                    print(f"[+] 프로세스 연결 완료: {controller.target}")
                
                # 후킹 스크립트 로드
                script_code = controller._build_script()
                controller.script = controller.session.create_script(script_code)
                
                # GUI 유틸리티에 스크립트 설정
                gui_utils.script = controller.script
                
                # 커스텀 메시지 핸들러 설정
                controller.script.on('message', message_handler)
                controller.script.load()
                
                if controller.spawn:
                    device.resume(pid)
                
                print("[+] 스크립트 로드 완료")
                return True
            except Exception as e:
                print(f"[!] 오류 발생: {e}")
                return False
        
        # 커스텀 핸들러로 실행
        if not run_with_custom_handler():
            sys.exit(1)
        
        # 주요 GUI 요소 핸들러 찾기 워크플로우
        print("\n=== GUI 요소 핸들러 찾기 ===")
        print("1. 시스템의 모든 윈도우를 스캔합니다.")
        gui_utils.scan_all_windows()
        time.sleep(1)
        
        # 윈도우 목록 출력
        gui_utils.print_windows()
        
        # 사용자에게 윈도우 선택 요청
        print("\n특정 윈도우를 선택하여 자세한 정보를 확인할 수 있습니다.")
        hwnd = input("윈도우 핸들 입력 (또는 목록에서 번호 입력, 건너뛰려면 Enter): ")
        
        if hwnd:
            try:
                # 입력이 숫자면 윈도우 목록의 인덱스로 간주
                idx = int(hwnd)
                if 0 <= idx < len(gui_utils.windows):
                    hwnd = list(gui_utils.windows.keys())[idx]
            except ValueError:
                # 입력이 문자열이면 그대로 사용
                pass
                
            # 윈도우 정보 조회
            gui_utils.get_window_info(hwnd)
            time.sleep(1)
            
            # 윈도우의 컨트롤 목록 출력
            gui_utils.print_controls(hwnd)
            
            # 윈도우 모니터링 시작
            gui_utils.monitor_window(hwnd)
        
        # 사용자에게 버튼 클릭 등 상호작용 요청
        print("\n대상 프로그램의 버튼, 메뉴, 컨트롤 등을 클릭하면")
        print("해당 GUI 요소의 핸들러 함수를 탐지합니다.")
        print("(창에 마우스를 올려놓고 Tab 키를 눌러 포커스를 이동시키면서 Space 등으로 활성화할 수도 있습니다.)")
        
        # 핸들러 탐지 대기
        gui_utils.wait_for_handler(timeout=60)
        
        # 모든 핸들러 출력
        if gui_utils.handlers:
            print("\n=== 탐지된 모든 핸들러 목록 ===")
            gui_utils.print_handlers()
            
            # 보고서 저장
            report_path = "gui_handlers_report.txt"
            gui_utils.generate_handler_report(report_path)
        else:
            print("\n[!] 탐지된 핸들러가 없습니다.")
        
        # 종료 전 잠시 대기
        input("\n프로그램을 종료하려면 Enter 키를 누르세요...")
        
    except KeyboardInterrupt:
        print("\n[!] 사용자에 의해 중단되었습니다.")
    except Exception as e:
        print(f"\n[!] 오류 발생: {e}")
    finally:
        # Frida 세션 정리
        if hasattr(controller, 'session') and controller.session:
            print("[*] Frida 세션 종료 중...")
            controller.session.detach()

if __name__ == "__main__":
    import frida
    main() 