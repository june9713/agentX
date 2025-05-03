#!/usr/bin/env python3
# a64dbg/controller.py - Frida session controller

import frida
import time
import importlib
import os
import sys

class FridaController:
    def __init__(self, target, spawn=False):
        self.target = target
        self.spawn = spawn
        self.session = None
        self.script = None

    def _on_message(self, message, data):
        """후킹 스크립트에서 send된 메시지 처리 콜백"""
        if message['type'] == 'send':
            payload = message.get('payload', {})
            # 후킹 스크립트에서 보낸 정보 출력
            if isinstance(payload, dict):
                # hook 종류와 세부내용 구성
                hook_name = payload.get('hook')
                detail = ", ".join(f"{k}={v}" for k,v in payload.items() if k != 'hook')
                print(f"[HookMessage] {hook_name}: {detail}")
            else:
                print(f"[HookMessage] {payload}")
        elif message['type'] == 'error':
            # 스크립트 내부 에러 출력
            print(f"[Script Error] {message['description']}\n{message.get('stack')}")

    def _load_hooks(self):
        """hooks 디렉토리에서 모든 후킹 모듈 로드"""
        hooks_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'hooks')
        sys.path.append(hooks_dir)  # hooks 디렉토리를 Python 경로에 추가
        
        hooks = []
        # 파일 확장자가 .py이고 __init__.py가 아닌 모든 파일 로드
        for filename in os.listdir(hooks_dir):
            if filename.endswith('.py') and filename != '__init__.py':
                module_name = filename[:-3]  # .py 확장자 제거
                try:
                    module = importlib.import_module(f"hooks.{module_name}")
                    if hasattr(module, 'hook_script'):
                        hooks.append(module.hook_script)
                except ImportError as e:
                    print(f"[Error] Failed to import hook module '{module_name}': {e}")
        
        return hooks

    def _build_script(self):
        """여러 후킹 스크립트를 결합하여 하나의 스크립트 문자열 생성"""
        # 동적으로 모든 후킹 스크립트 모듈 로드
        hook_scripts = self._load_hooks()
        
        script_parts = []
        # (1) 기본 모듈 정보 조회 코드 추가
        script_parts.append("""
            // 기본 모듈 정보 출력 (kernel32.dll, user32.dll 베이스 주소)
            var k32 = Module.findBaseAddress("kernel32.dll");
            var u32 = Module.findBaseAddress("user32.dll");
            send({hook: "Info", message: "kernel32.dll base: " + k32 + ", user32.dll base: " + u32});
        """)
        
        # (2) 개별 후킹 스크립트 추가
        for hook_script in hook_scripts:
            script_parts.append(hook_script)
            
        # 모든 스크립트 조각 결합
        return "\n".join(script_parts)

    def run(self):
        # 로컬 장치의 Frida 인스턴스 사용
        device = frida.get_local_device()
        pid = None
        
        try:
            if self.spawn:
                # 새 프로세스 실행 (spawn)
                pid = device.spawn([self.target])
                self.session = device.attach(pid)
                print(f"[+] Spawned and attached to process with PID: {pid}")
            else:
                # 기존 프로세스에 attach (이름 또는 PID)
                try:
                    pid = int(self.target)
                    self.session = device.attach(pid)
                    print(f"[+] Attached to process with PID: {pid}")
                except ValueError:
                    self.session = device.attach(self.target)
                    print(f"[+] Attached to process: {self.target}")

            # 후킹 스크립트 로드
            script_code = self._build_script()
            self.script = self.session.create_script(script_code)
            self.script.on('message', self._on_message)  # 메시지 콜백 등록
            self.script.load()  # 스크립트 주입

            if self.spawn and pid:
                device.resume(pid)  # spawn한 프로세스 실행 재개
                print(f"[+] Resumed process with PID: {pid}")

            print("** Frida attach 성공! (종료하려면 Ctrl+C) **")
            
            # 프로세스가 종료될 때까지 대기
            while True:
                time.sleep(1)
                
        except frida.ProcessNotFoundError:
            print(f"[!] Error: Process '{self.target}' not found.")
            sys.exit(1)
        except frida.ServerNotRunningError:
            print("[!] Error: Frida server is not running.")
            sys.exit(1)
        except KeyboardInterrupt:
            print("\n** Detaching Frida 세션 **")
            if self.session:
                self.session.detach()
            sys.exit(0)
        except Exception as e:
            print(f"[!] Unexpected error: {e}")
            if self.session:
                self.session.detach()
            sys.exit(1) 