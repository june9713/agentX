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
        """Process messages sent by the hook script"""
        if message['type'] == 'send':
            payload = message.get('payload', {})
            # Print information sent by the hook script
            if isinstance(payload, dict):
                # Construct hook name and details
                hook_name = payload.get('hook')
                detail = ", ".join(f"{k}={v}" for k,v in payload.items() if k != 'hook')
                print(f"[HookMessage] {hook_name}: {detail}")
            else:
                print(f"[HookMessage] {payload}")
        elif message['type'] == 'error':
            # Print internal script errors
            print(f"[Script Error] {message['description']}\n{message.get('stack')}")

    def _load_hooks(self):
        """Load all hook modules from the hooks directory"""
        hooks_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'hooks')
        sys.path.append(hooks_dir)  # Add hooks directory to Python path
        
        hooks = []
        # Load all files with .py extension except __init__.py
        for filename in os.listdir(hooks_dir):
            if filename.endswith('.py') and filename != '__init__.py':
                module_name = filename[:-3]  # Remove .py extension
                try:
                    module = importlib.import_module(f"hooks.{module_name}")
                    if hasattr(module, 'hook_script'):
                        hooks.append(module.hook_script)
                except ImportError as e:
                    print(f"[Error] Failed to import hook module '{module_name}': {e}")
        
        return hooks

    def _build_script(self):
        """Combine multiple hook scripts into a single script string"""
        # Dynamically load all hook script modules
        hook_scripts = self._load_hooks()
        
        script_parts = []
        # (1) 기본 모듈 정보 조회 코드 추가
        script_parts.append("""
            // Print basic module information (kernel32.dll, user32.dll base addresses)
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