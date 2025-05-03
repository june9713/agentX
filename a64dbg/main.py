#!/usr/bin/env python3
# a64dbg/main.py - Entry point for the Frida-based debugging framework

import sys
from controller import FridaController

def print_usage():
    print(f"Usage: python {sys.argv[0]} [--spawn] <process name | PID | exe path>")
    print("  --spawn 옵션을 사용하면 새 프로세스를 실행하여 후킹합니다.")
    sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_usage()

    spawn_mode = False
    target = None

    # '--spawn' 옵션 처리
    args = sys.argv[1:]
    if args[0] == "--spawn":
        if len(args) < 2:
            print_usage()
        spawn_mode = True
        target = args[1]
    else:
        target = args[0]

    # FridaController 초기화 및 실행
    controller = FridaController(target, spawn=spawn_mode)
    controller.run() 