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
        print(f"[*] connecting to process: {target}")
        controller = FridaController(target)
        
        # define callback function
        gui_utils = GuiElementUtils(None)  # temporarily initialize
        
        def message_handler(message, data):
            if message['type'] == 'send':
                payload = message.get('payload', {})
                if isinstance(payload, dict) and payload.get('hook') == 'GuiElement':
                    gui_utils.event_handler(message, data)
                else:
                    # pass other messages to the default handler
                    controller._on_message(message, data)
        
        # set message handler for script
        def run_with_custom_handler():
            # use local Frida instance
            device = controller.device = frida.get_local_device()
            
            try:
                # connect to process
                if controller.spawn:
                    pid = device.spawn([controller.target])
                    controller.session = device.attach(pid)
                    print(f"[+] process created and connected (PID: {pid})")
                else:
                    try:
                        pid = int(controller.target)
                        controller.session = device.attach(pid)
                    except ValueError:
                        controller.session = device.attach(controller.target)
                    print(f"[+] process connected: {controller.target}")
                
                # load hooking script
                script_code = controller._build_script()
                controller.script = controller.session.create_script(script_code)
                
                # set script to GUI utility
                gui_utils.script = controller.script
                
                # set custom message handler
                controller.script.on('message', message_handler)
                controller.script.load()
                
                if controller.spawn:
                    device.resume(pid)
                
                print("[+] script loaded")
                return True
            except Exception as e:
                print(f"[!] error occurred: {e}")
                return False
        
        # run with custom handler
        if not run_with_custom_handler():
            sys.exit(1)
        
        # find main GUI element handlers
        print("\n=== find main GUI element handlers ===")
        print("1. scan all windows in the system")
        gui_utils.scan_all_windows()
        time.sleep(1)
        
        # print window list
        gui_utils.print_windows()
        
        # request user to select a window
        print("\nselect a specific window to view detailed information")
        hwnd = input("input window handle (or enter to skip): ")
        
        if hwnd:
            try:
                # if input is a number, consider it as an index of the window list
                idx = int(hwnd)
                if 0 <= idx < len(gui_utils.windows):
                    hwnd = list(gui_utils.windows.keys())[idx]
            except ValueError:
                # if input is a string, use it as is
                pass
                
            # get window information
            gui_utils.get_window_info(hwnd)
            time.sleep(1)
            
            # print control list of the window
            gui_utils.print_controls(hwnd)
            
            # start monitoring the window
            gui_utils.monitor_window(hwnd)
        
        # request user to click buttons, etc.
        print("\nclick buttons, menus, controls of the target program")
        print("detect handler functions of the GUI elements")
        print("(hover over the window and press Tab key to move focus, and activate with Space, etc.)")
        
        # wait for handler detection
        gui_utils.wait_for_handler(timeout=60)
        
        # print all handlers
        if gui_utils.handlers:
            print("\n=== list of all detected handlers ===")
            gui_utils.print_handlers()
            
            # save report
            report_path = "gui_handlers_report.txt"
            gui_utils.generate_handler_report(report_path)
        else:
            print("\n[!] no handlers detected")
        
        # wait for user to exit
        input("\npress Enter to exit...")
        
    except KeyboardInterrupt:
        print("\n[!] terminated by user")
    except Exception as e:
        print(f"\n[!] error occurred: {e}")
    finally:
        # Frida 세션 정리
        if hasattr(controller, 'session') and controller.session:
            print("[*] terminating Frida session...")
            controller.session.detach()

if __name__ == "__main__":
    import frida
    main() 