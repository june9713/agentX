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
        Initialize class for finding Setup buttons
        
        Args:
            target: target process (name or PID)
            timeout: button handler detection timeout (seconds)
            setup_keywords: list of keywords to search for Setup related
        """
        self.target = target
        self.timeout = timeout
        self.controller = None
        self.gui_utils = None
        
        # Setup related keywords (default + user-defined keywords)
        self.setup_keywords = ['setup', 'install', 'configure', '설정', '설치', '구성']
        if setup_keywords:
            self.setup_keywords.extend(setup_keywords)
        
        # Convert all keywords to lowercase for case-insensitive search
        self.setup_keywords = [keyword.lower() for keyword in self.setup_keywords]
        
        # List of found Setup buttons
        self.setup_buttons = {}
        
        logger.info(f"SetupButtonFinder initialized with target: {target}, timeout: {timeout}")
        
    def run(self):
        """Main execution function"""
        try:
            # Connect to process
            logger.info(f"Connecting to process: {self.target}")
            print(f"[*] Connecting to process: {self.target}")
            self.controller = FridaController(self.target)
            
            # Initialize GUI utilities and set custom handler
            logger.info("Initializing GUI utilities")
            self.gui_utils = GuiElementUtils(None)
            if not self._setup_custom_handler():
                print("[!] Process connection failed")
                return False
            
            # Scan all windows
            print("[*] Scanning windows...")
            logger.info("Starting window scanning")
            try:
                self.gui_utils.scan_all_windows()
                logger.info("Window scanning completed")
            except Exception as e:
                logger.error(f"Error during window scanning: {e}")
                logger.error(f"Exception type: {type(e)}")
                logger.error(f"Traceback: {traceback.format_exc()}")
                print(f"[!] Error during window scanning: {e}")
            
            time.sleep(1)  # Wait for scanning to complete
            
            # Print list of found windows
            logger.info("Printing window information")
            try:
                self.gui_utils.print_windows()
            except Exception as e:
                logger.error(f"Error while printing windows: {e}")
                logger.error(f"Traceback: {traceback.format_exc()}")
            
            # Get detailed information for all windows
            logger.info("Getting detailed window information")
            for hwnd in self.gui_utils.windows.keys():
                try:
                    logger.debug(f"Getting information for window with HWND: {hwnd}")
                    self.gui_utils.get_window_info(hwnd)
                except Exception as e:
                    logger.error(f"Error getting info for window {hwnd}: {e}")
                    logger.error(f"Traceback: {traceback.format_exc()}")
                time.sleep(0.2)  # 요청 간격
            
            # Search for setup-related controls
            logger.info("Searching for setup controls")
            self._find_setup_controls()
            
            if not self.setup_buttons:
                print("[!] No setup buttons found. Scanning all controls.")
                logger.info("No setup buttons found. Scanning all controls.")
                self._scan_all_controls()
                
                # Suggest monitoring all windows to the user
                print("\n[*] Would you like to monitor all windows and click the Setup button directly?")
                response = input("  monitor all windows (y/n)? ")
                
                if response.lower() == 'y':
                    logger.info("Starting monitoring of all windows")
                    self._monitor_all_windows()
                else:
                    print("[*] Exiting program.")
                    logger.info("User chose not to monitor windows. Exiting.")
                    return False
            else:
                # Setup button found
                logger.info(f"Found {len(self.setup_buttons)} setup buttons")
                self._print_setup_buttons()
                
                # Monitor windows with found buttons
                logger.info("Monitoring windows with setup buttons")
                for hwnd in set([info['window_hwnd'] for info in self.setup_buttons.values()]):
                    try:
                        logger.debug(f"Monitoring window with HWND: {hwnd}")
                        self.gui_utils.monitor_window(hwnd)
                    except Exception as e:
                        logger.error(f"Error monitoring window {hwnd}: {e}")
                        logger.error(f"Traceback: {traceback.format_exc()}")
            
            # Request user to click the button
            print("\n[*] Now click the Setup button of the program.")
            print(f"[*] Waiting for button click event for {self.timeout} seconds...")
            
            # Wait for handler detection
            logger.info(f"Waiting for setup handlers for {self.timeout} seconds")
            setup_handlers = self._wait_for_setup_handlers()
            
            # Output results
            if setup_handlers:
                logger.info(f"Found {len(setup_handlers)} setup button handlers")
                print(f"\n[+] Found {len(setup_handlers)} setup button handlers:")
                self._print_setup_handlers(setup_handlers)
                
                # Save report
                report_file = "setup_button_handlers.txt"
                logger.info(f"Generating report to {report_file}")
                self._generate_report(setup_handlers, report_file)
                print(f"[+] Report saved to {report_file}")
            else:
                logger.info("No setup button handlers detected")
                print("\n[!] Setup button click event not detected")
            
            return True
            
        except KeyboardInterrupt:
            logger.info("Interrupted by user")
            print("\n[!] Interrupted by user")
            return False
        except Exception as e:
            logger.error(f"Error in run method: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            print(f"[!] error occurred: {e}")
            return False
        finally:
            # Frida 세션 정리
            if self.controller and hasattr(self.controller, 'session') and self.controller.session:
                logger.info("Detaching Frida session")
                print("[*] Detaching Frida session")
                self.controller.session.detach()
    
    def _setup_custom_handler(self):
        """
        custom message handler setup
        
        Returns:
            bool: success or failure
        """
        try:
            # Define message handler
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
                            # Send other messages to default controller handler
                            logger.debug("Sending to default controller handler")
                            self.controller._on_message(message, data)
                except Exception as e:
                    logger.error(f"Error in message handler: {e}")
                    logger.error(f"Traceback: {traceback.format_exc()}")
            
            # Use local Frida instance
            logger.info("Getting local Frida device")
            device = self.controller.device = frida.get_local_device()
            
            # Connect to process
            if self.controller.spawn:
                logger.info(f"Spawning process: {self.controller.target}")
                pid = device.spawn([self.controller.target])
                self.controller.session = device.attach(pid)
                logger.info(f"Process spawned and attached (PID: {pid})")
                print(f"[+] Process spawned and attached (PID: {pid})")
            else:
                try:
                    pid = int(self.controller.target)
                    logger.info(f"Attaching to PID: {pid}")
                    self.controller.session = device.attach(pid)
                except ValueError:
                    logger.info(f"Attaching to process name: {self.controller.target}")
                    self.controller.session = device.attach(self.controller.target)
                logger.info(f"Process attached: {self.controller.target}")
                print(f"[+] Process attached: {self.controller.target}")
            
            # Load hooking script
            logger.info("Building script")
            script_code = self.controller._build_script()
            logger.debug(f"Script code length: {len(script_code)}")
            
            logger.info("Creating script")
            self.controller.script = self.controller.session.create_script(script_code)
            
            # Set script for GUI utilities
            logger.info("Setting script for GUI utilities")
            self.gui_utils.script = self.controller.script
            
            # Set custom message handler
            logger.info("Setting custom message handler")
            self.controller.script.on('message', message_handler)
            
            logger.info("Loading script")
            self.controller.script.load()
            
            if self.controller.spawn:
                logger.info(f"Resuming process: {pid}")
                device.resume(pid)
            
            logger.info("Script loaded successfully")
            print("[+] Script loaded successfully")
            return True
        except Exception as e:
            logger.error(f"Error in setup_custom_handler: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            print(f"[!] Error setting up handler: {e}")
            return False
    
    def _find_setup_controls(self):
        """
        Find controls containing Setup keywords
        """
        logger.info("Finding setup controls")
        self.setup_buttons = {}
        button_idx = 0
        
        # Find setup-related buttons in all controls
        logger.info(f"Total controls: {len(self.gui_utils.controls)}")
        for control_id, info in self.gui_utils.controls.items():
            # Extract button text from control info
            control_text = info.get('text', '').lower()
            class_name = info.get('className', '').lower()
            
            # Find button - class name contains 'button' or control type is 'Button'
            is_button = ('button' in class_name) or (info.get('controlType') == 'Button')
            
            if is_button:
                logger.debug(f"Found button: {control_text} (ID: {control_id})")
                # Check if control text contains setup keywords
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
        Print all control information (especially if Setup buttons are not found)
        """
        logger.info("Scanning all controls")
        # Extract only buttons
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
            print("\n[*] Found all buttons:")
            data = []
            for idx, info in buttons.items():
                data.append([
                    idx,
                    info['text'],
                    info['control_id'],
                    info['window_title']
                ])
            
            print(tabulate(data, headers=["Number", "Button Text", "Control ID", "Window Title"], tablefmt="grid"))
    
    def _print_setup_buttons(self):
        """
        Print found Setup buttons
        """
        logger.info("Printing setup buttons")
        print("\n[+] Found Setup related buttons:")
        data = []
        for idx, info in self.setup_buttons.items():
            data.append([
                idx,
                info['text'],
                info['control_id'],
                info['window_title']
            ])
        
        print(tabulate(data, headers=["Number", "Button Text", "Control ID", "Window Title"], tablefmt="grid"))
    
    def _monitor_all_windows(self):
        """
        Start monitoring all windows
        """
        logger.info("Monitoring all windows")
        print("[*] Monitoring all windows...")
        for hwnd in self.gui_utils.windows.keys():
            try:
                logger.debug(f"Monitoring window with HWND: {hwnd}")
                self.gui_utils.monitor_window(hwnd)
            except Exception as e:
                logger.error(f"Error monitoring window {hwnd}: {e}")
                logger.error(f"Traceback: {traceback.format_exc()}")
    
    def _wait_for_setup_handlers(self):
        """
        Wait for Setup button handler detection
        
        Returns:
            dict: Detected Setup button handler information
        """
        logger.info("Waiting for setup handlers")
        # Record number of existing handlers
        handler_count_before = len(self.gui_utils.handlers)
        logger.info(f"Handlers before waiting: {handler_count_before}")
        
        # Wait for timeout
        start_time = time.time()
        while time.time() - start_time < self.timeout:
            # Check if new handlers are detected
            current_handlers = len(self.gui_utils.handlers)
            if current_handlers > handler_count_before:
                logger.info(f"New handlers detected: {current_handlers} > {handler_count_before}")
                break
            time.sleep(0.1)
        
        # Filter new handlers
        new_handlers = {}
        setup_handlers = {}
        
        # All new handlers detected within timeout
        for addr, info in self.gui_utils.handlers.items():
            timestamp = info.get('timestamp', '')
            if timestamp and time.strptime(timestamp, '%Y-%m-%d %H:%M:%S') > time.localtime(start_time):
                new_handlers[addr] = info
        
        logger.info(f"New handlers detected during wait: {len(new_handlers)}")
        
        # Filter Setup-related handlers
        for addr, info in new_handlers.items():
            control_text = info.get('controlText', '').lower()
            # Check if control text contains Setup keywords
            if any(keyword in control_text for keyword in self.setup_keywords):
                setup_handlers[addr] = info
        
        logger.info(f"Setup related handlers: {len(setup_handlers)}")
        return setup_handlers
    
    def _print_setup_handlers(self, handlers):
        """
        Print detected Setup button handlers
        
        Args:
            handlers: Handler information dictionary
        """
        logger.info("Printing setup handlers")
        data = []
        for addr, info in handlers.items():
            # Extract call stack (top 3 frames only)
            callstack = info.get('callStack', [])
            callstack_str = "\n".join(callstack[:3]) if callstack else "N/A"
            
            data.append([
                addr,
                info.get('controlText', ''),
                info.get('controlId', ''),
                callstack_str
            ])
        
        print(tabulate(data, headers=["Handler Address", "Button Text", "Control ID", "Call Stack (Top 3 frames)"], tablefmt="grid"))
    
    def _generate_report(self, handlers, output_file):
        """
        Create Setup button handler report
        
        Args:
            handlers: Handler information dictionary
            output_file: Output file path
        """
        logger.info(f"Generating report to {output_file}")
        report = []
        report.append("=== Setup button handler analysis report ===")
        report.append(f"Creation time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Target process: {self.target}")
        report.append(f"Search keywords: {', '.join(self.setup_keywords)}")
        report.append(f"Total detected handlers: {len(handlers)}")
        report.append("")
        
        # Found Setup button information
        if self.setup_buttons:
            report.append("--- Found Setup buttons ---")
            button_data = []
            for idx, info in self.setup_buttons.items():
                button_data.append([
                    idx,
                    info['text'],
                    info['control_id'],
                    info['window_title']
                ])
            
            button_table = tabulate(button_data, headers=["Number", "Button Text", "Control ID", "Window Title"], tablefmt="grid")
            report.append(button_table)
            report.append("")
        
        # Handler information
        report.append("--- Detected Setup button handlers ---")
        if handlers:
            handler_data = []
            for addr, info in handlers.items():
                # Include full call stack
                callstack = info.get('callStack', [])
                callstack_str = "\n  ".join(callstack) if callstack else "N/A"
                
                handler_data.append([
                    addr,
                    info.get('controlText', ''),
                    info.get('controlId', ''),
                    callstack_str
                ])
                
            handler_table = tabulate(handler_data, headers=["Handler Address", "Button Text", "Control ID", "Call Stack"], tablefmt="grid")
            report.append(handler_table)
        else:
            report.append("No detected Setup button handlers")
            
        report_str = '\n'.join(report)
        
        # Output file
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_str)
            logger.info(f"Report written to {output_file}")
        except Exception as e:
            logger.error(f"Error writing report to {output_file}: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Find setup button handlers in GUI applications')
    parser.add_argument('--target', type=int , default=45840 , help='Target process name or PID')
    parser.add_argument('--timeout', type=int, default=60, help='Handler detection timeout (seconds)')
    parser.add_argument('--keywords', type=str, default='' , help='Additional search keywords (comma separated)')
    args = parser.parse_args()
    
    # Process additional keywords
    additional_keywords = []
    if args.keywords:
        additional_keywords = [k.strip() for k in args.keywords.split(',')]
    
    logger.info(f"Starting SetupButtonFinder with target={args.target}, timeout={args.timeout}")
    # Run SetupButtonFinder
    finder = SetupButtonFinder(args.target, args.timeout, additional_keywords)
    finder.run()


if __name__ == "__main__":
    main() 