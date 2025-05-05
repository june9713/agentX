#!/usr/bin/env python3
# xursor_client.py - A client for interacting with xursor.py

import os
import sys
import time
import json
import logging
import traceback
import subprocess
import argparse
from typing import Dict, List, Any, Optional, Tuple
import threading

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("xursor_client.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Get the current directory to find xursor.py
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
xursor_path = os.path.join(parent_dir, "xursor.py")

# Validate xursor.py exists
if not os.path.exists(xursor_path):
    logger.error(f"xursor.py not found at {xursor_path}! Please make sure xursor.py is in the parent directory.")
    sys.exit(1)

# Import cmd_manager only if it exists
cmd_manager = None
try:
    from cmdman.cmd_manager import PersistentCmdManager, get_cmd_manager
    cmd_manager = get_cmd_manager()
    logger.info("Successfully imported cmd_manager")
except ImportError:
    logger.warning("cmdman.cmd_manager not found. Will use subprocess directly.")

class XursorClient:
    def __init__(self, api_key: str = None, model: str = "claude-3-opus-20240229"):
        """
        Initialize the Xursor client
        
        Args:
            api_key: API key for the LLM service
            model: Model to use (default: claude-3-opus-20240229)
        """
        self.api_key = api_key or os.environ.get("XURSOR_API_KEY")
        self.model = model
        self.workspace_path = os.getcwd()
        self.xursor_process = None
        
        if not self.api_key:
            raise ValueError("API key not provided. Use --api-key or set XURSOR_API_KEY environment variable.")
            
    def _execute_command(self, cmd: str, timeout: int = 60) -> Dict[str, Any]:
        """
        Execute a command using cmd_manager if available, otherwise use subprocess
        
        Args:
            cmd: Command to execute
            timeout: Timeout in seconds
            
        Returns:
            Dictionary with command execution results
        """
        if cmd_manager:
            return cmd_manager.execute_command(cmd, timeout=timeout)
        
        # Fallback to subprocess if cmd_manager not available
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
                universal_newlines=True
            )
            
            stdout, stderr = process.communicate(timeout=timeout)
            
            return {
                "success": process.returncode == 0,
                "stdout": stdout,
                "stderr": stderr,
                "returncode": process.returncode
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Command timed out after {timeout} seconds",
                "returncode": -1
            }
        except Exception as e:
            return {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "returncode": -1
            }
    
    def _start_xursor(self) -> Tuple[subprocess.Popen, threading.Thread]:
        """
        Start xursor.py in interactive mode
        
        Returns:
            Tuple of (subprocess.Popen, output_thread)
        """
        # Start xursor.py in a subprocess
        cmd = [
            sys.executable,
            xursor_path,
            "--api-key", self.api_key,
            "--model", self.model,
            "--workspace", self.workspace_path
        ]
        
        logger.info(f"Starting xursor.py: {' '.join(cmd)}")
        
        # Use subprocess.PIPE for input and output
        self.xursor_process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            bufsize=1  # Line buffered
        )
        
        # Create a thread to continuously read output
        output = {"data": ""}
        stop_thread = threading.Event()
        
        def read_output():
            while not stop_thread.is_set():
                if self.xursor_process.poll() is not None:
                    break
                    
                line = self.xursor_process.stdout.readline()
                if line:
                    output["data"] += line
                    sys.stdout.write(line)
                    sys.stdout.flush()
                else:
                    time.sleep(0.1)
        
        output_thread = threading.Thread(target=read_output, daemon=True)
        output_thread.start()
        
        # Wait for initialization
        time.sleep(3)
        
        return self.xursor_process, output_thread, output, stop_thread
    
    def _stop_xursor(self, output_thread: threading.Thread, stop_thread: threading.Event):
        """
        Stop xursor.py subprocess
        """
        if self.xursor_process:
            try:
                if self.xursor_process.poll() is None:
                    # Send exit command
                    self.xursor_process.stdin.write("exit\n")
                    self.xursor_process.stdin.flush()
                    
                    # Wait briefly for clean exit
                    time.sleep(1)
                    
                    # Terminate if still running
                    if self.xursor_process.poll() is None:
                        self.xursor_process.terminate()
                        self.xursor_process.wait(timeout=5)
            except Exception as e:
                logger.error(f"Error stopping xursor process: {e}")
                
            # Stop the output thread
            stop_thread.set()
            output_thread.join(timeout=2)
            
            self.xursor_process = None
    
    def execute_cmd_session(self, query: str) -> str:
        """
        Execute a command session with Xursor
        
        Args:
            query: User query to process
            
        Returns:
            Final result string
        """
        try:
            logger.info(f"Starting Xursor command session with query: {query}")
            
            # Start xursor process
            xursor_process, output_thread, output, stop_thread = self._start_xursor()
            
            # Get current directory
            cmd_result = self._execute_command("echo %CD%", timeout=30)
            current_dir = cmd_result['stdout'].strip()
            
            # Create initial prompt
            initial_prompt = f"""사용자 요청: 현재의 디렉토리 패스는 {current_dir} 입니다. 
주의: 항상 작업을 위한 디렉토리로 먼저 이동을 한 뒤에 본격적인 작업을 시작합니다.
{query}

이 작업을 수행하기 위한 윈도우즈 CMD 명령어 시퀀스를 하나씩 제공해주세요. 각 명령어 실행 결과를 확인한 후 다음 명령어를 제시하겠습니다.

작업이 완료되면 반드시 다음의 명령어로 명확하게 종료를 표시해주세요:
echo ##TASK_COMPLETE##[%random%] > task_complete.flag && echo {{"status":"complete","timestamp":"%date% %time%","message":"에이전트작업완료"}}

불필요한 설명은 절대 하지 않고 모두 코드로만 대화 합니다"""

            # Send initial prompt to xursor
            logger.info("Sending initial prompt to Xursor")
            xursor_process.stdin.write(initial_prompt + "\n")
            xursor_process.stdin.flush()
            
            # Clear output to capture response
            output["data"] = ""
            
            # Create task completion flag file checker
            max_iterations = 10
            iteration = 0
            final_result = ""
            
            # Initialize flag file state
            if os.path.exists("task_complete.flag"):
                os.remove("task_complete.flag")
                
            # Main interaction loop
            while iteration < max_iterations:
                iteration += 1
                logger.info(f"Command iteration {iteration}/{max_iterations}")
                
                # Wait for Xursor to respond
                wait_time = 0
                max_wait = 300  # 5 minutes
                sleep_interval = 3  # Check every 3 seconds
                
                while wait_time < max_wait:
                    if "I'll help you with that" in output["data"] or "Here's the next command" in output["data"]:
                        break
                        
                    if os.path.exists("task_complete.flag"):
                        logger.info("Task completion flag file found")
                        with open("task_complete.flag", "r") as f:
                            flag_content = f.read().strip()
                        if "##TASK_COMPLETE##" in flag_content:
                            logger.info("Task completed with completion flag")
                            final_result = "작업이 완료되었습니다. 완료 플래그 파일이 생성되었습니다."
                            # JSON 상태 파일의 내용 읽기
                            cmd_result = self._execute_command('type task_complete.flag', timeout=30)
                            if cmd_result["success"]:
                                final_result += f"\n\n완료 정보: {cmd_result['stdout']}"
                            break
                            
                    time.sleep(sleep_interval)
                    wait_time += sleep_interval
                
                # Check if task is complete
                if os.path.exists("task_complete.flag"):
                    break
                
                # Extract command from Xursor's response
                command = self._extract_command_from_response(output["data"])
                
                if not command:
                    logger.warning("No command found in response")
                    xursor_process.stdin.write("명령어를 찾을 수 없습니다. CMD 명령어를 코드 블록으로 명확하게 제시해주세요.\n")
                    xursor_process.stdin.flush()
                    time.sleep(5)
                    continue
                
                # Execute command
                cmd_result_pre = self._execute_command("dir", timeout=30)
                rsltstrpre = '---작업 전의 dir 결과 ---\n'
                rsltstrpre += cmd_result_pre['stdout'].strip()
                rsltstrpre += cmd_result_pre['stderr'].strip()
                
                logger.info(f"Executing command: {command}")
                cmd_result = self._execute_command(command, timeout=300)
                
                cmd_result_post = self._execute_command("dir", timeout=30)
                rsltstrpost = '\n\n---작업 후의 dir 결과 ---\n'
                rsltstrpost += cmd_result_post['stdout'].strip()
                rsltstrpost += cmd_result_post['stderr'].strip()
                
                # Prepare result for xursor
                if cmd_result["success"]:
                    rsltstr = "----stdout---\n" + cmd_result['stdout'] + "\n\n---stderr---\n" + cmd_result['stderr']
                    result_message = f"""명령어 실행 결과:\n{rsltstrpre}\n----명령어 실행 결과----\n{rsltstr}\n{rsltstrpost}\n현재의 로그 콘솔을 통해 원하는 작업이 실행이 되었는지 확인 후, 아니라고 생각한다면 계획을 수정하여 다음 명령어를 제시하거나, 모든 작업이 완료되었다고 판단되는 경우에는 다음의 명령어를 실행하세요:

echo ##TASK_COMPLETE##[%random%] > task_complete.flag && echo {{"status":"complete","timestamp":"%date% %time%","message":"에이전트작업완료"}}"""
                else:
                    error_output = cmd_result["stderr"] if cmd_result["stderr"] else "알 수 없는 오류"
                    result_message = f"""명령어 실행 중 오류 발생:\n{rsltstrpre}\n----명령어 실행 오류----\n{error_output}\n{rsltstrpost}\n현재의 로그 콘솔을 통해 원하는 작업이 실행이 되었는지 확인 후, 아니라고 생각한다면 계획을 수정하여 다음 명령어를 제시하거나, 모든 작업이 완료되었다고 판단되는 경우에는 다음의 명령어를 실행하세요:

echo ##TASK_COMPLETE##[%random%] > task_complete.flag && echo {{"status":"complete","timestamp":"%date% %time%","message":"에이전트작업완료"}}"""
                
                # Send result back to xursor
                xursor_process.stdin.write(result_message + "\n")
                xursor_process.stdin.flush()
                
                # Clear output for next round
                output["data"] = ""
                
                # Check if task is completed
                if os.path.exists("task_complete.flag"):
                    logger.info("Task completion flag file found")
                    with open("task_complete.flag", "r") as f:
                        flag_content = f.read().strip()
                    if "##TASK_COMPLETE##" in flag_content:
                        logger.info("Task completed with completion flag")
                        final_result = "작업이 완료되었습니다. 완료 플래그 파일이 생성되었습니다."
                        # JSON 상태 파일의 내용 읽기
                        cmd_result = self._execute_command('type task_complete.flag', timeout=30)
                        if cmd_result["success"]:
                            final_result += f"\n\n완료 정보: {cmd_result['stdout']}"
                        break
            
            # Prepare summary
            summary = f"총 {iteration}회 명령어 실행 완료.\n"
            
            # Final directory status
            cmd_result = self._execute_command("dir", timeout=30)
            summary += f"\n최종 디렉토리 상태:\n{cmd_result['stdout'][:500]}...\n"
            
            logger.info(summary)
            final_result = (final_result + "\n\n" + summary) if final_result else summary
            
            return final_result
        
        except Exception as e:
            logger.error(f"Error in execute_cmd_session: {str(e)}")
            logger.error(traceback.format_exc())
            return f"오류 발생: {str(e)}"
        finally:
            # Stop xursor process
            if output_thread and stop_thread:
                self._stop_xursor(output_thread, stop_thread)
    
    def _extract_command_from_response(self, response_text: str) -> str:
        """
        Extract command from Xursor's response
        
        Args:
            response_text: Response text from Xursor
            
        Returns:
            Extracted command or empty string
        """
        try:
            # Extract from code blocks
            import re
            
            # Code block pattern (anything surrounded by ```)
            code_block_pattern = r'```(?:cmd|bat|bash|shell|powershell|)?\s*(.*?)\s*```'
            code_blocks = re.findall(code_block_pattern, response_text, re.DOTALL)
            
            if code_blocks:
                # Use the last code block
                cmd = code_blocks[-1].strip()
                logger.info(f"Found command in code block: {cmd}")
                return cmd
            
            # Extract from plain text if no code blocks found
            lines = response_text.split('\n')
            
            # Common CMD command prefixes
            common_cmd_prefixes = [
                'dir', 'cd', 'copy', 'del', 'echo', 'type', 'mkdir', 'rmdir', 
                'ping', 'ipconfig', 'netstat', 'tasklist', 'findstr', 'systeminfo',
                'ver', 'chdir', 'cls', 'date', 'time', 'rd', 'md', 'ren', 'move'
            ]
            
            # Command indicators
            cmd_indicators = ["명령어:", "실행:", "CMD:", "명령:", "커맨드:", "command:", "다음 명령어:"]
            for line in lines:
                for indicator in cmd_indicators:
                    if indicator.lower() in line.lower():
                        cmd = line.split(indicator, 1)[1].strip()
                        logger.info(f"Found command with indicator: {cmd}")
                        return cmd
            
            # Look for lines starting with common CMD commands
            for line in lines:
                line_stripped = line.strip()
                for prefix in common_cmd_prefixes:
                    if re.match(f"^{prefix}\\b", line_stripped, re.IGNORECASE):
                        logger.info(f"Found command by prefix: {line_stripped}")
                        return line_stripped
            
            # Look for quoted commands
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
            return ""
            
        except Exception as e:
            logger.error(f"Error extracting command: {e}")
            logger.error(traceback.format_exc())
            return ""

def main():
    """
    Main entry point for xursor_client.py
    """
    try:
        # Parse command line arguments
        parser = argparse.ArgumentParser(description="Xursor Client - Interact with Xursor for command execution")
        parser.add_argument("--api-key", help="API key for LLM service", default=os.environ.get("XURSOR_API_KEY"))
        parser.add_argument("--model", help="Model to use", default="claude-3-opus-20240229")
        parser.add_argument("query", nargs="?", help="Query to process")
        
        args = parser.parse_args()
        
        # Get query from command line or user input
        query = args.query
        if not query:
            query = input("Enter your command task query: ")
        
        # Create and run client
        client = XursorClient(api_key=args.api_key, model=args.model)
        result = client.execute_cmd_session(query)
        
        # Print result
        print("\n--- Task Result ---")
        print(result)
        
    except Exception as e:
        logger.error(f"Unexpected error in main: {e}")
        logger.error(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main() 