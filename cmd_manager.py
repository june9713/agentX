import subprocess
import logging
import os
import time
import traceback
from datetime import datetime
from typing import Dict, Any, Optional, List, Union

# 로깅 설정
logger = logging.getLogger(__name__)

class CmdManager:
    """
    서버 PC에서 CMD 명령어를 실행하고 결과를 반환하는 관리자 클래스
    """
    
    def __init__(self):
        """
        CmdManager 초기화
        """
        self.last_command = None
        self.last_result = None
    
    def execute_command(self, command: str, timeout: int = 30, 
                        working_dir: Optional[str] = None, 
                        request_id: Optional[str] = None) -> Dict[str, Any]:
        """
        CMD 명령어를 실행하고 결과를 반환합니다.
        
        Args:
            command: 실행할 CMD 명령어
            timeout: 명령어 실행 제한 시간(초)
            working_dir: 명령어를 실행할 작업 디렉토리
            request_id: 요청 추적을 위한 ID
            
        Returns:
            명령어 실행 결과를 포함하는 딕셔너리
        """
        if not request_id:
            request_time = datetime.now().strftime("%Y%m%d_%H%M%S")
            request_id = f"cmd_{request_time}"
            
        tag = f"[CMD_EXECUTE][{request_id}]"
        start_time = time.time()
        logger.info(f"{tag} Command execution requested: {command}")
        
        self.last_command = command
        result = {
            "command": command,
            "success": False,
            "stdout": "",
            "stderr": "",
            "exit_code": None,
            "execution_time": 0,
            "error": None
        }
        
        try:
            # 작업 디렉토리 설정
            cwd = working_dir if working_dir else os.getcwd()
            logger.debug(f"{tag} Working directory: {cwd}")
            
            # subprocess 명령 실행
            logger.debug(f"{tag} Executing command with timeout {timeout}s")
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
                cwd=cwd,
                text=True,
                encoding='utf-8',
                errors='replace'
            )
            
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                exit_code = process.returncode
                logger.debug(f"{tag} Command completed with exit code: {exit_code}")
                
                # 결과 저장
                result["success"] = exit_code == 0
                result["stdout"] = stdout
                result["stderr"] = stderr
                result["exit_code"] = exit_code
                
            except subprocess.TimeoutExpired:
                logger.warning(f"{tag} Command timed out after {timeout}s")
                process.kill()
                stdout, stderr = process.communicate()
                
                result["success"] = False
                result["stdout"] = stdout
                result["stderr"] = stderr
                result["error"] = f"Command timed out after {timeout} seconds"
                result["exit_code"] = -1
                
        except Exception as e:
            end_time = time.time()
            error_msg = f"Error executing command: {str(e)}"
            logger.error(f"{tag} {error_msg}")
            logger.debug(f"{tag} Exception details: {traceback.format_exc()}")
            
            result["success"] = False
            result["error"] = error_msg
            result["exit_code"] = -1
            
        finally:
            end_time = time.time()
            execution_time = end_time - start_time
            result["execution_time"] = round(execution_time, 2)
            
            # 로그 크기 제한을 위해 stdout/stderr 길이 확인
            stdout_len = len(result["stdout"])
            stderr_len = len(result["stderr"])
            
            logger.info(f"{tag} Command completed in {execution_time:.2f}s, exit code: {result['exit_code']}")
            logger.debug(f"{tag} stdout length: {stdout_len}, stderr length: {stderr_len}")
            
            if stdout_len > 200:
                logger.debug(f"{tag} stdout preview: {result['stdout'][:200]}...")
            else:
                logger.debug(f"{tag} stdout: {result['stdout']}")
                
            if stderr_len > 200:
                logger.debug(f"{tag} stderr preview: {result['stderr'][:200]}...")
            else:
                logger.debug(f"{tag} stderr: {result['stderr']}")
            
            self.last_result = result
            return result
    
    def get_last_command(self) -> Optional[str]:
        """마지막으로 실행한 명령어를 반환합니다."""
        return self.last_command
    
    def get_last_result(self) -> Optional[Dict[str, Any]]:
        """마지막으로 실행한 명령어의 결과를 반환합니다."""
        return self.last_result


# 싱글톤 인스턴스
_cmd_manager = None

def get_cmd_manager() -> CmdManager:
    """CmdManager의 싱글톤 인스턴스를 반환합니다."""
    global _cmd_manager
    if _cmd_manager is None:
        _cmd_manager = CmdManager()
    return _cmd_manager 