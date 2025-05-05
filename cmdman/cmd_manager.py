# file: persistent_cmd_manager.py
import subprocess
import threading
import queue
import logging
import time
import random
from datetime import datetime
from typing import Dict, Any, Optional
import difflib

logger = logging.getLogger(__name__)

_PROMPT   = "$G"        # plain ">"
_END_MARK = "__CMD_DONE__"

cmdmanager = None
class PersistentCmdManager:
    def __init__(self, codepage: str = "949"):          # 949 = CP949 (euc-kr)
        self._proc = subprocess.Popen(
            ["cmd.exe", "/Q", "/K", f"CHCP {codepage} & PROMPT {_PROMPT}"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="cp949",         # ① decode ALL output with CP949
            errors="replace",         #    never crash on bad bytes
            bufsize=1,                # line-buffered
        )
        self._out_q: queue.Queue[str] = queue.Queue()
        self._err_q: queue.Queue[str] = queue.Queue()
        # background readers
        threading.Thread(target=self._pump, args=(self._proc.stdout, self._out_q), daemon=True).start()
        threading.Thread(target=self._pump, args=(self._proc.stderr, self._err_q), daemon=True).start()
        self.last_result: Optional[Dict[str, Any]] = None

    @staticmethod
    def _pump(stream, q):
        for line in iter(stream.readline, ""):
            print("line"  ,line)
            q.put(line)
            
    @staticmethod
    def _count_diff_chars(str1, str2):
        """Count the number of different characters between two strings."""
        if len(str1) != len(str2):
            return max(len(str1), len(str2))
        return sum(c1 != c2 for c1, c2 in zip(str1, str2))
            
    def _drain(self, q, until_marker: str, timeout: float):
        lines, start = [], time.time()
        filtered_lines = []
        prev_line = ""
        
        while time.time() - start < timeout:
            try:
                line = q.get(timeout=0.05)
            except queue.Empty:
                continue
            if until_marker in line:
                break
            lines.append(line)
        
        # Filter out lines that are very similar to previous ones (progress updates)
        for line in lines:
            if not prev_line or self._count_diff_chars(prev_line, line) > 3:
                filtered_lines.append(line)
            prev_line = line
        
        # Always keep the last line of similar progress updates
        if lines and not filtered_lines:
            filtered_lines.append(lines[-1])
        
        return "".join(filtered_lines)


    def execute_command(self, cmd: str, timeout: int = 30) -> Dict[str, Any]:
        tag = f"[PERSIST_CMD][{datetime.now().strftime('%H:%M:%S')}]"
        logger.debug(f"{tag} ⇢ {cmd}")

        if self._proc.poll() is not None:
            raise RuntimeError("cmd.exe process has exited!")

        # 1) send command + sentinel
        self._proc.stdin.write(f"{cmd} & echo {_END_MARK} & echo {_END_MARK} 1>&2\n")
        self._proc.stdin.flush()

        # 2) collect output
        stdout = self._drain(self._out_q, _END_MARK, timeout)
        stderr = self._drain(self._err_q, _END_MARK, timeout)   # errors are usually small/instant

        result = {
            "command": cmd,
            "stdout": stdout,
            "stderr": stderr,
            "success": len(stderr.strip()) == 0,
        }
        self.last_result = result
        logger.debug(f"{tag} done (success={result['success']})")
        return result

    def close(self):
        if self._proc.poll() is None:
            self._proc.stdin.write("exit\n")
            self._proc.stdin.flush()
            self._proc.wait(2)

def get_cmd_manager():
    global cmdmanager
    if cmdmanager is None:
        cmdmanager = PersistentCmdManager() 
        cmdmanager.uid = random.randint(1000000000, 9999999999)
    return cmdmanager

