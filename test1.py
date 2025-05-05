#!/usr/bin/env python
# File: test1.py - 콘솔 명령어 출력 포함 테스트

import os
import subprocess
import sys

def execute_command(cmd):
    """
    명령어 실행 및 결과 반환
    """
    print(f"실행 명령어: {cmd}")
    result = subprocess.run(cmd, shell=True, text=True, capture_output=True, encoding='cp949', errors='replace')
    
    if result.returncode == 0:
        print(f"명령어 성공, 출력:\n{result.stdout}")
        return {
            "success": True,
            "stdout": result.stdout,
            "stderr": ""
        }
    else:
        print(f"명령어 실패, 오류:\n{result.stderr}")
        return {
            "success": False,
            "stdout": result.stdout,
            "stderr": result.stderr
        }

def main():
    """
    이전 명령어 출력을 다음 명령어 입력에 포함시키는 테스트
    """
    print("=" * 50)
    print("콘솔 명령어 출력 포함 테스트")
    print("=" * 50)
    
    # 첫 번째 명령어: 현재 디렉토리 파일 목록 확인
    cmd1 = "dir /b"
    result1 = execute_command(cmd1)
    
    # 명령어 결과를 가지고 다음 명령어 생성
    if result1["success"]:
        # 결과에서 첫 번째 Python 파일 찾기
        py_files = [line.strip() for line in result1["stdout"].splitlines() if line.strip().endswith(".py")]
        
        if py_files:
            first_py_file = py_files[0]
            print(f"찾은 Python 파일: {first_py_file}")
            
            # 두 번째 명령어: 파일 내용 확인
            cmd2 = f"type {first_py_file}"
            result2 = execute_command(cmd2)
            
            # 세 번째 명령어: 파일 크기 확인
            cmd3 = f"dir {first_py_file}"
            result3 = execute_command(cmd3)
            
            print("\n=== 프로세스 정리 및 요약 ===")
            print(f"1. 실행한 명령어: {cmd1}")
            print(f"   결과: {len(py_files)}개의 Python 파일 발견")
            print(f"2. 실행한 명령어: {cmd2}")
            print(f"   결과: {first_py_file} 파일 내용 확인")
            print(f"3. 실행한 명령어: {cmd3}")
            print(f"   결과: {first_py_file} 파일 크기 정보 확인")
        else:
            print("Python 파일을 찾지 못했습니다.")
    else:
        print("첫 번째 명령어 실행에 실패했습니다.")

if __name__ == "__main__":
    main()



