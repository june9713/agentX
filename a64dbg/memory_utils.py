#!/usr/bin/env python3
# a64dbg/memory_utils.py - Memory operation utilities

import binascii

class MemoryUtils:
    def __init__(self, script):
        """
        초기화 함수
        
        Args:
            script: Frida 스크립트 객체 (controller에서 생성된 script)
        """
        self.script = script
        self._setup_handlers()
        
    def _setup_handlers(self):
        """메모리 관련 이벤트 핸들러 설정"""
        # 필요시 특별한 메시지 처리 로직 추가
        pass
        
    def enumerate_modules(self):
        """모든 모듈 정보 조회"""
        self.script.post('memory_request', {'cmd': 'enumerate_modules'})
        
    def enumerate_exports(self, module_name):
        """특정 모듈의 export 함수 조회
        
        Args:
            module_name: 모듈 이름 (예: 'kernel32.dll')
        """
        self.script.post('memory_request', {
            'cmd': 'enumerate_exports',
            'module_name': module_name
        })
        
    def dump_memory(self, address, size):
        """특정 주소의 메모리 덤프
        
        Args:
            address: 메모리 주소 (16진수 문자열 또는 정수)
            size: 덤프할 크기 (바이트)
        """
        # 주소 형식 변환
        if isinstance(address, str):
            if address.startswith('0x'):
                address = int(address, 16)
            else:
                address = int(address)
                
        self.script.post('memory_request', {
            'cmd': 'dump_memory',
            'address': hex(address),
            'size': size
        })
        
    def write_memory(self, address, data):
        """특정 주소에 메모리 쓰기
        
        Args:
            address: 메모리 주소 (16진수 문자열 또는 정수)
            data: 바이트 배열 또는 16진수 문자열
        """
        # 주소 형식 변환
        if isinstance(address, str):
            if address.startswith('0x'):
                address = int(address, 16)
            else:
                address = int(address)
        
        # 데이터 형식 변환
        if isinstance(data, bytes) or isinstance(data, bytearray):
            data = binascii.hexlify(data).decode('utf-8')
        elif isinstance(data, list):  # 정수 리스트인 경우
            data = ''.join([f'{b:02x}' for b in data])
            
        self.script.post('memory_request', {
            'cmd': 'write_memory',
            'address': hex(address),
            'data': data
        })
        
    def search_pattern(self, pattern, module_name=None):
        """메모리에서 특정 패턴 검색 (예시 - 현재 구현 안됨)
        
        Args:
            pattern: 검색할 16진수 패턴 (예: "90 90 ?? 90")
            module_name: 검색할 모듈 이름 (없으면 전체 메모리)
        """
        # 이 기능은 아직 Frida 스크립트에 구현되지 않았으므로 안내 메시지 출력
        print("[!] Pattern search not implemented yet")
        
    def patch_code(self, address, new_bytes):
        """코드 패치 - 특정 주소의 코드를 새로운 바이트로 대체
        
        Args:
            address: 패치할 메모리 주소
            new_bytes: 새로운 바이트 (16진수 문자열 또는 바이트 배열)
        """
        # 내부적으로 write_memory 호출
        self.write_memory(address, new_bytes)
        print(f"[+] Patched code at {hex(address)}")

# 사용 예:
# memory_utils = MemoryUtils(controller.script)
# memory_utils.enumerate_modules()
# memory_utils.dump_memory(0x12345678, 128) 