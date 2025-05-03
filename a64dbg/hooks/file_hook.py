#!/usr/bin/env python3
# a64dbg/hooks/file_hook.py - File API hooks

# JavaScript Frida hook for CreateFileW function
hook_script = """
// CreateFileW hook implementation
var createFileW = Module.getExportByName("kernel32.dll", "CreateFileW");
Interceptor.attach(createFileW, {
    onEnter: function(args) {
        // 인자0: LPCWSTR 파일 경로 포인터
        var fileName = Memory.readUtf16String(args[0]);
        send({hook: "CreateFileW", file: fileName});
        
        // 조건 1: 파일명이 ".tmp"로 끝나면 다른 파일로 경로 교체
        if (fileName.endsWith(".tmp")) {
            var dummyName = Memory.allocUtf16String("C:\\\\temp\\\\dummy.txt");
            args[0] = dummyName;
            send({hook: "CreateFileW", note: "filename replaced", newName: "C:\\\\temp\\\\dummy.txt"});
        }
        
        // 조건 2: 파일명에 "notallowed" 문자열이 포함된 경우 플래그 설정 (후처리용)
        this.blockFile = false;
        if (fileName.indexOf("notallowed") !== -1) {
            this.blockFile = true;
        }
        
        // 추가 파일 액세스 정보 기록
        this.fileName = fileName;
        this.desiredAccess = args[1].toInt32();  // 원하는 접근 권한 (GENERIC_READ, GENERIC_WRITE 등)
    },
    onLeave: function(retval) {
        // onEnter에서 blockFile 플래그가 설정된 경우, 반환값 조작
        if (this.blockFile) {
            // INVALID_HANDLE_VALUE (-1, 0xFFFFFFFF)로 반환값 변경
            retval.replace(ptr("0xFFFFFFFF"));
            send({hook: "CreateFileW", note: "forced failure for blocked file", file: this.fileName});
        }
        
        // 최종 반환값 로깅 (문자열로 변환하여 출력)
        var accessTypeStr = "";
        if (this.desiredAccess & 0x80000000) accessTypeStr += "GENERIC_READ ";
        if (this.desiredAccess & 0x40000000) accessTypeStr += "GENERIC_WRITE ";
        
        send({
            hook: "CreateFileW_ret", 
            file: this.fileName, 
            access: accessTypeStr.trim(),
            retval: retval.toString()
        });
    }
});

// 필요시 추가적인 파일 관련 API 후킹 (ReadFile, WriteFile 등)
// 예시:
/*
var readFile = Module.getExportByName("kernel32.dll", "ReadFile");
Interceptor.attach(readFile, {
    onEnter: function(args) {
        this.hFile = args[0];
        this.buffer = args[1];
        this.numberOfBytesToRead = args[2].toInt32();
    },
    onLeave: function(retval) {
        send({hook: "ReadFile", bytesRead: this.numberOfBytesToRead, success: retval.toInt32()});
    }
});
*/
""" 