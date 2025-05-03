#!/usr/bin/env python3
# a64dbg/hooks/memory_hook.py - Memory operations hooks

# JavaScript Frida hook for memory operations
hook_script = """
// 메모리 조작 및 모니터링을 위한 유틸리티 함수
(function() {
    // 모듈 정보 수집 및 출력
    function enumerateModules() {
        Process.enumerateModules({
            onMatch: function(module) {
                send({
                    hook: "MemoryInfo", 
                    type: "Module",
                    name: module.name, 
                    base: module.base, 
                    size: module.size,
                    path: module.path
                });
            },
            onComplete: function() {
                send({hook: "MemoryInfo", note: "Module enumeration completed"});
            }
        });
    }
    
    // 특정 모듈의 내보낸 함수 수집
    function enumerateExports(moduleName) {
        var exports = Module.enumerateExportsSync(moduleName);
        if (exports.length > 20) {
            send({hook: "MemoryInfo", note: `${moduleName} has ${exports.length} exports, showing first 20`});
            exports = exports.slice(0, 20);
        }
        
        for (var i = 0; i < exports.length; i++) {
            var exp = exports[i];
            send({
                hook: "MemoryInfo", 
                type: "Export",
                module: moduleName,
                name: exp.name, 
                address: exp.address,
                type: exp.type
            });
        }
    }
    
    // 메모리 영역 덤프
    function dumpMemory(address, size) {
        try {
            var buf = Memory.readByteArray(ptr(address), size);
            // Frida의 send()는 ArrayBuffer를 자동으로 처리
            send({hook: "MemoryDump", address: address, size: size}, buf);
            return true;
        } catch (e) {
            send({hook: "MemoryDump", error: e.message});
            return false;
        }
    }
    
    // 메모리 쓰기
    function writeMemory(address, hexBytes) {
        try {
            var bytes = [];
            for (var i = 0; i < hexBytes.length; i += 2) {
                bytes.push(parseInt(hexBytes.substr(i, 2), 16));
            }
            Memory.writeByteArray(ptr(address), bytes);
            send({hook: "MemoryWrite", address: address, bytes: hexBytes, status: "success"});
            return true;
        } catch (e) {
            send({hook: "MemoryWrite", address: address, error: e.message});
            return false;
        }
    }
    
    // 모듈 목록 즉시 출력 (예시용)
    setTimeout(enumerateModules, 1000);
    
    // 요청에 대한 핸들러를 추가 - Python에서 호출 가능한 기능 제공
    recv('memory_request', function(message) {
        var cmd = message.cmd;
        
        if (cmd === 'enumerate_modules') {
            enumerateModules();
        }
        else if (cmd === 'enumerate_exports') {
            enumerateExports(message.module_name);
        }
        else if (cmd === 'dump_memory') {
            dumpMemory(message.address, message.size);
        }
        else if (cmd === 'write_memory') {
            writeMemory(message.address, message.data);
        }
        else {
            send({hook: "MemoryInfo", error: "Unknown command: " + cmd});
        }
    });
    
    // 사용 가능한 명령어 알림
    send({
        hook: "MemoryInfo", 
        note: "Memory operations initialized. Available commands: enumerate_modules, enumerate_exports, dump_memory, write_memory"
    });
})();
""" 