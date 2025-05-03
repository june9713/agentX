#!/usr/bin/env python3
# a64dbg/hooks/registry_hook.py - Registry API hooks

# JavaScript Frida hook for registry functions
hook_script = """
// Registry API 후킹
(function() {
    // RegOpenKeyExW 후킹
    var regOpenKeyExW = Module.getExportByName("advapi32.dll", "RegOpenKeyExW");
    Interceptor.attach(regOpenKeyExW, {
        onEnter: function(args) {
            // arg0: hKey (루트 키)
            // arg1: lpSubKey (서브 키 경로)
            // arg2: ulOptions (옵션)
            // arg3: samDesired (접근 권한)
            // arg4: phkResult (결과 핸들 포인터)
            
            var rootKey = args[0];
            var subKeyPtr = args[1];
            var subKey = subKeyPtr.isNull() ? "(NULL)" : Memory.readUtf16String(subKeyPtr);
            var samDesired = args[3].toInt32();
            
            // 루트 키 문자열 변환
            var rootKeyStr = "UNKNOWN";
            var HKEY_LOCAL_MACHINE = ptr("0x80000002");
            var HKEY_CURRENT_USER = ptr("0x80000001");
            var HKEY_CLASSES_ROOT = ptr("0x80000000");
            var HKEY_USERS = ptr("0x80000003");
            
            if (rootKey.equals(HKEY_LOCAL_MACHINE)) rootKeyStr = "HKEY_LOCAL_MACHINE";
            else if (rootKey.equals(HKEY_CURRENT_USER)) rootKeyStr = "HKEY_CURRENT_USER";
            else if (rootKey.equals(HKEY_CLASSES_ROOT)) rootKeyStr = "HKEY_CLASSES_ROOT";
            else if (rootKey.equals(HKEY_USERS)) rootKeyStr = "HKEY_USERS";
            
            // 접근 권한 문자열 변환
            var accessStr = [];
            if (samDesired & 0x20019) accessStr.push("KEY_READ");
            if (samDesired & 0x20006) accessStr.push("KEY_WRITE");
            if (samDesired & 0xF0000) accessStr.push("KEY_ALL_ACCESS");
            
            send({
                hook: "RegOpenKeyExW", 
                rootKey: rootKeyStr,
                subKey: subKey,
                access: accessStr.join("|") || "0x" + samDesired.toString(16)
            });
            
            // 내부 상태 저장
            this.subKey = subKey;
            this.rootKeyStr = rootKeyStr;
        },
        onLeave: function(retval) {
            // 반환 값 (ERROR_SUCCESS=0 등)
            var status = retval.toInt32();
            
            // 상태 코드 문자열 변환
            var statusStr = status === 0 ? "ERROR_SUCCESS" : "0x" + status.toString(16);
            
            send({
                hook: "RegOpenKeyExW_ret", 
                rootKey: this.rootKeyStr,
                subKey: this.subKey,
                status: statusStr
            });
        }
    });
    
    // RegQueryValueExW 후킹
    var regQueryValueExW = Module.getExportByName("advapi32.dll", "RegQueryValueExW");
    Interceptor.attach(regQueryValueExW, {
        onEnter: function(args) {
            // arg0: hKey (레지스트리 키 핸들)
            // arg1: lpValueName (값 이름)
            // arg2: lpReserved (예약됨, NULL)
            // arg3: lpType (값 유형 포인터)
            // arg4: lpData (데이터 버퍼 포인터)
            // arg5: lpcbData (데이터 크기 포인터)
            
            var hKey = args[0];
            var valueNamePtr = args[1];
            var valueName = valueNamePtr.isNull() ? "(Default)" : Memory.readUtf16String(valueNamePtr);
            
            send({
                hook: "RegQueryValueExW", 
                valueName: valueName
            });
            
            // 내부 상태 저장
            this.valueName = valueName;
            this.lpType = args[3];
            this.lpData = args[4];
            this.lpcbData = args[5];
        },
        onLeave: function(retval) {
            // 반환 값 (ERROR_SUCCESS=0 등)
            var status = retval.toInt32();
            
            // 상태 코드가 성공인 경우만 값 읽기 시도
            if (status === 0 && !this.lpType.isNull() && !this.lpcbData.isNull()) {
                var type = Memory.readUInt(this.lpType);
                var dataSize = Memory.readUInt(this.lpcbData);
                
                var typeStr = "UNKNOWN";
                var value = null;
                
                // 값 타입에 따라 적절히 처리
                if (type === 1) { // REG_SZ
                    typeStr = "REG_SZ";
                    if (!this.lpData.isNull() && dataSize > 0) {
                        value = Memory.readUtf16String(this.lpData);
                    }
                } else if (type === 4) { // REG_DWORD
                    typeStr = "REG_DWORD";
                    if (!this.lpData.isNull() && dataSize >= 4) {
                        value = Memory.readUInt(this.lpData);
                    }
                } else if (type === 3) { // REG_BINARY
                    typeStr = "REG_BINARY";
                    if (!this.lpData.isNull() && dataSize > 0) {
                        // 바이너리 데이터는 16진수로 변환 (최대 16바이트)
                        var bytes = Memory.readByteArray(this.lpData, Math.min(dataSize, 16));
                        value = [];
                        for (var i = 0; i < bytes.byteLength; i++) {
                            value.push(bytes[i].toString(16).padStart(2, '0'));
                        }
                        value = value.join(' ') + (dataSize > 16 ? "..." : "");
                    }
                }
                
                send({
                    hook: "RegQueryValueExW_ret", 
                    valueName: this.valueName,
                    type: typeStr,
                    value: value,
                    status: "ERROR_SUCCESS"
                });
            } else {
                send({
                    hook: "RegQueryValueExW_ret", 
                    valueName: this.valueName,
                    status: status === 0 ? "ERROR_SUCCESS" : "0x" + status.toString(16)
                });
            }
        }
    });
    
    // RegSetValueExW 후킹 (필요시 활성화)
    /*
    var regSetValueExW = Module.getExportByName("advapi32.dll", "RegSetValueExW");
    Interceptor.attach(regSetValueExW, {
        onEnter: function(args) {
            // arg0: hKey (레지스트리 키 핸들)
            // arg1: lpValueName (값 이름)
            // arg2: Reserved (예약됨, 0)
            // arg3: dwType (값 유형)
            // arg4: lpData (데이터 버퍼 포인터)
            // arg5: cbData (데이터 크기)
            
            var valueNamePtr = args[1];
            var valueName = valueNamePtr.isNull() ? "(Default)" : Memory.readUtf16String(valueNamePtr);
            var type = args[3].toInt32();
            var dataSize = args[5].toInt32();
            
            // 유형에 따라 값 표시
            var typeStr = "UNKNOWN";
            var value = null;
            
            if (type === 1) { // REG_SZ
                typeStr = "REG_SZ";
                value = Memory.readUtf16String(args[4]);
            } else if (type === 4) { // REG_DWORD
                typeStr = "REG_DWORD";
                value = Memory.readUInt(args[4]);
            }
            
            send({
                hook: "RegSetValueExW", 
                valueName: valueName,
                type: typeStr,
                value: value,
                size: dataSize
            });
            
            this.valueName = valueName;
        },
        onLeave: function(retval) {
            var status = retval.toInt32();
            send({
                hook: "RegSetValueExW_ret", 
                valueName: this.valueName,
                status: status === 0 ? "ERROR_SUCCESS" : "0x" + status.toString(16)
            });
        }
    });
    */
})();
""" 