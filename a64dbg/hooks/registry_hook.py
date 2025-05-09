#!/usr/bin/env python3
# a64dbg/hooks/registry_hook.py - Registry API hooks

# JavaScript Frida hook for registry functions
hook_script = """
// Registry API hooking
(function() {
    // RegOpenKeyExW hooking
    var regOpenKeyExW = Module.getExportByName("advapi32.dll", "RegOpenKeyExW");
    Interceptor.attach(regOpenKeyExW, {
        onEnter: function(args) {
            // arg0: hKey (root key)
            // arg1: lpSubKey (sub key path)
            // arg2: ulOptions (options)
            // arg3: samDesired (access permissions)
            // arg4: phkResult (result handle pointer)
            
            var rootKey = args[0];
            var subKeyPtr = args[1];
            var subKey = subKeyPtr.isNull() ? "(NULL)" : Memory.readUtf16String(subKeyPtr);
            var samDesired = args[3].toInt32();
            
            // convert root key to string
            var rootKeyStr = "UNKNOWN";
            var HKEY_LOCAL_MACHINE = ptr("0x80000002");
            var HKEY_CURRENT_USER = ptr("0x80000001");
            var HKEY_CLASSES_ROOT = ptr("0x80000000");
            var HKEY_USERS = ptr("0x80000003");
            
            if (rootKey.equals(HKEY_LOCAL_MACHINE)) rootKeyStr = "HKEY_LOCAL_MACHINE";
            else if (rootKey.equals(HKEY_CURRENT_USER)) rootKeyStr = "HKEY_CURRENT_USER";
            else if (rootKey.equals(HKEY_CLASSES_ROOT)) rootKeyStr = "HKEY_CLASSES_ROOT";
            else if (rootKey.equals(HKEY_USERS)) rootKeyStr = "HKEY_USERS";
            
            // convert access permissions to string
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
            
            // save internal state
            this.subKey = subKey;
            this.rootKeyStr = rootKeyStr;
        },
        onLeave: function(retval) {
            // return value (ERROR_SUCCESS=0, etc.)
            var status = retval.toInt32();
            
            // convert status code to string
            var statusStr = status === 0 ? "ERROR_SUCCESS" : "0x" + status.toString(16);
            
            send({
                hook: "RegOpenKeyExW_ret", 
                rootKey: this.rootKeyStr,
                subKey: this.subKey,
                status: statusStr
            });
        }
    });

    // RegQueryValueExW hooking
    var regQueryValueExW = Module.getExportByName("advapi32.dll", "RegQueryValueExW");
    Interceptor.attach(regQueryValueExW, {
        onEnter: function(args) {
            // arg0: hKey (registry key handle)
            // arg1: lpValueName (value name)
            // arg2: lpReserved (reserved, NULL)
            // arg3: lpType (value type pointer)
            // arg4: lpData (data buffer pointer)
            // arg5: lpcbData (data size pointer)
            
            var hKey = args[0];
            var valueNamePtr = args[1];
            var valueName = valueNamePtr.isNull() ? "(Default)" : Memory.readUtf16String(valueNamePtr);
            
            send({
                hook: "RegQueryValueExW", 
                valueName: valueName
            });
            
            // save internal state
            this.valueName = valueName;
            this.lpType = args[3];
            this.lpData = args[4];
            this.lpcbData = args[5];
        },
        onLeave: function(retval) {
            // return value (ERROR_SUCCESS=0, etc.)
            var status = retval.toInt32();
            
            // try to read value only if the status code is successful
            if (status === 0 && !this.lpType.isNull() && !this.lpcbData.isNull()) {
                var type = Memory.readUInt(this.lpType);
                var dataSize = Memory.readUInt(this.lpcbData);
                
                var typeStr = "UNKNOWN";
                var value = null;
                
                // handle value type appropriately
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
                        // binary data is converted to hexadecimal (maximum 16 bytes)
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
    
    // RegSetValueExW hooking (if needed)
    /*
    var regSetValueExW = Module.getExportByName("advapi32.dll", "RegSetValueExW");
    Interceptor.attach(regSetValueExW, {
        onEnter: function(args) {
            // arg0: hKey (registry key handle)
            // arg1: lpValueName (value name)
            // arg2: Reserved (reserved, 0)
            // arg3: dwType (value type)
            // arg4: lpData (data buffer pointer)
            // arg5: cbData (data size)
            
            var valueNamePtr = args[1];
            var valueName = valueNamePtr.isNull() ? "(Default)" : Memory.readUtf16String(valueNamePtr);
            var type = args[3].toInt32();
            var dataSize = args[5].toInt32();
            
            // display value based on type
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