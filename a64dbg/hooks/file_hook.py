#!/usr/bin/env python3
# a64dbg/hooks/file_hook.py - File API hooks

# JavaScript Frida hook for CreateFileW function
hook_script = """
// CreateFileW hook implementation
var createFileW = Module.getExportByName("kernel32.dll", "CreateFileW");
Interceptor.attach(createFileW, {
    onEnter: function(args) {
        // args[0]: LPCWSTR file path pointer
        var fileName = Memory.readUtf16String(args[0]);
        send({hook: "CreateFileW", file: fileName});
        
        // condition 1: if the file name ends with ".tmp", replace the path with another file
        if (fileName.endsWith(".tmp")) {
            var dummyName = Memory.allocUtf16String("C:\\\\temp\\\\dummy.txt");
            args[0] = dummyName;
            send({hook: "CreateFileW", note: "filename replaced", newName: "C:\\\\temp\\\\dummy.txt"});
        }
        
        // condition 2: if the file name contains the string "notallowed", set the flag (for post-processing)
        this.blockFile = false;
        if (fileName.indexOf("notallowed") !== -1) {
            this.blockFile = true;
        }
        
        // record additional file access information
        this.fileName = fileName;
        this.desiredAccess = args[1].toInt32();  // desired access (GENERIC_READ, GENERIC_WRITE, etc.)
    },
    onLeave: function(retval) {
        // if the blockFile flag is set in onEnter, manipulate the return value
        if (this.blockFile) {
            // change the return value to INVALID_HANDLE_VALUE (-1, 0xFFFFFFFF)
            retval.replace(ptr("0xFFFFFFFF"));
            send({hook: "CreateFileW", note: "forced failure for blocked file", file: this.fileName});
        }
        
        // log the final return value (convert to string for output)
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

// if needed, additional file-related API hooking (ReadFile, WriteFile, etc.)
// example:
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