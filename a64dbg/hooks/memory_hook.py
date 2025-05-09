#!/usr/bin/env python3
# a64dbg/hooks/memory_hook.py - Memory operations hooks

# JavaScript Frida hook for memory operations
hook_script = """
// utility functions for memory manipulation and monitoring
(function() {
    // collect and print module information
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
    
    // collect exported functions of a specific module
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
    
    // dump memory region
    function dumpMemory(address, size) {
        try {
            var buf = Memory.readByteArray(ptr(address), size);
            // Frida's send() automatically handles ArrayBuffer
            send({hook: "MemoryDump", address: address, size: size}, buf);
            return true;
        } catch (e) {
            send({hook: "MemoryDump", error: e.message});
            return false;
        }
    }
    
    // write memory
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
    
    // print module list immediately (example)
    setTimeout(enumerateModules, 1000);
    
    // add handler for requests - provide callable functions from Python
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
    
    // notify available commands
    send({
        hook: "MemoryInfo", 
        note: "Memory operations initialized. Available commands: enumerate_modules, enumerate_exports, dump_memory, write_memory"
    });
})();
""" 