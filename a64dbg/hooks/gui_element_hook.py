#!/usr/bin/env python3
# a64dbg/hooks/gui_element_hook.py - GUI element handler detection hooks

# JavaScript Frida hook for GUI element handlers
hook_script = """
// GUI element handler detection and hooking
(function() {
    // define constants for window-related messages
    const WM_COMMAND = 0x0111;
    const WM_NOTIFY = 0x004E;
    const WM_CTLCOLORBTN = 0x0135;
    const WM_CTLCOLOREDIT = 0x0133;
    const WM_CTLCOLORSTATIC = 0x0138;
    const WM_SETTEXT = 0x000C;
    const WM_GETTEXT = 0x000D;
    const WM_LBUTTONDOWN = 0x0201;
    const WM_LBUTTONUP = 0x0202;
    
    // mapping message names
    const msgNames = {};
    msgNames[WM_COMMAND] = "WM_COMMAND";
    msgNames[WM_NOTIFY] = "WM_NOTIFY";
    msgNames[WM_CTLCOLORBTN] = "WM_CTLCOLORBTN";
    msgNames[WM_CTLCOLOREDIT] = "WM_CTLCOLOREDIT";
    msgNames[WM_CTLCOLORSTATIC] = "WM_CTLCOLORSTATIC"; 
    msgNames[WM_SETTEXT] = "WM_SETTEXT";
    msgNames[WM_GETTEXT] = "WM_GETTEXT";
    msgNames[WM_LBUTTONDOWN] = "WM_LBUTTONDOWN";
    msgNames[WM_LBUTTONUP] = "WM_LBUTTONUP";

    // list of monitored window handles
    var monitoredWindows = {};
    
    // for storing callbacks - original window procedure for each window handle
    var originalWndProcs = {};
    
    // for mapping button/control IDs
    var controlIds = {};
    var controlHandles = {};
    
    // GetWindowTextW 후킹하여 윈도우/컨트롤 텍스트 캡처
    var getWindowTextW = Module.getExportByName("user32.dll", "GetWindowTextW");
    Interceptor.attach(getWindowTextW, {
        onEnter: function(args) {
            this.hWnd = args[0];
            this.textBuffer = args[1];
            this.maxCount = args[2].toInt32();
        },
        onLeave: function(retval) {
            if (retval.toInt32() > 0) {
                var text = Memory.readUtf16String(this.textBuffer);
                // window handle and text mapping save
                if (text && text.length > 0) {
                    controlHandles[this.hWnd] = text;
                    send({
                        hook: "GuiElement", 
                        type: "WindowText", 
                        hwnd: this.hWnd.toString(),
                        text: text
                    });
                }
            }
        }
    });
    
    // GetDlgItemTextW hooking to map dialog items
    var getDlgItemTextW = Module.getExportByName("user32.dll", "GetDlgItemTextW");
    Interceptor.attach(getDlgItemTextW, {
        onEnter: function(args) {
            this.hDlg = args[0];
            this.nIDDlgItem = args[1].toInt32();
            this.textBuffer = args[2];
            this.maxCount = args[3].toInt32();
        },
        onLeave: function(retval) {
            if (retval.toInt32() > 0) {
                var text = Memory.readUtf16String(this.textBuffer);
                // save control ID and text mapping
                if (text && text.length > 0) {
                    if (!controlIds[this.hDlg]) {
                        controlIds[this.hDlg] = {};
                    }
                    controlIds[this.hDlg][this.nIDDlgItem] = text;
                    send({
                        hook: "GuiElement", 
                        type: "DialogItemText", 
                        dialogHwnd: this.hDlg.toString(),
                        itemId: this.nIDDlgItem,
                        text: text
                    });
                }
            }
        }
    });

    // SendMessageW hooking - used for most control interactions
    var sendMessageW = Module.getExportByName("user32.dll", "SendMessageW");
    Interceptor.attach(sendMessageW, {
        onEnter: function(args) {
            this.hWnd = args[0];
            this.msg = args[1].toInt32();
            this.wParam = args[2];
            this.lParam = args[3];
            
            // log only if the message is in the list to record
            if (this.msg in msgNames) {
                var msgName = msgNames[this.msg];
                
                // if there is a control text, show it together
                var controlText = controlHandles[this.hWnd] || "Unknown";
                
                // WM_COMMAND message is sent many times, so check added (button click, menu selection, etc.)
                if (this.msg === WM_COMMAND) {
                    // if HIWORD(wParam) is 0, it is a menu or accelerator, if 1, it is an accelerator
                    // if HIWORD(wParam) is other than 0, it is a control notification code
                    var controlId = this.wParam.toInt32() & 0xFFFF;  // LOWORD(wParam) = control ID
                    var notifyCode = (this.wParam.toInt32() >> 16) & 0xFFFF;  // HIWORD(wParam) = notification code
                    var controlHwnd = this.lParam;  // lParam = control handle
                    
                    // convert notification code to string (only frequently used ones)
                    var notifyCodeName = "Unknown";
                    switch(notifyCode) {
                        case 0: notifyCodeName = "BN_CLICKED"; break;  // button click
                        case 1: notifyCodeName = "BN_PAINT"; break;
                        case 2: notifyCodeName = "BN_HILITE"; break;
                        case 3: notifyCodeName = "BN_UNHILITE"; break;
                        case 4: notifyCodeName = "BN_DISABLE"; break;
                        case 5: notifyCodeName = "BN_DOUBLECLICKED"; break;
                    }
                    
                    // find the text corresponding to the control ID
                    var controlIdText = "";
                    if (controlIds[this.hWnd] && controlIds[this.hWnd][controlId]) {
                        controlIdText = controlIds[this.hWnd][controlId];
                    }
                    
                    if (notifyCode === 0) {  // BN_CLICKED - button click
                        var buttonHandlerAddr = this.returnAddress;
                        
                        send({
                            hook: "GuiElement", 
                            type: "ButtonClick",
                            controlId: controlId,
                            controlText: controlIdText,
                            controlHwnd: controlHwnd.toString(),
                            handler: buttonHandlerAddr,
                            callStack: Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).map(s => s.toString())
                        });
                        
                        // save the button handler address for later analysis
                        this.buttonHandlerAddr = buttonHandlerAddr;
                    } else {
                        send({
                            hook: "GuiElement", 
                            type: "Control",
                            msg: msgName,
                            controlId: controlId,
                            notifyCode: notifyCode,
                            notifyCodeName: notifyCodeName,
                            controlText: controlIdText
                        });
                    }
                }
                // text setting message - label, edit box, etc.
                else if (this.msg === WM_SETTEXT) {
                    var text = Memory.readUtf16String(this.lParam);
                    send({
                        hook: "GuiElement", 
                        type: "SetText",
                        hwnd: this.hWnd.toString(),
                        controlText: controlText,
                        text: text
                    });
                    
                    // update the control text so it can be referenced later
                    controlHandles[this.hWnd] = text;
                }
                // WM_LBUTTONDOWN - mouse click
                else if (this.msg === WM_LBUTTONDOWN) {
                    var x = this.wParam.toInt32() & 0xFFFF;
                    var y = (this.wParam.toInt32() >> 16) & 0xFFFF;
                    
                    send({
                        hook: "GuiElement", 
                        type: "MouseDown",
                        hwnd: this.hWnd.toString(),
                        controlText: controlText,
                        x: x,
                        y: y
                    });
                }
            }
        },
        onLeave: function(retval) {
            // processing for specific messages
            if (this.msg === WM_COMMAND && (this.wParam.toInt32() >> 16) === 0) {
                // processing after button click - log the return value
                send({
                    hook: "GuiElement", 
                    type: "ButtonClick_ret",
                    handler: this.buttonHandlerAddr ? this.buttonHandlerAddr.toString() : "Unknown",
                    retval: retval.toString()
                });
            }
        }
    });
    
    // SetWindowLongPtrW hooking - monitor window procedure changes
    var setWindowLongPtrW = null;
    try {
        setWindowLongPtrW = Module.getExportByName("user32.dll", "SetWindowLongPtrW");
    } catch (e) {
        // for 32-bit systems, use SetWindowLongW
        try {
            setWindowLongPtrW = Module.getExportByName("user32.dll", "SetWindowLongW");
        } catch (e) {
            send({hook: "GuiElement", error: "Failed to find SetWindowLongPtrW/SetWindowLongW"});
        }
    }
    
    if (setWindowLongPtrW) {
        Interceptor.attach(setWindowLongPtrW, {
            onEnter: function(args) {
                this.hWnd = args[0];
                this.nIndex = args[1].toInt32();
                this.dwNewLong = args[2];
                
                // GWL_WNDPROC (previous: -4, current: GWLP_WNDPROC = -4)
                if (this.nIndex === -4) {
                    // set the new window procedure - used for window subclassing
                    send({
                        hook: "GuiElement", 
                        type: "WindowProcChange",
                        hwnd: this.hWnd.toString(),
                        oldProc: "Unknown",
                        newProc: this.dwNewLong.toString()
                    });
                }
            },
            onLeave: function(retval) {
                // previous window procedure returned
                if (this.nIndex === -4) {
                    originalWndProcs[this.hWnd] = retval;
                    
                    send({
                        hook: "GuiElement", 
                        type: "WindowProcChange_ret",
                        hwnd: this.hWnd.toString(),
                        oldProc: retval.toString(),
                        newProc: this.dwNewLong.toString()
                    });
                }
            }
        });
    }
    
    // CreateWindowExW hooking - detect creation of new windows and controls
    var createWindowExW = Module.getExportByName("user32.dll", "CreateWindowExW");
    Interceptor.attach(createWindowExW, {
        onEnter: function(args) {
            this.className = Memory.readUtf16String(args[1]);
            this.windowName = Memory.readUtf16String(args[2]);
            this.style = args[3].toInt32();
            this.hParent = args[7];
            this.hMenu = args[8];  // used as control ID for child windows
            this.hInstance = args[9];
            
            // determine control type by class name
            var controlType = "Unknown";
            if (this.className) {
                if (this.className === "Button") controlType = "Button";
                else if (this.className === "Edit") controlType = "Edit";
                else if (this.className === "Static") controlType = "Label";
                else if (this.className === "ComboBox") controlType = "ComboBox";
                else if (this.className === "ListBox") controlType = "ListBox";
                else controlType = this.className;
            }
            
            send({
                hook: "GuiElement", 
                type: "CreateWindow",
                className: this.className,
                windowName: this.windowName,
                controlType: controlType,
                style: "0x" + this.style.toString(16),
                parentHwnd: this.hParent.toString(),
                controlId: this.hMenu.toInt32()
            });
        },
        onLeave: function(retval) {
            // created window handle
            if (!retval.isNull()) {
                var hwnd = retval;
                
                // save the window name and handle relationship
                if (this.windowName && this.windowName.length > 0) {
                    controlHandles[hwnd] = this.windowName;
                }
                
                // save control ID
                if (!this.hParent.isNull() && this.hMenu.toInt32() !== 0) {
                    if (!controlIds[this.hParent]) {
                        controlIds[this.hParent] = {};
                    }
                    controlIds[this.hParent][this.hMenu.toInt32()] = this.windowName || this.className;
                }
                
                send({
                    hook: "GuiElement", 
                    type: "CreateWindow_ret",
                    className: this.className,
                    windowName: this.windowName,
                    hwnd: hwnd.toString(),
                    parentHwnd: this.hParent.toString(),
                    controlId: this.hMenu.toInt32()
                });
            }
        }
    });
    
    // GetWindowThreadProcessId hooking - process/thread mapping
    var getWindowThreadProcessId = Module.getExportByName("user32.dll", "GetWindowThreadProcessId");
    Interceptor.attach(getWindowThreadProcessId, {
        onEnter: function(args) {
            this.hWnd = args[0];
            this.lpdwProcessId = args[1];
        },
        onLeave: function(retval) {
            var threadId = retval.toInt32();
            var processId = 0;
            
            if (!this.lpdwProcessId.isNull()) {
                processId = Memory.readUInt(this.lpdwProcessId);
            }
            
            // if there is a control text, show it together
            var controlText = controlHandles[this.hWnd] || "Unknown";
            
            send({
                hook: "GuiElement", 
                type: "WindowThreadInfo",
                hwnd: this.hWnd.toString(),
                controlText: controlText,
                threadId: threadId,
                processId: processId
            });
        }
    });
    
    // window handle to find the action function
    recv('gui_request', function(message) {
        var cmd = message.cmd;
        
        if (cmd === 'scan_all_windows') {
            // find all top-level windows and collect information
            enumerateTopWindows();
        }
        else if (cmd === 'get_window_info') {
            // get detailed information about a specific window handle
            getWindowInfo(ptr(message.hwnd));
        }
        else if (cmd === 'monitor_window') {
            // register a specific window as a monitoring target
            monitorWindow(ptr(message.hwnd));
        }
        else if (cmd === 'stop_monitor_window') {
            // stop monitoring a specific window
            stopMonitorWindow(ptr(message.hwnd));
        }
        else {
            send({hook: "GuiElement", error: "Unknown command: " + cmd});
        }
    });
    
    // function to find all top-level windows
    function enumerateTopWindows() {
        var EnumWindows = new NativeFunction(
            Module.getExportByName("user32.dll", "EnumWindows"),
            'int', ['pointer', 'pointer']
        );
        
        var GetWindowTextLengthW = new NativeFunction(
            Module.getExportByName("user32.dll", "GetWindowTextLengthW"),
            'int', ['pointer']
        );
        
        var GetWindowTextW = new NativeFunction(
            Module.getExportByName("user32.dll", "GetWindowTextW"),
            'int', ['pointer', 'pointer', 'int']
        );
        
        var IsWindowVisible = new NativeFunction(
            Module.getExportByName("user32.dll", "IsWindowVisible"),
            'int', ['pointer']
        );
        
        var GetClassName = new NativeFunction(
            Module.getExportByName("user32.dll", "GetClassNameW"),
            'int', ['pointer', 'pointer', 'int']
        );
        
        var windowCount = 0;
        
        var enumCallback = new NativeCallback(function(hwnd, lParam) {
            var visible = IsWindowVisible(hwnd);
            
            if (visible) {
                var textLength = GetWindowTextLengthW(hwnd);
                var title = "";
                
                if (textLength > 0) {
                    var titleBuffer = Memory.alloc((textLength + 1) * 2);
                    GetWindowTextW(hwnd, titleBuffer, textLength + 1);
                    title = Memory.readUtf16String(titleBuffer);
                }
                
                var classNameBuffer = Memory.alloc(256 * 2);
                GetClassName(hwnd, classNameBuffer, 256);
                var className = Memory.readUtf16String(classNameBuffer);
                
                windowCount++;
                
                send({
                    hook: "GuiElement", 
                    type: "TopLevelWindow",
                    hwnd: hwnd.toString(),
                    title: title,
                    className: className,
                    visible: true
                });
                
                // save the window handle and title mapping
                if (title && title.length > 0) {
                    controlHandles[hwnd] = title;
                }
            }
            
            return 1;  // continue enumeration
        }, 'int', ['pointer', 'pointer']);
        
        EnumWindows(enumCallback, NULL);
        
        send({
            hook: "GuiElement", 
            type: "WindowScanComplete",
            count: windowCount
        });
    }
    
    // function to get detailed information about a specific window handle
    function getWindowInfo(hwnd) {
        var GetWindowLongW = new NativeFunction(
            Module.getExportByName("user32.dll", "GetWindowLongW"),
            'long', ['pointer', 'int']
        );
        
        var EnumChildWindows = new NativeFunction(
            Module.getExportByName("user32.dll", "EnumChildWindows"),
            'int', ['pointer', 'pointer', 'pointer']
        );
        
        var GetWindowTextW = new NativeFunction(
            Module.getExportByName("user32.dll", "GetWindowTextW"),
            'int', ['pointer', 'pointer', 'int']
        );
        
        var GetClassName = new NativeFunction(
            Module.getExportByName("user32.dll", "GetClassNameW"),
            'int', ['pointer', 'pointer', 'int']
        );
        
        var GetDlgCtrlID = new NativeFunction(
            Module.getExportByName("user32.dll", "GetDlgCtrlID"),
            'int', ['pointer']
        );
        
        // get the window procedure address
        var wndProc = GetWindowLongW(hwnd, -4);  // GWLP_WNDPROC
        
        var childCount = 0;
        var children = [];
        
        // child window enumeration callback
        var enumChildCallback = new NativeCallback(function(childHwnd, lParam) {
            var titleBuffer = Memory.alloc(256 * 2);
            GetWindowTextW(childHwnd, titleBuffer, 256);
            var title = Memory.readUtf16String(titleBuffer);
            
            var classNameBuffer = Memory.alloc(256 * 2);
            GetClassName(childHwnd, classNameBuffer, 256);
            var className = Memory.readUtf16String(classNameBuffer);
            
            var controlId = GetDlgCtrlID(childHwnd);
            
            var childInfo = {
                hwnd: childHwnd.toString(),
                title: title,
                className: className,
                controlId: controlId
            };
            
            children.push(childInfo);
            childCount++;
            
            return 1;  // continue enumeration
        }, 'int', ['pointer', 'pointer']);
        
        EnumChildWindows(hwnd, enumChildCallback, NULL);
        
        // get the window text
        var titleBuffer = Memory.alloc(256 * 2);
        GetWindowTextW(hwnd, titleBuffer, 256);
        var title = Memory.readUtf16String(titleBuffer);
        
        // get the window class name
        var classNameBuffer = Memory.alloc(256 * 2);
        GetClassName(hwnd, classNameBuffer, 256);
        var className = Memory.readUtf16String(classNameBuffer);
        
        send({
            hook: "GuiElement", 
            type: "WindowInfo",
            hwnd: hwnd.toString(),
            title: title,
            className: className,
            wndProc: wndProc,
            childCount: childCount,
            children: children
        });
    }
    
    // set a specific window to be monitored
    function monitorWindow(hwnd) {
        if (monitoredWindows[hwnd]) {
            send({
                hook: "GuiElement", 
                type: "MonitorWindow",
                hwnd: hwnd.toString(),
                status: "Already monitoring"
            });
            return;
        }
        
        monitoredWindows[hwnd] = true;
        
        send({
            hook: "GuiElement", 
            type: "MonitorWindow",
            hwnd: hwnd.toString(),
            status: "Started monitoring"
        });
    }
    
    // stop monitoring a specific window
    function stopMonitorWindow(hwnd) {
        if (!monitoredWindows[hwnd]) {
            send({
                hook: "GuiElement", 
                type: "StopMonitorWindow",
                hwnd: hwnd.toString(),
                status: "Not monitoring"
            });
            return;
        }
        
        delete monitoredWindows[hwnd];
        
        send({
            hook: "GuiElement", 
            type: "StopMonitorWindow",
            hwnd: hwnd.toString(),
            status: "Stopped monitoring"
        });
    }
    
    // initialize complete notification
    send({
        hook: "GuiElement", 
        type: "Initialized",
        note: "GUI element handler detector initialized. Available commands: scan_all_windows, get_window_info, monitor_window, stop_monitor_window"
    });
})();
""" 