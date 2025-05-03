#!/usr/bin/env python3
# a64dbg/hooks/gui_element_hook.py - GUI element handler detection hooks

# JavaScript Frida hook for GUI element handlers
hook_script = """
// GUI 요소 핸들러 탐지 및 후킹
(function() {
    // 윈도우 관련 상수 정의
    const WM_COMMAND = 0x0111;
    const WM_NOTIFY = 0x004E;
    const WM_CTLCOLORBTN = 0x0135;
    const WM_CTLCOLOREDIT = 0x0133;
    const WM_CTLCOLORSTATIC = 0x0138;
    const WM_SETTEXT = 0x000C;
    const WM_GETTEXT = 0x000D;
    const WM_LBUTTONDOWN = 0x0201;
    const WM_LBUTTONUP = 0x0202;
    
    // 메시지 이름 매핑
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

    // 모니터링 중인 윈도우 핸들 목록
    var monitoredWindows = {};
    
    // 콜백 저장용 - 각 윈도우 핸들에 대한 기존 윈도우 프로시저
    var originalWndProcs = {};
    
    // 버튼/컨트롤 ID를 매핑하기 위한 정보
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
                // 윈도우 핸들과 텍스트 매핑 저장
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
    
    // GetDlgItemTextW 후킹하여 다이얼로그 아이템 매핑
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
                // 컨트롤 ID와 텍스트 매핑 저장
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

    // SendMessageW 후킹 - 대부분의 컨트롤 상호작용에 사용됨
    var sendMessageW = Module.getExportByName("user32.dll", "SendMessageW");
    Interceptor.attach(sendMessageW, {
        onEnter: function(args) {
            this.hWnd = args[0];
            this.msg = args[1].toInt32();
            this.wParam = args[2];
            this.lParam = args[3];
            
            // 기록할 메시지 목록에 있는 경우에만 로깅
            if (this.msg in msgNames) {
                var msgName = msgNames[this.msg];
                
                // 컨트롤 텍스트가 있으면 함께 표시
                var controlText = controlHandles[this.hWnd] || "Unknown";
                
                // WM_COMMAND 메시지는 많이 보내지므로 체크 추가 (버튼 클릭, 메뉴 선택 등)
                if (this.msg === WM_COMMAND) {
                    // HIWORD(wParam)이 0이면 메뉴 또는 액셀러레이터, 1이면 액셀러레이터
                    // HIWORD(wParam)이 그 외이면 컨트롤 알림 코드
                    var controlId = this.wParam.toInt32() & 0xFFFF;  // LOWORD(wParam) = 컨트롤 ID
                    var notifyCode = (this.wParam.toInt32() >> 16) & 0xFFFF;  // HIWORD(wParam) = 알림 코드
                    var controlHwnd = this.lParam;  // lParam = 컨트롤 핸들
                    
                    // 알림 코드를 문자열로 변환 (자주 쓰이는 것만)
                    var notifyCodeName = "Unknown";
                    switch(notifyCode) {
                        case 0: notifyCodeName = "BN_CLICKED"; break;  // 버튼 클릭
                        case 1: notifyCodeName = "BN_PAINT"; break;
                        case 2: notifyCodeName = "BN_HILITE"; break;
                        case 3: notifyCodeName = "BN_UNHILITE"; break;
                        case 4: notifyCodeName = "BN_DISABLE"; break;
                        case 5: notifyCodeName = "BN_DOUBLECLICKED"; break;
                    }
                    
                    // 컨트롤 ID에 해당하는 텍스트를 찾아봄
                    var controlIdText = "";
                    if (controlIds[this.hWnd] && controlIds[this.hWnd][controlId]) {
                        controlIdText = controlIds[this.hWnd][controlId];
                    }
                    
                    if (notifyCode === 0) {  // BN_CLICKED - 버튼 클릭
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
                        
                        // 나중에 분석을 위해 버튼 핸들러 주소 저장
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
                // 텍스트 설정 메시지 - 라벨, 에디트 박스 등
                else if (this.msg === WM_SETTEXT) {
                    var text = Memory.readUtf16String(this.lParam);
                    send({
                        hook: "GuiElement", 
                        type: "SetText",
                        hwnd: this.hWnd.toString(),
                        controlText: controlText,
                        text: text
                    });
                    
                    // 나중에 참조할 수 있도록 컨트롤 텍스트 업데이트
                    controlHandles[this.hWnd] = text;
                }
                // WM_LBUTTONDOWN - 마우스 클릭
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
            // 특정 메시지에 대한 처리
            if (this.msg === WM_COMMAND && (this.wParam.toInt32() >> 16) === 0) {
                // 버튼 클릭 후 처리 - 반환값도 로깅
                send({
                    hook: "GuiElement", 
                    type: "ButtonClick_ret",
                    handler: this.buttonHandlerAddr ? this.buttonHandlerAddr.toString() : "Unknown",
                    retval: retval.toString()
                });
            }
        }
    });
    
    // SetWindowLongPtrW 후킹 - 윈도우 프로시저 변경을 모니터링
    var setWindowLongPtrW = null;
    try {
        setWindowLongPtrW = Module.getExportByName("user32.dll", "SetWindowLongPtrW");
    } catch (e) {
        // 32비트 시스템에서는 SetWindowLongW 사용
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
                
                // GWL_WNDPROC (이전: -4, 현재: GWLP_WNDPROC = -4)
                if (this.nIndex === -4) {
                    // 새로운 윈도우 프로시저 설정 - 윈도우 서브클래싱을 위해 사용됨
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
                // 이전 윈도우 프로시저가 반환됨
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
    
    // CreateWindowExW 후킹 - 새 윈도우와 컨트롤 생성 탐지
    var createWindowExW = Module.getExportByName("user32.dll", "CreateWindowExW");
    Interceptor.attach(createWindowExW, {
        onEnter: function(args) {
            this.className = Memory.readUtf16String(args[1]);
            this.windowName = Memory.readUtf16String(args[2]);
            this.style = args[3].toInt32();
            this.hParent = args[7];
            this.hMenu = args[8];  // 차일드 윈도우에서는 컨트롤 ID로 사용됨
            this.hInstance = args[9];
            
            // 클래스명으로 컨트롤 종류 판단
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
            // 생성된 윈도우 핸들
            if (!retval.isNull()) {
                var hwnd = retval;
                
                // 윈도우 이름과 핸들 관계 저장
                if (this.windowName && this.windowName.length > 0) {
                    controlHandles[hwnd] = this.windowName;
                }
                
                // 컨트롤 ID 저장
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
    
    // GetWindowThreadProcessId 후킹 - 프로세스/스레드 매핑
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
            
            // 컨트롤 텍스트가 있으면 함께 표시
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
    
    // 윈도우 핸들을 통해 동작 함수를 찾아내는 명령어 핸들러
    recv('gui_request', function(message) {
        var cmd = message.cmd;
        
        if (cmd === 'scan_all_windows') {
            // 모든 최상위 윈도우를 찾아서 정보 수집
            enumerateTopWindows();
        }
        else if (cmd === 'get_window_info') {
            // 특정 윈도우 핸들의 자세한 정보 조회
            getWindowInfo(ptr(message.hwnd));
        }
        else if (cmd === 'monitor_window') {
            // 특정 윈도우를 모니터링 대상으로 등록
            monitorWindow(ptr(message.hwnd));
        }
        else if (cmd === 'stop_monitor_window') {
            // 특정 윈도우 모니터링 중지
            stopMonitorWindow(ptr(message.hwnd));
        }
        else {
            send({hook: "GuiElement", error: "Unknown command: " + cmd});
        }
    });
    
    // 모든 최상위 윈도우를 찾는 함수
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
                
                // 윈도우 핸들과 제목 매핑 저장
                if (title && title.length > 0) {
                    controlHandles[hwnd] = title;
                }
            }
            
            return 1;  // 계속 열거
        }, 'int', ['pointer', 'pointer']);
        
        EnumWindows(enumCallback, NULL);
        
        send({
            hook: "GuiElement", 
            type: "WindowScanComplete",
            count: windowCount
        });
    }
    
    // 특정 윈도우 핸들의 상세 정보를 조회하는 함수
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
        
        // 윈도우 프로시저 주소 가져오기
        var wndProc = GetWindowLongW(hwnd, -4);  // GWLP_WNDPROC
        
        var childCount = 0;
        var children = [];
        
        // 차일드 윈도우 열거 콜백
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
            
            return 1;  // 계속 열거
        }, 'int', ['pointer', 'pointer']);
        
        EnumChildWindows(hwnd, enumChildCallback, NULL);
        
        // 윈도우의 텍스트 가져오기
        var titleBuffer = Memory.alloc(256 * 2);
        GetWindowTextW(hwnd, titleBuffer, 256);
        var title = Memory.readUtf16String(titleBuffer);
        
        // 윈도우의 클래스 이름 가져오기
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
    
    // 특정 윈도우를 모니터링하도록 설정
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
    
    // 특정 윈도우 모니터링 중지
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
    
    // 초기화 완료 알림
    send({
        hook: "GuiElement", 
        type: "Initialized",
        note: "GUI element handler detector initialized. Available commands: scan_all_windows, get_window_info, monitor_window, stop_monitor_window"
    });
})();
""" 