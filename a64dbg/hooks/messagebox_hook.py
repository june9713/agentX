#!/usr/bin/env python3
# a64dbg/hooks/messagebox_hook.py - UI API hooks

# JavaScript Frida hook for MessageBoxW function
hook_script = """
// MessageBoxW hook implementation
var messageBoxW = Module.getExportByName("user32.dll", "MessageBoxW");
Interceptor.attach(messageBoxW, {
    onEnter: function(args) {
        var hwnd = args[0];           // 부모 창 핸들
        var textPtr = args[1];        // 메시지 본문 문자열 포인터
        var captionPtr = args[2];     // 메시지 캡션 문자열 포인터
        var uType = args[3].toInt32(); // 메시지 박스 타입 (MB_OK, MB_YESNO 등)
        
        var text = Memory.readUtf16String(textPtr);
        var caption = Memory.readUtf16String(captionPtr);
        
        // 메시지 박스 정보 로깅
        send({
            hook: "MessageBoxW", 
            text: text, 
            caption: caption, 
            type: uType
        });
        
        // 메시지 박스 타입 문자열 변환
        var typeStr = "";
        if (uType & 0x0) typeStr = "MB_OK";
        else if (uType & 0x1) typeStr = "MB_OKCANCEL";
        else if (uType & 0x2) typeStr = "MB_ABORTRETRYIGNORE";
        else if (uType & 0x3) typeStr = "MB_YESNOCANCEL";
        else if (uType & 0x4) typeStr = "MB_YESNO";
        
        send({hook: "MessageBoxW", note: "message box type", type: typeStr});
        
        // 조건: 본문에 "secret" 단어가 포함되면 내용을 변경
        if (text.indexOf("secret") !== -1) {
            var newText = "Hooked by Frida!";
            var newTextPtr = Memory.allocUtf16String(newText);
            args[1] = newTextPtr;  // 본문 문자열 포인터를 새로 할당한 문자열로 교체
            send({hook: "MessageBoxW", note: "message text modified", original: text, modified: newText});
        }
        
        // 조건: "warning" 또는 "경고" 제목이면 아이콘을 변경 (예시)
        if (caption.indexOf("warning") !== -1 || caption.indexOf("경고") !== -1) {
            // MB_ICONINFORMATION (0x40)으로 아이콘 변경
            args[3] = ptr(uType | 0x40);
            send({hook: "MessageBoxW", note: "icon changed to information"});
        }
    },
    onLeave: function(retval) {
        // MessageBoxW 반환값 (사용자가 누른 버튼)
        var result = retval.toInt32();
        
        // 버튼 반환값 문자열로 변환
        var resultStr = "";
        switch(result) {
            case 1: resultStr = "IDOK"; break;
            case 2: resultStr = "IDCANCEL"; break;
            case 3: resultStr = "IDABORT"; break;
            case 4: resultStr = "IDRETRY"; break;
            case 5: resultStr = "IDIGNORE"; break;
            case 6: resultStr = "IDYES"; break;
            case 7: resultStr = "IDNO"; break;
            default: resultStr = "UNKNOWN"; break;
        }
        
        send({
            hook: "MessageBoxW_ret", 
            result: result,
            resultStr: resultStr
        });
        
        // 예시: 모든 "아니오" 응답을 "예" 응답으로 변경
        // if (result === 7) { // IDNO
        //     retval.replace(ptr("6")); // IDYES로 변경
        //     send({hook: "MessageBoxW", note: "response changed from NO to YES"});
        // }
    }
});
""" 