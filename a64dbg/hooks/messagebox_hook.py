#!/usr/bin/env python3
# a64dbg/hooks/messagebox_hook.py - UI API hooks

# JavaScript Frida hook for MessageBoxW function
hook_script = """
// MessageBoxW hook implementation
var messageBoxW = Module.getExportByName("user32.dll", "MessageBoxW");
Interceptor.attach(messageBoxW, {
    onEnter: function(args) {
        var hwnd = args[0];           // parent window handle
        var textPtr = args[1];        // message body string pointer
        var captionPtr = args[2];     // message caption string pointer
        var uType = args[3].toInt32(); // message box type (MB_OK, MB_YESNO, etc.)
        
        var text = Memory.readUtf16String(textPtr);
        var caption = Memory.readUtf16String(captionPtr);
        
        // log message box information
        send({
            hook: "MessageBoxW", 
            text: text, 
            caption: caption, 
            type: uType
        });
        
        // convert message box type to string
        var typeStr = "";
        if (uType & 0x0) typeStr = "MB_OK";
        else if (uType & 0x1) typeStr = "MB_OKCANCEL";
        else if (uType & 0x2) typeStr = "MB_ABORTRETRYIGNORE";
        else if (uType & 0x3) typeStr = "MB_YESNOCANCEL";
        else if (uType & 0x4) typeStr = "MB_YESNO";
        
        send({hook: "MessageBoxW", note: "message box type", type: typeStr});
        
        // condition: if the body contains the word "secret", change the content
        if (text.indexOf("secret") !== -1) {
            var newText = "Hooked by Frida!";
            var newTextPtr = Memory.allocUtf16String(newText);
            args[1] = newTextPtr;  // replace the body string pointer with the new string
            send({hook: "MessageBoxW", note: "message text modified", original: text, modified: newText});
        }
        
        // condition: if the title contains "warning" or "경고", change the icon (example)
        if (caption.indexOf("warning") !== -1 || caption.indexOf("경고") !== -1) {
            // change the icon to MB_ICONINFORMATION (0x40)
            args[3] = ptr(uType | 0x40);
            send({hook: "MessageBoxW", note: "icon changed to information"});
        }
    },
    onLeave: function(retval) {
        // MessageBoxW return value (the button pressed by the user)
        var result = retval.toInt32();
        
        // convert the return value to string
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
        
        // example: change all "no" responses to "yes" responses
        // if (result === 7) { // IDNO
        //     retval.replace(ptr("6")); // change to IDYES
        //     send({hook: "MessageBoxW", note: "response changed from NO to YES"});
        // }
    }
});
""" 