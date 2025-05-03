Frida-Python을 기반으로 범용적으로 사용 가능한 자동화 디버깅 프레임워크를 구성하는 방법을 조사하겠습니다. 다양한 플랫폼(EXE, DLL 등)에 적용 가능한 구조화된 코드 예제와 함께, 주요 기능(함수 후킹, 메모리 조작, 로그 수집 등)을 포함한 실제 실행 가능한 프로젝트 형태로 정리해드리겠습니다.


# Frida-Python을 활용한 Windows 디버깅 자동화 프레임워크 구축

## 개요

Frida를 Python에서 활용하여 **범용 디버깅 자동화 프레임워크**를 구축할 수 있습니다. 이 프레임워크는 Windows 실행 파일(EXE, DLL) 수준에서 **함수 후킹**, **메모리 읽기/쓰기**, **로그 수집**, **조건부 패치 적용** 등의 기능을 제공합니다. Frida를 이용하면 대상 프로세스에 코드를 주입해 함수 호출을 가로채고 조작할 수 있으며, 별도의 드라이버나 디버거 없이도 사용자 모드 함수들을 모니터링할 수 있습니다. 본 섹션에서는 Frida-Python 기반으로 이러한 프레임워크를 구현하고, 예제로 Win32 API (예: `CreateFileW`, `MessageBoxW`) 후킹과 활용 방법을 소개합니다.

## Frida-Python 기반 후킹의 개념과 기능

Frida는 동적 바이너리 삽입 도구로, Python 스크립트에서 대상 프로세스에 접속(Attach)하거나 프로세스를 생성(Spawn)하여 **실행 중인 함수 호출을 가로채고 조작**할 수 있습니다. Python 측에서는 Frida 라이브러리를 통해 대상 프로세스에 **JavaScript 후킹 스크립트**를 주입하며, 이 스크립트에서 `Interceptor.attach`를 사용해 특정 함수의 주소를 후킹합니다. 후킹된 함수가 호출되면 Frida가 정의된 콜백(`onEnter`, `onLeave`)를 실행하여 **인자 값 로깅**, **인자 수정** 및 **리턴값 변경** 등을 수행할 수 있습니다.

주요 기능은 다음과 같습니다:

* **함수 후킹 및 동적 삽입:** `Kernel32.dll`이나 `User32.dll` 등의 모듈에서 `CreateFileW`, `MessageBoxW`와 같은 타겟 함수를 찾아 후킹합니다. Frida의 `Module.getExportByName` 또는 `Module.findBaseAddress` 등을 이용해 함수 주소를 가져오고 `Interceptor.attach`로 후킹합니다.

* **호출 인자 및 리턴값 로깅:** 후킹한 함수의 `onEnter` 콜백에서 전달된 인자를 읽어들이고, `onLeave` 콜백에서 반환값을 확인하여 Python 측으로 전송(`send`)하거나 콘솔에 출력합니다. 예를 들어 `CreateFileW` 후킹 시 파일 경로 인자를 읽어서 출력하고, `MessageBoxW` 후킹 시 메시지 텍스트와 캡션을 출력합니다.

* **인자/리턴값 조작 (조건부 패치):** 특정 조건에서 함수 인자나 리턴값을 수정하여 동작을 변경할 수 있습니다. Frida에서는 `args[n]`을 변경하여 함수에 전달되는 인자를 덮어쓸 수 있고, `retval.replace(...)`를 호출하여 함수의 반환값도 바꿀 수 있습니다. 이를 활용하면 예를 들어, 열지 말아야 할 파일 이름에 대해 `CreateFileW`의 반환값을 실패로 만들거나, `MessageBoxW`의 메시지 내용을 동적으로 수정할 수 있습니다.

* **메모리 읽기/쓰기 및 모듈 정보 조회:** 후킹 스크립트 내에서 `Memory.readUtf16String`, `Memory.readByteArray`, `Memory.writeUInt`, `Memory.allocUtf16String` 등의 API를 사용하여 프로세스 메모리를 읽거나 쓸 수 있습니다. 또한 `Process.enumerateModules()`나 `Module.findBaseAddress("모듈명")`를 통해 대상 프로세스에 로드된 모듈들의 정보를 얻을 수 있습니다.

이러한 기능들을 Python 프레임워크 구조 하에서 모듈화하여 구현하면, 다양한 대상 프로그램에 대해 재사용 가능하고 확장 가능한 디버깅 도구를 얻을 수 있습니다.

## 프로젝트 구조 설계

이 프레임워크는 **모듈화된 프로젝트 구조**로 구성하여 유지보수와 확장성을 높입니다. 예시 프로젝트 구조는 다음과 같습니다:

```
frida_debug_framework/
├── main.py              # 프로그램 진입점: 인자 파싱 및 프레임워크 실행
├── controller.py        # Frida 세션 관리 및 후킹 스크립트 로드/메시지 처리
└── hooks/               # 후킹 스크립트 모듈 디렉터리
    ├── __init__.py
    ├── file_hook.py     # CreateFileW 등 파일 관련 API 후킹 스크립트 정의
    └── messagebox_hook.py  # MessageBoxW 등 UI 관련 API 후킹 스크립트 정의
```

* **`main.py`** – 프레임워크 실행을 위한 엔트리 포인트입니다. 사용자로부터 대상 프로세스 정보를 입력받아 attach 또는 spawn 모드를 결정하고, `FridaController`를 통해 후킹을 시작합니다.
* **`controller.py`** – 핵심 제어 로직을 담은 컨트롤러 모듈입니다. Frida의 Python API를 사용하여 대상 프로세스에 연결하고(`attach`) 또는 프로세스를 생성(`spawn`)한 후, `hooks` 디렉터리 내 정의된 후킹 스크립트들을 불러와 주입합니다. 또한 후킹 스크립트에서 전달(`send`)되는 메시지를 받아 로그를 출력하고, 필요한 경우 추가 동작(예: 종료 처리)을 수행합니다.
* **`hooks/`** – 각 후킹 대상별로 JavaScript 후킹 코드를 보관하는 모듈들입니다. 예시로 `file_hook.py`에는 파일 입출력 API 후킹에 대한 코드가, `messagebox_hook.py`에는 메시지 박스 API 후킹 코드가 포함됩니다. 새로운 API를 후킹하고 싶다면 이 디렉터리에 새로운 후킹 모듈을 추가하고 `controller.py`에서 불러와 사용할 수 있습니다.

이러한 구조를 통해 후킹 로직을 개별 파일로 분리함으로써 코드가 깔끔해지고, 필요에 따라 특정 후킹 기능만 수정하거나 빼고 넣기가 쉬워집니다.

## 핵심 기능 구현

이제 각 구성 요소별로 중요한 코드와 그 동작을 설명합니다. 코드 블록과 설명을 분리하여, 구현 내용을 단계별로 살펴보겠습니다.

### main.py – 실행 엔트리 포인트

`main.py`에서는 실행시 인자를 받아 대상 프로세스를 지정하고, `FridaController`를 초기화하여 후킹을 시작합니다. 프로세스를 **Attach**할지 **Spawn**할지는 인자나 상황에 따라 결정되며, 아래 코드에서는 `--spawn` 플래그로 분기하도록 구현했습니다.

````python
```python
import sys
from controller import FridaController

def print_usage():
    print(f"Usage: python {sys.argv[0]} [--spawn] <process name | PID | exe path>")
    print("  --spawn 옵션을 사용하면 새 프로세스를 실행하여 후킹합니다.")
    sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_usage()

    spawn_mode = False
    target = None

    # '--spawn' 옵션 처리
    args = sys.argv[1:]
    if args[0] == "--spawn":
        if len(args) < 2:
            print_usage()
        spawn_mode = True
        target = args[1]
    else:
        target = args[0]

    # FridaController 초기화 및 실행
    controller = FridaController(target, spawn=spawn_mode)
    controller.run()
```python
````

**설명:** 명령줄 인자를 파싱하여 `--spawn`이 지정된 경우와 아닌 경우를 구분합니다. `--spawn`가 있으면 `target`을 실행 파일 경로로 간주하여 새로운 프로세스를 \*\*생성(spawn)\*\*하고, 없으면 `target`을 프로세스 이름 또는 PID로 간주하여 \*\*기존 프로세스에 연결(attach)\*\*합니다. 그런 다음 `FridaController`를 생성하고 `run()` 메소드를 호출하여 후킹을 진행합니다. 사용법 메시지에서 프로세스 이름, PID, 또는 exe 경로를 인자로 받을 수 있음을 명시하여, 유연하게 대상 지정이 가능합니다.

### controller.py – Frida 세션 제어 및 후킹 관리

`controller.py`에는 Frida 세션을 관리하고, 여러 후킹 스크립트를 로드하며, 후킹된 함수들의 이벤트 메시지를 처리하는 `FridaController` 클래스가 정의됩니다.

````python
```python
import frida

class FridaController:
    def __init__(self, target, spawn=False):
        self.target = target
        self.spawn = spawn
        self.session = None
        self.script = None

    def _on_message(self, message, data):
        """후킹 스크립트에서 send된 메시지 처리 콜백"""
        if message['type'] == 'send':
            payload = message.get('payload', {})
            # 후킹 스크립트에서 보낸 정보 출력
            if isinstance(payload, dict):
                # hook 종류와 세부내용 구성
                hook_name = payload.get('hook')
                detail = ", ".join(f"{k}={v}" for k,v in payload.items() if k != 'hook')
                print(f"[HookMessage] {hook_name}: {detail}")
            else:
                print(f"[HookMessage] {payload}")
        elif message['type'] == 'error':
            # 스크립트 내부 에러 출력
            print(f"[Script Error] {message['description']}\n{message.get('stack')}")

    def _build_script(self):
        """여러 후킹 스크립트를 결합하여 하나의 스크립트 문자열 생성"""
        from hooks import file_hook, messagebox_hook
        script_parts = []
        # (1) 기본 모듈 정보 조회 코드 추가
        script_parts.append("""
            // 기본 모듈 정보 출력 (kernel32.dll, user32.dll 베이스 주소)
            var k32 = Module.findBaseAddress("kernel32.dll");
            var u32 = Module.findBaseAddress("user32.dll");
            send({hook: "Info", message: "kernel32.dll base: " + k32 + ", user32.dll base: " + u32});
        """)
        # (2) 개별 후킹 스크립트 추가
        script_parts.append(file_hook.hook_script)
        script_parts.append(messagebox_hook.hook_script)
        # 모든 스크립트 조각 결합
        return "\n".join(script_parts)

    def run(self):
        # 로컬 장치의 Frida 인스턴스 사용
        device = frida.get_local_device()
        pid = None
        if self.spawn:
            # 새 프로세스 실행 (spawn)
            pid = device.spawn([self.target])
            self.session = device.attach(pid)
        else:
            # 기존 프로세스에 attach (이름 또는 PID)
            try:
                pid = int(self.target)
                self.session = device.attach(pid)
            except ValueError:
                self.session = device.attach(self.target)

        # 후킹 스크립트 로드
        script_code = self._build_script()
        self.script = self.session.create_script(script_code)
        self.script.on('message', self._on_message)  # 메시지 콜백 등록
        self.script.load()  # 스크립트 주입

        if self.spawn and pid:
            device.resume(pid)  # spawn한 프로세스 실행 재개

        print("** Frida attach 성공! (종료하려면 Ctrl+C) **")
        try:
            # 프로세스가 종료될 때까지 대기
            import time
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("** Detaching Frida 세션 **")
            self.session.detach()
```python
````

**설명:**

* **Frida 세션 연결:** `run()` 메소드는 Frida 로컬 장치를 획득한 후(`frida.get_local_device()`), `self.spawn` 플래그에 따라 지정된 프로세스를 spawn하거나 attach 합니다. `device.attach(...)`를 통해 **로컬 프로세스에 Attach**하며, 이 때 Windows 환경에서는 별도의 Frida 서버 없이도 동작합니다. (Android와 달리 Windows에서는 Frida 서버를 미리 실행할 필요 없이, Python 스크립트가 바로 대상 프로세스에 주입됩니다.)
* **후킹 스크립트 결합:** `_build_script()` 메소드는 `hooks` 폴더 내 각 모듈의 `hook_script` 문자열을 불러와 하나의 큰 JavaScript 코드로 합칩니다. 예시로 **(1)** 부분에서는 `Module.findBaseAddress`를 사용해 `kernel32.dll`과 `user32.dll`의 메모리 시작 주소를 조회하고 이를 `send`로 출력하도록 스크립트를 삽입했습니다. **(2)** 부분에서는 개별 후킹 코드(`file_hook.hook_script`, `messagebox_hook.hook_script`)를 순서대로 추가합니다. 이렇게 문자열들을 `"\n".join()`으로 합쳐 최종 스크립트를 생성합니다.
* **스크립트 주입 및 메시지 처리:** `session.create_script(...)`로 Frida 스크립트를 생성하고, `script.on('message', self._on_message)`를 통해 **JavaScript 측에서 보낸 메시지**를 `_on_message` 콜백으로 처리하도록 설정합니다. 이후 `script.load()`를 호출하면 해당 스크립트가 대상 프로세스에 주입되어 즉시 실행됩니다.
* **메시지 콜백 `_on_message`:** 후킹된 함수에서 `send({...})`가 호출되면 Python 측에서는 `_on_message`가 실행됩니다. `message['type']`이 `'send'`일 경우 후킹 코드에서 전달한 `payload`를 읽어 로그를 출력합니다. 위 구현에서는 `payload`를 딕셔너리로 보낸 경우 `hook` 키(어떤 후킹에서 온 메시지인지)와 기타 정보를 함께 출력하도록 했습니다. 예를 들어 `payload = {hook: "CreateFileW", file: "C:\\test.txt"}`으로 보내면 `[HookMessage] CreateFileW: file=C:\test.txt` 형태로 로그가 찍힙니다. 만약 `message['type']`가 `'error'`이면 주입한 스크립트에서 예외가 발생한 상황이므로 에러 설명과 스택 트레이스를 출력합니다.
* **프로세스 실행 재개 및 종료 처리:** `spawn`된 프로세스는 기본적으로 일시정지 상태로 생성되므로, 스크립트를 주입한 후 `device.resume(pid)`를 호출하여 **대상 프로세스의 실행을 재개**합니다. 마지막으로, 메인 스레드를 `while True`로 지속 대기시켜 후킹이 유지되도록 하고, Ctrl+C (KeyboardInterrupt)를 처리하여 세션을 detach(분리)하며 깨끗이 종료합니다.

### hooks/file\_hook.py – 파일 API 후킹 예제 (CreateFileW)

이 모듈에는 `CreateFileW` 함수를 후킹하여 파일 접근을 모니터링하고 조작하는 코드가 들어있습니다. Windows API `CreateFileW`는 파일을 열 때 사용되는 함수로, 첫 번째 인자로 파일 경로(LPCWSTR)가 전달됩니다. 이 예제에서는 해당 경로를 로그로 남기고, 특정 조건에 따라 인자를 변경하거나 반환값을 조작합니다.

````python
```python
# hooks/file_hook.py
hook_script = """
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
    },
    onLeave: function(retval) {
        // onEnter에서 blockFile 플래그가 설정된 경우, 반환값 조작
        if (this.blockFile) {
            // INVALID_HANDLE_VALUE (-1, 0xFFFFFFFF)로 반환값 변경
            retval.replace(ptr("0xFFFFFFFF"));
            send({hook: "CreateFileW", note: "forced failure, returning INVALID_HANDLE"});
        }
        // 최종 반환값 로깅 (문자열로 변환하여 출력)
        send({hook: "CreateFileW_ret", retval: retval.toString()});
    }
});
"""
```python
````

**설명:**
이 JavaScript 코드는 `kernel32.dll`에서 `CreateFileW` 함수의 주소를 찾아(`Module.getExportByName`) 후킹합니다.

* **인자 로깅:** `onEnter`에서 `args[0]` (파일 경로 포인터)을 `Memory.readUtf16String`으로 읽어 실제 파일 경로 문자열을 얻습니다. 이를 `send`를 통해 Python 측에 전송하면, 앞서 설정된 `_on_message` 콜백에서 `[HookMessage] CreateFileW: file=<경로>` 형식으로 출력됩니다. (유니코드 문자열을 읽기 위해 `readUtf16String`을 사용했습니다.)

* **조건부 인자 수정:** 예제로 두 가지 조건을 구현했습니다.

  1. 파일 이름이 `.tmp`로 끝나는 경우, 임시 파일에 접근하는 것으로 간주하여 `dummy.txt`라는 다른 경로로 **대체**합니다. `Memory.allocUtf16String` 함수를 사용하여 대상 프로세스 메모리에 `"C:\\temp\\dummy.txt"` 유니코드 문자열을 할당하고, `args[0]`를 이 새 문자열의 포인터로 교체합니다. 이렇게 하면 원래 함수가 열려고 했던 파일 대신 `dummy.txt` 파일을 열도록 조작할 수 있습니다. 이 사실을 로깅하기 위해 추가로 `send`로 `"filename replaced"` 노트를 보냅니다. (경로 문자열에서 백슬래시 `\`를 이스케이프 하기 위해 `\\\\`처럼 표기한 것에 유의하십시오.)
  2. 파일 이름에 `"notallowed"`라는 문자열이 포함된 경우(`indexOf("notallowed") != -1`), 해당 파일은 열리지 말아야 한다고 가정하고, `this.blockFile` 플래그를 `true`로 설정합니다. 이 플래그는 `onLeave`에서 반환값을 조작하기 위한 용도로 사용됩니다. (`this` 객체는 각각의 함수 호출마다 독립적으로 유지되며, `onEnter`에서 설정한 값을 동일한 호출의 `onLeave`에서 사용할 수 있습니다.)

* **조건부 반환값 수정:** `onLeave`에서, `this.blockFile`이 `true`로 설정된 경우에 한하여 `retval.replace(ptr("0xFFFFFFFF"))`를 호출합니다. 이는 **함수의 반환값을 0xFFFFFFFF로 교체**하는 동작으로, Windows API에서 `CreateFileW`의 반환형(HANDLE)에 대해 `INVALID_HANDLE_VALUE` (보통 `-1`로 정의됨)에 해당합니다. 즉, 특정 파일에 대해서는 강제로 파일 열기에 실패한 것처럼 만드는 패치를 적용한 것입니다. 이때 실제로 `SetLastError` 등까지 조정하지는 않았지만, 개념적으로는 해당 API 호출의 효과를 무력화시킨 것입니다. 반환값을 변경한 후에도 `send`로 이를 로깅하여, Python 측 로그에서 "forced failure"가 확인되도록 했습니다.

* **메모리 접근:** 이 후킹 코드에서도 Frida의 `Memory` API 사용 예시를 볼 수 있습니다. `Memory.readUtf16String`으로 대상 프로세스의 메모리(파일 경로 문자열)를 읽었고, `Memory.allocUtf16String`으로 새로운 문자열을 대상에 써넣었습니다. 또한 `retval.replace`를 통해 내부적으로 레지스터/메모리에 있는 반환값을 조작했습니다. 필요에 따라 `Memory.writeByteArray`나 `Memory.writeU8` 등을 사용하면 임의의 메모리 패치도 가능하며, `Module.findBaseAddress("모듈명")`으로 얻은 주소를 기반으로 특정 바이트를 NOP (`0x90`)로 바꾸는 등 코드 패치도 응용할 수 있습니다.

### hooks/messagebox\_hook.py – 메시지박스 API 후킹 예제 (MessageBoxW)

이 모듈에는 GUI 상의 메시지 박스 생성 함수인 `MessageBoxW`를 후킹하여, 호출 시 전달되는 텍스트를 가로채고 수정하는 예제가 담겨 있습니다. `MessageBoxW` 함수의 시그니처는 `int MessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)`로, 두 번째 인자가 표시할 본문 텍스트, 세 번째 인자가 창 제목(캡션)입니다.

````python
```python
# hooks/messagebox_hook.py
hook_script = """
var messageBoxW = Module.getExportByName("user32.dll", "MessageBoxW");
Interceptor.attach(messageBoxW, {
    onEnter: function(args) {
        var textPtr = args[1];    // 메시지 본문 문자열 포인터
        var captionPtr = args[2]; // 메시지 캡션 문자열 포인터
        var text = Memory.readUtf16String(textPtr);
        var caption = Memory.readUtf16String(captionPtr);
        send({hook: "MessageBoxW", text: text, caption: caption});
        // 조건: 본문에 "secret" 단어가 포함되면 내용을 변경
        if (text.indexOf("secret") !== -1) {
            var newText = "Hooked by Frida!";
            var newTextPtr = Memory.allocUtf16String(newText);
            args[1] = newTextPtr;  // 본문 문자열 포인터를 새로 할당한 문자열로 교체
            send({hook: "MessageBoxW", note: "message text modified"});
        }
    },
    onLeave: function(retval) {
        // MessageBoxW 반환값 (사용자가 누른 버튼: IDOK=1 등)
        send({hook: "MessageBoxW_ret", retval: retval.toInt32()});
    }
});
"""
```python
````

**설명:**
이 JavaScript 후킹 코드는 `user32.dll`의 `MessageBoxW`를 대상으로 `Interceptor.attach`를 수행합니다.

* **텍스트 인자 로깅:** `onEnter`에서 `args[1]` (메시지 본문)과 `args[2]` (메시지 창 제목)에 들어있는 메모리를 `Memory.readUtf16String`으로 읽어 각각 `text`와 `caption` 문자열을 얻습니다. 이들을 `send`로 Python에 보내면, 로그에는 `[HookMessage] MessageBoxW: text=<내용>, caption=<제목>` 형식으로 출력됩니다. 예를 들어 프로그램이 `MessageBoxW(NULL, L"Hello", L"Title", ...)`을 호출했다면, 해당 문자열이 캡처되어 로그로 확인할 수 있습니다.

* **조건부 메시지 수정:** 본문 텍스트 `text`에 `"secret"`이라는 단어가 포함되어 있는지를 검사하여, 포함된 경우에 한해 다른 내용으로 **변경**합니다. 새로운 문자열 `"Hooked by Frida!"`을 `Memory.allocUtf16String`으로 할당한 뒤, `args[1]` 포인터를 가리키던 주소를 이 새 문자열의 주소로 바꾸었습니다. 이로써 원래 프로그램이 띄우는 메시지 창의 내용이 우리가 지정한 텍스트로 대체됩니다. (예: 원래 "This is a secret message"였다면 "Hooked by Frida!"로 바뀌어 표시됨) 이 변경 사실도 `send`로 노트가 전달되어 로그로 남습니다.
  ※ 이처럼 **함수 인자를 실시간으로 수정**하면 원본 프로그램의 동작을 일부 제어할 수 있는데, Frida는 이러한 인자 수정과 반환값 교체 등을 즉시 적용하여 프로그램 실행 흐름에 반영합니다.

* **메시지 박스 반환값:** `MessageBoxW` 함수는 사용자가 누른 버튼에 따라 정수 값을 반환합니다 (예: IDOK=1, IDCANCEL=2 등). `onLeave`에서 이 `retval`을 받아 `toInt32()`로 변환후 로그를 남겼습니다. (이번 예제에서는 반환값을 별도로 조작하지는 않았지만, 필요하다면 위 `CreateFileW` 예제와 같이 `retval.replace(...)`를 통해 원하는 값으로 바꿀 수도 있습니다.)

* **메모리 관리:** 새로 할당한 문자열 `newTextPtr`는 Frida가 내부적으로 대상 프로세스 메모리에 확보한 영역을 가리킵니다. Frida가 스크립트 detach 시 정리를 해주므로 일반적으로 메모리 누수 걱정은 크지 않지만, 빈번한 할당을 피하기 위해 조건에 따라 필요한 경우에만 호출하도록 하였습니다. 또한 문자열 포인터를 바꾸는 작업은 **원본 문자열이 읽기 전용 메모리에 있을 경우에도 안전**하게 새로운 쓰기 가능한 메모리를 사용하므로, 직접 메모리 내용을 덮어쓰는 방식보다 안정적입니다.

## 실행 방법 및 활용 시나리오

이 섹션에서는 작성한 프레임워크를 실제로 실행하고 테스트하는 방법을 설명합니다. 프레임워크를 사용하기 전, **Frida Python 라이브러리 설치**가 필요합니다 (`pip install frida-tools` 등으로 설치 가능합니다). 또한 대상 프로세스에 접근 권한이 필요하므로, 관리자 권한으로 실행하는 것이 좋습니다.

1. **프로세스 지정 및 실행:** 후킹을 원하는 대상 프로세스를 정합니다. 이미 실행 중인 프로세스에 후킹하려면 그 **프로세스 이름**이나 **PID**를 전달하고, 새로 프로세스를 실행해서 후킹하려면 `--spawn` 옵션과 실행 파일 경로를 함께 전달합니다.
   예시 - 메모장(Notepad)을 대상으로:

   * **실행 중 프로세스에 Attach:**  메모장을 먼저 실행한 뒤, 프레임워크를 실행합니다.

     ```bash
     python main.py notepad.exe
     ```

     위 명령은 현재 실행 중인 `notepad.exe` 프로세스에 attach하여 후킹을 시작합니다.
   * **새 프로세스 Spawn:**  프레임워크가 메모장을 새로 실행하며 후킹을 시작하도록 합니다.

     ```bash
     python main.py --spawn "C:\\Windows\\System32\\notepad.exe"
     ```

     이 경우 `main.py`가 Notepad 프로세스를 직접 실행하고(`spawn`), 곧바로 해당 프로세스에 attach하여 후킹을 진행합니다.

2. **후킹 동작 확인:** 프레임워크를 실행하면 터미널에 `** Frida attach 성공! ...` 이 출력되며 대상 프로세스가 정상적으로 동작하게 됩니다. 이제 대상 프로그램에서 후킹된 함수들이 호출되는 시나리오를 만들어 로그를 관찰합니다. 예를 들어:

   * **CreateFileW 후킹 테스트:** 메모장에서 *파일 열기* 또는 *다른 이름으로 저장* 등을 수행하면 내부적으로 `CreateFileW`가 호출됩니다. 사용자가 "example.txt" 파일을 열었다고 가정하면, 터미널에 `[HookMessage] CreateFileW: file=C:\path\to\example.txt` 형태로 해당 파일 경로가 로그됩니다. 만약 "notallowed.txt"라는 이름의 파일을 열었다면, `onEnter`에서 설정된 조건에 따라 `[HookMessage] CreateFileW: ...` 로그 후에 `forced failure` 로그가 이어지고, 실제로 메모장에서는 파일 열기에 실패했음을 볼 수 있습니다 (의도적으로 실패를 유발한 경우).
   * **MessageBoxW 후킹 테스트:** 메모장에서 새 파일에 내용을 적은 후 저장하지 않고 창을 닫으면 "저장하시겠습니까?"라는 메시지 박스가 뜹니다. 이때 프레임워크 측에서는 `[HookMessage] MessageBoxW: text="저장하시겠습니까...?", caption="메모장"` 형태로 원본 메시지와 캡션을 캡처하여 출력합니다. 만약 해당 문자열에 우리가 지정한 `"secret"` 키워드가 있었다면, 실제 메시지 창의 내용이 "Hooked by Frida!"로 바뀌어 표시되었을 것입니다. 사용자가 메시지 박스에서 누른 버튼에 따라 `[HookMessage] MessageBoxW_ret: retval=...` 로그가 남고, 예를 들어 \*\*예(Y)\*\*를 눌렀다면 retval=6 등이 출력됩니다.

3. **프레임워크 종료:** 테스트가 완료되면 터미널에서 Ctrl+C를 눌러 프레임워크를 중지시킬 수 있습니다. 그러면 내부적으로 Frida 세션을 정리(detach)하고 대상 프로세스와의 연결을 해제합니다. Attach 모드로 실행한 경우 대상 프로세스는 계속 실행되지만, Spawn 모드로 실행한 경우 프레임워크가 종료해도 대상 프로세스는 남아 있으므로 필요시 수동으로 종료하면 됩니다.

以上のフレームワークは 다양한 Windows 프로그램에 적용可能하며, 후킹 대상 함수와 스크립트를 추가하여 쉽게 기능을 확장할 수 있습니다. Frida를 이용하면 설명한 것처럼 **실행 중인 함수의 인자나 동작을 가로채어 관찰하고 수정**할 수 있으므로, 리버스 엔지니어링이나 보안 모니터링, 혹은 특정 소프트웨어의 동적 패치 등에 강력한 도구로 활용될 수 있습니다. 이번 예제 코드를 기반으로, 필요에 따라 다른 Win32 API (예: `ReadFile`, `WriteFile`, `CryptEncrypt` 등)나 사용자 정의 함수 주소를 후킹하여 자신만의 디버깅 자동화 도구를 구축해 보시기 바랍니다.
