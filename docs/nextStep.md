좋습니다. C/C++ 윈도우 실행 파일을 대상으로 하고, 다양한 목적의 자동화 디버깅을 위해 LyScript와 Python을 사용하는 64비트 기반의 실제 동작 가능한 프로젝트 구성을 리서치하겠습니다. 구조화된 모듈 설계와 함께, 실행에 필요한 파일 구분 및 실습 가능한 코드 샘플도 제공하겠습니다. 결과가 준비되면 알려드리겠습니다.


# x64dbg와 LyScript를 이용한 64비트 EXE 디버깅 자동화 프레임워크 구축

## 개요 (Overview)

Windows 64비트 실행 파일을 **x64dbg 디버거**로 자동 디버깅하기 위해 Python 기반의 프레임워크를 설계합니다. 이를 위해 x64dbg의 Python 플러그인인 **LyScript** 및 그 확장 모듈 **LyScriptTools**를 활용하여, 디버거와 통신하며 다양한 디버깅 작업(레지스터 조회/설정, 메모리 읽기/쓰기, 브레이크포인트 관리 등)을 자동화합니다. 본 답변에서는 실제로 동작 가능한 프로젝트 구조를 제시하고, 각 구성 요소별로 코드 예제와 설명을 제공합니다. 또한 동적 분석, 패치 자동화, 로그 수집 등 다양한 용도에 유연하게 활용할 수 있는 템플릿 형태로 구현하며, **LyScript 공식 문서**의 정보를 인용하여 신뢰성을 높였습니다.

> **전제 조건:** 이 프레임워크를 사용하려면 x64dbg에 LyScript 플러그인이 설치되고, Python 환경에 LyScript 패키지가 설치되어 있어야 합니다. LyScript 플러그인은 x64dbg의 `plugins/` 디렉토리에 넣어 활성화하며, Python 측에서는 pip로 `LyScript64` (64비트용)와 `LyScriptTools64` 패키지를 설치합니다. Python 3.6 이상이 필요합니다.
> **사용 환경:** x64dbg를 관리자 권한으로 실행하고 디버깅할 대상 프로그램을 로드한 후, Python으로 작성된 본 프레임워크 코드를 실행해야 합니다. LyScript는 **독립 실행이 불가능**하므로 반드시 디버거가 활성화된 상태에서 동작해야 함을 유의하십시오.

## 프로젝트 구조 및 설계 (Project Structure & Design)

본 프로젝트는 **모듈화된 구조**로 구성되어 각 기능을 역할별로 분리합니다. 주요 파일과 역할은 다음과 같습니다:

* **`x64dbg_controller.py`** – x64dbg와 통신하는 핵심 **컨트롤러 클래스**를 정의합니다. 이 클래스는 LyScript의 API를 활용하여 디버거 연결, 레지스터/메모리 조작, 실행 제어, 브레이크포인트 관리 등의 기능을 제공합니다. (예: `connect()`, `get_register()`, `read_memory()`, `set_breakpoint()` 메서드 등)
* **`main.py`** – 상기 컨트롤러 클래스를 사용하여 **실제 디버깅 자동화 동작을 수행**하는 진입점 스크립트입니다. 여기서 컨트롤러를 초기화하고 일련의 디버깅 동작(예시용)을 수행합니다. (예: 프로세스 연결 → 레지스터 값 조회/수정 → 메모리 읽기/패치 → 브레이크포인트 설정 → 한 단계 실행 등)
* *(선택 사항)* **`tasks/` 디렉토리 또는 추가 모듈** – 필요에 따라 동적 분석 작업, 패치 스크립트, 로그 수집 기능 등을 구현하는 모듈을 추가로 작성할 수 있습니다. 이들은 `x64dbg_controller.py`의 기능을 호출하여 특정 목적의 자동화를 수행하도록 구성합니다.

이러한 구조를 통해 **기능 확장과 유지보수**를 용이하게 했습니다. 컨트롤러 클래스를 중심으로 공통 기능을 제공하고, 개별 분석/패치/로그 수집 등의 로직은 별도 모듈 또는 클래스에서 구현함으로써, 서로 다른 자동화 작업에도 재사용할 수 있는 **유연한 프레임워크 템플릿**을 갖추게 됩니다. 다음 섹션에서는 각 구성 요소의 구현과 사용 예제를 자세히 설명합니다.

## x64dbg 연결 및 통신 설정 (Connecting to x64dbg)

LyScript를 통해 x64dbg에 연결하려면 우선 **디버그 세션**을 초기화해야 합니다. `LyScript64` 모듈에서 제공하는 `MyDebug` 클래스를 사용하여 디버거와의 통신 객체(`dbg`)를 생성합니다. 그 다음 `dbg.connect()` 메서드로 x64dbg와의 **소켓 연결**을 맺습니다. 연결이 성공하면 `True`를 반환하며, 이 연결은 Python 스크립트가 종료되거나 `dbg.close()`로 수동 종료하기 전까지 \*\*지속(persistent)\*\*됩니다.

아래 코드는 `x64dbg_controller.py`에서 `connect()` 메서드를 구현한 예시입니다:

```python
# x64dbg_controller.py (일부 발췌)
      # 64비트 대상이므로 LyScript64 사용

class X64dbgController:
    def __init__(self):
        self.dbg = MyDebug()            # 디버거 제어 인스턴스 생성
    def connect(self):
        """x64dbg 디버거와의 통신을 시작한다."""
        result = self.dbg.connect()     # x64dbg에 연결 시도
        return result  # 연결 성공 시 True
    def disconnect(self):
        """디버거와의 연결을 종료한다."""
        self.dbg.close()               # 소켓 세션 종료
    def is_connected(self):
        """현재 디버거와 연결되어 있는지 확인한다."""
        return self.dbg.is_connect()   # 연결 유지 상태 확인Q
```

위 코드에서 `MyDebug()` 객체 생성 후 `connect()`를 호출하는 구조를 볼 수 있습니다. 실제 사용 시에는 `connect()` 반환값을 체크하여 연결 성공 여부를 판단합니다. LyScript 공식 문서에 따르면 `dbg.connect()` 호출로 **디버거 세션이 시작**되며, `dbg.is_connect()`를 통해 소켓 연결이 유효한지 검사할 수 있습니다. 마지막으로 `dbg.close()`를 통해 연결을 해제할 수 있습니다.

예를 들어, 아래와 같이 `X64dbgController`를 사용하면 x64dbg에 연결할 수 있습니다:

```python
# main.py (발췌)
dbg = X64dbgController()
if dbg.connect():
    print("x64dbg 연결 성공!")
else:
    print("x64dbg 연결 실패 : 디버거가 실행 중인지 확인하세요.")
```

연결이 성공하면 `"x64dbg 연결 성공!"`과 함께 백그라운드에서 x64dbg와 Python 사이에 통신 채널이 마련됩니다. 이제 이 `dbg` 객체를 통해 다양한 디버깅 명령을 수행할 준비가 되었습니다.

## 레지스터 조회 및 수정 (Register Access and Modification)

프로그램의 **CPU 레지스터 값**을 읽고 쓰는 것은 디버깅의 기본 작업입니다. LyScript를 사용하면 `get_register(name)`과 `set_register(name, value)` 함수를 통해 손쉽게 레지스터를 다룰 수 있습니다.

컨트롤러 클래스 `X64dbgController`에는 레지스터 관련 편의 메서드들이 구현되어 있습니다. 예를 들어 `get_register("RAX")`는 RAX 레지스터의 값을 반환하고, `set_register("RAX", 0x1234)`는 RAX에 `0x1234` 값을 써줍니다. 아래는 해당 부분의 구현과 사용 예시입니다:

```python
# x64dbg_controller.py (레지스터 관련 메서드)
class X64dbgController:
    # ... (생략) ...
    def get_register(self, reg_name):
        """지정한 레지스터의 값을 읽어온다."""
        return self.dbg.get_register(reg_name)
    def set_register(self, reg_name, value):
        """지정한 레지스터에 새 값을 쓴다."""
        return self.dbg.set_register(reg_name, value)
    def get_flag(self, flag_name):
        """플래그 레지스터(bit)의 현재 상태를 반환한다."""
        return self.dbg.get_flag_register(flag_name)
    def set_flag(self, flag_name, state: bool):
        """플래그 레지스터(bit)를 설정한다 (True=1, False=0)."""
        return self.dbg.set_flag_register(flag_name, state)
```

LyScript 플러그인의 동작은 내부적으로 x64dbg의 명령을 호출하는 방식으로 구현되어 있습니다. 예를 들어 `dbg.get_register("rax")`를 호출하면 현재 디버거에서 **RAX 레지스터 값을 정수로 반환**하며, `dbg.set_register("rax", 100)`을 호출하면 RAX 레지스터에 100 (`0x64`)을 쓰고 True/False 결과를 돌려줍니다.

사용 예시:

```python
# main.py (레지스터 사용 예)
rax_value = dbg.get_register("RAX")  # RAX 값 읽기
print(f"현재 RAX = 0x{rax_value:X}")
dbg.set_register("RAX", 0x1234)     # RAX에 0x1234 써주기
new_rax = dbg.get_register("RAX")
print(f"변경 후 RAX = 0x{new_rax:X}")
```

실행하면 이전/이후의 RAX 값이 각각 출력됩니다. (예: `현재 RAX = 0x0`, `변경 후 RAX = 0x1234`). 이처럼 필요한 모든 레지스터 이름(`RIP`, `RSP`, `RBP`, `RBX` 등)을 문자열로 지정하여 값을 조회하거나 변경할 수 있습니다. 플래그 레지스터(ZF, CF 등) 또한 `get_flag_register`, `set_flag_register`로 조작 가능합니다. 이를 활용하면 **레지스터 기반 조건 우회**(예: `IsDebuggerPresent` 플래그를 강제로 0으로 설정하여 안티-디버깅 우회) 같은 작업도 스크립트로 쉽게 자동화할 수 있습니다.

## 메모리 읽기/쓰기 및 패치 (Memory Read/Write & Patching)

디버깅 중에 프로세스 메모리를 조사하거나 수정하는 일도 빈번합니다. LyScriptTools 확장 모듈은 이러한 목적을 위해 다양한 **메모리 읽기/쓰기 함수**를 제공합니다. 바이트, 워드(2바이트), 더블워드(4바이트), 쿼드워드(8바이트) 단위로 읽고 쓸 수 있는 함수를 갖추고 있으며, LyScript에서는 이를 편리하게 호출할 수 있도록 `read_memory_byte`, `read_memory_word`, `read_memory_dword`, `read_memory_qword` 등의 메서드를 제공합니다. 대응하는 쓰기 메서드로 `write_memory_byte` 등도 존재합니다.

컨트롤러 클래스에서는 인자로 크기를 받아 적절한 함수를 호출하는 `read_memory(address, size)`와 `write_memory(address, value, size)` 메서드를 정의해 두었습니다:

```python
# x64dbg_controller.py (메모리 관련 메서드)
class X64dbgController:
    # ... (생략) ...
    def read_memory(self, address, size=1):
        """주어진 메모리 주소에서 size만큼 데이터를 읽어온다 (바이트 배열 또는 정수 반환)."""
        if size == 1:
            return self.dbg.read_memory_byte(address)
        elif size == 2:
            return self.dbg.read_memory_word(address)
        elif size == 4:
            return self.dbg.read_memory_dword(address)
        elif size == 8:
            return self.dbg.read_memory_qword(address)
        else:
            # size 바이트만큼 바이트 배열로 반환
            data = []
            for offset in range(size):
                byte = self.dbg.read_memory_byte(address + offset)
                data.append(byte)
            return data
    def write_memory(self, address, value, size=1):
        """주어진 메모리 주소에 value 값을 기록한다 (size에 맞게)."""
        if size == 1:
            return self.dbg.write_memory_byte(address, value)
        elif size == 2:
            return self.dbg.write_memory_word(address, value)
        elif size == 4:
            return self.dbg.write_memory_dword(address, value)
        elif size == 8:
            return self.dbg.write_memory_qword(address, value)
        else:
            # 바이트 리스트나 bytes를 받았다고 가정하고 한 바이트씩 기록
            data = value if isinstance(value, (bytes, bytearray, list)) else [value]
            result = True
            for offset, b in enumerate(data):
                ok = self.dbg.write_memory_byte(address + offset, b)
                if not ok:
                    result = False
            return result
```

위 메서드를 활용하면 임의의 메모리 주소에서 데이터를 읽거나 쓸 수 있습니다. 예를 들어, 다음 코드는 현재 명령어 주소(`RIP`)부터 10바이트를 읽어와 출력하는 예제입니다:

```python
# main.py (메모리 읽기 예)
rip = dbg.get_register("RIP")
print(f"현재 RIP = 0x{rip:X}")
bytes_at_rip = dbg.read_memory(rip, size=10)  # RIP부터 10바이트 읽기
print("명령어 메모리 (10바이트):", [f"0x{b:X}" for b in bytes_at_rip])
```

실행 결과 (예시):

```
현재 RIP = 0x7FF6A1C01000  
명령어 메모리 (10바이트): ['0x55', '0x8B', '0xEC', '0x48', '0x83', '0xEC', '0x20', '0x89', '0x4D', '0xF8']
```

이는 지정한 주소의 메모리 바이트값들을 16진수로 나열한 것입니다. LyScript의 `read_memory_byte`를 반복 호출하여 이처럼 연속된 메모리 내용을 확인할 수 있습니다.

**메모리 쓰기/패치**도 유사합니다. 예를 들어 어떤 함수의 첫 바이트(프로로그 영역)를 NOP (`0x90`)로 패치하려면 해당 주소에 `0x90` 값을 써주면 됩니다. 아래는 한 바이트 패치 예시입니다:

```python
# main.py (메모리 쓰기/패치 예)
target_addr = rip  # (예시로 현재 RIP 위치를 패치)
original_byte = dbg.read_memory(target_addr, 1)
dbg.write_memory(target_addr, 0x90, 1)  # 지정 주소의 1바이트를 0x90으로 변경
patched_byte = dbg.read_memory(target_addr, 1)
print(f"패치 전 바이트: 0x{original_byte:X} -> 패치 후 바이트: 0x{patched_byte:X}")
```

실행하면 패치 전후의 바이트 값을 보여줍니다 (예: `패치 전 바이트: 0x55 -> 패치 후 바이트: 0x90`). 이렇게 스크립트를 이용해 다수의 메모리 위치를 일괄 수정함으로써 **자동 패치** 작업을 수행할 수 있습니다. 가령, 바이너리의 조건 분기 명령을 조작하여 강제로 분기시키거나 (`JE`를 `JMP`로 바꾸는 등), 연속적인 NOP 패치를 통해 함수를 무력화하는 등의 기능도 구현 가능합니다.

## 브레이크포인트 설정과 실행 제어 (Breakpoints & Execution Control)

**브레이크포인트**는 특정 주소에서 프로그램 실행을 일시 중단시켜 상태를 검사할 수 있게 하는 중요 기능입니다. LyScript를 통해 소프트웨어 브레이크포인트를 쉽게 관리할 수 있습니다. `dbg.set_breakpoint(address)`를 호출하면 해당 주소에 소프트웨어 브레이크포인트를 설정하고 성공 여부를 반환합니다. 설정 후 `dbg.get_all_breakpoint()`를 사용하면 현재 설정된 모든 브레이크포인트의 목록을 얻을 수도 있습니다. 또한 `dbg.check_breakpoint(address)`를 통해 특정 주소의 브레이크포인트가 **현재 히트(hit)되었는지** 여부를 확인할 수 있습니다. 필요 시 `dbg.delete_breakpoint(address)`로 해제도 가능합니다.

컨트롤러 클래스의 구현과 사용 예시는 다음과 같습니다:

```python
# x64dbg_controller.py (브레이크포인트 관련 메서드)
class X64dbgController:
    # ... (생략) ...
    def set_breakpoint(self, address):
        """지정한 주소에 소프트웨어 브레이크포인트를 건다."""
        return self.dbg.set_breakpoint(address)
    def delete_breakpoint(self, address):
        """지정한 주소의 브레이크포인트를 삭제한다."""
        return self.dbg.delete_breakpoint(address)
    def check_breakpoint(self, address):
        """브레이크포인트가 한번이라도 실행되어 걸렸는지 여부를 확인한다."""
        return self.dbg.check_breakpoint(address)
    def list_breakpoints(self):
        """현재 설정된 모든 브레이크포인트 정보를 가져온다."""
        return self.dbg.get_all_breakpoint()
```

사용 예시로, 현재 명령어 포인터(RIP) 위치에 브레이크포인트를 설정하고 확인하는 동작을 보겠습니다:

```python
# main.py (브레이크포인트 설정 예)
current_ip = dbg.get_register("RIP")
dbg.set_breakpoint(current_ip)         # 현재 명령 주소에 BP 설정
bp_list = dbg.list_breakpoints()
print("설정된 브레이크포인트들:", bp_list)
hit = dbg.check_breakpoint(current_ip)
print(f"현재 주소 브레이크포인트 히트 여부: {hit}")
```

위 코드에서 `"설정된 브레이크포인트들"`로 출력된 리스트에는 각 브레이크포인트의 주소(`addr`), 유효 여부(`enabled`), 히트 횟수(`hitcount`), 타입(`type`) 등이 딕셔너리 형태로 나옵니다. `check_breakpoint(current_ip)`의 반환값은 해당 BP가 실제 실행 중에 걸렸는지 나타냅니다. (참고: `check_breakpoint`는 “브레이크포인트 명중 여부”를 알려주는 함수로, **프로그램을 실행(run)시킨 뒤** 호출해야 의미 있는 결과를 얻습니다.)

브레이크포인트를 건 후에는 **실행 제어**가 필요합니다. LyScript는 `dbg.set_debug("명령")` 함수로 디버거의 실행을 제어합니다. 전달할 수 있는 문자열 명령에는 `"Run"`(계속 실행), `"Pause"`(일시정지), `"StepIn"`(한 명령어 내부로 한 단계 들어가기), `"StepOver"`(한 명령어 실행 - 함수 호출은 통과), `"StepOut"`(현재 함수 빠져나가기), `"Stop"`(디버그 중지) 등이 있습니다. `dbg.set_debug(...)` 호출은 해당 동작을 수행하도록 디버거를 제어하고, 명령 수신이 성공하면 True를 반환합니다. 추가로 `dbg.is_running()`과 `dbg.is_run_locked()` 메서드를 통해 **프로세스 실행 여부**나 **일시정지 상태 여부**를 확인할 수 있습니다.

컨트롤러 클래스에서는 흔히 쓰는 몇 가지 실행 명령을 메서드로 제공하고 있습니다:

```python
# x64dbg_controller.py (실행 제어 메서드)
class X64dbgController:
    # ... (생략) ...
    def run(self):
        """디버깅 대상 프로그램을 계속 실행한다."""
        return self.dbg.set_debug("Run")
    def pause(self):
        """프로그램 실행을 일시 정지한다."""
        return self.dbg.set_debug("Pause")
    def step_in(self):
        """한 명령어 단위로 Step-In 실행한다."""
        return self.dbg.set_debug("StepIn")
    def step_over(self):
        """한 명령어 단위로 Step-Over 실행한다."""
        return self.dbg.set_debug("StepOver")
    def stop(self):
        """디버깅을 중지하고 대상 프로세스를 종료한다."""
        return self.dbg.set_debug("Stop")
    def is_running(self):
        """현재 피디버깅 프로세스가 실행 중인지 확인한다."""
        return self.dbg.is_running()
    def is_paused(self):
        """현재 디버거가 실행 일시정지 상태인지 확인한다."""
        return self.dbg.is_run_locked()
```

이러한 메서드를 활용하여 **동적 실행 흐름 제어**가 가능합니다. 예를 들어, 한 명령씩 단계 실행하며 레지스터를 확인하는 간단한 동적 분석 루틴은 다음과 같습니다:

```python
# main.py (한 명령어씩 실행하며 레지스터 로깅 예)
step_count = 3
for i in range(step_count):
    dbg.step_in()  # 한 명령어 실행
    rip = dbg.get_register("RIP")
    rax = dbg.get_register("RAX")
    print(f"[스텝 {i+1}] RIP=0x{rip:X}, RAX=0x{rax:X}")
```

위 예시는 현재 위치에서 **3개의 명령**을 차례로 수행(`StepIn`)하면서, 각 단계마다 RIP와 RAX 값을 출력합니다. 이렇게 하면 프로그램이 실행 흐름을 따라 어떻게 진행되는지 추적하고 중요한 레지스터의 변화를 **로그 수집**할 수 있습니다. 만약 특정 조건에서만 로그를 남기고 싶다면 if문으로 값 체크 후 출력하거나, 파일에 기록하는 등의 확장이 가능합니다.

추가로, `Run` 명령을 사용하면 브레이크포인트까지 **프로그램을 계속 실행**시킬 수 있습니다. 예컨대 특정 함수 진입에 BP를 설정해두고 `dbg.run()`을 호출하면, 그 지점까지 자동으로 진행한 뒤 일시정지됩니다. 그런 다음 `is_paused()` 등을 확인하여 멈췄는지 검사하고, 멈췄다면 원하는 데이터를 수집하는 식으로 활용할 수 있습니다. 필요시 `dbg.set_debug("Wait")` 명령을 사용하여 **다음 이벤트까지 대기**하는 방식도 고려할 수 있습니다.

요약하면, LyScript를 통해 사용자는 **브레이크포인트 트리거 → 실행 제어(재개/단계실행) → 상태 점검**의 사이클을 모두 Python 코드로 구현할 수 있습니다. 이를 이용해 반복적이고 복잡한 동적 분석 작업을 자동화하거나, 수동으로 하기 번거로운 패치/검사 작업을 스크립팅할 수 있습니다.

## 실행 예제 및 활용 방법 (Example Usage & How to Run)

이 절에서는 위에서 구축한 구성요소를 종합하여, 실제로 **디버깅 자동화 시나리오**를 수행하는 예제를 보여드립니다. 예제 시나리오는 다음과 같습니다:

1. **x64dbg 연결** – 디버거와 통신 세션을 시작합니다.
2. **레지스터 조회/설정** – 일부 중요한 레지스터 값을 출력하고 변경해 봅니다.
3. **메모리 확인 및 패치** – 현재 명령어 위치의 메모리를 읽어 출력하고, 바이트를 수정하는 패치를 적용합니다.
4. **브레이크포인트 설정** – 패치한 지점에 브레이크포인트를 설정합니다.
5. **한 단계 실행 및 로그 출력** – 한 명령어를 실행하여 패치 적용 결과를 확인하고, 그때의 레지스터 상태를 로그로 남깁니다.
6. **정리** – 브레이크포인트를 해제하고 디버거 세션을 종료합니다.

아래는 `main.py`의 전체 예제 코드입니다:

```python
# main.py (전체 예제 코드)
from x64dbg_controller import X64dbgController

def main():
    dbg = X64dbgController()
    if not dbg.connect():
        print("x64dbg 연결에 실패했습니다. 디버거 실행 여부를 확인하세요.")
        return
    print("x64dbg 연결 완료.")

    # 1. 현재 RIP 값 출력
    rip = dbg.get_register("RIP")
    print(f"[1] 현재 RIP = 0x{rip:X}")

    # 2. 현재 RAX 값 출력 및 변경
    rax_val = dbg.get_register("RAX")
    print(f"[2] 현재 RAX = 0x{rax_val:X}")
    dbg.set_register("RAX", 0xBEEF)  # RAX 레지스터에 0xBEEF로 설정
    print(f"    RAX 값을 0xBEEF로 변경 완료. (확인: 0x{dbg.get_register('RAX'):X})")

    # 3. RIP 위치의 메모리 바이트들 출력 및 첫 바이트 패치
    bytes_before = dbg.read_memory(rip, size=5)
    print(f"[3] RIP 주위 메모리(5바이트) = {[hex(b) for b in bytes_before]}")
    dbg.write_memory(rip, 0x90, size=1)  # RIP 위치 한 바이트 -> 0x90 (NOP)
    patched_byte = dbg.read_memory(rip, size=1)
    print(f"    패치 수행: 0x{bytes_before[0]:X} -> 0x{patched_byte:X} (주소 0x{rip:X})")

    # 4. 해당 RIP에 브레이크포인트 설정
    dbg.set_breakpoint(rip)
    print(f"[4] 0x{rip:X} 주소에 브레이크포인트 설정 완료.")

    # 5. 한 명령어 Step-In 실행 후 레지스터 상황 출력
    dbg.step_in()  # 한 스텝 실행 (패치한 NOP 명령어 수행됨)
    new_rip = dbg.get_register("RIP")
    rax_new = dbg.get_register("RAX")
    print(f"[5] 한 스텝 실행 후 RIP = 0x{new_rip:X}, RAX = 0x{rax_new:X}")

    # (선택) 브레이크포인트 히트 여부 확인 및 리스트 출력
    hit = dbg.check_breakpoint(rip)
    bp_list = dbg.list_breakpoints()
    print(f"    브레이크포인트 히트여부: {hit}, 전체 BP 목록: {bp_list}")

    # 6. 브레이크포인트 해제 및 디버거 세션 종료
    dbg.delete_breakpoint(rip)
    dbg.disconnect()
    print("[6] 브레이크포인트 해제 및 디버거 연결 종료.")

if __name__ == "__main__":
    main()
```

**실행 방법:**

1. x64dbg를 열어 디버깅할 **64비트 실행 파일**을 로드합니다 (예: F9로 일시정지된 초기 상태). LyScript 플러그인이 정상 로드되어 있어야 합니다.
2. Python에서 `main.py`를 실행합니다. (`python main.py`)
3. 스크립트의 출력 결과를 확인합니다.

예상 출력의 일부 예시는 다음과 같습니다 (실제 값은 디버깅 대상에 따라 달라질 수 있습니다):

```
x64dbg 연결 완료.
[1] 현재 RIP = 0x7FF6A1C01000
[2] 현재 RAX = 0x0
    RAX 값을 0xBEEF로 변경 완료. (확인: 0xBEEF)
[3] RIP 주위 메모리(5바이트) = ['0x55', '0x8b', '0xec', '0x48', '0x83']
    패치 수행: 0x55 -> 0x90 (주소 0x7FF6A1C01000)
[4] 0x7FF6A1C01000 주소에 브레이크포인트 설정 완료.
[5] 한 스텝 실행 후 RIP = 0x7FF6A1C01001, RAX = 0xBEEF
    브레이크포인트 히트여부: True, 전체 BP 목록: [{'addr': 140700675026945, 'enabled': 1, 'hitcount': 1, 'type': 1}]
[6] 브레이크포인트 해제 및 디버거 연결 종료.
```

각 단계별로 의도한 작업이 수행된 것을 알 수 있습니다:

* **\[1]** 현재 RIP 주소를 출력했습니다.
* **\[2]** RAX 값을 확인하고 0xBEEF로 변경한 뒤, 실제 변경되었는지 다시 읽어 확인했습니다.
* **\[3]** RIP 부근 5바이트 기계어 코드를 읽어오고, 그 중 첫 바이트(0x55)를 0x90(NOP)으로 써서 패치했습니다. 다시 읽어 확인하니 0x90으로 변경된 것이 보입니다.
* **\[4]** 해당 RIP 주소에 브레이크포인트를 설정했습니다.
* **\[5]** `step_in()`으로 한 명령어를 실행하여, RIP이 한 바이트 증가(0x...1000 -> 0x...1001)한 것을 확인했습니다. 또한 RAX 레지스터는 이전 단계에서 우리가 0xBEEF로 바꾼 값이 유지되고 있음을 볼 수 있습니다. (이 예에서는 실행한 한 명령이 NOP이므로 레지스터 변화가 없었습니다.) 추가로, 브레이크포인트 히트 여부 `True`와 브레이크포인트 리스트를 출력하여, 우리가 건 BP가 한 번 실행에 걸렸음(`hitcount": 1`)을 알 수 있습니다.
* **\[6]** 마지막으로 설정했던 브레이크포인트를 지우고 x64dbg와의 연결을 종료하여 정리를 마쳤습니다.

## 마무리 및 확장 (Conclusion & Further Expansion)

이렇게 구성한 **자동화 디버깅 프레임워크**를 이용하면, 사용자가 원한다면 위 예제의 흐름을 응용하여 다양한 작업을 자동화할 수 있습니다. 예를 들면:

* **동적 분석 스크립트**: 특정 루틴을 탐지하기 위해 여러 브레이크포인트를 설정하고, 루프를 돌며 `step_in()`으로 한 단계씩 실행하면서 레지스터나 메모리 변화를 **로그로 기록**할 수 있습니다. 이는 수동으로 F8/F7을 누르며 기록하는 수고를 덜어 줍니다.
* **패치 자동화 도구**: 반복적으로 적용해야 하는 바이너리 패치를 Python 코드로 만들어 놓고, 한 번의 실행으로 여러 값을 변경한 뒤 실행을 계속하거나 덤프를 얻을 수 있습니다. (예: 안티 디버깅 코드 무력화, 조건문 강제 분기 등)
* **메모리 스캔/덤프**: LyScriptTools에는 메모리 검색이나 모듈 정보 획득 등의 API도 있으므로, 이를 활용해 특정 패턴을 메모리에서 찾아내거나 필요한 데이터를 추출하는 스크립트를 작성할 수 있습니다.
* **이벤트 기반 확장**: 본 예제에서는 간단히 일정 실행 후 수동으로 상태를 확인했지만, LyScript 플러그인은 향상된 사용을 위해 별도의 **이벤트 훅**(예: 예외 발생 시 Python으로 알림) 기능을 제공하기도 합니다. 필요하다면 LyShark 개발자의 고급 예제를 참고하여 socket 통신을 응용한 이벤트 처리 기능도 붙일 수 있습니다.

마지막으로, 신뢰성 있는 구현을 위해 **LyScript 공식 자료**를 참조하는 것이 중요합니다. LyScript 개발자의 블로그에서는 본 답변에서 다룬 API 사용법 (레지스터/메모리/브레이크포인트/실행제어)에 대해 상세히 설명하고 있으며, 예제 코드도 제공하고 있습니다. 이러한 문서를 참고하면 추가 기능 구현이나 문제 해결에 큰 도움이 됩니다.

以上의 구조화된 코드와 설명을 통해 사용자는 **직접 실행 가능한 예제 프로젝트**를 얻을 수 있으며, 이를 바탕으로 자신만의 자동 디버깅 도구를 구축하고 확장해나갈 수 있을 것입니다.

**참고 자료:** x64dbg 및 LyScript/LyScriptTools 공식 문서 및 개발자 블로그 등.
