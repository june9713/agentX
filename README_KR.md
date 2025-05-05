# Xursor - Cursor AI 커스텀 에이전트

Xursor는 Cursor AI의 에이전트 모드를 모방한 커스텀 구현체입니다. 코드베이스 검색, 파일 편집, 명령어 실행 등 다양한 도구를 활용해 코딩 작업을 도와줍니다.

## 설치 요구사항

```bash
pip install requests
```

## 사용 방법

### API 키 설정

Xursor는 대규모 언어 모델(LLM) API를 사용합니다. 환경 변수를 통해 API 키를 설정할 수 있습니다:

```bash
# Windows
set XURSOR_API_KEY=your_api_key_here

# Linux/Mac
export XURSOR_API_KEY=your_api_key_here
```

### 명령행 인터페이스

Xursor는 다음과 같은 명령행 인터페이스를 제공합니다:

```bash
python xursor.py [--api-key API_KEY] [--model MODEL] [--workspace WORKSPACE_PATH] [query]
```

#### 매개변수 설명:

- `--api-key`: LLM 서비스용 API 키 (환경 변수 XURSOR_API_KEY로도 설정 가능)
- `--model`: 사용할 모델 (기본값: claude-3-opus-20240229)
- `--workspace`: 작업 디렉토리 경로 (기본값: 현재 디렉토리)
- `query`: 처리할 쿼리 (생략 시 대화형 모드로 실행)

### 사용 예시

#### 단일 쿼리 처리:

```bash
python xursor.py "main.py 파일의 버그를 찾아줘"
```

#### 대화형 모드 사용:

```bash
python xursor.py
```

대화형 모드에서는 프롬프트가 표시되며, 여러 쿼리를 연속적으로 입력할 수 있습니다. `exit` 또는 `quit`를 입력하거나 Ctrl+C를 누르면 종료됩니다.

## 지원되는 도구

Xursor는 다음과 같은 도구들을 지원합니다:

1. **codebase_search**: 코드베이스에서 연관성 높은 코드 스니펫을 검색합니다
2. **read_file**: 파일 내용을 읽습니다
3. **run_terminal_cmd**: 터미널 명령어를 실행합니다
4. **list_dir**: 디렉토리 내용을 나열합니다
5. **grep_search**: 파일 내용에서 패턴을 검색합니다
6. **edit_file**: 파일을 편집하거나 새 파일을 생성합니다
7. **file_search**: 파일명으로 파일을 검색합니다

## 지원되는 모델

- claude-3-opus-20240229
- claude-3-sonnet-20240229
- gpt-4-turbo

## 예시 작업 흐름

1. Xursor 에이전트 실행
2. 작업에 대한 설명 입력
3. Xursor가 필요한 도구를 사용하여 작업 수행
4. 결과 확인 및 필요시 추가 지시 제공

## 주의사항

- 실제 API 연동은 구현되어 있지 않습니다. 실제 사용을 위해서는 선택한 LLM 제공업체의 API에 맞게 `_call_llm_api` 메서드를 구현해야 합니다.
- 코드베이스 검색 기능은 단순 키워드 매칭으로 구현되어 있으며, 실제 의미론적 검색(semantic search)을 구현하려면 임베딩 기반 검색 기능을 추가해야 합니다. 