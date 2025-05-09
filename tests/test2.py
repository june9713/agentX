
translation_dict = {
    "chatgpt.py 파일 로드 완료": "chatgpt.py file loading completed",
    "이번 명령의 목적:": "Purpose of this command:",
    "현재의 디렉토리 패스는": "Current directory path is",
    "이번 명령의 결과:": "Result of this command:",
    "이번 명령의 요약 명령:": "Summary command for this command:",
    "요약은 다음의 내용을 포함합니다....": "The summary includes the following content....",
    "작업이 완료되었습니다. 완료 플래그 파일이 생성되었습니다.": "Task has been completed. Completion flag file has been created.",
    "완료 정보:": "Completion information:",
    "최대 반복 횟수에 도달했습니다. 작업이 완료되지 않았을 수 있습니다.": "Maximum number of iterations reached. The task may not have been completed.",
    "작업 상태: 완료됨": "Task status: Completed",
    "작업 상태: 미완료": "Task status: Incomplete",
    "작업 결과 요약": "Task result summary",
    "완료 상태: 성공": "Completion status: Success",
    "완료 태그:": "Completion tag:",
    "완료 상태: 미완료 또는 실패": "Completion status: Incomplete or failed",
    "최종 디렉토리 상태:": "Final directory status:",
    "명령 실행 중 오류 발생:": "Error occurred during command execution:",
    "오류 발생:": "Error occurred:",
    "input query?": "Input query?",
    "CMD 작업을 위한 쿼리를 입력하세요:": "Enter a query for CMD task:",
    "--- 작업 결과 ---": "--- Task result ---",
    "작업 모드를 선택하세요:": "Select operation mode:",
    "코드 분석 및 수정 (기존 기능)": "Code analysis and modification (existing feature)",
    "CMD 명령어 실행 세션": "CMD command execution session",
    "오늘의 날씨에 대해서 알려주세요:": "Please tell me about today's weather:",
    "페이지 구조": "Page structure",
    "웹페이지 구조": "Web page structure",
    "대상 요소": "Target elements",
    "타겟 요소": "Target elements",
    "선택자": "Selectors",
    "크롤링 방법": "Crawling method",
    "자바스크립트 처리": "JavaScript handling",
    "동적 콘텐츠": "Dynamic content",
    "목적:": "Purpose:",
    "시작": "Start",
    "주의: 항상 작업을 위한 디렉토리로 먼저 이동을 한 뒤에 본격적인 작업을 시작합니다.": "Note: Always move to the working directory first before starting the actual work.",
    "이전 작업이 성공 한 것으로 간주합니다.": "We consider the previous task to be successful.",
    "다음 작업을 상정하여 다음 명령어를 제시하세요.": "Please suggest the next command considering the next task.",
    "만약 결과 요약 을 통해 원하는 내용을 얻지 못했다면 simplify_command 를 수정하여 로그를 줄이는 방법과 이유를 명확히 제시합니다": "If you did not get the desired content through the result summary, clearly present how and why to modify the simplify_command to reduce the logs",
    "목적에 가장 부합하도록 요약해주세요": "Please summarize to best match the purpose",
    "d:디렉토리의 파일목록을 조회한 결과를 제공하오니 목적에 가장 부합하도록 요약해주세요.": "I provide the result of listing files in the d: directory, please summarize to best match the purpose.",
    "a truncate not nessacery logs for rsltstr of this command, explain how to remove not nessacery logs and why": "a truncate not necessary logs for rsltstr of this command, explain how to remove not necessary logs and why",
    "----에이전트의 최종목표----": "----Agent's final goal----",
    "----현재의 명령어 실행 결과----": "----Current command execution result----",
    "----결과 요약----": "----Result summary----",
    "과도하게 반복되는 문장을 제거하고, 불필요한 내용을 삭제합니다. 만약 성공이라면 분명하게 작업이 목표에 맞게 성공했음을 표시합니다.": "Remove excessively repeated sentences and delete unnecessary content. If successful, clearly indicate that the task has succeeded according to the goal.",
    "실패한 경우 분명히 실패한 원인을 제공합니다.": "In case of failure, clearly provide the cause of failure.",
    "다음 형식으로 정확히 응답해주세요:": "Please respond exactly in the following format:",
    "응답은 위 형식만 정확히 포함해야 합니다. 다른 설명이나 텍스트는 포함하지 마세요.": "The response must contain exactly only the above format. Do not include other explanations or text.",
    "---작업 전의 dir 결과 ---": "---dir result before operation---",
    "---작업 후의 dir 결과 ---": "---dir result after operation---"
}


with open("./agents/chatgpt/chrome_cdp_client.py", "r" , encoding="utf-8") as f:
    content = f.read()
with open("./agents/chatgpt/chrome_cdp_client_backup.py", "w", encoding="utf-8") as f:
    f.write(content)

for key, value in translation_dict.items():
    content = content.replace(key, value)

with open("./agents/chatgpt/chrome_cdp_client.py", "w", encoding="utf-8") as f:
    f.write(content)