from agents.chatgpt.chrome_cdp_client import ChromeCDPClient
import traceback
import sys






if __name__ == "__main__":
    import glob
    import os
    removal_files = glob.glob("./tmp/crawl/*.*")
    for file in removal_files:
        os.remove(file)
    try:
        print("Creating ChromeCDPClient...")
        ccc = ChromeCDPClient()
        print("ChromeCDPClient created successfully")
        print("Starting analysis...")
        ccc.analisys_crawl_page(ccc.browser, "https://translate.google.co.kr/?sl=en&tl=ko&op=translate", "구글번역이 어떻게 음성을 실시간으로 처리하는지 크롤링하세요" , "https://translate.google.co.kr/?sl=en&tl=ko&op=translate")
        print("Analysis complete")
    except Exception as e:
        print(f"Error: {e}")
        print(traceback.format_exc())
    
    input("Press Enter to continue...")





