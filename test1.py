from agents.chatgpt.chrome_cdp_client import ChromeCDPClient
import traceback
import sys






if __name__ == "__main__":
    try:
        print("Creating ChromeCDPClient...")
        ccc = ChromeCDPClient()
        print("ChromeCDPClient created successfully")
        print("Starting analysis...")
        ccc.analisys_crawl_page(ccc.browser, "https://www.youtube.com/watch?v=o7wf2b2CRc4", "유튜브 영상의 요약을 크롤링하세요" , "https://www.youtube.com/watch?v=CfC0rnfGKJg")
        print("Analysis complete")
    except Exception as e:
        print(f"Error: {e}")
        print(traceback.format_exc())
    
    input("Press Enter to continue...")





