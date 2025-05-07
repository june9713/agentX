from agents.chatgpt.chrome_cdp_client import ChromeCDPClient
import traceback
import sys






if __name__ == "__main__":
    try:
        print("Creating ChromeCDPClient...")
        ccc = ChromeCDPClient()
        print("ChromeCDPClient created successfully")
        print("Starting analysis...")
        ccc.analisys_crawl_page(ccc.browser, "https://www.google.com", "구글에 접속한 뒤에 구글의 소소를 참조하여 구글맵의 웹소스를 확인하고, 구글맵을이용하여,지명,혹은,건물명의gps주소추출")
        print("Analysis complete")
    except Exception as e:
        print(f"Error: {e}")
        print(traceback.format_exc())
    
    input("Press Enter to continue...")





