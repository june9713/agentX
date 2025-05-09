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
        ccc = ChromeCDPClient(browser_path = "C:\Program Files\Slimjet\slimjet.exe"  , profile_name = "Default" , position = (0, 0) , size = (1024, 768) , pythonpath = "./Scripts/python.exe")
        print("ChromeCDPClient created successfully")
        print("Starting analysis...")
        ccc.analisys_crawl_page(ccc.browser, "https://translate.google.co.kr/?sl=en&tl=ko&op=translate", "Please crawl how Google Translate processes voice in real-time", "https://translate.google.co.kr/?sl=en&tl=ko&op=translate")
        print("Analysis complete")
    except Exception as e:
        print(f"Error: {e}")
        print(traceback.format_exc())
    
    input("Press Enter to continue...")