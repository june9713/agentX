from agents.chatgpt.chrome_cdp_client import ChromeCDPClient
import traceback
import sys

if __name__ == "__main__":
    try:
        print("Creating ChromeCDPClient...")
        ccc = ChromeCDPClient(
            browser_path="C:\Program Files\Slimjet\slimjet.exe",
            profile_name="Default",
            position=(0, 0),
            size=(1024, 768),
            pythonpath="./Scripts/python.exe"
        )
        print("ChromeCDPClient created successfully")
        print("Starting command session...")
        ccc.cmd_session_main()
    except Exception as e:
        print(f"Error: {e}")
        print(traceback.format_exc())
    
    input("Press Enter to continue...")