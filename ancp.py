import os
import signal
import subprocess
import time

# Global variable to hold the process
pfcp_process = None

def start_pfcp_server():
    global pfcp_process
    pfcp_process = subprocess.Popen(['python3', 'pfcp_server.py'])
    print("PFCP server started, listening on port 8805")

def monitor_server():
    while True:
        try:
            if pfcp_process.poll() is not None:  # Check if process has terminated
                print("PFCP server has stopped. Restarting...")
                start_pfcp_server()
            time.sleep(5)
        except KeyboardInterrupt:
            print("Monitor script interrupted. Exiting...")
            if pfcp_process:
                pfcp_process.terminate()  # Gracefully terminate the server process
                pfcp_process.wait()  # Wait for the process to terminate
            break

def signal_handler(sig, frame):
    print('Monitor script terminating...')
    if pfcp_process:
        pfcp_process.terminate()
        pfcp_process.wait()
    os._exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    start_pfcp_server()
    monitor_server()

