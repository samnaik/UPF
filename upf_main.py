import os
import signal
import threading
import pfcp_server  # Assuming pfcp_server.py is in the same directory and contains the necessary functions

stop_event = threading.Event()

def start_pfcp():
    pfcp_server.load_state()

    # Start PFCP server in a separate thread
    server_thread = threading.Thread(target=pfcp_server.start_pfcp_server)
    server_thread.daemon = True
    server_thread.start()

    # Start sending heartbeat requests in a separate thread
    heartbeat_thread = threading.Thread(target=pfcp_server.send_heartbeat_requests)
    heartbeat_thread.daemon = True
    heartbeat_thread.start()

    # Start the CLI in the main thread
    cli_thread = threading.Thread(target=pfcp_server.cli_thread)
    cli_thread.daemon = True
    cli_thread.start()

    # Wait for the threads to finish
    server_thread.join()
    heartbeat_thread.join()
    cli_thread.join()

    # Save state on exit
    pfcp_server.save_state()

def signal_handler(sig, frame):
    print('Terminating...')
    stop_event.set()
    pfcp_server.stop_event.set()
    pfcp_server.save_state()
    os.killpg(os.getpgid(os.getpid()), signal.SIGKILL)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    start_pfcp()

