import socket
import struct
import time
import threading
import signal
import random

# Constants for PFCP message types
PFCP_HEARTBEAT_REQUEST = 1
PFCP_HEARTBEAT_RESPONSE = 2
PFCP_ASSOCIATION_SETUP_REQUEST = 5
PFCP_ASSOCIATION_SETUP_RESPONSE = 6
PFCP_ASSOCIATION_RELEASE_REQUEST = 7
PFCP_ASSOCIATION_RELEASE_RESPONSE = 8
PFCP_SESSION_ESTABLISHMENT_REQUEST = 50
PFCP_SESSION_ESTABLISHMENT_RESPONSE = 51
PFCP_SESSION_MODIFICATION_REQUEST = 52
PFCP_SESSION_MODIFICATION_RESPONSE = 53
PFCP_SESSION_DELETION_REQUEST = 54
PFCP_SESSION_DELETION_RESPONSE = 55

# Address and port configuration
UPF_ADDRESS = "127.0.0.1"
UPF_PORT = 8805

# Global variables to manage state
stop_event = threading.Event()
sock = None

# Signal handler for graceful termination
def signal_handler(sig, frame):
    print('Terminating...')
    stop_event.set()
    sock.close()
    exit(0)

# Function to send PFCP heartbeat request
def send_heartbeat():
    while not stop_event.is_set():
        header = struct.pack("!BBHQLHH", 1, PFCP_HEARTBEAT_REQUEST, 12, 0, 0, 0, 0)
        sock.sendto(header, (UPF_ADDRESS, UPF_PORT))
        print("Sent Heartbeat Request")
        time.sleep(5)

# Function to send PFCP messages
def send_pfcp_message(message_type, seid=0):
    header = struct.pack("!BBHII", 1, message_type, 12, seid, 0)
    sock.sendto(header, (UPF_ADDRESS, UPF_PORT))

# Function to wait for user input before sending the next message
def wait_for_enter(prompt):
    input(prompt)

def main():
    global sock
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    signal.signal(signal.SIGINT, signal_handler)

    # Start sending heartbeat messages
    heartbeat_thread = threading.Thread(target=send_heartbeat)
    heartbeat_thread.start()

    while not stop_event.is_set():
        # Wait for Enter before sending Association Setup Request
        wait_for_enter("Press Enter to send Association Setup Request...")
        send_pfcp_message(PFCP_ASSOCIATION_SETUP_REQUEST)
        print("Sent Association Setup Request")

        # Generate a unique session_id for each session establishment request
        session_id = random.randint(1, 1000000)
        wait_for_enter("Press Enter to send Session Establishment Request...")
        send_pfcp_message(PFCP_SESSION_ESTABLISHMENT_REQUEST, seid=session_id)
        print(f"Sent Session Establishment Request with SEID: {session_id}")

        # Use the same session_id for modification and deletion requests
        wait_for_enter("Press Enter to send Session Modification Request...")
        send_pfcp_message(PFCP_SESSION_MODIFICATION_REQUEST, seid=session_id)
        print(f"Sent Session Modification Request with SEID: {session_id}")

        wait_for_enter("Press Enter to send Session Deletion Request...")
        send_pfcp_message(PFCP_SESSION_DELETION_REQUEST, seid=session_id)
        print(f"Sent Session Deletion Request with SEID: {session_id}")

        # Wait for Enter to bring down the association
        wait_for_enter("Press Enter to send Association Release Request...")
        send_pfcp_message(PFCP_ASSOCIATION_RELEASE_REQUEST)
        print("Sent Association Release Request")

        print("Test sequence completed. Restarting...")

    heartbeat_thread.join()

if __name__ == "__main__":
    main()
