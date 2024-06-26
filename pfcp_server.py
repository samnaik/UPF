import socket
import struct
import threading
import time
import json
import os
import signal
import sys
import readline  # For command history and line editing
from threading import Event, Lock

# PFCP Constants
PFCP_PORT = 8805
PFCP_HEADER_FORMAT = "!BBHII"
PFCP_VERSION = 1
STATE_FILE = 'pfcp_state.json'
HEARTBEAT_INTERVAL = 10  # Interval to send heartbeat requests (seconds)
HEARTBEAT_TIMEOUT = 15  # Timeout to wait for heartbeat response (seconds)

# PFCP Message Types
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

# Mapping of PFCP message types to their text descriptions
PFCP_MESSAGE_TYPES = {
    PFCP_HEARTBEAT_REQUEST: "PFCP_HEARTBEAT_REQUEST",
    PFCP_HEARTBEAT_RESPONSE: "PFCP_HEARTBEAT_RESPONSE",
    PFCP_ASSOCIATION_SETUP_REQUEST: "PFCP_ASSOCIATION_SETUP_REQUEST",
    PFCP_ASSOCIATION_SETUP_RESPONSE: "PFCP_ASSOCIATION_SETUP_RESPONSE",
    PFCP_SESSION_ESTABLISHMENT_REQUEST: "PFCP_SESSION_ESTABLISHMENT_REQUEST",
    PFCP_SESSION_ESTABLISHMENT_RESPONSE: "PFCP_SESSION_ESTABLISHMENT_RESPONSE",
    PFCP_SESSION_MODIFICATION_REQUEST: "PFCP_SESSION_MODIFICATION_REQUEST",
    PFCP_SESSION_MODIFICATION_RESPONSE: "PFCP_SESSION_MODIFICATION_RESPONSE",
    PFCP_SESSION_DELETION_REQUEST: "PFCP_SESSION_DELETION_REQUEST",
    PFCP_ASSOCIATION_RELEASE_REQUEST: "PFCP_ASSOCIATION_RELEASE_REQUEST",
    PFCP_ASSOCIATION_RELEASE_RESPONSE: "PFCP_ASSOCIATION_RELEASE_RESPONSE",
    PFCP_SESSION_DELETION_RESPONSE: "PFCP_SESSION_DELETION_RESPONSE"
}

lock = Lock()
stop_event = Event()

# Storage for sessions, neighbors, statistics, and monitor mode
sessions = {}
neighbors = {}
monitor_mode = False
pfcp_stats = {
    'received': {
        PFCP_HEARTBEAT_REQUEST: 0,
        PFCP_HEARTBEAT_RESPONSE: 0,
        PFCP_ASSOCIATION_SETUP_REQUEST: 0,
        PFCP_ASSOCIATION_SETUP_RESPONSE: 0,
        PFCP_ASSOCIATION_RELEASE_REQUEST: 0,  # Add this line
        PFCP_SESSION_ESTABLISHMENT_REQUEST: 0,
        PFCP_SESSION_ESTABLISHMENT_RESPONSE: 0,
        PFCP_SESSION_MODIFICATION_REQUEST: 0,
        PFCP_SESSION_MODIFICATION_RESPONSE: 0,
        PFCP_SESSION_DELETION_REQUEST: 0,
        PFCP_SESSION_DELETION_RESPONSE: 0,
    },
    'sent': {
        PFCP_HEARTBEAT_REQUEST: 0,
        PFCP_HEARTBEAT_RESPONSE: 0,
        PFCP_ASSOCIATION_SETUP_REQUEST: 0,
        PFCP_ASSOCIATION_SETUP_RESPONSE: 0,
        PFCP_ASSOCIATION_RELEASE_RESPONSE: 0,  # Add this line
        PFCP_SESSION_ESTABLISHMENT_REQUEST: 0,
        PFCP_SESSION_ESTABLISHMENT_RESPONSE: 0,
        PFCP_SESSION_MODIFICATION_REQUEST: 0,
        PFCP_SESSION_MODIFICATION_RESPONSE: 0,
        PFCP_SESSION_DELETION_REQUEST: 0,
        PFCP_SESSION_DELETION_RESPONSE: 0,
    }
}

class IEType:
    NODE_ID = 60
    RECOVERY_TIME_STAMP = 96
    F_SEID = 57
    CREATE_PDR = 1
    CREATE_FAR = 3
    QOS_PARAMETERS = 101  # Hypothetical IE Type for QoS Parameters
    CREATE_URR = 102  # Hypothetical IE Type for Create URR

class NodeID:
    def __init__(self, node_id):
        self.node_id = node_id

    def encode(self):
        ie_type = 60  # Example IE Type for NodeID
        length = len(self.node_id) + 1
        node_id_type = 0
        return struct.pack("!HHB", ie_type, length, node_id_type) + self.node_id.encode()

    @staticmethod
    def decode(data):
        ie_type, length, node_id_type = struct.unpack("!HHB", data[:5])
        node_id = data[5:5 + length - 1].decode()
        return NodeID(node_id)


class RecoveryTimeStamp:
    def __init__(self, timestamp):
        self.timestamp = timestamp

    def encode(self):
        ie_type = IEType.RECOVERY_TIME_STAMP
        length = 4
        return struct.pack("!HHI", ie_type, length, self.timestamp)

    @staticmethod
    def decode(data):
        ie_type, length, timestamp = struct.unpack("!HHI", data[:8])
        return RecoveryTimeStamp(timestamp)

class FSEID:
    def __init__(self, seid, ipv4):
        self.seid = seid
        self.ipv4 = ipv4

    def encode(self):
        ie_type = IEType.F_SEID
        ipv4_bytes = socket.inet_aton(self.ipv4)
        length = 8 + len(ipv4_bytes)
        return struct.pack("!HHQ", ie_type, length, self.seid) + ipv4_bytes

    @staticmethod
    def decode(data):
        ie_type, length, seid = struct.unpack("!HHQ", data[:12])
        ipv4 = socket.inet_ntoa(data[12:12+4])
        return FSEID(seid, ipv4)

class CreatePDR:
    def __init__(self, pdr_id):
        self.pdr_id = pdr_id

    def encode(self):
        ie_type = IEType.CREATE_PDR
        length = 2
        return struct.pack("!HHH", ie_type, length, self.pdr_id)

    @staticmethod
    def decode(data):
        ie_type, length, pdr_id = struct.unpack("!HHH", data[:6])
        return CreatePDR(pdr_id)

class CreateFAR:
    def __init__(self, far_id):
        self.far_id = far_id

    def encode(self):
        ie_type = IEType.CREATE_FAR
        length = 2
        return struct.pack("!HHH", ie_type, length, self.far_id)

    @staticmethod
    def decode(data):
        ie_type, length, far_id = struct.unpack("!HHH", data[:6])
        return CreateFAR(far_id)

class QoSParameters:
    def __init__(self, priority, packet_delay, packet_loss):
        self.priority = priority
        self.packet_delay = packet_delay
        self.packet_loss = packet_loss

    def encode(self):
        ie_type = IEType.QOS_PARAMETERS
        length = 12  # Assuming each parameter is a 4-byte integer
        return struct.pack("!HHIII", ie_type, length, self.priority, self.packet_delay, self.packet_loss)

    @staticmethod
    def decode(data):
        ie_type, length, priority, packet_delay, packet_loss = struct.unpack("!HHIII", data[:16])
        return QoSParameters(priority, packet_delay, packet_loss)

class CreateURR:
    def __init__(self, urr_id, measurement_period):
        self.urr_id = urr_id
        self.measurement_period = measurement_period

    def encode(self):
        ie_type = IEType.CREATE_URR
        length = 8  # Assuming urr_id and measurement_period are 4-byte integers
        return struct.pack("!HHII", ie_type, length, self.urr_id, self.measurement_period)

    @staticmethod
    def decode(data):
        ie_type, length, urr_id, measurement_period = struct.unpack("!HHII", data[:12])
        return CreateURR(urr_id, measurement_period)

class PFCPHeader:
    def __init__(self, version, message_type, length, seid, seq):
        self.version = version
        self.message_type = message_type
        self.length = length
        self.seid = seid
        self.seq = seq

    def encode(self):
        return struct.pack("!BBHII", self.version << 5, self.message_type, self.length, self.seid, self.seq)

    @staticmethod
    def decode(data):
        version_message_type, message_type, length, seid, seq = struct.unpack("!BBHII", data)
        version = version_message_type >> 5
        return PFCPHeader(version, message_type, length, seid, seq)


class PFCPMessage:
    def __init__(self, header, ies):
        self.header = header
        self.ies = ies

    def encode(self):
        message = self.header.encode()
        for ie in self.ies:
            message += ie.encode()
        return message

    @staticmethod
    def decode(data):
        header = PFCPHeader.decode(data[:12])
        ies = []
        offset = 12
        while offset < len(data):
            ie_type, length = struct.unpack("!HH", data[offset:offset+4])
            ie_data = data[offset+4:offset+4+length]
            if ie_type == 60:  # Example IE Type for NodeID
                ies.append(NodeID.decode(ie_data))
            # Add other IE decodings here
            offset += 4 + length
        return PFCPMessage(header, ies)

def save_state():
    try:
        with lock:
            with open(STATE_FILE, 'w') as f:
                json.dump({'sessions': sessions, 'neighbors': neighbors, 'pfcp_stats': pfcp_stats}, f)
    except RecursionError:
        print("Recursion error while saving state. Trying again...")
        save_state()

def load_state():
    global sessions, neighbors, pfcp_stats
    with lock:
        if os.path.exists(STATE_FILE):
            try:
                if os.path.getsize(STATE_FILE) > 0:
                    with open(STATE_FILE, 'r') as f:
                        state = json.load(f)
                        sessions = state.get('sessions', {})
                        neighbors = state.get('neighbors', {})
                        pfcp_stats = {
                            'received': {int(k): v for k, v in state.get('pfcp_stats', {}).get('received', {}).items()},
                            'sent': {int(k): v for k, v in state.get('pfcp_stats', {}).get('sent', {}).items()}
                        }
                    print("State loaded from", STATE_FILE)
                else:
                    print(f"{STATE_FILE} is empty. Initializing state.")
            except json.JSONDecodeError:
                print(f"Error decoding JSON from {STATE_FILE}. Initializing state.")
        else:
            print(f"{STATE_FILE} does not exist. Initializing state.")

def signal_handler(sig, frame):
    print('Terminating...')
    stop_event.set()
    save_state()
    os.killpg(os.getpgid(os.getpid()), signal.SIGTERM)

def print_if_monitor_mode(message):
    if monitor_mode:
        print(message)

# Function to handle PFCP heartbeat request
def handle_heartbeat_request(sock, addr, message):
    print_if_monitor_mode("Received Heartbeat Request")
    pfcp_stats['received'][PFCP_HEARTBEAT_REQUEST] += 1

    # Decode the PFCP header from the message
    header = PFCPHeader.decode(message[:12])
    response_header = PFCPHeader(PFCP_VERSION, PFCP_HEARTBEAT_RESPONSE, 0, header.seid, header.seq)
    response_message = PFCPMessage(response_header, [])

    try:
        # Convert PFCPMessage to bytes
        response_message_bytes = response_message.encode()
        sock.sendto(response_message_bytes, addr)
        pfcp_stats['sent'][PFCP_HEARTBEAT_RESPONSE] += 1
    except Exception as e:
        print(f"Error encoding and sending heartbeat response: {e}")



# Function to handle PFCP heartbeat response
def handle_heartbeat_response(addr, seid):
    try:
        print_if_monitor_mode("\n===== [PFCP_HEARTBEAT_RESPONSE] Received =====")
        pfcp_stats['received'][PFCP_HEARTBEAT_RESPONSE] += 1
        if seid in neighbors:
            neighbors[seid]['last_heartbeat'] = time.time()
        else:
            print_if_monitor_mode(f"Unexpected heartbeat response from {addr}")
    except Exception as e:
        print_if_monitor_mode(f"Error handling heartbeat response: {e}")

# Function to handle PFCP association setup request
def handle_association_setup_request(sock, addr, message):
    try:
        print_if_monitor_mode("\n===== [PFCP_ASSOCIATION_SETUP_REQUEST] Received =====")
        pfcp_stats['received'][PFCP_ASSOCIATION_SETUP_REQUEST] += 1
        header = PFCPHeader.decode(message[:12])
        node_id = None
        recovery_time_stamp = None
        offset = 12
        while offset < len(message):
            ie_type, length = struct.unpack("!HH", message[offset:offset+4])
            ie_data = message[offset+4:offset+4+length]
            if ie_type == IEType.NODE_ID:
                node_id = NodeID.decode(ie_data).node_id
            elif ie_type == IEType.RECOVERY_TIME_STAMP:
                recovery_time_stamp = RecoveryTimeStamp.decode(ie_data).timestamp
            offset += 4 + length
        neighbors[header.seid] = {'node_id': node_id, 'address': addr, 'recovery_time_stamp': recovery_time_stamp, 'last_heartbeat': time.time()}
        response_header = PFCPHeader(PFCP_VERSION, PFCP_ASSOCIATION_SETUP_RESPONSE, 0, header.seid, header.seq)
        response_message = PFCPMessage(response_header, [NodeID('192.168.1.1'), RecoveryTimeStamp(int(time.time()))])
        sock.sendto(response_message.encode(), addr)
        pfcp_stats['sent'][PFCP_ASSOCIATION_SETUP_RESPONSE] += 1
        save_state()
        print_if_monitor_mode("----- [PFCP_ASSOCIATION_SETUP_RESPONSE] Sent -----")
    except Exception as e:
        print_if_monitor_mode(f"Error handling association setup request: {e}")

def handle_association_release_request(sock, addr, message):
    try:
        print_if_monitor_mode("\n===== [PFCP_ASSOCIATION_RELEASE_REQUEST] Received =====")
        pfcp_stats['received'][PFCP_ASSOCIATION_RELEASE_REQUEST] += 1
        header = PFCPHeader.decode(message[:12])
        if header.seid in neighbors:
            print_if_monitor_mode(f"Deleting neighbor: {header.seid}")
            del neighbors[header.seid]
            response_header = PFCPHeader(PFCP_VERSION, PFCP_ASSOCIATION_RELEASE_RESPONSE, 0, header.seid, header.seq)
            response_message = PFCPMessage(response_header, [])
            sock.sendto(response_message.encode(), addr)
            pfcp_stats['sent'][PFCP_ASSOCIATION_RELEASE_RESPONSE] += 1
            save_state()
            print_if_monitor_mode("----- [PFCP_ASSOCIATION_RELEASE_RESPONSE] Sent -----")
        else:
            print_if_monitor_mode(f"Association not found: {header.seid}")
    except Exception as e:
        print_if_monitor_mode(f"Error handling association release request: {e}")
        raise



def handle_session_establishment_request(sock, addr, message):
    try:
        print_if_monitor_mode("\n===== [PFCP_SESSION_ESTABLISHMENT_REQUEST] Received =====")
        pfcp_stats['received'][PFCP_SESSION_ESTABLISHMENT_REQUEST] += 1

        # Decode the PFCP header
        header = PFCPHeader.decode(message[:12])
        session_id = header.seid
        session = {
            'seid': session_id,
            'node_id': None,
            'pdrs': [],
            'fars': [],
            'qos_parameters': None,
            'urrs': []
        }

        # Decode Information Elements (IEs)
        offset = 12
        while offset < len(message):
            ie_type, length = struct.unpack("!HH", message[offset:offset+4])
            ie_data = message[offset+4:offset+4+length]
            if ie_type == IEType.NODE_ID:
                session['node_id'] = NodeID.decode(ie_data).node_id
            elif ie_type == IEType.F_SEID:
                f_seid = FSEID.decode(ie_data)
                session['f_seid'] = f_seid.seid
            elif ie_type == IEType.CREATE_PDR:
                pdr_id = CreatePDR.decode(ie_data).pdr_id
                session['pdrs'].append(pdr_id)
                print_if_monitor_mode(f"PDR ID: {pdr_id}")
            elif ie_type == IEType.CREATE_FAR:
                far_id = CreateFAR.decode(ie_data).far_id
                session['fars'].append(far_id)
                print_if_monitor_mode(f"FAR ID: {far_id}")
            elif ie_type == IEType.QOS_PARAMETERS:
                qos_parameters = QoSParameters.decode(ie_data)
                session['qos_parameters'] = qos_parameters
                print_if_monitor_mode(f"QoS Parameters: Priority: {qos_parameters.priority}, "
                                      f"Packet Delay: {qos_parameters.packet_delay}, "
                                      f"Packet Loss: {qos_parameters.packet_loss}")
            elif ie_type == IEType.CREATE_URR:
                urr = CreateURR.decode(ie_data)
                session['urrs'].append(urr)
                print_if_monitor_mode(f"URR: ID: {urr.urr_id}, Measurement Period: {urr.measurement_period}")
            offset += 4 + length

        sessions[session_id] = session

        # Create response header and IEs
        response_header = PFCPHeader(PFCP_VERSION, PFCP_SESSION_ESTABLISHMENT_RESPONSE, 0, session_id, header.seq)
        f_seid_ie = FSEID(session_id, "192.168.1.1").encode()
        response_ies = [f_seid_ie]
        response_message = PFCPMessage(response_header, response_ies).encode()

        # Update the length field in the header
        response_header.length = len(response_message)
        response_message = response_header.encode() + response_message[12:]

        # Send response
        sock.sendto(response_message, addr)
        pfcp_stats['sent'][PFCP_SESSION_ESTABLISHMENT_RESPONSE] += 1
        save_state()
        print_if_monitor_mode("----- [PFCP_SESSION_ESTABLISHMENT_RESPONSE] Sent -----")
    except Exception as e:
        print_if_monitor_mode(f"Error handling session establishment request: {e}")




# Function to handle PFCP session modification request
def handle_session_modification_request(sock, addr, message):
    try:
        print_if_monitor_mode("\n===== [PFCP_SESSION_MODIFICATION_REQUEST] Received =====")
        pfcp_stats['received'][PFCP_SESSION_MODIFICATION_REQUEST] += 1
        header = PFCPHeader.decode(message[:12])
        session_id = header.seid
        if session_id in sessions:
            offset = 12
            while offset < len(message):
                ie_type, length = struct.unpack("!HH", message[offset:offset+4])
                ie_data = message[offset+4:offset+4+length]
                if ie_type == IEType.CREATE_PDR:
                    sessions[session_id]['pdrs'].append(CreatePDR.decode(ie_data).pdr_id)
                elif ie_type == IEType.CREATE_FAR:
                    sessions[session_id]['fars'].append(CreateFAR.decode(ie_data).far_id)
                elif ie_type == IEType.QOS_PARAMETERS:
                    sessions[session_id]['qos_parameters'] = QoSParameters.decode(ie_data)
                elif ie_type == IEType.CREATE_URR:
                    sessions[session_id]['urrs'].append(CreateURR.decode(ie_data))
                offset += 4 + length
            response_header = PFCPHeader(PFCP_VERSION, PFCP_SESSION_MODIFICATION_RESPONSE, 0, session_id, header.seq)
            response_message = PFCPMessage(response_header, [NodeID('192.168.1.1')])
            sock.sendto(response_message.encode(), addr)
            pfcp_stats['sent'][PFCP_SESSION_MODIFICATION_RESPONSE] += 1
            print_if_monitor_mode("----- [PFCP_SESSION_MODIFICATION_RESPONSE] Sent -----")
            save_state()
        else:
            print_if_monitor_mode("Session ID not found")
    except Exception as e:
        print_if_monitor_mode(f"Error handling session modification request: {e}")

# Function to handle PFCP session deletion request
def handle_session_deletion_request(sock, addr, message):
    try:
        print_if_monitor_mode("\n===== [PFCP_SESSION_DELETION_REQUEST] Received =====")
        pfcp_stats['received'][PFCP_SESSION_DELETION_REQUEST] += 1
        header = PFCPHeader.decode(message[:12])
        session_id = header.seid
        if session_id in sessions:
            del sessions[session_id]
            response_header = PFCPHeader(PFCP_VERSION, PFCP_SESSION_DELETION_RESPONSE, 0, session_id, header.seq)
            response_message = PFCPMessage(response_header, [NodeID('192.168.1.1')])
            sock.sendto(response_message.encode(), addr)
            pfcp_stats['sent'][PFCP_SESSION_DELETION_RESPONSE] += 1
            save_state()
            print_if_monitor_mode("----- [PFCP_SESSION_DELETION_RESPONSE] Sent -----")
        else:
            print_if_monitor_mode("Session ID not found")
    except Exception as e:
        print_if_monitor_mode(f"Error handling session deletion request: {e}")

# Function to process incoming PFCP messages
def process_message(sock, addr, message):
    try:
        message_type = struct.unpack("!B", message[1:2])[0]
        if message_type == PFCP_HEARTBEAT_REQUEST:
            handle_heartbeat_request(sock, addr, message)
        elif message_type == PFCP_HEARTBEAT_RESPONSE:
            header = PFCPHeader.decode(message[:12])
            handle_heartbeat_response(addr, header.seid)
        elif message_type == PFCP_ASSOCIATION_SETUP_REQUEST:
            handle_association_setup_request(sock, addr, message)
        elif message_type == PFCP_ASSOCIATION_RELEASE_REQUEST:
            handle_association_release_request(sock, addr, message)
        elif message_type == PFCP_SESSION_ESTABLISHMENT_REQUEST:
            handle_session_establishment_request(sock, addr, message)
        elif message_type == PFCP_SESSION_MODIFICATION_REQUEST:
            handle_session_modification_request(sock, addr, message)
        elif message_type == PFCP_SESSION_DELETION_REQUEST:
            handle_session_deletion_request(sock, addr, message)
        else:
            print_if_monitor_mode(f"Unknown message type received: {message_type}")
    except Exception as e:
        print_if_monitor_mode(f"Error processing message: {e}")



def start_pfcp_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", PFCP_PORT))
    print("PFCP server started, listening on port", PFCP_PORT)

    while not stop_event.is_set():
        try:
            sock.settimeout(1)
            data, addr = sock.recvfrom(4096)
            process_message(sock, addr, data)
        except socket.timeout:
            continue
        except Exception as e:
            print_if_monitor_mode(f"Error receiving data: {e}")
    sock.close()

def send_heartbeat_requests():
    while not stop_event.is_set():
        time.sleep(HEARTBEAT_INTERVAL)
        with lock:
            for seid, neighbor in list(neighbors.items()):
                if time.time() - neighbor['last_heartbeat'] > HEARTBEAT_TIMEOUT:
                    print_if_monitor_mode(f"Deleting neighbor {seid} due to heartbeat timeout")
                    del neighbors[seid]
                    continue
                header = PFCPHeader(PFCP_VERSION, PFCP_HEARTBEAT_REQUEST, 0, seid, 0)
                message = PFCPMessage(header, [])
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(message.encode(), neighbor['address'])
                sock.close()
                pfcp_stats['sent'][PFCP_HEARTBEAT_REQUEST] += 1

# Function to handle show commands
def show_subscriber_summary():
    print("\nSubscriber Summary:")
    for session_id, session in sessions.items():
        print(f"SEID: {session_id}")
        print(f"  Node ID: {session['node_id']}")
        print(f"  PDRs: {session['pdrs']}")
        print(f"  FARs: {session['fars']}")
        if session['qos_parameters']:
            qos = session['qos_parameters']
            print(f"  QoS Parameters: Priority {qos.priority}, Packet Delay {qos.packet_delay}, Packet Loss {qos.packet_loss}")
        if session['urrs']:
            for urr in session['urrs']:
                print(f"  URR: ID {urr.urr_id}, Measurement Period {urr.measurement_period}")
        print()

def show_upf_peers():
    print("\nUPF Peers:")
    for peer_id, peer in neighbors.items():
        print(f"Peer ID: {peer_id}")
        print(f"  Node ID: {peer['node_id']}")
        print(f"  Address: {peer['address']}")
        print(f"  Last Heartbeat: {time.ctime(peer['last_heartbeat'])}")
        print()


def show_pfcp_stats():
    print("\nPFCP Statistics:")
    print("Received Messages:")
    for msg_type, count in sorted(pfcp_stats['received'].items()):
        if count > 0 and msg_type in {
            PFCP_HEARTBEAT_REQUEST,
            PFCP_ASSOCIATION_SETUP_REQUEST,
            PFCP_SESSION_ESTABLISHMENT_REQUEST,
            PFCP_SESSION_MODIFICATION_REQUEST,
            PFCP_SESSION_DELETION_REQUEST
        }:
            print(f"  {PFCP_MESSAGE_TYPES.get(msg_type, 'Unknown')}: {count}")
    print("Sent Messages:")
    for msg_type, count in sorted(pfcp_stats['sent'].items()):
        if count > 0 and msg_type in {
            PFCP_HEARTBEAT_RESPONSE,
            PFCP_ASSOCIATION_SETUP_RESPONSE,
            PFCP_SESSION_ESTABLISHMENT_RESPONSE,
            PFCP_SESSION_MODIFICATION_RESPONSE,
            PFCP_SESSION_DELETION_RESPONSE,
            PFCP_HEARTBEAT_REQUEST
        }:
            print(f"  {PFCP_MESSAGE_TYPES.get(msg_type, 'Unknown')}: {count}")

def clear_pfcp_stats():
    global pfcp_stats
    pfcp_stats['received'] = {key: 0 for key in pfcp_stats['received']}
    pfcp_stats['sent'] = {key: 0 for key in pfcp_stats['sent']}
    print("PFCP statistics cleared")


def show_help():
    print("Available commands:")
    print("  show subscriber summary - Display subscriber summary")
    print("  show upf peers - Display UPF peers information")
    print("  show pfcp stats - Display PFCP statistics")
    print("  clear pfcp stats - Clear PFCP statistics")
    print("  mon - Enable monitor mode")
    print("  dis - Disable monitor mode")
    print("  help - Show this help message")

def handle_show_command(command):
    global monitor_mode
    command = command.strip().lower()
    if command == "":
        return
    if command == "show subscriber summary":
        show_subscriber_summary()
    elif command == "show upf peers":
        show_upf_peers()
    elif command == "show pfcp stats":
        show_pfcp_stats()
    elif command == "clear pfcp stats":
        clear_pfcp_stats()
    elif command == "mon":
        monitor_mode = True
        print("Monitor mode enabled")
    elif command == "dis":
        monitor_mode = False
        print("Monitor mode disabled")
    elif command == "help":
        show_help()
    else:
        print("Unknown show command")

def cli_thread():
    while not stop_event.is_set():
        try:
            command = input("> ")
            handle_show_command(command)
        except (EOFError, KeyboardInterrupt):
            print("\nExiting CLI...")
            stop_event.set()
            break

if __name__ == "__main__":
    def signal_handler(sig, frame):
        print('Terminating...')
        stop_event.set()
        save_state()
        os.killpg(os.getpgid(os.getpid()), signal.SIGTERM)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Load previous state if exists
    load_state()

    # Start PFCP server in a separate thread
    server_thread = threading.Thread(target=start_pfcp_server)
    server_thread.daemon = True
    server_thread.start()

    # Start sending heartbeat requests in a separate thread
    heartbeat_thread = threading.Thread(target=send_heartbeat_requests)
    heartbeat_thread.daemon = True
    heartbeat_thread.start()

    # Start the CLI in the main thread
    cli_thread()

    # Wait for the threads to finish
    server_thread.join()
    heartbeat_thread.join()

    # Save state on exit
    save_state()

