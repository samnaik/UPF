import unittest
from unittest.mock import Mock
from pfcp_server import PFCPHeader, NodeID, PFCPMessage, handle_heartbeat_request, handle_session_establishment_request, PFCP_HEARTBEAT_REQUEST, PFCP_SESSION_ESTABLISHMENT_REQUEST

class TestPFCPFunctions(unittest.TestCase):

    def test_pfcp_header_encode_decode(self):
        header = PFCPHeader(1, 1, 0, 0, 1)
        encoded = header.encode()
        decoded = PFCPHeader.decode(encoded)
        self.assertEqual(header.version, decoded.version)
        self.assertEqual(header.message_type, decoded.message_type)
        self.assertEqual(header.length, decoded.length)
        self.assertEqual(header.seid, decoded.seid)
        self.assertEqual(header.seq, decoded.seq)

    def test_node_id_encode_decode(self):
        node_id = NodeID("TestNode")
        encoded = node_id.encode()
        decoded = NodeID.decode(encoded)
        self.assertEqual(node_id.node_id, decoded.node_id)

    def test_pfcp_message_encode_decode(self):
        header = PFCPHeader(1, 1, 0, 0, 1)
        node_id = NodeID("TestNode")
        message = PFCPMessage(header, [node_id])
        encoded = message.encode()
        decoded = PFCPMessage.decode(encoded)
        self.assertEqual(message.header.version, decoded.header.version)
        self.assertEqual(message.header.message_type, decoded.header.message_type)
        self.assertEqual(message.header.length, decoded.header.length)
        self.assertEqual(message.header.seid, decoded.header.seid)
        self.assertEqual(message.header.seq, decoded.header.seq)
        self.assertEqual(message.ies[0].node_id, decoded.ies[0].node_id)

    def test_handle_heartbeat_request(self):
        sock = Mock()
        addr = ("127.0.0.1", 8805)
        header = PFCPHeader(1, PFCP_HEARTBEAT_REQUEST, 0, 0, 1)
        message = PFCPMessage(header, [])
        encoded_message = message.encode()
        handle_heartbeat_request(sock, addr, encoded_message)
        sock.sendto.assert_called()

    def test_handle_session_establishment_request(self):
        sock = Mock()
        addr = ("127.0.0.1", 8805)
        header = PFCPHeader(1, PFCP_SESSION_ESTABLISHMENT_REQUEST, 0, 0, 1)
        node_id = NodeID("TestNode")
        message = PFCPMessage(header, [node_id])
        encoded_message = message.encode()
        handle_session_establishment_request(sock, addr, encoded_message)
        sock.sendto.assert_called()

if __name__ == "__main__":
    unittest.main()
import unittest
