#!/usr/bin/env python3
"""
0MQ (ZeroMQ) Client for ICSSploit
A Python client to interact with 0MQ devices using pyzmq
"""

import asyncio
import sys
import time
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass
from enum import Enum
from src.modules.clients.base import Base

# Import pyzmq components
try:
    import zmq
    from zmq import Context, Socket
    from zmq.error import ZMQError
    PYZMQ_AVAILABLE = True
except ImportError as e:
    print(f"Error: pyzmq not installed or import failed: {e}")
    print("Please install with: pip install pyzmq")
    PYZMQ_AVAILABLE = False


class ZMQSocketType(Enum):
    """0MQ socket types"""
    REQ = 3
    REP = 4
    PUB = 1
    SUB = 2
    PUSH = 8
    PULL = 7
    PAIR = 5
    DEALER = 6
    ROUTER = 9
    XPUB = 10
    XSUB = 11
    STREAM = 12


class ZMQTransport(Enum):
    """0MQ transport protocols"""
    TCP = "tcp"
    IPC = "ipc"
    INPROC = "inproc"
    PGM = "pgm"
    EPGM = "epgm"
    NORM = "norm"
    WS = "ws"
    WSS = "wss"


class ZMQPattern(Enum):
    """0MQ communication patterns"""
    REQUEST_REPLY = "request_reply"
    PUBLISH_SUBSCRIBE = "publish_subscribe"
    PIPELINE = "pipeline"
    EXCLUSIVE_PAIR = "exclusive_pair"
    ASYNC_CLIENT_SERVER = "async_client_server"


@dataclass
class ZMQDevice:
    """0MQ device information"""
    address: str
    port: int
    socket_type: ZMQSocketType
    transport: ZMQTransport
    pattern: ZMQPattern
    topics: List[str] = None
    connected: bool = False
    last_seen: float = 0.0
    
    def __post_init__(self):
        if self.topics is None:
            self.topics = []


class ZMQClient(Base):
    """0MQ client for ICSSploit"""
    
    # Client options (similar to module options)
    options = ['target', 'port', 'socket_type', 'transport', 'timeout', 'topic']
    
    def __init__(self, name: str, address: str = '', port: int = 5555, 
                 socket_type: ZMQSocketType = ZMQSocketType.REQ,
                 transport: ZMQTransport = ZMQTransport.TCP,
                 timeout: int = 5, context = None):
        """
        Initialize 0MQ client
        
        Args:
            name: Name of this target
            address: Target 0MQ device address
            port: 0MQ port (default: 5555)
            socket_type: 0MQ socket type (default: REQ)
            transport: 0MQ transport protocol (default: TCP)
            timeout: Socket timeout in seconds
            context: ZMQ context (optional, will create if None)
        """
        super(ZMQClient, self).__init__(name=name)
        
        # Set options (similar to modules)
        self.target = address
        self.port = port
        self.socket_type = socket_type
        self.transport = transport
        self.timeout = timeout
        self.topic = None
        
        # Internal attributes
        self._address = address
        self._port = port
        self._socket_type = socket_type
        self._transport = transport
        self._timeout = timeout
        if PYZMQ_AVAILABLE:
            self._context = context or zmq.Context.instance()
        else:
            self._context = None
        self._socket = None
        self._connected = False
        self._topic = None
        
        if not PYZMQ_AVAILABLE:
            self.logger.error("pyzmq library not available. Please install with: pip install pyzmq")
    
    @property
    def target(self):
        """Get target address"""
        return self._address
    
    @target.setter
    def target(self, value):
        """Set target address"""
        self._address = value
    
    @property
    def port(self):
        """Get port"""
        return self._port
    
    @port.setter
    def port(self, value):
        """Set port"""
        self._port = int(value) if value else 5555
    
    @property
    def socket_type(self):
        """Get socket type"""
        return self._socket_type
    
    @socket_type.setter
    def socket_type(self, value):
        """Set socket type"""
        if isinstance(value, str):
            # Convert string to enum
            for st in ZMQSocketType:
                if st.name == value.upper():
                    self._socket_type = st
                    break
        else:
            self._socket_type = value
    
    @property
    def transport(self):
        """Get transport"""
        return self._transport
    
    @transport.setter
    def transport(self, value):
        """Set transport"""
        if isinstance(value, str):
            # Convert string to enum
            for t in ZMQTransport:
                if t.name == value.upper():
                    self._transport = t
                    break
        else:
            self._transport = value
    
    @property
    def timeout(self):
        """Get timeout"""
        return self._timeout
    
    @timeout.setter
    def timeout(self, value):
        """Set timeout"""
        self._timeout = int(value) if value else 5
    
    @property
    def topic(self):
        """Get topic"""
        return self._topic
    
    @topic.setter
    def topic(self, value):
        """Set topic"""
        self._topic = value
    
    def connect(self) -> bool:
        """Connect to 0MQ device and verify connectivity"""
        if not PYZMQ_AVAILABLE:
            self.logger.error("pyzmq library not available. Please install with: pip install pyzmq")
            return False
            
        try:
            self.logger.info(f"Testing connectivity to {self._transport.value}://{self._address}:{self._port}...")
            
            # Create socket
            self._socket = self._context.socket(self._socket_type.value)
            self._socket.setsockopt(zmq.LINGER, 0)
            self._socket.setsockopt(zmq.RCVTIMEO, self._timeout * 1000)
            self._socket.setsockopt(zmq.SNDTIMEO, self._timeout * 1000)
            
            # Connect to endpoint
            endpoint = f"{self._transport.value}://{self._address}:{self._port}"
            self._socket.connect(endpoint)
            
            # Test connection based on socket type
            if self._socket_type == ZMQSocketType.REQ:
                # For REQ socket, try to send a ping
                try:
                    self._socket.send_string("PING")
                    response = self._socket.recv_string()
                    if response:
                        self._connected = True
                        self.logger.info(f"Successfully connected to 0MQ device at {endpoint}")
                        return True
                except ZMQError as e:
                    if "Resource temporarily unavailable" in str(e):
                        self.logger.warning(f"Connected to {endpoint} but server is not responding (timeout)")
                        # Don't mark as connected if server doesn't respond
                        return False
                    else:
                        self.logger.warning(f"Connected to {endpoint} but device may not be responding: {e}")
                        self._connected = True  # Still consider connected for other errors
                        return True
                    
            elif self._socket_type == ZMQSocketType.SUB:
                # For SUB socket, subscribe to all topics
                self._socket.setsockopt_string(zmq.SUBSCRIBE, "")
                self._connected = True
                self.logger.info(f"Successfully connected to 0MQ SUB device at {endpoint}")
                return True
                
            elif self._socket_type == ZMQSocketType.PUB:
                # For PUB socket, just connect
                self._connected = True
                self.logger.info(f"Successfully connected to 0MQ PUB device at {endpoint}")
                return True
                
            else:
                # For other socket types, just connect
                self._connected = True
                self.logger.info(f"Successfully connected to 0MQ device at {endpoint}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to connect to 0MQ device: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from 0MQ device"""
        if self._socket and self._connected:
            self._socket.close()
            self._connected = False
            self.logger.info("Disconnected from 0MQ device")
    
    def send_message(self, message: str, topic: str = None) -> bool:
        """Send a message to the 0MQ device"""
        if not self._socket or not self._connected:
            self.logger.error("Not connected to 0MQ device")
            return False
        
        try:
            if topic and self._socket_type == ZMQSocketType.PUB:
                # For PUB socket, send topic and message
                self._socket.send_string(f"{topic} {message}")
            else:
                # For other socket types, send message directly
                self._socket.send_string(message)
            
            self.logger.info(f"Sent message: {message}")
            return True
            
        except ZMQError as e:
            self.logger.error(f"Failed to send message: {e}")
            return False
    
    def receive_message(self, timeout: int = None) -> Optional[str]:
        """Receive a message from the 0MQ device"""
        if not self._socket or not self._connected:
            self.logger.error("Not connected to 0MQ device")
            return None
        
        try:
            if timeout:
                self._socket.setsockopt(zmq.RCVTIMEO, timeout * 1000)
            
            message = self._socket.recv_string()
            self.logger.info(f"Received message: {message}")
            return message
            
        except ZMQError as e:
            if "Resource temporarily unavailable" in str(e):
                self.logger.warning("No message received within timeout")
            else:
                self.logger.error(f"Failed to receive message: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error receiving message: {e}")
            return None
    
    def request_reply(self, request: str, timeout: int = None) -> Optional[str]:
        """Send a request and wait for reply (for REQ socket)"""
        if self._socket_type != ZMQSocketType.REQ:
            self.logger.error("Request-reply only works with REQ socket type")
            return None
        
        if not self.send_message(request):
            return None
        
        return self.receive_message(timeout)
    
    def subscribe(self, topic: str) -> bool:
        """Subscribe to a topic (for SUB socket)"""
        if self._socket_type != ZMQSocketType.SUB:
            self.logger.error("Subscribe only works with SUB socket type")
            return False
        
        try:
            self._socket.setsockopt_string(zmq.SUBSCRIBE, topic)
            self.logger.info(f"Subscribed to topic: {topic}")
            return True
        except ZMQError as e:
            self.logger.error(f"Failed to subscribe to topic {topic}: {e}")
            return False
    
    def discover_devices(self, start_port: int = 5555, end_port: int = 5565) -> List[ZMQDevice]:
        """Discover 0MQ devices on the network"""
        devices = []
        
        for port in range(start_port, end_port + 1):
            try:
                # Try different socket types
                for socket_type in [ZMQSocketType.REQ, ZMQSocketType.SUB]:
                    try:
                        test_client = ZMQClient(
                            name=f"ZMQScanner_{port}_{socket_type.name}",
                            address=self._address,
                            port=port,
                            socket_type=socket_type,
                            transport=self._transport,
                            timeout=2
                        )
                        
                        if test_client.connect():
                            device = ZMQDevice(
                                address=self._address,
                                port=port,
                                socket_type=socket_type,
                                transport=self._transport,
                                pattern=self._get_pattern_for_socket(socket_type),
                                connected=True,
                                last_seen=time.time()
                            )
                            devices.append(device)
                            self.logger.info(f"Found 0MQ device at {self._address}:{port} ({socket_type.name})")
                            test_client.disconnect()
                            break  # Found device on this port, try next port
                            
                    except Exception:
                        continue
                        
            except Exception:
                continue
        
        return devices
    
    def _get_pattern_for_socket(self, socket_type: ZMQSocketType) -> ZMQPattern:
        """Get communication pattern for socket type"""
        if socket_type in [ZMQSocketType.REQ, ZMQSocketType.REP]:
            return ZMQPattern.REQUEST_REPLY
        elif socket_type in [ZMQSocketType.PUB, ZMQSocketType.SUB]:
            return ZMQPattern.PUBLISH_SUBSCRIBE
        elif socket_type in [ZMQSocketType.PUSH, ZMQSocketType.PULL]:
            return ZMQPattern.PIPELINE
        elif socket_type == ZMQSocketType.PAIR:
            return ZMQPattern.EXCLUSIVE_PAIR
        elif socket_type in [ZMQSocketType.DEALER, ZMQSocketType.ROUTER]:
            return ZMQPattern.ASYNC_CLIENT_SERVER
        else:
            return ZMQPattern.REQUEST_REPLY
    
    def get_target_info(self) -> Tuple[str, str, str, str, str, int]:
        """Get 0MQ device information"""
        try:
            if not self.connect():
                return ("Unknown", "Unknown", "offline", "False", self._address, self._port)
            
            device_type = f"{self._socket_type.name}"
            unit_id = f"{self._transport.value}"
            status = "online" if self._connected else "offline"
            accessible = "True" if self._connected else "False"
            address = self._address
            port = self._port
            
            self.disconnect()
            return (device_type, unit_id, status, accessible, address, port)
            
        except Exception as e:
            self.logger.error(f"Error getting target info: {e}")
            return ("Unknown", "Unknown", "offline", "False", self._address, self._port)
    
    def enumerate_device(self) -> Dict[str, List[Tuple[str, Any]]]:
        """Enumerate 0MQ device capabilities"""
        result = {}
        
        if not self.connect():
            return result
        
        try:
            # Test different operations based on socket type
            if self._socket_type == ZMQSocketType.REQ:
                # Test request-reply
                test_requests = ["PING", "INFO", "STATUS", "VERSION"]
                responses = []
                
                for req in test_requests:
                    try:
                        resp = self.request_reply(req, timeout=2)
                        if resp:
                            responses.append((req, resp))
                    except:
                        continue
                
                if responses:
                    result['request_reply'] = responses
            
            elif self._socket_type == ZMQSocketType.SUB:
                # Test subscription
                test_topics = ["status", "data", "control", "info"]
                subscribed_topics = []
                
                for topic in test_topics:
                    if self.subscribe(topic):
                        subscribed_topics.append((topic, "subscribed"))
                
                if subscribed_topics:
                    result['subscriptions'] = subscribed_topics
            
            elif self._socket_type == ZMQSocketType.PUB:
                # Test publishing
                test_topics = ["status", "data", "control", "info"]
                published_topics = []
                
                for topic in test_topics:
                    if self.send_message("test", topic):
                        published_topics.append((topic, "published"))
                
                if published_topics:
                    result['publications'] = published_topics
        
        finally:
            self.disconnect()
        
        return result
    
    def check_permissions(self) -> Dict[str, bool]:
        """Check 0MQ device permissions"""
        permissions = {
            'send_messages': False,
            'receive_messages': False,
            'subscribe': False,
            'publish': False,
            'request_reply': False
        }
        
        if not self.connect():
            return permissions
        
        try:
            # Test send permissions
            if self.send_message("test"):
                permissions['send_messages'] = True
            
            # Test receive permissions
            if self.receive_message(timeout=1):
                permissions['receive_messages'] = True
            
            # Test subscribe permissions (for SUB socket)
            if self._socket_type == ZMQSocketType.SUB:
                if self.subscribe("test"):
                    permissions['subscribe'] = True
            
            # Test publish permissions (for PUB socket)
            if self._socket_type == ZMQSocketType.PUB:
                if self.send_message("test", "test"):
                    permissions['publish'] = True
            
            # Test request-reply permissions (for REQ socket)
            if self._socket_type == ZMQSocketType.REQ:
                if self.request_reply("test", timeout=2):
                    permissions['request_reply'] = True
        
        finally:
            self.disconnect()
        
        return permissions
    
    def __del__(self):
        """Cleanup on deletion"""
        if self._socket:
            self.disconnect() 