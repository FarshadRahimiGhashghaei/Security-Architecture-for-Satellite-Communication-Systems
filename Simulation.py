import random
from datetime import datetime
import numpy as np
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# RSA Encryption and Decryption
class RSAEncryption:
    def __init__(self):
        self.keys = {}

    def encrypt(self, data, public_key_pem):
        public_key = RSA.import_key(public_key_pem)
        cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
        encrypted_data = cipher.encrypt(data.encode('utf-8'))
        return encrypted_data

    def decrypt(self, encrypted_data, private_key_pem):
        private_key = RSA.import_key(private_key_pem)
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        decrypted_data = cipher.decrypt(encrypted_data)
        return decrypted_data.decode('utf-8')

rsa_encryption = RSAEncryption()

# Simulate Quantum Key Distribution (QKD)
class QKD:
    def __init__(self):
        self.keys = {}

    def generate_key(self, satellite, ground_station):
        num_qubits = 10
        alice_bits = np.random.randint(2, size=num_qubits)
        alice_bases = np.random.randint(2, size=num_qubits)
        bob_bases = np.random.randint(2, size=num_qubits)
        matching_bases = (alice_bases == bob_bases)
        alice_key = [alice_bits[i] for i in range(num_qubits) if matching_bases[i]]
        key = alice_key[0] if alice_key else 0  # Using the first bit as the key for simplicity
        self.keys[(satellite, ground_station)] = key

        # Display qubit states and basis states
        print(f"QKD Key generation between {satellite} and {ground_station}:")
        print(f"Alice's bits: {alice_bits}")
        print(f"Alice's bases: {alice_bases}")
        print(f"Bob's bases: {bob_bases}")
        print(f"Matching bases: {matching_bases}")
        print(f"Alice's key: {alice_key}")
        print(f"Final key: {key}")

        return key

    def get_key(self, satellite, ground_station):
        return self.keys.get((satellite, ground_station))

# Define roles and users
roles = {
    'admin': ['add_user', 'remove_user', 'access_sensitive_data'],
    'user': ['access_data'],
    'guest': ['access_public_data']
}

users = {
    'alice': {'role': 'admin', 'mfa': True},
    'bob': {'role': 'user', 'mfa': True},
    'charlie': {'role': 'guest', 'mfa': False}
}

# Define network segments
class NetworkSegment:
    def __init__(self, name):
        self.name = name
        self.allowed_roles = []
        self.traffic = []

    def add_allowed_role(self, role):
        self.allowed_roles.append(role)

    def add_traffic(self, user, data):
        if users[user]['role'] in self.allowed_roles:
            self.traffic.append((user, data))
            print(f"Traffic added to {self.name} by {user}: {data}")
        else:
            print(f"Access denied for {user} to {self.name}")

# Define segments
segments = {
    'public': NetworkSegment('public'),
    'internal': NetworkSegment('internal'),
    'sensitive': NetworkSegment('sensitive')
}

# Set allowed roles for each segment
segments['public'].add_allowed_role('guest')
segments['internal'].add_allowed_role('user')
segments['internal'].add_allowed_role('admin')
segments['sensitive'].add_allowed_role('admin')

# Satellite and Ground Station classes
class Satellite:
    def __init__(self, name):
        self.name = name
        self.channels = {}
        self.rsa_keys = {}

    def add_channel(self, ground_station, secure=True, method='QKD'):
        if secure:
            if method == 'QKD':
                key = qkd.generate_key(self.name, ground_station.name)
                self.channels[ground_station] = (key, method)
            elif method == 'RSA':
                private_key = RSA.generate(2048)
                public_key = private_key.publickey()
                private_key_pem = private_key.export_key()
                public_key_pem = public_key.export_key()
                self.rsa_keys[ground_station] = private_key_pem
                self.channels[ground_station] = (public_key_pem, method)
                print(f"RSA Key pair generated for {self.name} and {ground_station.name}")
        else:
            self.channels[ground_station] = (None, None)

    def transmit_data(self, ground_station, user, data):
        if ground_station in self.channels:
            key, method = self.channels[ground_station]
            if key is not None:
                if method == 'QKD':
                    # Encrypt data using a simple XOR with the QKD key
                    encrypted_data = ''.join(chr(ord(char) ^ key) for char in data)
                elif method == 'RSA':
                    encrypted_data = rsa_encryption.encrypt(data, key)
                print(f"{self.name} transmitted encrypted data to {ground_station.name}: {encrypted_data}")
                ground_station.receive_data(self, user, encrypted_data, key, method)
            else:
                print(f"{self.name} transmitted data to {ground_station.name}: {data}")
                ground_station.receive_data(self, user, data, key, method)
        else:
            print(f"{self.name} has no channel to {ground_station.name}")

class GroundStation:
    def __init__(self, name):
        self.name = name
        self.segments = segments

    def receive_data(self, satellite, user, data, key, method):
        if key is not None:
            if method == 'QKD':
                # Decrypt data using a simple XOR with the QKD key
                decrypted_data = ''.join(chr(ord(char) ^ key) for char in data)
            elif method == 'RSA':
                decrypted_data = rsa_encryption.decrypt(data, satellite.rsa_keys[self])
            print(f"{self.name} received decrypted data from {satellite.name}: {decrypted_data}")
            self.segments['sensitive'].add_traffic(user, decrypted_data)
        else:
            print(f"{self.name} received data from {satellite.name}: {data}")
            self.segments['public'].add_traffic(user, data)

# Create QKD instance and RSAEncryption instance
qkd = QKD()
rsa_encryption = RSAEncryption()

# Create satellites and ground stations
satellites = [Satellite(f"Satellite_{i+1}") for i in range(3)]
ground_stations = [GroundStation(f"Ground_Station_{i+1}") for i in range(3)]

# Establish channels between satellites and ground stations
satellites[0].add_channel(ground_stations[0], secure=True, method='QKD')
satellites[1].add_channel(ground_stations[1], secure=True, method='QKD')
satellites[2].add_channel(ground_stations[2], secure=True, method='QKD')
satellites[0].add_channel(ground_stations[0], secure=True, method='RSA')
satellites[1].add_channel(ground_stations[1], secure=True, method='RSA')
satellites[2].add_channel(ground_stations[2], secure=True, method='RSA')

# Simulate adding traffic
satellites[0].transmit_data(ground_stations[0], 'alice', 'sensitive_data')
satellites[1].transmit_data(ground_stations[1], 'bob', 'user_data')
satellites[2].transmit_data(ground_stations[2], 'charlie', 'public_data')

# Define threat detection
class ThreatDetection:
    def __init__(self):
        self.threats_detected = 0
        self.log = []

    def detect_threat(self, segment, user, action):
        # Simple rule: if a guest tries to access internal or sensitive data, it's a threat
        if segment in ['internal', 'sensitive'] and users[user]['role'] == 'guest':
            self.threats_detected += 1
            self.log.append((datetime.now(), user, segment, action))
            print(f"Threat detected: {user} tried to {action} in {segment}")

threat_detection = ThreatDetection()

# Example threat detection
threat_detection.detect_threat('internal', 'charlie', 'access_data')

# Simulate Multi-Factor Authentication (MFA)
class MFA:
    def __init__(self):
        self.authenticated_users = set()

    def authenticate(self, user):
        if users[user]['mfa']:
            self.authenticated_users.add(user)
            print(f"{user} authenticated successfully with MFA.")
        else:
            print(f"{user} failed MFA authentication.")

mfa = MFA()
mfa.authenticate('alice')
mfa.authenticate('bob')
mfa.authenticate('charlie')

# Simulate incident response
class IncidentResponse:
    def __init__(self):
        self.incidents = []

    def respond_to_incident(self, incident):
        print(f"Responding to incident: {incident}")
        self.incidents.append(incident)

incident_response = IncidentResponse()
for log_entry in threat_detection.log:
    incident_response.respond_to_incident(log_entry)
