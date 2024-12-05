from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from collections import deque
import numpy as np

# -----------------------------
# 1. Node Class (with RSA Encryption and Signing)
# -----------------------------
class Node:
    """
    Represents a user in the system with RSA keys.
    """
    def __init__(self, name):
        self.name = name
        self.private_key, self.public_key = self.generate_rsa_keys()

    def generate_rsa_keys(self):
        """
        Generates a pair of RSA keys (public and private).
        Returns:
            tuple: private_key (bytes), public_key (bytes)
        """
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key


# -----------------------------
# 2. Graph Class (for managing users and connections)
# -----------------------------
class Graph:
    """
    Represents a graph of nodes (users) with connections (friendships).
    """
    def __init__(self):
        self.nodes = {}  # Stores nodes by their names
        self.edges = {}  # Adjacency list for connections

    def add_person(self, person_id, person_data=None):
        """
        Adds a new user (node) to the graph.
        """
        node = Node(person_id)
        self.nodes[person_id] = node
        self.edges[person_id] = []

    def add_connection(self, person1, person2):
        """
        Adds a friendship (edge) between two users.
        """
        if person1 in self.nodes and person2 in self.nodes:
            self.edges[person1].append(person2)
            self.edges[person2].append(person1)
        else:
            raise ValueError("Both users must exist in the graph")

    def get_node(self, name):
        """
        Retrieves a node by name.
        """
        if name not in self.nodes:
            raise ValueError(f"User '{name}' does not exist.")
        return self.nodes[name]


# -----------------------------
# 3. Message Class (with encryption, decryption, signing, verifying, and FFT compression)
# -----------------------------
class Message:
    """
    Represents a message sent between users.
    """
    def __init__(self, sender, receiver, content, original_length=None):
        self.sender = sender
        self.receiver = receiver
        self.content = content
        self.original_length = original_length
        self.encrypted_content = None
        self.signature = None
        self.message_body = content

    def encrypt(self):
        """
        Encrypts the message content using the receiver's public key.
        """
        receiver_key = RSA.import_key(self.receiver.public_key)
        cipher = PKCS1_OAEP.new(receiver_key)
        self.encrypted_content = cipher.encrypt(self.content.encode())

    def decrypt(self):
        """
        Decrypts the message content using the receiver's private key.
        """
        receiver_key = RSA.import_key(self.receiver.private_key)
        cipher = PKCS1_OAEP.new(receiver_key)
        decrypted_content = cipher.decrypt(self.encrypted_content)
        return decrypted_content.decode()

    def sign(self):
        """
        Signs the message content using the sender's private key.
        """
        sender_key = RSA.import_key(self.sender.private_key)
        message_hash = SHA256.new(self.content.encode())
        self.signature = pkcs1_15.new(sender_key).sign(message_hash)

    def verify_signature(self):
        """
        Verifies the signature of the message using the sender's public key.
        Returns:
            bool: True if the signature is valid, False otherwise.
        """
        sender_key = RSA.import_key(self.sender.public_key)
        message_hash = SHA256.new(self.content.encode())
        try:
            pkcs1_15.new(sender_key).verify(message_hash, self.signature)
            return True
        except (ValueError, TypeError):
            return False

# -----------------------------
# 4. FFT Compression and Decompression
# -----------------------------
def fft_compress(message: str, blur_factor: float) -> str:
    ascii_values = np.array([ord(char) for char in message])
    fft_result = np.fft.fft(ascii_values)
    num_components_to_keep = int(len(fft_result) * blur_factor)
    fft_result[num_components_to_keep:] = 0
    compressed_values = np.fft.ifft(fft_result).real
    compressed_message = ''.join(chr(int(round(value))) for value in compressed_values)
    return compressed_message

def fft_decompress(compressed_message: str, original_length: int) -> str:
    compressed_values = np.array([ord(char) for char in compressed_message])
    fft_result = np.fft.fft(compressed_values)
    num_components_to_keep = int(len(fft_result) * 0.5)
    fft_result[num_components_to_keep:] = 0
    recovered_values = np.fft.ifft(fft_result).real
    recovered_message = ''.join(chr(int(round(value))) for value in recovered_values[:original_length])
    return recovered_message

# -----------------------------
# 5. BFS Function to Find Path Between Users
# -----------------------------
def bfs(graph, start, goal):
    queue = deque([(start, [start])])
    visited = set()

    while queue:
        node, path = queue.popleft()
        if node == goal:
            return path
        if node not in visited:
            visited.add(node)
            for neighbor in graph.edges[node]:
                if neighbor not in visited:
                    queue.append((neighbor, path + [neighbor]))
    return None

# -----------------------------
# 6. Main Function
# -----------------------------
def main():
    # Create a graph and add users
    graph = Graph()
    graph.add_person("Alice")
    graph.add_person("Bob")
    graph.add_person("Charlie")
    graph.add_person("David")
    graph.add_connection("Alice", "Bob")
    graph.add_connection("Bob", "Charlie")
    graph.add_connection("Charlie", "David")

    alice = graph.get_node("Alice")
    bob = graph.get_node("Bob")
    charlie = graph.get_node("Charlie")
    david = graph.get_node("David")

    # Task 1: Encrypted Message
    print("\nTask 1: Encrypted Message")
    message = Message(sender=alice, receiver=bob, content="Hello Bob, this is Alice.")
    message.encrypt()
    print(f"Encrypted Message from {alice.name} to {bob.name}: {message.encrypted_content}")

    decrypted_message = message.decrypt()
    print(f"Decrypted Message for {bob.name}: {decrypted_message}")

    # Task 2: Signed Message
    print("\nTask 2: Signed Message")
    message.sign()
    print(f"Signature by {alice.name}: {message.signature}")

    is_valid = message.verify_signature()
    print(f"Is the Signature Valid? {is_valid}")

    # Task 3: FFT Compression
    print("\nTask 3: FFT Compression")
    original_message = "This is a test message that will be blurry after FFT compression."
    blur_factor = 0.2
    compressed_message = fft_compress(original_message, blur_factor)

    message = Message(
        sender=alice,
        receiver=bob,
        content=compressed_message,
        original_length=len(original_message)
    )

    print("\nCreated Message (FFT Compressed):")
    print(message)

    path = bfs(graph, "Alice", "Bob")
    print("\nPath from Alice to Bob:", path)

    decompressed_message = fft_decompress(message.message_body, message.original_length)
    print("\nDecompressed Message:", decompressed_message)


# -----------------------------
# Run the Program
# -----------------------------
if __name__ == "__main__":
    main()
