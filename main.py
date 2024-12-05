from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


# -----------------------------
# 1. Node Class
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
# 2. Graph Class
# -----------------------------
class Graph:
    """
    Represents a graph of nodes (users) with connections (friendships).
    """
    def __init__(self):
        self.nodes = {}  # Stores nodes by their names
        self.edges = {}  # Adjacency list for connections

    def add_node(self, name):
        """
        Adds a new user (node) to the graph.
        """
        node = Node(name)
        self.nodes[name] = node
        self.edges[name] = []

    def add_edge(self, name1, name2):
        """
        Adds a friendship (edge) between two users.
        """
        if name1 in self.nodes and name2 in self.nodes:
            self.edges[name1].append(name2)
            self.edges[name2].append(name1)
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
# 3. Message Class
# -----------------------------
class Message:
    """
    Represents a message sent between users.
    """
    def __init__(self, sender, receiver, content):
        self.sender = sender
        self.receiver = receiver
        self.content = content
        self.encrypted_content = None
        self.signature = None

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
# 4. Main Function
# -----------------------------
def main():
    # Create a graph and add users
    graph = Graph()
    graph.add_node("Alice")
    graph.add_node("Bob")
    graph.add_node("Charlie")
    graph.add_edge("Alice", "Bob")
    graph.add_edge("Bob", "Charlie")

    alice = graph.get_node("Alice")
    bob = graph.get_node("Bob")
    charlie = graph.get_node("Charlie")

    # Specify sender and receiver explicitly
    sender = alice
    receiver = bob

    # Task 1: Send an Encrypted Message
    print("\nTask 3: Encrypted Message")
    message = Message(sender=sender, receiver=receiver, content="Hello Bob, this is Alice.")
    message.encrypt()
    print(f"Encrypted Message from {sender.name} to {receiver.name}: {message.encrypted_content}")

    decrypted_message = message.decrypt()
    print(f"Decrypted Message for {receiver.name}: {decrypted_message}")

    # Task 2: Send a Signed Message
    print("\nTask 4: Signed Message")
    message.sign()
    print(f"Signature by {sender.name}: {message.signature}")

    is_valid = message.verify_signature()
    print(f"Is the Signature Valid? {is_valid}")


# -----------------------------
# Run the Program
# -----------------------------
if __name__ == "__main__":
    main()
