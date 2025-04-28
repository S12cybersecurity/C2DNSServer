import socket
import base64
from dnslib import DNSRecord, RR, A

# DNS server configuration
IP = "0.0.0.0"  # Listen on all interfaces
PORT = 53   	# DNS port

# Dictionary of predefined commands as an example
commands = {
	"ping": "Pong!",
	"info": "System: Windows 10",
	"exit": "Close connection"
}

# Function to process DNS queries
def handle_request(data, addr, sock):
	dns_record = DNSRecord.parse(data)  
	qname = str(dns_record.q.qname)  # Get the queried name
	command = qname.split('.')[0]	# Extract the command (first subdomain)

	print(f"[+] DNS query from {addr}: {qname}")

	# Decode the command (if it's Base64)
	try:
    	decoded_cmd = base64.b64decode(command).decode()
	except:
    	decoded_cmd = command  # If it's not Base64, use it as plain text

	print(f"[+] Command received: {decoded_cmd}")

	# Get the response for the command
	response_data = commands.get(decoded_cmd, "Unrecognized command")

	# Encode the response in Base64 to fit the DNS protocol
	encoded_response = base64.b64encode(response_data.encode()).decode()

	# Create the DNS response
	reply = dns_record.reply()
	reply.add_answer(RR(qname, rdata=A("127.0.0.1")))  # Fake response with localhost
	reply.add_answer(RR(qname, rdata=A(".".join(str(ord(c)) for c in encoded_response[:4]))))  # Response in parts

	# Send the response to the client
	sock.sendto(reply.pack(), addr)

# Start the DNS server
def start_dns_server():
	print(f"[*] DNS server listening on {IP}:{PORT}")
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.bind((IP, PORT))

	while True:
    	data, addr = sock.recvfrom(512)  # Standard DNS query size
    	handle_request(data, addr, sock)

start_dns_server()
