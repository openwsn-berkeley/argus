'''
Argus client script which attaches to the broker and sends
sniffed packets to some IP address using ZEP encapsulation.
'''

import pika
import sys
import socket

RMQ_EXCHANGE = "beamlogic_sniffer"
RMQ_ROUTING_KEY = "packet"
ZEP_PORT = 17754

# Where we are going to send traffic
UDP_IP = "localhost"

connection = pika.BlockingConnection(pika.ConnectionParameters(
    host='localhost'))
channel = connection.channel()

result = channel.queue_declare(exclusive=True)
queue_name = result.method.queue

channel.queue_bind(exchange=RMQ_EXCHANGE,
	queue=queue_name,
	routing_key=RMQ_ROUTING_KEY)

sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP

recv_sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
recv_sock.bind((UDP_IP, ZEP_PORT))

print(' [*] Waiting for logs. To exit press CTRL+C')

def callback(ch, method, properties, body):
    timestamp, raw_packet = body.split("-")
    packet = raw_packet.strip().split(" ")
    beamlogic_header = packet[:19]
    print("======")
    print(raw_packet)
    print('beam logic =>', beamlogic_header)
    print('timestamp', packet[1:8])
    print('channel', int(packet[9], 16))
    print('RSSI', int(packet[10], 16))
    print('GPS latitude', packet[11:15])
    print('GPS longitude', packet[15:19])
    print("======")
    sock.sendto(body, (UDP_IP, ZEP_PORT))

channel.basic_consume(callback,
	queue=queue_name,
	no_ack=True)

channel.start_consuming()
