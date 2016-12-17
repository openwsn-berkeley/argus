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



class PublishThread(threading.Thread):
    '''
    Thread which publishes sniffed frames to the MQTT broker.
    '''
    
    MQTT_BROKER_HOST    = 'broker.hivemq.com'
    MQTT_BROKER_PORT    = 1883
    MQTT_BROKER_TOPIC   = 'argus/daumesnil'
    
    def __init__(self):
        
        # local variables
        self.client = paho.mqtt.client.Client()
        self.client.on_connect = self._mqtt_on_connect
        self.client.on_message = self._mqtt_on_message
        
        # start the thread
        threading.Thread.__init__(self)
        self.name            = 'SnifferThread'
        self.start()
    
    def run(self):
        self.client.connect(host=self.MQTT_BROKER_HOST, port=1883, keepalive=60)
        self.client.loop_forever()
    
    #======================== public ==========================================
    
    def publishFrame(self,frame):
        paho.mqtt.publish.single(
            
        )
        self.sock.sendto(''.join([chr(b) for b in frame]), ('8.8.8.8', self.ZEP_UDP_PORT))
        #raise NotImplementedError()
    
    #======================== private =========================================
    
    def _mqtt_on_connect(self,client,userdata,flags,rc):
        print("Connected to {0}, rc={1}".format(self.MQTT_BROKER_HOST,rc))
        #self.client.subscribe(self.MQTT_BROKER_TOPIC)
    
    def _mqtt_on_message(self,client,userdata,msg):
        raise SystemError()