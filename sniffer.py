#!/usr/bin/env python

import subprocess
import pika

RMQ_EXCHANGE = "beamlogic_sniffer"
RMQ_ROUTING_KEY = "packet"
RMQ_HOST = "localhost"

# In case it complains, you can use

#subprocess.call(["sudo", "rmmod", "ftdi_sio", "usbserial", "pl2303"])

proc = subprocess.Popen(['./adaptor', '-i', '4'],
                        stdout=subprocess.PIPE)

connection = pika.BlockingConnection(pika.ConnectionParameters(host=RMQ_HOST))
channel = connection.channel()

channel.exchange_declare(exchange=RMQ_EXCHANGE, type='topic')


while True:
  line = proc.stdout.readline()
  if line != '':
    #the real code does filtering here
    message =  line.rstrip()
    channel.basic_publish(exchange=RMQ_EXCHANGE,
                          routing_key=RMQ_ROUTING_KEY,
                          body=message)
  else:
    break
