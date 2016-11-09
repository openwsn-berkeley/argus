Argus
=====

Sniff once, replay live and everywhere

How to launch it?
-----------------

- On the sniffer side configure it by specifying the exchange (RMQ_EXCHANGE)
  and routing key (RMQ_ROUTING_KEY) you want to send packet to.
  All packets sniffed will be send over AMQP to the broker and redistributed to
  the clients.

- On the client side, just launch it with the same exchange and routing key.
  The program will replay all the traffic on your local loop.
  You can of course launch several client and replay traffic from any sniffer
  that is streaming its packets.
