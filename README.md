Argus
=====

Share a wireless sniffer through the cloud.

```
                    +--------+
                    | Argus  |
                    | Broker |
                    +--------+
                      ^    |
                      |    |
          +-----------+    +-------+-----------------+
          |                        |                 |
          |                        v                 v
    +--------+                +---------+       +---------+
    | Argus  |                |  Argus  |       |  Argus  |
    | Probe  |                | Client1 |  ...  | ClientN |
    +--------+                +---------+       +---------+
      |                            |                 |
  +-------+                   +---------+       +---------+
  |sniffer|                   |Wireshark|       |Wireshark|
  +-------+                   +---------+       +---------+
```

At the Argus client:
* `python ArgusClient.py` _(or double-click)_
* Enter the nickname of the probe
* Start Wireshark on your loopback interface

At the Argus probe:
* `python ArgusProbeBeamlogic.py` _(or double-click)_
* Enter the nickname of the probe

At the Argus Broker:
* _unmodified RabbitMQ broker_