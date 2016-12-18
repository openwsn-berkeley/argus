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
        |                          |                 |
    +--------+                +---------+       +---------+
    | sniffer|                |Wireshark|       |Wireshark|
    +--------+                +---------+       +---------+
```

At the Argus Probe:
* start `SiteAnalyzerAdapter.exe`
* close Wireshark
* `python ArgusProbe_Beamlogic.py` _(or double-click)_

At the Argus client:
* `python ArgusClient.py` _(or double-click)_

At the Argus Broker:
* _unmodified MQTT broker_
