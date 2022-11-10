# Master_Theses

Running environment:

  Start layer 2 controller:

  ryu-manager L2.py --ofp-tcp-listen-port 6633

  Start layer 3 controller:

  ryu-manager L3.py --ofp-tcp-listen-port 6655

  Start topology with mininet-wifi:

  sudo python3 tp_mob.py
