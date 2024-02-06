# Master_Theses
This work focuses on the innovation of vehicular networks through the application of software-defined networks
(SDN) to optimize connectivity and decision-making in urban mobility scenarios. Using the Ryu controller, the
Mininet-WiFi emulation environment and the SUMO urban mobility simulator, this research establishes a complete
and realistic experimental environment for the study of vehicular networks.
The Ryu controller plays a key role in the dynamic orchestration of network decisions, enabling continuous
adaptation to changes in the topology and communication demands of vehicular networks. Mininet-WiFi offers the
ability to emulate mobility scenarios, making it possible to analyze connectivity and performance in dynamic urban
environments. In addition, the SUMO simulator accurately replicates urban roads, providing realistic modeling of
the vehicle movements.
The combination of these tools allows a comprehensive evaluation of the performance of vehicular networks in
urban environments, as well as the study of resource management strategies and real-time decision-making. This
research contributes to the advancement of vehicular communication technologies and offers valuable insights for
the development of an efficient and safe urban mobility solutions.
This study highlights the importance of integrating SDN, mobility emulation and road simulation to improve
connectivity and quality of service in vehicular networks, providing a solid foundation for further researches in the
area.

In order to develop a proof of concept and explore the different capabilities that an SDN network can offer, it was
decided to create a topology fully managed by an SDN controller. To do this, it is necessary to define a topology,
select a controller and even an IDE or code editor in order to program applications to use the functionalities offered
by the controller.

Running environment:

  Starting controller:

  ryu-manager L3.py --ofp-tcp-listen-port 6655

  Start topology with mininet-wifi:

  sudo python3 tp_mob.py
