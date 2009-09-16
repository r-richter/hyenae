--------------------------------------------------------------------------------

                                Hyenae Readme

--------------------------------------------------------------------------------

  Hyenae
    Advanced Network Packet Generator

  Copyright (C) 2009  Robin Richter

  Contact  : richterr@users.sourceforge.net
  Homepage : http://sourceforge.net/projects/hyenae/

--------------------------------------------------------------------------------

  1. About Hyenae

  Hyenae is a highly flexible and platform independent network packet generator.
  It allows you to reproduce low level ethernet attack scenarios (such as MITM,
  DoS and DDoS) to reveal potential security vulnerabilities of your network.
  Besides smart wildcard-based address randomization, a highly customizable
  packet generation control and an interactive attack assistant, Hyenae comes
  with a clusterable remote daemon for setting up distributed attack networks.

  Hyenae was developed with ease-of-use in mind while still remaining flexible
  and configurable. To realize this aim, Hyenae uses address patterns, which
  will minimize the number of arguments you have to provide because all
  necessary parameters, such as the way you want to randomize your addresses or
  the IP address version to use, can be derived from the pattern format you
  provided. See section 5, "Address Patterns", for more detailed information.

  This utility suite was developed only for network security testing purposes
  such as evaluation of firewall rules, flood detection and intrusion detection.
  Hyenae's developers disclaim all liability for any direct, indirect or
  consequential damages arising out of or connected with the use or misuse of
  Hyenae Utility Suite. The user alone assumes all risks and responsibility of
  his/her own actions associated with the use of the Hyenae Utility Suite. Every
  effort has been made to supply accurate information related to Hyenae. It is
  subject to change without prior notice.

--------------------------------------------------------------------------------

  2. Current Features

  * Platform independence
  * Assisted ARP-Request flood setup
  * Assisted ARP-Cache poisoning setup
  * Assisted PPPoE session initiation flood setup
  * Assisted Blind PPPoE session termination setup
  * Assisted ICMP-Echo flood setup
  * Assisted ICMP-Smurf attack setup
  * Assisted ICMP based TCP-Connection reset setup
  * Assisted TCP-SYN flood setup
  * Assisted TCP-Land attack setup
  * Assisted Blind TCP-Connection reset setup
  * Assisted UDP flood setup
  * Assisted DNS-Query flood setup
  * Assisted DHCP-Discover flood setup
  * Assisted DHCP starvation setup
  * Assisted DHCP-Release forcing setup
  * Customizable ARP-Reply based attacks
  * Customizable PPPoE-Discover based attacks
  * Customizable ICMP-Echo based attacks (IPv4 and IPv6)
  * CUstomizable ICMP "Destination Unreachable" based attacks (IPv4)
  * Customizable TCP based attacks (IPv4 and IPv6)
  * Customizable UDP based attacks (IPv4 and IPv6)
  * Customizable DNS-Query based attacks (IPv4 and IPv6)
  * Customizable DHCP-Discover based attacks (IPv4)
  * Customizable DHCP-Request based attacks (IPv4)
  * Customizable DHCP-Release based attacks (IPv4)
  * Random or fixed packet count and or attack duration
  * Random or fixed send delay for breaking flood detections
  * Pattern based packet address configuration
  * Intelligent address and address protocol detection
  * Smart wildcard-based randomization
  * Daemon for setting up remote attack networks

--------------------------------------------------------------------------------

  3. Command Line Usage (hyenae)

  hyenae (Starts attack assistant...)

  hyenae [-s src-pat] [-d dst-pat] [-S sec-src-pat] [-D sec-dst-pat]
         [-i if-n] [-I if-i] [-r srv-pat] [-R srv-file] [-a att-type]
         [-A ip-v-asm] [-t ip-ttl] [-o opcode] [-f tcp-flags]
         [-k tcp-ack] [-w tcp-win] [-q seq-sid] [-Q seq-sid-ins]
         [-y dns_qry] [-c min-cnt] [-C max-cnt] [-e min-del] [-E max-del]
         [-u min-dur] [-U max-dur] [-p rnd-payload] [-P payload-file]
         [-mNlLV]

    -s Source address pattern

    -d Destination address pattern

    -S Secondary source address pattern. Defines the sender address on ARP-Reply
       attacks, the requested IP-Address on DHCP-Request attacks and the TCP
       source address pattern on TCP based ICMP "Destination Unreachable"
       attacks.

    -D Secondary destination address pattern. Defines the target address on
       ARP-Reply attacks, the server identifier (IP-Address) on DHCP-Release
       attacks  and the TCP destination address pattern on TCP based ICMP
       "Destination Unreachable" attacks.

    -i Network interface to operate on (specified by name). This argument is
       ignored on remote attacks.

    -I Network interface to operate on (specified by index). A list
       of all available network interfaces and their indexes can be obtained
       by starting Hyenae with the -l option. This argument is ignored on remote
       attacks.

    -r Single remote attack. If set, Hyenae will execute the specified attack
       on the Hyenae Daemon specified by the given server address pattern. A
       server address pattern has the following pattern format:

         // For plain connections
         [IP-Address]@[Port]

         // For password protected daemons
         [IP-Addresss]@[Port]+[Password]

       Hyenae will automatically recognize the provided IP address version.
       Wildcards are not valid within server address patterns. The password
       strip is only required when connecting to a Hyenae Daemon which has
       activated password authentication. Note: Since Hyenae currently does not
       support encrypted communication, your password is transferred in plain
       text, and can be logged by others.

    -R Clustered remote attack. If set, Hyenae will simultaneously execute the
       specified attack using the Hyenae Daemons specified in the server file at
       the given path. A server list file should have the following format:

         # Comment
         Server=[IP-Address]@[Port]
         Server=[IP-Address]@[Port]+[Password]
         ...

       Hyenae will automatically recognize the version of the IP address
       provided. Wildcards are not valid within server address patterns. The
       password strip is only required when connecting to a Hyenae Daemon which
       has activated password authentication. Note: Since Hyenae currently does
       not support encrypted communication, your password is transferred in
       plain text, and can be logged by others.

    -a Attack protocol. A list of all available attacks can be obtained by
       starting Hyenae with the -L option.

    -A IP address version to assume when a completely random IP strip is found
       within an address pattern. This value can be either 4 or 6. By default
       this is set to 4 (IPv4).

    -t Defines the hop limit (TTL) on IP based attacks. The hop limit can be a
       value between 1 and 255. If not set, a hop limit size of 128 will be
       used.

    -o Defines the ICMP "Destination Unreachable" message code on ICMP
       "Destination Unreachable" based attacks or the PPPoE discover code on
       PPPoE-Discover based attacks.

       Valid values on PPPoE attacks:

         padi (Active Discovery Initiation)
         padt (Active Discovery Termination)

       Valid values on ICMP attacks:

         network  (Network Unreachable)
         host     (Host Unreachable)
         protocol (Protocol Unreachable)
         port     (Port Unreachable)

    -f TCP flags. This option is required on TCP attacks and defines the TCP
       control flags to set for the generated packets. Valid values are any
       combination of:

         F (FIN)
         S (SYN)
         R (RST)
         P (PSH)
         A (ACK)

    -k TCP acknowledgement number. Defines the TCP acknowledgement number to use
       on TCP based attacks. If not set or set to 0, an acknowledgement number
       of 0 will be used.

    -w TCP window size. Defines the TCP window size to use on TCP based attacks.
       If not set or set to 0, a window size of 0 will be used.

    -q TCP sequence number / PPPoE session id. Defines the TCP sequence number
       on TCP based, or the session id on PPPoE-Discover based attacks. If not
       set or set to 0 on TCP based attacks, every generated packet (unless a
       step value was given) will carry a completely randomized sequence number.
       If set to 0 on PPPoE attacks, every generated packet (unless a step value
       was given) will carry the session id 0. If a sequence number or session
       id incrementation step value was given, this argument will be used as
       the initial sequence number or session id to be incremented.

    -Q TCP sequence number / PPPoE session id incrementation steps. If set, the
       sequence number or session id of every generated packet will be
       incremented by the given value.

    -y DNS query pattern. A DNS query pattern is required on DNS-Query based
       attacks to define the list of domain names to query. The list should have
       the following format:

       # Single DNS query
       [www.domain1.com]

       # Multiple DNS queries
       [www.domain1.com],[www.domain2.com],...

    -c Minimum number of packets to generate. If not set or set to 0, an
       unlimited amount of packets will be generated, unless an attack duration
       was set. If you provide a maximum number of packets to generate, the
       minimum number of packets will be automatically set to one. If not set or
       set to 0 on remote attacks, the packet limit of the daemon will be used
       instead.

    -C Maximum number of packets to generate. If not set or set to 0, the
       specified minimum number of packets (-c X) will be generated. If no
       minimum number of packets to generate is specified, an unlimited
       amount of packets will be generated.

    -e Minimum number of milliseconds to wait until the next packet is sent.

    -E Maximum number of milliseconds that may pass before the next packet is
       sent. If set, Hyenae will wait a random number of milliseconds between
       the minimum (-e X or 0 if not set) and the maximum number (-E X) before
       sending the next packet. This is useful for breaking flood detections.

    -u Minimum attack duration in milliseconds. If not set or set to 0, the
       attack duration will be endless, unless a packet count was given. If not
       set or set to 0 on remote attacks, the attack duration limit of the
       daemon will be used instead.

    -U If set, Hyenae will stop the attack when a duration of a random number
       of milliseconds between the minimum (-u X or 0 if not set) and the
       maximum number (-U X) is reached.

    -p Random packet payload. If set, a random data block (payload) of the
       given length will be added to the generated packets (if supported by the
       chosen attack type). By default all packets will be generated with an
       empty data block.  If the total length of the packet (including the
       protocol headers) exceeds the MTU limit and Hyenae was called without the
       -m option, an error occurs. The total length of a packet depends on IP
       protocol and the attack type used. The default MTU limit is 1500 bytes.

    -P File-based packet payload. If set, the contents of a file at the
       given path will be added as the data block (payload) of the generated
       packets.  If the total length of the packet (including the protocol
       headers) exceeds the MTU limit and Hyenae was called without the -m
       option, an error occurs. The total length of a packet depends on IP
       protocol and the attack type used. The default MTU limit is 1500 bytes.

    -m If set, the default MTU limit of 1500 bytes will be ignored and even
       packets with a length greater than 1500 bytes will by sent. If the packet
       length exceeds the supported MTU limit, pcap will fail to write the data
       to the network. You should never provide this option unless you know what
       you are doing.

    -N No sending (cold run). If set, Hyenae will start a run through its attack
       routines without actually writing any data to the network. This can be
       very useful to pre-check the generated packets or the remote daemon
       behaviour before executing the actual attack.

    -l Prints a list of all available network interfaces and exits.

    -L Prints a list of all available attacks and exits.

    -V Prints the current version of Hyenae and exits.

--------------------------------------------------------------------------------

  4. Command Line Usage (hyenaed)

  hyenaed [-i if-n] [-I if-i] [-a bind-ip] [-p port] [-b bcklog]
          [-t tru-ip-lst] [-T none-tru-ip-lst] [-A ip-v]
          [-c cli-pkt-lmt] [-u cli-dur-lmt] [-m max-cl]
          [-k pwd] [-flV]

    -i Network interface to attack on (specified by name). This will not set
       the network interface on which to listen for connections.

    -I Network interface to attack on (specified by index). This will not set
       the network interface on which to listen for connections. A list of all
       available network interfaces and their indexes can be obtained by
       starting Hyenae with the -l option.

    -a IP address to bind the daemon's server socket to. The default value is
       127.0.0.1 (localhost). The Hyenae Daemon can not be bound to the
       network interface you want to attack from.

    -p The port number on which the daemon shall listen for incoming
       connections. By default the daemon will listen on port 666.

    -b Number of backlog connections the daemon shall handle. The default
       value is 5.

    -t Trusted IP address list. Specifies an IP list file which will be used as
       a trusted list of IP addresses. If set, only clients using the specified
       IP addresses will be allowed to connect to the daemon. An IP address list
       has the following format:

         # Comment
         IP-Address=[IP-Address]
         IP-Address=[IP-Address]
         ...

       Wildcards are not valid within IP address list files.

    -T Untrusted IP address list. Specifies an IP list file which will be
       used as a list of untrusted IP addresses. If set, all clients using
       the specified IP addresses will not be able to connect to the daemon. An
       IP address list has the following format:

         # Comment
         IP-Address=[IP-Address]
         IP-Address=[IP-Address]
         ...

       Wildcards are not valid within IP address list files.

    -A IP version the listening socket shall use. This can be either 4 or 6.
       The default version is 4 (IPv4).

    -c Packet limit for clients. Specifies the maximum number of packets a
       single client can request to attack with. If not set or set to 0, you
       must specify an attack duration limit.

    -u Attack duration limit for clients. Specifies the maximum number of
       milliseconds a single client can request to attack for. If not set or set
       to 0, you must specify a packet limit.

    -m Maximum number of clients allowed to connect. The default value is 10.

    -k Password protection. If set, only clients which are using this password
       will be able to control this daemon. Note: Since Hyenae currently does
       not support encrypted communication, your password is transferred in
       plain text, and can be logged by others.

    -f Log-File path. By default, all daemon logs will be written to
       /var/log/hyenaed.log on *nix systems or .\hyenaed.log on windows
       systems.

    -l Prints a list of all available network interfaces and exits.

    -V Prints the current version of Hyenae and exits.

--------------------------------------------------------------------------------

  5. Address Patterns

  Hyenae uses address patterns to define the source and destination address
  (and for ARP-Replies, sender and target as well) of the generated packets.
  Each pattern can contain wildcards to randomize certain octets or even the
  whole address strip or port. Hyenae uses an address adequate randomization
  algorithm that makes sure to produce valid addresses. As an example, if you
  have a pattern with an IP address strip like 25%.168.0.1, Hyenae will
  recognize that it can only place a random value from 0 to 5 here. It will
  also use the required notation (decimal or hexadecimal) and detect that the
  specified address is an IPv4 address and will use the IPv4 protocol for the
  given attack (if possible). Address patterns can have the following formats:

    [HW-Address]-[IP-Address]@[Port]
    [HW-Address]-[IP-Address]
    [HW-Address]

  Hyenae will automatically recognize the pattern and even every single
  address format (HW, IPv4 or IPv4), so you don't have to pass extra arguments,
  since everything we need to know can be derived from the given pattern. If you
  want to randomize a complete address strip (HW-Address or IP-Address) simply
  put a single % in it:

    %-192.1%%.%.%%@%2%

  This one will use a random hardware address and a partially randomized IP
  address, adequate to the octet digits you specified. Notice that you can
  even specify the number of random octet digits to create (but make sure that
  the number of digits within the octet is valid for the used format), the last
  octet of the IP address strip will be a random 2 digit value. The same works
  within the port strip (separated by an '@'), the more wildcards you place,
  the more digits the random port number will have. In the example above, the
  port number will be 3 digits long and will also have a 2 within its center.
  Here are some examples:

    // Ok
    00:D2:F%:D4:DD:%%-192.168.%%.%@%%
    %-192.168.%%%.%@%%
    00:D2:F%:D4:DD:%%-%@%%
    %-%@%
    %-%

    // Error: HW address octets have a fixed length of 2 digits!
    00:%:00::00:00:00-192.168.0.1@21

  If you are using only a single wildcard as the IP address strip, Hyenae will
  generate a complete random IP address. By default, Hyenae will interpret or
  "assume" random IP address strips as IPv4 addresses. You can change the
  assumed version by calling Hyenae with the -A option.

  In some cases you will need to randomize a pattern equaly to another one. If
  you are generating ARP packets for example, the source hardware address needs
  equal the senders hardware address otherwise the packet will be droped by the
  target host. In such a case, Hyenae will use an equal randomization on both of
  the patterns (aas long as they match each other).

  // HW-Address randomization on ARP packets

  // HW-Address strip Will be equaly randomized
  Source Pattern: %
  Sender Pattern: %-192.168.0.1

  // HW-Address strip Will be equaly randomized
  Source Pattern: %%:22:33:44:55:66
  Sender Pattern: %%:22:33:44:55:66-192.168.0.1

  // HW-Adress strip won't be equaly randomized
  Source Pattern: 11:%%:33:44:55:66
  Sender Pattern: %%:22:33:44:55:66-192.168.0.1

--------------------------------------------------------------------------------

  6. Attack Synopsis

  hyenae -a arp-reply
         -s [HW-Address]
         -d [HW-Address]
         -S [HW-Address]-[IP-Address (IPv4 only)]
         -D [HW-Address]-[IP-Address (IPv4 only)]

  hyenae -a arp-request
         -s [HW-Address]
         -d [HW-Address]
         -S [HW-Address]-[IP-Address (IPv4 only)]
         -D [HW-Address]-[IP-Address (IPv4 only)]

  hyenae -a pppoe-discover
         -s [HW-Address]
         -d [HW-Address]
         -o [PPPoE Discovery Code]
  Optional:
         -q [PPPoE Session ID Offset]
         -Q [PPPoE Session ID Incrementation Steps]

  hyenae -a icmp-echo
         -s [HW-Address]-[IP-Address (IPv4 or IPv6)]
         -d [HW-Address]-[IP-Address (IPv4 or IPv6)]
  Optional:
         -t [IP Time To Live (TTL)]

  hyenae -a icmp-unreach-tcp
         -s [HW-Address]-[IP-Address (IPv4 only)]
         -d [HW-Address]-[IP-Address (IPv4 only)]
         -S [HW-Address]-[IP-Address (IPv4 only)]@[Port]
         -D [HW-Address]-[IP-Address (IPv4 only)]@[Port]
         -o [ICMP Message Code]
  Optional:
         -t [IP Time To Live (TTL)]
         -k [TCP Achnkowledgement Number]
         -w [TCP Window Size]
         -q [TCP Sequence Number Offset]
         -Q [TCP Sequence Number Incrementation Steps]

  hyenae -a tcp
         -s [HW-Address]-[IP-Address (IPv4 or IPv6)]@[Port]
         -d [HW-Address]-[IP-Address (IPv4 or IPv6)]@[Port]
         -f [TCP-Flags]
  Optional:
         -t [IP Time To Live (TTL)]
         -k [TCP Achnkowledgement Number]
         -w [TCP Window Size]
         -q [TCP Sequence Number Offset]
         -Q [TCP Sequence Number Incrementation Steps]

  hyenae -a udp
         -s [HW-Address]-[IP-Address (IPv4 or IPv6)]@[Port]
         -d [HW-Address]-[IP-Address (IPv4 or IPv6)]@[Port]
  Optional:
         -t [IP Time To Live (TTL)]

  hyenae -a dns-query
         -s [HW-Address]-[IP-Address (IPv4 or IPv6)]
         -d [HW-Address]-[IP-Address (IPv4 or IPv6)]
         -y [DNS query pattern]
  Optional:
         -t [IP Time To Live (TTL)]

  hyenae -a dhcp-discover
         -s [HW-Address]-[IP-Address (IPv4 only)]
         -d [HW-Address]-[IP-Address (IPv4 only)]
  Optional:
         -t [IP Time To Live (TTL)]
         -S [IP-Address (IPv4 only)]

  hyenae -a dhcp-request
         -s [HW-Address]-[IP-Address (IPv4 only)]
         -d [HW-Address]-[IP-Address (IPv4 only)]
         -D [IP-Address (IPv4 only)]
  Optional:
         -t [IP Time To Live (TTL)]
         -S [IP-Address (IPv4 only)]

  hyenae -a dhcp-release
         -s [HW-Address]-[IP-Address (IPv4 only)]
         -d [HW-Address]-[IP-Address (IPv4 only)]
         -D [IP-Address (IPv4 only)]
  Optional:
         -t [IP Time To Live (TTL)]


--------------------------------------------------------------------------------
