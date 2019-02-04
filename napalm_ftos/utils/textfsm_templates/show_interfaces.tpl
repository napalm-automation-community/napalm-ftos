#TenGigabitEthernet 0/1 is up, line protocol is up
#Port is part of Port-channel 1
#Description: server01
#Hardware is DellEth, address is f4:8e:38:0b:9f:eb
#    Current address is f4:8e:38:0b:9f:eb
#Server Port AdminState is N/A
#Pluggable media not present
#Interface index is 1048580
#Internet address is not set
#Mode of IPv4 Address Assignment : NONE
#DHCP Client-ID :f48e380b9feb
#MTU 12000 bytes, IP MTU 11982 bytes
#LineSpeed 10000 Mbit
#Flowcontrol rx off tx off
#ARP type: ARPA, ARP Timeout 04:00:00
#Last clearing of "show interface" counters 34w5d18h
#Queueing strategy: fifo
#Input Statistics:
#     133514717974 packets, 229408861088851 bytes
#     5416075499 64-byte pkts, 19862748260 over 64-byte pkts, 20256390556 over 127-byte pkts
#     7962448036 over 255-byte pkts, 3698526194 over 511-byte pkts, 76318529429 over 1023-byte pkts
#     4146407 Multicasts, 1598807 Broadcasts, 133508972760 Unicasts
#     0 runts, 0 giants, 0 throttles
#     0 CRC, 0 overrun, 2986469 discarded
#Output Statistics:
#     145665520762 packets, 401220571785513 bytes, 0 underruns
#     9502573529 64-byte pkts, 26808793614 over 64-byte pkts, 29858864452 over 127-byte pkts
#     6153993561 over 255-byte pkts, 4447938431 over 511-byte pkts, 68893357175 over 1023-byte pkts
#     585990816 Multicasts, 1402198145 Broadcasts, 143677331801 Unicasts
#     0 throttles, 0 discarded, 0 collisions, 0 wreddrops
#Rate info (interval 299 seconds):
#     Input 65.00 Mbits/sec,       4816 packets/sec, 0.66% of line-rate
#     Output 149.00 Mbits/sec,       7549 packets/sec, 1.50% of line-rate
#Time since last interface status change: 23w1d6h
Value IFACE_NAME (.*)
Value ADMIN_STATUS (\w+)
Value OPER_STATUS (\w+)
Value DESCRIPTION (.*)
Value MAC_ADDRESS (([a-f0-9]{2}:){5}[a-f0-9]{2})
Value LAST_FLAPPED (.*)
Value LINE_SPEED (.*bit)

Start
  ^\s*${IFACE_NAME} is ${ADMIN_STATUS}, line protocol is ${OPER_STATUS}
  ^\s*Description: ${DESCRIPTION}
  ^.*Current address is ${MAC_ADDRESS}
  ^Time since last interface status change: ${LAST_FLAPPED}
  ^LineSpeed ${LINE_SPEED} -> Record
