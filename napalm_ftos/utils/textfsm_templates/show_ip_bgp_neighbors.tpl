#BGP neighbor is 10.170.252.4, remote AS 64805, external link
#  Member of peer-group ebgp for session parameters
#  BGP remote router ID 10.170.255.2
#  BGP state ESTABLISHED, in this state for 23w0d:03:13:04
#  Last read 00:00:00, Last write 00:00:42
#  Hold time is 180, keepalive interval is 60 seconds
#  Received 266684 messages, 0 in queue
#     1 opens, 0 notifications, 12 updates
#     266671 keepalives, 0 route refresh requests
#  Sent 266703 messages, 0 in queue
#     1 opens, 0 notifications, 13 updates
#     266689 keepalives, 0 route refresh requests
#
#  Route refresh request: received 0, sent messages 0
#  Soft reconfiguration inbound configured and effective
#  Minimum time between advertisement runs is 30 seconds
#  Minimum time before advertisements start is 0 seconds
#
#  Capabilities received from neighbor for IPv4 Unicast :
#    MULTIPROTO_EXT(1)
#    ROUTE_REFRESH(2)
#    CISCO_ROUTE_REFRESH(128)
#
#
#
#  Capabilities advertised to neighbor for IPv4 Unicast :
#    MULTIPROTO_EXT(1)
#    ROUTE_REFRESH(2)
#    CISCO_ROUTE_REFRESH(128)
#
#
#
#  Neighbor is using BGP peer-group mode BFD configuration
#  Cumulative Prefixes Ignored since last reset
#    Our own AS in AS-PATH : 9
#
#
#  For address family: IPv4 Unicast
#  BGP local RIB : Routes to be Added 0, Replaced 0, Withdrawn 0
#  InQ : Added 0, Replaced 0, Withdrawn 0
#  OutQ : Added 0, Withdrawn 0
#  Allow local AS number 0 times in AS-PATH attribute
#  Prefixes accepted 9, withdrawn 8 by peer, martian prefixes ignored 0
#  Prefixes advertised 12, denied 1, withdrawn 6 from peer
#
#  Connections established 1; dropped 0
#  Last reset never
#Local host: 10.170.252.5, Local port: 62266
#Foreign host: 10.170.252.4, Foreign port: 179
#
Value REMOTE_AS (\d+)
Value ROUTER_ID ([a-f0-9\.:]+)
Value CONNECTION_STATE (\w+)
Value HOLDTIME (\d+)
Value KEEPALIVE (\d+)
Value INPUT_MESSAGES (\d+)
Value INPUT_UPDATES (\d+)
Value OUTPUT_MESSAGES (\d+)
Value MESSAGES_QUEUED_OUT (\d+)
Value OUTPUT_UPDATES (\d+)
Value ACCEPTED_PREFIX_COUNT (\d+)
Value ADVERTISED_PREFIX_COUNT (\d+)
Value FLAP_COUNT (\d+)
Value LOCAL_ADDRESS ([a-f0-9\.:]+)
Value LOCAL_PORT (\d+)
Value Filldown REMOTE_ADDRESS ([a-f0-9\.:]+)
Value REMOTE_PORT (\d+)

Start
  ^BGP neighbor is ${REMOTE_ADDRESS}, remote AS ${REMOTE_AS},
  ^\s*BGP remote router ID ${ROUTER_ID}
  ^\s*BGP state ${CONNECTION_STATE},
  ^\s*Hold time is ${HOLDTIME}, keepalive interval is ${KEEPALIVE} seconds
  ^\s*Received ${INPUT_MESSAGES} messages -> Received
  ^\s*Sent ${OUTPUT_MESSAGES} messages, ${MESSAGES_QUEUED_OUT} in queue -> Sent
  ^\s*Prefixes accepted ${ACCEPTED_PREFIX_COUNT},
  ^\s*Prefixes advertised ${ADVERTISED_PREFIX_COUNT},
  ^\s*Connections established \d+; dropped ${FLAP_COUNT}
  ^Local host: ${LOCAL_ADDRESS}, Local port: ${LOCAL_PORT}
  ^Foreign host: ${REMOTE_ADDRESS}, Foreign port: ${REMOTE_PORT} -> Record

Received
  ^.*, ${INPUT_UPDATES} updates -> Start

Sent
  ^.*, ${OUTPUT_UPDATES} updates -> Start
