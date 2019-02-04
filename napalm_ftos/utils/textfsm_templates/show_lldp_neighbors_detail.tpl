#========================================================================
# Local Interface Te 0/1 has 1 neighbor
#  Total Frames Out: 678604
#  Total Frames In: 701502
#  Total Neighbor information Age outs: 0
#  Total Multiple Neighbors Detected: 0
#  Total Frames Discarded: 0
#  Total In Error Frames: 0
#  Total Unrecognized TLVs: 701499
#  Total TLVs Discarded: 0
#  Next packet will be sent after 23 seconds
#  The neighbors are given below:
#  -----------------------------------------------------------------------
#
#    Remote Chassis ID Subtype: Mac address (4)
#    Remote Chassis ID:  f4:8e:38:0b:9f:eb
#    Remote Port Subtype:  Mac address (3)
#    Remote Port ID:  f4:8e:38:0b:9f:eb
#    Remote Port Description:  eth0
#    Local Port ID: TenGigabitEthernet 0/1
#    Locally assigned remote Neighbor Index: 6
#    Remote TTL:  120
#    Information valid for next 119 seconds
#    Time since last information change of this neighbor:  23w1d5h
#    Remote System Name:  server01
#    Remote Management Address (IPv4):  10.11.12.13
#    Remote Management Address (IPv6):  fe80::1060:ff13:83fe:6f
#    Remote System Desc:  Debian GNU/Linux 9 (stretch) Linux
#     4.14.63-stretch1.0 #7 SMP Thu Aug 16 15:19:22 CEST 2018 x86_64
#    Existing System Capabilities:  Bridge WLAN Access Point Router Station only
#    Enabled System Capabilities:  Bridge Router
#    MAC PHY Configuration:
#      Auto-neg supported: 1
#      Auto-neg enabled: 1
#      Auto-neg advertised capabilities:
#        1000BASE-X, -LX, -SX, -CX full duplex mode,
#        PAUSE for full-duplex links,
#        other or unknown
#      Operational MAU type:
#        1000BaseBX80DOWNHD: Fiber over bi-directional single mode laser, half duplex mode
#    UnknownTLVList:
#    OrgUnknownTLVList:
#          ((00-12-0f),  3,  5)
#   ---------------------------------------------------------------------------
Value LOCAL_INTERFACE (.*)
Value REMOTE_CHASSIS_ID (.*)
Value REMOTE_PORT (.*)
Value REMOTE_PORT_DESCRIPTION (.+)
Value REMOTE_SYSTEM_NAME (.*)
Value REMOTE_SYSTEM_DESCRIPTION (.+)
Value REMOTE_SYSTEM_DESCRIPTION2 (.+)
Value REMOTE_SYSTEM_CAPAB (.*)
Value REMOTE_SYSTEM_ENABLE_CAPAB (.*)

Start
  # A line of ='s delimits neighbor records
  ^=======================+ -> Record Neighbor

Neighbor
  ^\s*Local Interface ${LOCAL_INTERFACE} has \d+ neighbors?
  ^\s*Remote Chassis ID:\s+${REMOTE_CHASSIS_ID}
  ^\s*Remote Port ID:\s+${REMOTE_PORT}
  ^\s*Remote Port Description:\s+${REMOTE_PORT_DESCRIPTION}
  ^\s*Remote System Name:\s+${REMOTE_SYSTEM_NAME}
  # We need to change state to capture the entire next line
  ^\s*Remote System Desc: ${REMOTE_SYSTEM_DESCRIPTION} -> Description
  ^\s*Existing System Capabilities:\s+${REMOTE_SYSTEM_CAPAB}
  ^\s*Enabled System Capabilities:\s+${REMOTE_SYSTEM_ENABLE_CAPAB} -> Record

Description
  # Capture the entire line and go back to Neighbor state
  ^${REMOTE_SYSTEM_DESCRIPTION2} -> Neighbor
