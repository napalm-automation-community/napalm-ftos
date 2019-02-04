#
# CPU utilization 	5Sec 	1Min 	5Min
# -------------------------------------------
# UNIT0 			  4% 	  4% 	  4%
Value UNIT (\d+)
Value FSEC (\d+)
Value OMIN (\d+)
Value FMIN (\d+)

Start
  ^\s*UNIT${UNIT}\s+${FSEC}%\s+${OMIN}%\s+${FMIN}% -> Record
