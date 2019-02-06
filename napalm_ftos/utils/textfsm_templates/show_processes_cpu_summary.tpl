Value UNIT (\d+)
Value FSEC (\d+)
Value OMIN (\d+)
Value FMIN (\d+)

Start
  ^\s*UNIT${UNIT}\s+${FSEC}%\s+${OMIN}%\s+${FMIN}% -> Record
