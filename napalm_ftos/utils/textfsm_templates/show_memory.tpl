Value UNIT (\d+)
Value TOTAL (\d+)
Value USED (\d+)

Start
  ^\s*Statistics On Unit ${UNIT} -> Unit

Unit
  ^\s*${TOTAL}\s+${USED} -> Record
