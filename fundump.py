from idautils import *
from idaapi import *
from idc import *

from binascii import hexlify

"""
 Dumps all functions which start with 'sub'
 Format: {FunctionName}:{hexstring}
 Output file: {InputName}.fundump
"""

buf = ""

ea = BeginEA()
for funcea in Functions(SegStart(ea), SegEnd(ea)):
	name = GetFunctionName(funcea)

	if not name.startswith("sub"):
		continue

	start = funcea
	end = FindFuncEnd(start) 
	
	fbytes = GetManyBytes(start, end-start)

	buf += "%s:%s" % (name, hexlify(fbytes)) + "\n"

f = open(GetInputFile() + ".fundump", "w")
f.write(buf[:-1])
f.close()