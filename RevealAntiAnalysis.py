import idc
import idautils

'''
- Reveals several anti-analysis tricks and
 - Patches int 3
 - Patches IsDebuggerPresent

- [TODO] Reveals various suspicious API calls
'''

ANTIANALYSIS_COLOR = 0x0000ff
SUSPICIOUS_COLOR = 0x00ffff
NOP = 0x90

MOV_EAX_0 = [0xB8, 0x00, 0x00, 0x00, 0x00]

ANTIANALYSIS_INSTRUCTIONS = ['rdtsc', 'cpuid', 'int', 'sidt', 'sldt', 'sgdt']

ANTIANALYSIS_FUNCTIONS = ['FindWindow', 'IsDebuggerPresent', 'OutputDebugString', 'CheckRemoteDebuggerPresent'\
'DebugActiveProcess', 'GetThreadContext', 'IsProcessorFeaturePresent']

SUSPICIOUS_FUNCTIONS = {
	'FindFirstFileExA': 'Possible ransomware',
	'FindNextFileExA': 'Possible ransomware'
}

def strip(s):
	return s.strip().replace("\t","")

def get_antianalysis_function(ea):
	m = idc.GetMnem(ea)

	if m == 'call':
		f = strip(idc.GetDisasm(ea).split('call')[1])
		if ':' in f:
			f = f.split(':')[1]
		if f in ANTIANALYSIS_FUNCTIONS:
			return f
	
	return None

def get_antianalysis_instruction(ea):
	ins = idc.GetMnem(ea)

	for ai in ANTIANALYSIS_INSTRUCTIONS:
		if ai == ins:
			return ai

	return None

start = idc.MinEA()
end = idc.MaxEA()

while start < end:
	f = get_antianalysis_function(start)
	if f:
		idc.SetColor(start, idc.CIC_ITEM, ANTIANALYSIS_COLOR)
		print("%s at %x" % (f, start))

		if f == 'IsDebuggerPresent':
			nexti = idc.NextHead(start)
			if nexti - start >= len(MOV_EAX_0):
				print("Patching IsDebuggerPresent")
				for i in range(len(MOV_EAX_0)):
					idc.PatchByte(start+i, MOV_EAX_0[i])
				for i in range(nexti-start-len(MOV_EAX_0)):
					idc.PatchByte(start+i+len(MOV_EAX_0), NOP)


	ins = get_antianalysis_instruction(start)
	if ins:
		idc.SetColor(start, idc.CIC_ITEM, ANTIANALYSIS_COLOR)
		print("%s at %x" % (ins, start))

	if idc.GetMnem(start) == 'int' and idc.GetOperandValue(start, 0) == 3:
		idc.PatchByte(start, NOP)
		print('Patched int3!')

	start = idc.NextHead(start)