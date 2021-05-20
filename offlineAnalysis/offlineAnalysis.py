from intervalTree import *
from os import listdir
from os.path import isdir, isfile, join
import sys
import logging

def getDictConsumers(directoryTaintedLogs):
	logFiles = [f for f in listdir(directoryTaintedLogs) if isfile(join(directoryTaintedLogs, f))]
	consumers = {}
	for logFile in logFiles:
		# consider only general taint logs
		if "mem" not in logFile and "ins" not in logFile:
			with open(directoryTaintedLogs + logFile) as f:
				logContent = [x.strip() for x in f.readlines()]
				for log in logContent:
					splittedLog = log.split(" ")
					# consider only taint logs that involves memory areas
					memoryLogs = ["mem", "mem-imm", "mem-reg", "reg-mem"]
					instructionType = splittedLog[0].replace(";", "")
					if instructionType in memoryLogs:
						cons = int(splittedLog[1], 16)
						memAddressIndex = 5 if instructionType == "reg-mem" else 4
						memAddress = splittedLog[memAddressIndex].split("(")[0]
						# first time we encounter that cons
						if cons not in consumers.keys():
							consumers[cons] = [int(memAddress, 16)]
						# cons already exist -> update the set
						else:
							if int(memAddress, 16) not in consumers[cons]:
								consumers[cons].append(int(memAddress, 16))
	return consumers


def populateTaintedChunks(directoryTaintedLogs):
	logFiles = [f for f in listdir(directoryTaintedLogs) if isfile(join(directoryTaintedLogs, f))]
	hook_id: (str, int) = None
	root: TaintedChunk = None
	prodLargeRange = {}  # dict(hook_id, memoryRange)
	prodMap = {}  # dict(hook_id, list<memoryRange>)

	for logFile in logFiles:
		# consider only memory areas logs
		if "mem" in logFile:
			with open(directoryTaintedLogs + logFile) as f:
				logContent = [x.strip() for x in f.readlines()]
				for log in logContent:
					splittedLog = log.split(" ")
					if splittedLog[0] == "-":
						hook_id = (splittedLog[1], int(splittedLog[2], 16))
						memoryRange = (int(splittedLog[3], 16), int(splittedLog[4], 16))
						prodLargeRange[hook_id] = memoryRange
					else:
						memoryRange = (int(splittedLog[0], 16), int(splittedLog[1], 16))
						if hook_id not in prodMap.keys():
							prodMap[hook_id] = [memoryRange]
						else:
							if memoryRange not in prodMap[hook_id]:
								prodMap[hook_id].append(memoryRange)
	for prod in prodMap:
		memoryRanges = prodMap[prod]
		memoryRanges.sort()
		for idx, memoryRange in enumerate(memoryRanges):
			start, end = memoryRange

			# create memory chunks
			for idx2, nextRanges in enumerate(memoryRanges[idx + 1:]):
				if memoryRanges[--idx2][1] == memoryRanges[++idx2][0]:
					end = memoryRanges[idx2][1]

			# insert chunk in interval tree
			if root is None:
				root = TaintedChunk(start, end, prod[1], 1, prod[0])
			else:
				insertTaintedChunk(root, start, end, prod[1], 1, prod[0])

	return root, prodLargeRange


def update_hashmaps(insCounterDict, byteInsDict, ipAddr, memAddr, readSize):
	# first time that we encounter the instruction
	if ipAddr not in insCounterDict.keys():
		insCounterDict[ipAddr] = 1
	else:
		insCounterDict[ipAddr] += 1

	for i in range(0, readSize):
		# byte never encountered
		if memAddr + i not in byteInsDict.keys():
			byteInsDict[memAddr + i] = [ipAddr]
		else:
			if ipAddr not in byteInsDict[memAddr + i]:
				byteInsDict[memAddr + i].append(ipAddr)


def fTechnique(directoryTaintedLogs):
	logFiles = [f for f in listdir(directoryTaintedLogs) if isfile(join(directoryTaintedLogs, f))]
	memoryLogs = ["mem", "mem-imm", "mem-reg", "reg-mem"]
	insCounterDict = {}  # dict<ipAddr: int, size: int> (hit counter)
	byteInsDict = {}  # dict<memAddr: int, list<int>> (set of instruction that accessed that byte)
	for logFile in logFiles:
		# consider only general taint logs
		if "mem" not in logFile and "ins" not in logFile:
			with open(directoryTaintedLogs + logFile) as f:
				logContent = [x.strip() for x in f.readlines()]
				for log in logContent:
					splittedLog = log.split(" ")
					instructionType = splittedLog[0].replace(";", "")
					# consider only the instruction that involves memory areas
					if instructionType in memoryLogs:
						ipAddress = int(splittedLog[1], 16)
						assertType = int(splittedLog[6])
						# for "mem", "mem-imm" and "mem-reg" the memory operand is the first
						if instructionType == "mem" or instructionType == "mem-imm" or instructionType == "mem-reg":
							if assertType != 2:
								memAddress = int(splittedLog[4].split("(")[0], 16)
								memSize = int(splittedLog[4].split("(")[1].replace(")", ""))
								update_hashmaps(insCounterDict, byteInsDict, ipAddress, memAddress, memSize)
						# for "reg-mem" the memory operand is the second
						elif assertType != 1:
							memAddress = int(splittedLog[5].split("(")[0], 16)
							memSize = int(splittedLog[5].split("(")[1].replace(")", ""))
							update_hashmaps(insCounterDict, byteInsDict, ipAddress, memAddress, memSize)
	# Now calculate "preliminary" chunks
	preliminaryChunks = {}  # dict<int, list<int>>
	hitCount = sys.maxsize  # infinite max size
	ins = 0x00000000
	# for all bytes in the map
	for bytesIns in byteInsDict.keys():
		byteInsDict[bytesIns].sort()
		# for all instruction in the bytes-set
		for currentIns in byteInsDict[bytesIns]:
			insCount = insCounterDict[currentIns]
			if insCount < hitCount:
				hitCount = insCount
				ins = currentIns
		# add instruction to preliminary map
		if ins not in preliminaryChunks.keys():
			preliminaryChunks[ins] = [bytesIns]
		else:
			if bytesIns not in preliminaryChunks[ins]:
				preliminaryChunks[ins].append(bytesIns)
		# reset hit count
		hitCount = sys.maxsize

	# from preliminary chunks to final chunks
	chunkIndex = 1
	definitiveChunks = {}  # dict<int, list<(chunkStart: int, chunkEnd: int)>
	for chunk in preliminaryChunks.keys():
		preliminaryChunks[chunk].sort()
		for idx, currentIns in enumerate(preliminaryChunks[chunk]):
			chunkStart = currentIns
			# determine chunks size
			for nextIns in preliminaryChunks[chunk][idx + 1:]:
				if nextIns == chunkStart + chunkIndex:
					++chunkIndex
			chunkEnd = chunkStart + chunkIndex
			if chunk not in definitiveChunks:
				# create entry
				definitiveChunks[chunk] = [(chunkStart, chunkEnd)]
			else:
				if (chunkStart, chunkEnd) not in definitiveChunks[chunk]:
					definitiveChunks[chunk].append((chunkStart, chunkEnd))
			chunkIndex = 1

	return definitiveChunks


def populateDefinitiveChunks(definitiveChunks):
	root: TaintedChunk = None

	for chunk in definitiveChunks.keys():
		definitiveChunks[chunk].sort()
		for currentRange in definitiveChunks[chunk]:
			if root is None:
				root = TaintedChunk(currentRange[0], currentRange[1], 0x0, 1, "f_technique")
			else:
				insertTaintedChunk(root, currentRange[0], currentRange[1], 0x0, 1, "f_technique")

	return root


def findProdHeuristics(directoryTaintedLogs, definitiveChunksRoot):
	logFiles = [f for f in listdir(directoryTaintedLogs) if isfile(join(directoryTaintedLogs, f))]
	memoryLogs = ["mem", "mem-imm", "mem-reg", "reg-mem"]
	rangeProd = {}  # dict<pair<startMem: int, endMem: int>, pair<insAddress: int, color: int>>
	addrCol = {}  # dict<address: int, color: int>
	for logFile in logFiles:
		# consider only general taint logs
		if "mem" not in logFile and "ins" not in logFile:
			with open(directoryTaintedLogs + logFile) as f:
				logContent = [x.strip() for x in f.readlines()]
				for log in logContent:
					splittedLog = log.split(" ")
					instructionType = splittedLog[0].replace(";", "")
					# consider only the instruction that involves memory areas
					if instructionType in memoryLogs:
						taintColor = int(splittedLog[2].replace("[", "").replace("]", ""))
						assertType = int(splittedLog[6])
						# for "mem", "mem-imm" and "mem-reg" the memory operand is the first
						if instructionType == "mem" or instructionType == "mem-imm" or instructionType == "mem-reg":
							memAddress = int(splittedLog[4].split("(")[0], 16)
							if memAddress not in addrCol.keys():
								addrCol.update({memAddress: taintColor})
							else:
								addrCol[memAddress] = taintColor
						# for "reg-mem" the memory operand is the second
						else:
							memAddress = int(splittedLog[5].split("(")[0], 16)
							if memAddress not in addrCol.keys():
								addrCol.update({memAddress: taintColor})
							else:
								addrCol[memAddress] = taintColor
						# if the memory is the destination operand -> it will be overwritten (expect for cmp and test)
						instructionSymbol = splittedLog[3]
						if instructionSymbol != "cmp" and instructionSymbol != "test" and instructionSymbol != "push" and \
								(instructionType == "mem-imm" or instructionType == "mem-reg"):
							taintColor = int(splittedLog[2].replace("[", "").replace("]", ""))
							memAddress = int(splittedLog[4].split("(")[0], 16)
							xorHash = int(splittedLog[7], 16)
							res: TaintedChunk = searchTaintedChunk(definitiveChunksRoot, memAddress)
							if res is not None:
								if (res.start, res.end) not in rangeProd.keys():
									rangeProd.update({(res.start, res.end): (xorHash, taintColor)})
								else:
									rangeProd[(res.start, res.end)] = (xorHash, taintColor)
	return rangeProd, addrCol


def addrColourToChunksRoot(definitiveChunksRoot, addrCols):
	res: TaintedChunk = None

	for address, col in addrCols.items():
		res = searchTaintedChunk(definitiveChunksRoot, address)
		if res is not None:
			res.colour = col
def main():
	# sanity check
	if len(sys.argv) != 3:
		print("Usage: python offlineAnalysis.py PATH_TO_TAINTED_LOGS PATH_TO_CALL_STACK_LOG (e.g. offlineAnalysis.py C:\\Pin315\\taint\\ C:\\Pin315\\callstack.log)")
		return -1

	directoryTaintedLogs = sys.argv[1]
	callStackLog = sys.argv[2]

	# sanity checks
	if isdir(directoryTaintedLogs) is False:
		print("The given path to the tainted logs is not a directory!")
	if isfile(callStackLog) is False:
		print("The given path to the call stack log is not a file!")

	# create logging file
	for handler in logging.root.handlers[:]:
		logging.root.removeHandler(handler)
	try:
		f = open("offlineAnalysis.gv", "w")
	except IOError:
		print("File offlineAnalysis.gv not present, creating the file...")
	finally:
		f.close()

	logging.basicConfig(filename="offlineAnalysis.gv", format='%(message)s', level=logging.INFO)

	'''
	Create a dictionary where the:
		- keys: list of all consumers
		- value: list of addresses consumed by these consumers
	'''
	consumers = getDictConsumers(directoryTaintedLogs)

	'''
	Create an interval tree that contains the tainted memory areas during the program execution
	'''
	taintProducerRoot, prodLargeRange = populateTaintedChunks(directoryTaintedLogs)

	definitiveChunks = fTechnique(directoryTaintedLogs)
	'''
	# DEBUG CHUNKS
	for chunk in definitiveChunks.keys():
		print(hex(chunk))
		for currentRange in definitiveChunks[chunk]:
			print("            ", hex(currentRange[0]), ",", hex(currentRange[1]))
	'''

	'''
	Create an interval tree that contains the definitive tainted chunks
	'''
	definitiveChunksRoot = populateDefinitiveChunks(definitiveChunks)

	'''
	Producer identification
	'''
	rangeProd, addrCol = findProdHeuristics(directoryTaintedLogs, definitiveChunksRoot)

	'''
	Add colors to interval tree
	'''
	addrColourToChunksRoot(definitiveChunksRoot, addrCol)

	'''
	It's time to build the .dot file (graph)
	'''
	consumerChunks = {} # dict<address,list<pair<start,end>>>
	chunks = [] # list<pair<start,end>>
	rangeHookId = {} # dict<pair<start,end>, hookID>, hookID = pair<hookName,xor>
	prodHooks = [] # list<hookID>, hookID = pair<hookName,xor>
	producerChunks = {} # dict<hookID, hookID_product>, hookID = pair<hookName,xor>, hookID_product = pair<list<range>, range>
	producerIds = [] # list<pair<insAddress: int, colour: int>>
	producerIdsChunks = {} # dict<pair<insAddress: int, colour: int>, list<pair<start, end>>>
	colourChunks = {} # dict<int, list<pair<start, end>>>
	# for each consumer
	for consumer in consumers:
		consumers[consumer].sort()
		# for each consumed address by the consumer
		for consumedAddress in consumers[consumer]:
			# if address is in tainted chunks (log files)
			res = searchTaintedChunk(taintProducerRoot, consumedAddress)
			if res is not None:
				currentRange = (res.start, res.end)
				# insert chunk
				if currentRange not in chunks:
					chunks.append(currentRange)
				# insert consumer
				if consumer not in consumerChunks.keys():
					consumerChunks[consumer] = [currentRange]
				else:
					if currentRange not in consumerChunks[consumer]:
						consumerChunks[consumer].append(currentRange)
				# insert producer
				hookID = (res.name, res.xorValue)
				rangeHookId[currentRange] = hookID
				# add hookID to producer set (unique ID in dot file)
				if hookID not in prodHooks:
					prodHooks.append(hookID)
				if hookID not in producerChunks.keys():
					hookID_product = HookIdProduct([currentRange], None)
					producerChunks[hookID] = hookID_product
				else:
					if currentRange not in producerChunks[hookID].hookChunks:
						producerChunks[hookID].hookChunks.append(hookID_product)
			# address is in chunks from fTechnique
			else:
				res = searchTaintedChunk(definitiveChunksRoot, consumedAddress)
				if res is not None:
					currentRange = (res.start, res.end)
					# insert chunk
					if currentRange not in chunks:
						chunks.append(currentRange)
					# insert consumer
					if consumer not in consumerChunks.keys():
						consumerChunks[consumer] = [currentRange]
					else:
						if currentRange not in consumerChunks[consumer]:
							consumerChunks[consumer].append(currentRange)
					# if the producer is in the heuristic output
					if currentRange in rangeProd.keys():
						if rangeProd[currentRange] not in producerIds:
							producerIds.append(rangeProd[currentRange])
						if currentRange not in chunks:
							chunks.append(currentRange)
						if rangeProd[currentRange] not in producerIdsChunks.keys():
							producerIdsChunks[rangeProd[currentRange]] = [currentRange]
						else:
							if currentRange not in producerIdsChunks[rangeProd[currentRange]]:
								producerIdsChunks[rangeProd[currentRange]].append(currentRange)
					# if the producer is a special node
					elif res.colour != 0:
						if currentRange not in chunks:
							chunks.append(currentRange)
							if res.colour not in colourChunks.keys():
								colourChunks[res.colour] = [currentRange]
							else:
								if currentRange not in colourChunks[res.colour]:
									colourChunks[res.colour].append(currentRange)

	# define large chunks with more than 10 intervals
	THRESHOLD = 10
	largeChunks = [] # list<pair<start,end>>
	for hookId, hookId_products in producerChunks.items():
		if len(hookId_products.hookChunks) >= THRESHOLD:
			if hookId in prodLargeRange.keys():
				hookId_products.hookLargeChunks = prodLargeRange[hookId]
				if prodLargeRange[hookId] not in largeChunks:
					largeChunks.append(prodLargeRange[hookId])

	# WRITE DOT FILE
	output = ""
	output += "digraph {\n\tnode[shape=box]\n"
	for k, v in consumerChunks.items():
		output += "\"" + hex(id(k)) + "\" [label=\"" + hex(k) + "\"];\n"
	if output:
		logging.info(output)
	output = ""
	for k, v in producerChunks.items():
		output += "\"" + hex(id(k)) + "\" [label=\"" + k[0] + "\n " + hex(k[1]) + "\"];\n"
	if output:
		logging.info(output)
	output = ""

	for k, v in producerIdsChunks.items():
		output += "\"" + hex(id(k)) + "\" [label=\"" + hex(k[0]) + "\n " + hex(k[1]) + "\"];\n"
	if output:
		logging.info(output)
	output = ""

	for k, v in colourChunks.items():
		output += "\"" + hex(id(k)) + "\" [label=\"" + hex(k) + "\"];\n"
	if output:
		logging.info(output)
	output = ""

	for chunk in chunks:
		if chunk in rangeHookId.keys():
			it_h = rangeHookId[chunk]
			if it_h in prodLargeRange.keys():
				prodLargeRangeMem = prodLargeRange[it_h]
				if prodLargeRangeMem in largeChunks:
					output += "\"" + hex(id(prodLargeRangeMem)) + "\" [label=\"[" + hex(prodLargeRangeMem[0]) + "-\\n" + hex(prodLargeRangeMem[1]) + "]\"];\n";
				else:
					output += "\"" + hex(id(chunk[0])) + "\" [label=\"[" + hex(chunk[0]) + "-\\n" + hex(chunk[1]) + "]\"];\n"
			else:
				output += "\"" + hex(id(chunk[0])) + "\" [label=\"[" + hex(chunk[0]) + "-\\n" + hex(chunk[1]) + "]\"];\n"
		else:
			output += "\"" + hex(id(chunk[0])) + "\" [label=\"[" + hex(chunk[0]) + "-\\n" + hex(chunk[1]) + "]\"];\n"
	if output:
		logging.info(output)
	output = ""

	# WRITE RELATIONSHIP TO DOT FILE
	lrange_cons = {} # dict<range, list<int>>
	for consumer in consumerChunks.keys():
		rangeMap = consumerChunks[consumer]
		for currentRange in rangeMap:
			if currentRange in rangeHookId.keys():
				hookID = rangeHookId[currentRange]
				if hookID in prodLargeRange.keys():
					largeRange = prodLargeRange[hookID]
					if largeRange in largeChunks:
						if largeRange not in lrange_cons.keys():
							lrange_cons[largeRange] = [consumer]
							output += "\"" + hex(id(largeRange)) + "\" -> \"" + hex(id(consumer)) + "\";\n"
						else:
							if consumer not in lrange_cons[largeRange]:
								lrange_cons[largeRange].append(consumer)
							output += "\"" + hex(id(largeRange)) + "\" -> \"" + hex(id(consumer)) + "\";\n"
					elif currentRange in chunks:
						output += "\"" + hex(id(currentRange[0])) + "\" -> \"" + hex(id(consumer)) + "\";\n"
				elif currentRange in chunks:
					output += "\"" + hex(id(currentRange[0])) + "\" -> \"" + hex(id(consumer)) + "\";\n"
			elif currentRange in chunks:
				output += "\"" + hex(id(currentRange[0])) + "\" -> \"" + hex(id(consumer)) + "\";\n"
	if output:
		logging.info(output)
	output = ""

	lrange_prod = [] # list<range>
	# dict<hookID, hookID_product>, hookID = pair<hookName,xor>, hookID_product = pair<list<range>, range>
	for producer in producerChunks.keys():
		currentHookChunks = producerChunks[producer].hookChunks
		for currentRange in currentHookChunks:
			if currentRange in rangeHookId.keys():
				hookID = rangeHookId[currentRange]
				if hookID in prodLargeRange.keys():
					largeRange = prodLargeRange[hookID]
					if largeRange in largeChunks:
						if largeRange not in lrange_prod:
							lrange_prod.append(largeRange)
							output += "\"" + hex(id(producer)) + "\" -> \"" + hex(id(largeRange[0])) + "\";\n"
					elif currentRange in chunks:
						output += "\"" + hex(id(producer)) + "\" -> \"" + hex(id(currentRange[0])) + "\";\n"
				elif currentRange in chunks:
					output += "\"" + hex(id(producer)) + "\" -> \"" + hex(id(currentRange[0])) + "\";\n"
			elif currentRange in chunks:
				output += "\"" + hex(id(producer)) + "\" -> \"" + hex(id(currentRange[0])) + "\";\n"
	if output:
		logging.info(output)
	output = ""

	for prodId in producerIdsChunks.keys():
		ranges = producerIdsChunks[prodId]
		for currentRange in ranges:
			if currentRange in chunks:
				output += "\"" + hex(id(prodId)) + "\" -> \"" + hex(id(currentRange[0])) + "\";\n"
	if output:
		logging.info(output)
	output = ""

	for colour in colourChunks.keys():
		ranges = colourChunks[colour]
		for currentRange in ranges:
			if currentRange in chunks:
				output += "\"" + hex(id(colour)) + "\" -> \"" + hex(id(currentRange[0])) + "\";\n"
	if output:
		logging.info(output)
	output = ""

	output += "}"
	logging.info(output)
	output = ""

	return 0


if __name__ == "__main__":
	main()
