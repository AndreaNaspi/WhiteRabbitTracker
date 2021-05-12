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
							consumers[cons] = {int(memAddress, 16)}
						# cons already exist -> update the set
						else:
							consumers[cons].add(int(memAddress, 16))
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
							memAddress = int(splittedLog[4].split("(")[0], 16)
							memSize = int(splittedLog[4].split("(")[1].replace(")", ""))
							update_hashmaps(insCounterDict, byteInsDict, ipAddress, memAddress, memSize)
						# for "reg-mem" the memory operand is the second
						else:
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
							insAddress = int(splittedLog[1], 16)
							res: TaintedChunk = searchTaintedChunk(definitiveChunksRoot, memAddress)
							if res is not None:
								if (res.start, res.end) not in rangeProd.keys():
									rangeProd.update({(res.start, res.end): (insAddress, taintColor)})
								else:
									rangeProd[(res.start, res.end)] = (insAddress, taintColor)
	return rangeProd, addrCol


def addrColourToChunksRoot(definitiveChunksRoot, addrCols):
	res: TaintedChunk = None

	for address, col in addrCols.items():
		res = searchTaintedChunk(definitiveChunksRoot, address)
		if res is not None:
			res.colour = col
def main():
	# sanity check
	if len(sys.argv) != 2:
		print("Usage: python offlineAnalysis.py PATH_TO_TAINTED_LOGS (e.g. C:\\Pin315\\taint\\)")
		return -1

	directoryTaintedLogs = sys.argv[1]

	# sanity check
	if isdir(directoryTaintedLogs) is False:
		print("The given path is not a directory!")

	# create logging file
	for handler in logging.root.handlers[:]:
		logging.root.removeHandler(handler)
	logging.basicConfig(filename="offlineAnalysis.log", level=logging.INFO)

	'''
	Create a dictionary where the:
		- keys: list of all consumers
		- value: set of addresses consumed by these consumers
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

	return 0


if __name__ == "__main__":
	main()
