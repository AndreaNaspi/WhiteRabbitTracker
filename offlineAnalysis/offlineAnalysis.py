import os
import sys

def main():
	# Sanity check
	if(len(sys.argv) != 2):
		print("Usage: python offlineAnalysis.py PATH_TO_TAINTED_LOGS (e.g. C:\\Pin315\\taint\\)");
		return -1;

	directoryTaintedLogs = sys.argv[1];

	# Sanity check
	if(os.path.isdir(directoryTaintedLogs) is False):
		print("The given path is not a directory!");

	return 0;

if __name__ == "__main__":
   main()