class HookIdProduct:
    def __init__(self, hookChunks: list, hookLargeChunks: (int, int)):
        self.hookChunks = hookChunks
        self.hookLargeChunks = hookLargeChunks

class TaintedChunk:
    def __init__(self, start: int, end: int, xorValue: str, colour: int, name: str):
        self.start = start
        self.end = end
        self.xorValue = xorValue
        self.colour = colour
        self.name = name
        self.left = None
        self.right = None

def insertTaintedChunk(root: TaintedChunk, start: int, end: int, xorValue: str, colour: int, name: str):
    if root.start == start and root.end == end and root.colour == colour and root.name == name:
        return False
    # right subtree
    if root.end < start:
        if root.right:
            return insertTaintedChunk(root.right, start, end, xorValue, colour, name)
        else:
            root.right = TaintedChunk(start, end, xorValue, colour, name)
            return True
    # left subtree
    else:
        if root.left:
            return insertTaintedChunk(root.left, start, end, xorValue, colour, name)
        else:
            root.left = TaintedChunk(start, end, xorValue, colour, name)
            return True
    return False

def searchTaintedChunk(root: TaintedChunk, address: int):
    if not root:
        return None

    if root.start <= address < root.end:
        return root
    elif address > root.end:
        return searchTaintedChunk(root.right, address)
    else:
        return searchTaintedChunk(root.left, address)
    return None
