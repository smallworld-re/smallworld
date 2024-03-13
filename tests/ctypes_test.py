import ctypes

import smallworld

if __name__ == "__main__":

    class StructA(ctypes.LittleEndianStructure):
        _pack_ = 8

    StructA._fields_ = [
        ("data", ctypes.c_void_p),
        ("next", smallworld.ctypes.typed_pointer(StructA)),
    ]
    origA = StructA()
    origA.data = 42
    origA.next = 43
    clone = smallworld.ctypes.deepcopy(origA)

    if clone.data != origA.data:
        raise ValueError(f"Copy failed; clone.data wrong: {clone.data}")
    if clone.next != origA.next:
        raise ValueError(f"Copy failed; clone.next wrong: {clone.next}")

    class StructB(ctypes.LittleEndianStructure):
        _pack_ = 8
        _fields_ = [("struct", StructA)]

    origB = StructB()
    origB.struct = origA

    clone = smallworld.ctypes.deepcopy(origB)
    if clone.struct.data != origB.struct.data:
        raise ValueError(f"Copy failed; clone.struct.data wrong: {clone.struct.data}")
    if clone.struct.next != origB.struct.next:
        raise ValueError(f"Copy failed; clone.struct.next wrong: {clone.struct.next}")

    Array10 = ctypes.c_void_p * 10
    origA10 = Array10(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
    clone = smallworld.ctypes.deepcopy(origA10)
    if len(origA10) != len(clone):
        raise ValueError(f"Copy failed; len(clone) wrong: {len(clone)}")
    for i in range(0, len(origA10)):
        if origA10[i] != clone[i]:
            raise ValueError(f"Copy failed: clone[{i}] wrong: {clone[i]}")
