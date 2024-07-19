import ctypes

# TODO: Figure out how to type-hint a ctypes objects
# The base class for ctypes objects is private (with good reason.)
# There are hacky and likely-fragile ways to get it.


class TypedPointer(ctypes.c_void_p):
    """Typed pointer class

    This class fills a gap in ctypes ability to represent data.

    The existing typed pointer classes are designed
    as direct references to Python objects;
    it's not possible to set a specific address.

    c_void_p represents the correct kind of value,
    but has no associated data type.

    NOTE: Do not instantiate this class directly!
    The referenced type needs to be bound to a class,
    since ctypes uses instances to represent specific variables or fields.
    Use typed_pointer() to create a subclass for your type.
    """

    _reftype = None

    def __init__(self, *args, **kwargs):
        # No idea what the signature for this should be,
        # and don't want to pick one in case it changes
        if self.__class__ == TypedPointer:
            raise TypeError("Cannot instantiate TypedPointer directly")
        # NOTE: Due to a bug, can't use super() in ctypes subclasses
        ctypes.c_void_p.__init__(self, *args, **kwargs)

    @property
    def reftype(self):
        """Get the type referenced by this pointer
        Returns:
            The ctypes object defining the referenced type
        """
        return self._reftype

    def __str__(self):
        return f"Pointer {self.reftype} = {self.value}"

    def __eq__(self, other):
        return (
            isinstance(other, TypedPointer)
            and other.reftype == self.reftype
            and other.value == self.value
        )


_pointertypes = {
    None: ctypes.c_void_p,
    ctypes.c_char: ctypes.c_char_p,
    ctypes.c_wchar: ctypes.c_wchar_p,
}


def typed_pointer(reftype):
    """Create a typed pointer class

    The referenced type should be any ctypes type definition,
    or 'None' to represent 'void'

    Referenced types that already have a ctypes pointer value type
    will return that type, not a TypedPointer:

    - typed_pointer(c_char) returns c_char_p
    - typed_pointer(c_wchar) returns c_wchar_p
    - typed_pointer(None) returns c_void_p

    Arguments:
        reftype: The ctypes obejct defining the referenced type
    Returns:
        A subclass of TypedPointer representing your referenced type
    """
    if reftype in _pointertypes:
        return _pointertypes[reftype]
    else:
        # Dynamically create a new subclass of TypedPointer
        # to represent this particular reftype
        name = f"{reftype.__name__}Pointer"
        cls = type(name, (TypedPointer,), {"reftype": reftype})
        _pointertypes[reftype] = cls
        return cls


def label_for_ctype(memory, label, type, off=0):
    if issubclass(type, ctypes.Structure):
        for field_name, field_type in type._fields_:
            label_for_ctype(memory, f"{label}.{field_name}", field_type, off)
            off += ctypes.sizeof(field_type)
    elif issubclass(type, ctypes.Array):
        for i in range(0, type._length_):
            label_for_ctype(memory, f"{label}[{i}]", type._type_, off)
            off += ctypes.sizeof(type._type_)
    else:
        memory.set_label(off, ctypes.sizeof(type), label, None)


__all__ = [
    "label_for_ctype",
    "typed_pointer",
]
