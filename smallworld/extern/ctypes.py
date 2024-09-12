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

    Warning:
        Do not instantiate this class directly! The referenced type needs to be
        bound to a class, since ctypes uses instances to represent specific
        variables or fields. Use ``create_typed_pointer()`` to create a
        subclass for your type.
    """

    _type = None

    def __init__(self, *args, **kwargs):
        # No idea what the signature for this should be,
        # and don't want to pick one in case it changes
        if self.__class__ == TypedPointer:
            raise TypeError("Cannot instantiate TypedPointer directly")
        # NOTE: Due to a bug, can't use super() in ctypes subclasses
        ctypes.c_void_p.__init__(self, *args, **kwargs)

    @property
    def type(self):
        """The type referenced by this pointer."""

        return self._type

    def __str__(self):
        return f"Pointer {self.type} = {self.value}"

    def __eq__(self, other):
        return (
            isinstance(other, TypedPointer)
            and other.type == self.type
            and other.value == self.value
        )


_pointertypes = {
    None: ctypes.c_void_p,
    ctypes.c_char: ctypes.c_char_p,
    ctypes.c_wchar: ctypes.c_wchar_p,
}


def create_typed_pointer(reference):
    """Create a typed pointer class.

    The referenced type should be any ctypes type definition, or ``None`` to
    represent 'void'.

    Referenced types that already have a ctypes pointer value type will return
    that type, not a ``TypedPointer``::

        create_typed_pointer(c_char)  # returns c_char_p
        create_typed_pointer(c_wchar)  # returns c_wchar_p
        create_typed_pointer(None)  # returns c_void_p

    Arguments:
        reference: The ctypes object defining the referenced type.

    Returns:
        A subclass of ``TypedPointer`` representing your referenced type.
    """
    if reference in _pointertypes:
        return _pointertypes[reference]
    else:
        # Dynamically create a new subclass of TypedPointer to represent this
        # particular type
        name = f"{type.__name__}Pointer"
        cls = type(name, (TypedPointer,), {"type": reference})
        _pointertypes[reference] = cls
        return cls


__all__ = [
    "TypedPointer",
    "create_typed_pointer",
]
