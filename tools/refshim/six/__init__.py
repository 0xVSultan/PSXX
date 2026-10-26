"""The few names python-ecdsa takes from `six`, for Python 3 only (the reference packages are not installed, only unpacked)."""
PY2 = False
PY3 = True
integer_types = (int,)
string_types = (str,)
text_type = str
binary_type = bytes


def int2byte(i):
    return bytes((i,))


def byte2int(b):
    return b[0]


def b(s):
    return s.encode("latin-1")


def u(s):
    return s


def iterbytes(b_):
    return iter(b_)


def indexbytes(b_, i):
    return b_[i]


def python_2_unicode_compatible(c):
    return c


def with_metaclass(meta, *bases):
    class metaclass(type):
        def __new__(cls, name, this_bases, d):
            return meta(name, bases, d)
    return type.__new__(metaclass, "temporary_class", (), {})

next = next
