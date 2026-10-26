"""Raw LZMA1 with a preset dictionary, through liblzma (ctypes): Python's lzma module has no preset_dict. The overlays of card B are packed against the image of card A; the decoder is tools/stub/lzma_unpack.h with LZMA_DICT.

liblzma comes with MSYS2 (C:/msys64/ucrt64/bin/liblzma-5.dll); another one is taken from PSXX_LIBLZMA or from a directory of PATH."""
import ctypes as C, os

LZMA_FILTER_LZMA1 = 0x4000000000000001
LZMA_VLI_UNKNOWN = 0xFFFFFFFFFFFFFFFF
LZMA_PRESET_EXTREME = 0x80000000
LZMA_MF_BT4 = 0x14
LZMA_RUN, LZMA_FINISH = 0, 3
LZMA_OK, LZMA_STREAM_END = 0, 1


class _Options(C.Structure):                           # lzma_options_lzma (lzma/lzma12.h)
    _fields_ = [("dict_size", C.c_uint32), ("preset_dict", C.c_void_p), ("preset_dict_size", C.c_uint32), ("lc", C.c_uint32), ("lp", C.c_uint32), ("pb", C.c_uint32),
                ("mode", C.c_int), ("nice_len", C.c_uint32), ("mf", C.c_int), ("depth", C.c_uint32), ("ext_flags", C.c_uint32), ("ext_size_low", C.c_uint32),
                ("ext_size_high", C.c_uint32), ("reserved_int4", C.c_uint32), ("reserved_enum1", C.c_int), ("reserved_enum2", C.c_int), ("reserved_enum3", C.c_int),
                ("reserved_enum4", C.c_int), ("reserved_ptr1", C.c_void_p), ("reserved_ptr2", C.c_void_p)]


class _Filter(C.Structure):
    _fields_ = [("id", C.c_uint64), ("options", C.c_void_p)]


class _Stream(C.Structure):                            # lzma_stream (lzma/base.h)
    _fields_ = [("next_in", C.c_void_p), ("avail_in", C.c_size_t), ("total_in", C.c_uint64), ("next_out", C.c_void_p), ("avail_out", C.c_size_t),
                ("total_out", C.c_uint64), ("allocator", C.c_void_p), ("internal", C.c_void_p), ("reserved_ptr1", C.c_void_p), ("reserved_ptr2", C.c_void_p),
                ("reserved_ptr3", C.c_void_p), ("reserved_ptr4", C.c_void_p), ("seek_pos", C.c_uint64), ("reserved_int2", C.c_uint64), ("reserved_int3", C.c_size_t),
                ("reserved_int4", C.c_size_t), ("reserved_enum1", C.c_int), ("reserved_enum2", C.c_int)]


_dll = None


def _lib():
    global _dll
    if _dll:
        return _dll
    cands = [os.environ.get("PSXX_LIBLZMA", "")] + [os.path.join(d, "liblzma-5.dll") for d in os.environ.get("PATH", "").split(os.pathsep) if d] + ["C:/msys64/ucrt64/bin/liblzma-5.dll"]
    path = next((p for p in cands if p and os.path.isfile(p)), None)
    if not path:
        raise SystemExit("liblzma (liblzma-5.dll) not found: install it with MSYS2 or set PSXX_LIBLZMA")
    d = C.CDLL(path)
    d.lzma_lzma_preset.argtypes = [C.POINTER(_Options), C.c_uint32]
    d.lzma_raw_encoder.argtypes = [C.POINTER(_Stream), C.POINTER(_Filter)]
    d.lzma_raw_decoder.argtypes = [C.POINTER(_Stream), C.POINTER(_Filter)]
    d.lzma_code.argtypes = [C.POINTER(_Stream), C.c_int]
    d.lzma_end.argtypes = [C.POINTER(_Stream)]
    _dll = d
    return d


def _run(data, encode, dictionary, lc, lp, pb, out_cap):
    d = _lib()
    o = _Options()
    if d.lzma_lzma_preset(C.byref(o), 9 | LZMA_PRESET_EXTREME):
        raise RuntimeError("lzma_lzma_preset failed")
    o.dict_size = 1 << 20                              # the whole dictionary and the output are in reach (the decoder has no window of its own)
    o.lc, o.lp, o.pb = lc, lp, pb
    o.nice_len, o.mf, o.depth = 273, LZMA_MF_BT4, 1000
    keep = C.create_string_buffer(bytes(dictionary), len(dictionary))
    o.preset_dict, o.preset_dict_size = C.cast(keep, C.c_void_p), len(dictionary)
    flt = (_Filter * 2)(_Filter(LZMA_FILTER_LZMA1, C.cast(C.pointer(o), C.c_void_p)), _Filter(LZMA_VLI_UNKNOWN, None))
    s = _Stream()
    if (d.lzma_raw_encoder if encode else d.lzma_raw_decoder)(C.byref(s), flt) != LZMA_OK:
        raise RuntimeError("liblzma refused the options")
    inb = C.create_string_buffer(bytes(data), len(data))
    outb = C.create_string_buffer(out_cap)
    s.next_in, s.avail_in = C.cast(inb, C.c_void_p), len(data)
    s.next_out, s.avail_out = C.cast(outb, C.c_void_p), out_cap
    rc = d.lzma_code(C.byref(s), LZMA_FINISH if encode else LZMA_RUN)
    n = s.total_out
    d.lzma_end(C.byref(s))
    if rc not in (LZMA_OK, LZMA_STREAM_END):
        raise RuntimeError("liblzma failed: %d" % rc)
    return outb.raw[:n]


def compress(raw, dictionary, lc, lp, pb):
    if len(dictionary) % (1 << max(lp, pb)):
        raise ValueError("the dictionary has to be a multiple of %d bytes (lzma_unpack.h counts the positions from the output)" % (1 << max(lp, pb)))
    return _run(raw, True, dictionary, lc, lp, pb, len(raw) + len(raw) // 2 + 65536)


def decompress(stored, rawlen, dictionary, lc, lp, pb):
    return _run(stored, False, dictionary, lc, lp, pb, rawlen)
