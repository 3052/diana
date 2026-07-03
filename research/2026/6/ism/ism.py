import io
import re
import time
from collections import deque
from struct import Struct
from typing import cast
from bitstring import BitStream, BitArray
escapes = set([0x00, 0x01, 0x02, 0x03])

# def parse_sps(sps):
#     sps = ebsp2rbsp(sps)
#     data = {}

#     reader = bytearray(sps)
#     firstByte = int.from_bytes(reader[2:3], byteorder="big")
#     nextByte = int.from_bytes(reader[3:4], byteorder="big")
#     data['generalProfileCompatibilityFlags'] = reader[4:8]
#     data['constraintBytes'] = reader[8:14]
#     data['generalLevelIdc'] = int.from_bytes(reader[14:15], byteorder="big")

#     data['generalProfileSpace'] = (nextByte & 0xc0) >> 6
#     data['generalTierFlag'] = (nextByte & 0x20) >> 5
#     data['generalProfileIdc'] = nextByte & 0x1f

#     print(data)

#     return data

def flagFrom(flags, bitNr):
    return (flags & ( 1 << bitNr)) != 0

def parseProfileTierLevel(stream, flag, sub_layer, sps):
    ptl = dict()
    if flag:
        ptl['general_profile_space'] = stream.read('uint:2')
        ptl['general_tier_flag'] = stream.read('bool:1')
        ptl['general_profile_idc'] = stream.read('uint:5')
        ptl['general_profile_compatibility_flags'] = stream.read('uint:32')
        ptl['general_constraint_indicator_flags'] = stream.read('uint:48')
        ptl['general_progressive_source_flag'] = flagFrom(ptl['general_profile_compatibility_flags'], 47)
        ptl['general_interlaced_source_flag'] = flagFrom(ptl['general_profile_compatibility_flags'], 46)
        ptl['general_non_packed_constraint_flag'] = flagFrom(ptl['general_profile_compatibility_flags'], 45)
        ptl['general_frame_only_constraint_flag'] = flagFrom(ptl['general_profile_compatibility_flags'], 44)

    ptl['general_level_idc'] = stream.read('uint:8')

    if sub_layer > 0:
        ptl['sub_layers'] = []
        raise ValueError("No code has been created for sub layers ATM please give me ur sps: " + sps.hex())
        for i in range(sub_layer):
            ptl['sub_layers'][i]['profile_present_flag'] = stream.read('bool:1')
            ptl['sub_layers'][i]['level_present_flag'] = stream.read('bool:1')

    return ptl

def parse_avcc_sps(sps):
    sps = ebsp2rbsp(sps)
    stream = BitStream(sps)

    data = {}

    data['header'] = stream.read("uint:8") & 0x1f

    if data['header'] != 7:
        raise ValueError("Non SPS value parsed")
    print(sps.hex())
    data['profile'] = stream.read("uint:8")
    data['profile_compatibility'] = stream.read("uint:8")
    data['level'] = stream.read("uint:8")
    data['parameter_id'] = stream.read("ue")

    return data

def parse_hvcc_sps(sps):
    sps = ebsp2rbsp(sps)
    stream = BitStream(sps)
    
    data = {}

    # stream = BitStream(sps)
    data['header'] = ((stream.read("uint:16") >> 8) >> 1) & 0x3f
    
    if data['header'] != 33:
        raise ValueError("Non SPS value parsed")

    data['vps_id'] = stream.read("bits:4")
    data['max_sub_layers_minus_1'] = stream.read("uint:3")
    data['temporal_id_nesting_flag'] = stream.read("bool")
    data['profile_tier_level'] = parseProfileTierLevel(stream, True, data['max_sub_layers_minus_1'], sps)
    data['sps_id'] = stream.read("ue")
    data['chroma_format_idc'] = stream.read("ue")
    if data['chroma_format_idc'] == 3:
        data['seperate_colour_plane_flag'] = stream.read("bool")
    data['width'] = stream.read("ue")
    data['height'] = stream.read("ue")

    data['conformance_window_flag'] = stream.read("bool:1")
    if data['conformance_window_flag']:
        data['conformance_window'] = {
            "left_offset": stream.read("ue"),
            "right_offset": stream.read("ue"),
            "top_offset": stream.read("ue"),
            "bottom_offset": stream.read("ue")
        }
    data['bit_depth_luma_minus_8'] = stream.read("ue")
    data['bit_depth_chroma_minus_8'] = stream.read("ue")
    data['log_2_max_pic_order_cnt_lsb_minus_4'] = stream.read("ue")
    print(data)
    return data

def ebsp2rbsp(data: bytes) -> bytes:
    rbsp = bytearray(data[:2])
    length = len(data)
    for index in range(2, length):
        if index < length - 1 and data[index - 2] == 0x00 and data[index - 1] == 0x00 \
                and data[index + 0] == 0x03 and data[index + 1] in escapes:
            continue
        rbsp.append(data[index])
    return bytes(rbsp)

u8 = Struct(">B")
u88 = Struct(">Bx")
u16 = Struct(">H")
u1616 = Struct(">Hxx")
u32 = Struct(">I")
u64 = Struct(">Q")

s88 = Struct(">bx")
s16 = Struct(">h")
s1616 = Struct(">hxx")
s32 = Struct(">i")

unity_matrix = (s32.pack(0x10000) + s32.pack(0) * 3) * 2 + s32.pack(0x40000000)

TRACK_ENABLED = 0x1
TRACK_IN_MOVIE = 0x2
TRACK_IN_PREVIEW = 0x4

SELF_CONTAINED = 0x1


def box(box_type, payload):
    return u32.pack(8 + len(payload)) + box_type + payload


def full_box(box_type, version, flags, payload):
    return box(box_type, u8.pack(version) + u32.pack(flags)[1:] + payload)


def track_encryption_box(original_format, kid):
    # formats are MPEG-4 visual = 'mp4v' ; MPEG-4 AVC = 'avc1'
    # formats are MPEG-4 audio = 'mp4a' ; MPEG-4 system = 'mp4s'
    frma_payload = original_format  # original_format (4 bytes)
    sinf_payload = box(b"frma", frma_payload)  # original format box

    schm_payload = b"cenc"  # 4 bytes encryption type (scheme_type)
    # 4 bytes encryption version (scheme_version) 0x00010000 (Major version 1, Minor version 0)
    schm_payload += u32.pack(0x00010000)
    sinf_payload += full_box(b"schm", 0, 0, schm_payload)  # scheme type box

    tenc_payload = u8.pack(0)  # flags
    tenc_payload += u8.pack(0)  # version
    tenc_payload += u8.pack(1)  # default_isProtected
    tenc_payload += u8.pack(8)  # default_Per_Sample_IV_Size
    # this is only needed if we want to find track entries to decrypt by KID, otherwise we can just use trackid:key
    tenc_payload += kid or u8.pack(0) * 16
    schi_payload = full_box(b"tenc", 0, 0, tenc_payload)
    sinf_payload += box(b"schi", schi_payload)  # scheme information box

    return box(b"sinf", sinf_payload)

def build_ftyp(major_brand: bytes, version: int, compatbile_brands: list[bytes]):
    ftyp_payload = b"isml"  # major brand
    ftyp_payload += u32.pack(1)  # minor version
    ftyp_payload += b"".join([b"iso5", b"iso6", b"piff", b"msdh"])  # compatible brands
    return box(b"ftyp", ftyp_payload)  # File Type Box

def build_mvhd(creation_time:int, modification_time:int, timescale:int, duration:int, rate:int = 1, volume:int = 1, next_track_id:int = 0xffffffff):
    mvhd_payload = u64.pack(creation_time)
    mvhd_payload += u64.pack(modification_time)
    mvhd_payload += u32.pack(timescale)
    mvhd_payload += u64.pack(duration)
    mvhd_payload += s1616.pack(rate)  # rate
    mvhd_payload += s88.pack(volume)  # volume
    mvhd_payload += u16.pack(0)  # reserved
    mvhd_payload += u32.pack(0) * 2  # reserved
    mvhd_payload += unity_matrix
    mvhd_payload += u32.pack(0) * 6  # pre defined
    mvhd_payload += u32.pack(next_track_id)  # next track id
    return full_box(b"mvhd", 1, 0, mvhd_payload)  # Movie Header Box

def build_tkhd(creation_time: int, modification_time: int, track_id: int, duration: int,  width: int, height: int, layer: int = 0, alternate_group: int = 0, is_audio: int = 1):
    tkhd_payload = u64.pack(creation_time)
    tkhd_payload += u64.pack(modification_time)
    tkhd_payload += u32.pack(track_id)  # track id
    tkhd_payload += u32.pack(0)  # reserved
    tkhd_payload += u64.pack(duration)
    tkhd_payload += u32.pack(0) * 2  # reserved
    tkhd_payload += s16.pack(layer)  # layer
    tkhd_payload += s16.pack(alternate_group)  # alternate group
    tkhd_payload += s88.pack(1 if is_audio else 0)  # volume
    tkhd_payload += u16.pack(0)  # reserved
    tkhd_payload += unity_matrix
    tkhd_payload += u1616.pack(width)
    tkhd_payload += u1616.pack(height)
    return full_box(b"tkhd", 1, TRACK_ENABLED | TRACK_IN_MOVIE | TRACK_IN_PREVIEW, tkhd_payload)


def mdhd_parse_language(language:str):
    return ((ord(language[0]) - 0x60) << 10) | ((ord(language[1]) - 0x60) << 5) | (ord(language[2]) - 0x60)

def build_mdhd(creation_time: int, modification_time: int, timescale: int, duration: int, language:str):
    mdhd_payload = u64.pack(creation_time)
    mdhd_payload += u64.pack(modification_time)
    mdhd_payload += u32.pack(timescale)
    mdhd_payload += u64.pack(duration)
    mdhd_payload += u16.pack(
       mdhd_parse_language(language),
    )
    mdhd_payload += u16.pack(0)  # pre defined
    return full_box(b"mdhd", 1, 0, mdhd_payload)

def build_hdlr(is_audio: bool):
    hdlr_payload = u32.pack(0)  # pre defined
    hdlr_payload += b"soun" if is_audio else b"vide"  # handler type
    hdlr_payload += u32.pack(0) * 3  # reserved
    hdlr_payload += (b"Sound" if is_audio else b"Video") + b"Handler\0"  # name
    return full_box(b"hdlr", 0, 0, hdlr_payload)  # Handler Reference Box   

def build_smhd():
    smhd_payload = s88.pack(0)  # balance
    smhd_payload += u16.pack(0)  # reserved
    return full_box(b"smhd", 0, 0, smhd_payload)  # Sound Media Header

def build_vmhd():
    vmhd_payload = u16.pack(0)  # graphics mode
    vmhd_payload += u16.pack(0) * 3  # opcolor
    return full_box(b"vmhd", 0, 1, vmhd_payload)
    
def write_piff_header(
        stream,
        codec_private_data: bytes,
        track_id: int,
        fourcc: str,
        duration: int,
        timescale: int,
        width: int | None = 0,
        height: int | None = 0,
        is_encrypted: bool = False,
        kid: bytes | None = None,
        bitrate: int = 0,
        channels: int = 2,
        bits_per_sample: int = 16,
        sampling_rate: int = 0,
        nal_unit_length_field: int = 4,
    ):
    """ Built tree like
    mp4_init:
    ├─ ftyp (major brand, minor version, compatible brands)
    └─ moov
        ├─ mvhd (creation_time, modification_time, timescale, duration)
        └─ trak
            ├─ tkhd (track_id, is_audio, width, height)
            └─ mdia
                ├─ mdhd (timescale, language (3 letters))
                ├─ hdlr (vide if video else soun)
                ├─ elng (only if language is not 3 letters) - NOT CURRENTLY IMPLEMENTED
                └─ minf
                    ├─ vmhd if video smhd if audio else not implemented
                    ├─ dinf
                    |   └─ dref
                    |       └─ url
                    └─ stbl
                        ├─ stts
                        ├─ stsc
                        ├─ stco
                        ├─ stsz
                        └─ stsd STSD will be either encv or enca if encrypted or fourcc box if not encrypted
                            └─ encv (width, height) VIDEO
                                ├─  hvcC (general_profile_idc, general_profile_compatibility_flags, general_constraint_indicatior_flags, general_level_idc, chroma_format_idc, bit_depth_luma, bit_depth_chroma, vps, sps, pps)
                                ├─  sinf 
                                |   ├─ frma (original_format)
                                |   ├─ schm (scheme_type, scheme_version)
                                |   ├─ schi
                                |   └─ tenc (is_protected, sample_iv_size, kid)
                             
"""

    codec_private_data = bytes.fromhex(codec_private_data)
    fourcc = fourcc.upper()
    width = width or 0
    height = height or 0
    is_audio = width == 0 and height == 0
    creation_time = modification_time = int(time.time())
    language = "und"
    channels = channels or 2

    ftyp_payload = build_ftyp(b"isml", 1, [b"dvh1"])

    stream.write(ftyp_payload)  # File Type Box

    moov_payload = build_mvhd(creation_time, modification_time, timescale, duration)

    # Track Header Box
    trak_payload = build_tkhd(creation_time, modification_time, track_id, duration, is_audio=is_audio, width=width, height=height)

    mdia_payload = build_mdhd(creation_time, modification_time, timescale, duration, language)  # Media Header Box

    mdia_payload += build_hdlr(is_audio)

    minf_payload = build_smhd() if is_audio else build_vmhd()

    dref_payload = u32.pack(1)  # entry count
    dref_payload += full_box(b"url ", 0, SELF_CONTAINED, b"")  # Data Entry URL Box
    dinf_payload = full_box(b"dref", 0, 0, dref_payload)  # Data Reference Box
    minf_payload += box(b"dinf", dinf_payload)  # Data Information Box

    stsd_payload = u32.pack(1)  # entry count

    sample_entry_payload = u8.pack(0) * 6  # reserved
    sample_entry_payload += u16.pack(1)  # data reference index

    if is_audio:
        sample_entry_payload += u32.pack(0) * 2  # reserved
        sample_entry_payload += u16.pack(channels)
        sample_entry_payload += u16.pack(bits_per_sample)
        sample_entry_payload += u16.pack(0)  # pre defined
        sample_entry_payload += u16.pack(0)  # reserved
        sample_entry_payload += u1616.pack(sampling_rate)
        if fourcc.startswith("AAC"):
            esds_length = 34 + len(codec_private_data)

            esds_payload = u8.pack((esds_length & 0xFF000000) >> 24)
            esds_payload += u8.pack((esds_length & 0x00FF0000) >> 16)
            esds_payload += u8.pack((esds_length & 0x0000FF00) >> 8)
            esds_payload += u8.pack(esds_length & 0x000000FF)
            esds_payload += bytes([0x65, 0x73, 0x64, 0x73])  # type = esds
            esds_payload += bytes([0, 0, 0, 0])  # version = 0, flags = 0

            # ES_Descriptor (see ISO/IEC 14496-1 (Systems))
            esds_payload += u8.pack(0x03)  # tag = 0x03 (ES_DescrTag)
            esds_payload += u8.pack(20 + len(codec_private_data))  # size
            esds_payload += u8.pack((track_id & 0xFF00) >> 8)  # ES_ID = track_id
            esds_payload += u8.pack(track_id & 0x00FF)  # ""
            esds_payload += u8.pack(0)  # flags and streamPriority

            # DecoderConfigDescriptor (see ISO/IEC 14496-1 (Systems))
            esds_payload += u8.pack(0x04)  # tag = 0x04 (DecoderConfigDescrTag)
            esds_payload += u8.pack(15 + len(codec_private_data))  # size

            esds_payload += u8.pack(0x40)  # objectTypeIndication = 0x40 (MPEG-4 AAC)
            stream_type = 0x05 << 2  # streamType = 0x05 (Audiostream)
            stream_type |= 0 << 1  # upStream = 0
            stream_type |= 1  # reserved = 1
            esds_payload += u8.pack(stream_type)
            esds_payload += u8.pack(0xFF)  # buffersizeDB = undefined
            esds_payload += u8.pack(0xFF)  # ""
            esds_payload += u8.pack(0xFF)  # ""
            esds_payload += u8.pack((bitrate & 0xFF000000) >> 24)  # maxBitrate
            esds_payload += u8.pack((bitrate & 0x00FF0000) >> 16)  # ""
            esds_payload += u8.pack((bitrate & 0x0000FF00) >> 8)  # ""
            esds_payload += u8.pack(bitrate & 0x000000FF)  # ""
            esds_payload += u8.pack((bitrate & 0xFF000000) >> 24)  # avgbitrate
            esds_payload += u8.pack((bitrate & 0x00FF0000) >> 16)  # ""
            esds_payload += u8.pack((bitrate & 0x0000FF00) >> 8)  # ""
            esds_payload += u8.pack(bitrate & 0x000000FF)  # ""

            # DecoderSpecificInfo (see ISO/IEC 14496-1 (Systems))
            esds_payload += u8.pack(0x05)  # tag = 0x05 (DecSpecificInfoTag)
            esds_payload += u8.pack(len(codec_private_data))  # size
            esds_payload += codec_private_data

            sample_entry_payload += esds_payload

            if is_encrypted:
                sample_entry_payload += track_encryption_box(b"mp4a", kid)

            sample_entry_box = box(b"mp4a" if not is_encrypted else b"enca", sample_entry_payload)

        if fourcc == "EC-3":
            sample_entry_payload += box(b'dec3', codec_private_data[-5:])

            if is_encrypted:
                sample_entry_payload += track_encryption_box(b"ec-3", kid)

            sample_entry_box = box(b'ec-3' if not is_encrypted else b"enca", sample_entry_payload)
    else:
        sample_entry_payload += u16.pack(0)  # pre defined
        sample_entry_payload += u16.pack(0)  # reserved
        sample_entry_payload += u32.pack(0) * 3  # pre defined
        sample_entry_payload += u16.pack(width)
        sample_entry_payload += u16.pack(height)
        sample_entry_payload += u1616.pack(0x48)  # horiz resolution 72 dpi
        sample_entry_payload += u1616.pack(0x48)  # vert resolution 72 dpi
        sample_entry_payload += u32.pack(0)  # reserved
        sample_entry_payload += u16.pack(1)  # frame count

        if fourcc in ("H264", "AVC1"):
            sample_entry_payload += bytes([
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # compressor name
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # compressor name
            ])
            sample_entry_payload += u16.pack(0x18)  # depth
            sample_entry_payload += s16.pack(-1)  # pre defined
            sps, pps = codec_private_data.split(u32.pack(1))[1:]

            sample_entry_payload += get_avcc_box(sps, pps)

            if is_encrypted:
                sample_entry_payload += track_encryption_box(b"avc1", kid)

            sample_entry_box = box(b"avc1" if not is_encrypted else b"encv", sample_entry_payload)

        if fourcc in ("HEV1", "HVC1"):
            sample_entry_payload += bytes([
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # compressor name
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # compressor name
            ])
            sample_entry_payload += u16.pack(0x18)  # depth
            sample_entry_payload += s16.pack(-1)  # pre defined
            nalu = codec_private_data.split(u32.pack(1))[1:]
            vps, sps, pps = nalu
            sample_entry_payload += get_hvcc_box(vps, sps, pps)

            if is_encrypted:
                sample_entry_payload += track_encryption_box(b"hvc1", kid)

            sample_entry_box = box(b"hvc1" if not is_encrypted else b"encv", sample_entry_payload)

        if fourcc in ("DVHE", "DVH1"):
            compressor_name = "DOVI Coding"
            compressor_name_bytes = compressor_name.encode("ascii", errors="ignore")  # Ignore non-ASCII chars if any

            compressor_name_padded = compressor_name_bytes.ljust(32, b"\x00")  # Pad with null bytes to ensure 32 bytes

            sample_entry_payload += compressor_name_padded
            sample_entry_payload += u16.pack(0x18)  # depth
            sample_entry_payload += s16.pack(-1)  # pre defined
            nalu = codec_private_data.split(u32.pack(1))[1:]
            vps = next(x for x in nalu if (x[0] >> 1) == 0x20)
            sps = next(x for x in nalu if (x[0] >> 1) == 0x21)
            pps = next(x for x in nalu if (x[0] >> 1) == 0x22)
            print(vps.hex())
            print(sps.hex())
            print(pps.hex())

            sample_entry_payload += get_hvcc_box(vps, sps, pps)

            sample_entry_payload += get_dvmeta_box()

            if is_encrypted:
                sample_entry_payload += track_encryption_box(fourcc.lower().encode('utf-8'), kid)

            sample_entry_box = box(fourcc.lower().encode('utf-8') if not is_encrypted else b"encv", sample_entry_payload)

    stts_payload = u32.pack(0)  # entry count
    stbl_payload = full_box(b"stts", 0, 0, stts_payload)  # Decoding Time to Sample Box

    stsc_payload = u32.pack(0)  # entry count
    stbl_payload += full_box(b"stsc", 0, 0, stsc_payload)  # Sample To Chunk Box

    stco_payload = u32.pack(0)  # entry count
    stbl_payload += full_box(b"stco", 0, 0, stco_payload)  # Chunk Offset Box

    stsz_payload = u32.pack(0)  # sample size
    stsz_payload += u32.pack(0)  # sample count
    stbl_payload += full_box(b"stsz", 0, 0, stsz_payload)  # Sample Sizes Box

    stsd_payload += sample_entry_box
    stbl_payload += full_box(b"stsd", 0, 0, stsd_payload)  # Sample Description Box

    minf_payload += box(b"stbl", stbl_payload)  # Sample Table Box

    mdia_payload += box(b"minf", minf_payload)  # Media Information Box

    trak_payload += box(b"mdia", mdia_payload)  # Media Box

    moov_payload += box(b"trak", trak_payload)  # Track Box

    # it doesn't seem to be needed
    # mehd_payload = u64.pack(duration)
    # mvex_payload = full_box(b"mehd", 1, 0, mehd_payload)  # Movie Extends Header Box

    trex_payload = u32.pack(track_id)  # track id
    trex_payload += u32.pack(1)  # default sample description index
    trex_payload += u32.pack(0)  # default sample duration
    trex_payload += u32.pack(0)  # default sample size
    trex_payload += u32.pack(0)  # default sample flags
    mvex_payload = full_box(b"trex", 0, 0, trex_payload)  # Track Extends Box

    moov_payload += box(b"mvex", mvex_payload)  # Movie Extends Box
    stream.write(box(b"moov", moov_payload))  # Movie Box

def get_hvcc_box(vps: bytes, sps: bytes, pps: bytes, nal_unit_length_field=4):
    data = parse_hvcc_sps(sps)
    ptf = data['profile_tier_level']
    hvcc_payload = u8.pack(1) # Configuration version
    hvcc_payload += u8.pack((ptf['general_profile_space'] << 6) + (0x20 if ptf['general_tier_flag'] else 0) | ptf['general_profile_idc']) # general_profile_space + general_tier_flag + general_profile_idc
    hvcc_payload += u32.pack(ptf['general_profile_compatibility_flags']) # general_profile_compatibility_flags
    hvcc_payload += ptf['general_constraint_indicator_flags'].to_bytes(6, "big") # general_constraint_indicator_flags
    hvcc_payload += u8.pack(ptf['general_level_idc']) # general_level_idc
    hvcc_payload += u16.pack(0xf000) # reserved + min_spatial_segmentation_idc
    hvcc_payload += u8.pack(0xfc) # reserved + parallelismType
    hvcc_payload += u8.pack(data['chroma_format_idc']) # reserved + chromaFormat 
    hvcc_payload += u8.pack(data['bit_depth_luma_minus_8'] + 8) # reserved + bitDepthLumaMinus8
    hvcc_payload += u8.pack(data['bit_depth_chroma_minus_8'] + 8) # reserved + bitDepthChromaMinus8
    hvcc_payload += u16.pack(0) # average frame rate 
    hvcc_payload += u8.pack((0 << 6) | (0 << 3) | (0 << 2) | (nal_unit_length_field - 1)) # constantFrameRate + numTemporalLayers + temporalIdNested + lengthSizeMinusOne
    hvcc_payload += u8.pack(0x03) # numOfArrays (vps sps pps)

    hvcc_payload += u8.pack(0x20 | 0x80)
    hvcc_payload += u16.pack(1)
    hvcc_payload += u16.pack(len(vps))
    hvcc_payload += vps

    hvcc_payload += u8.pack(0x21 | 0x80)
    hvcc_payload += u16.pack(1)
    hvcc_payload += u16.pack(len(sps))
    hvcc_payload += sps

    hvcc_payload += u8.pack(0x22 | 0x80)
    hvcc_payload += u16.pack(1)
    hvcc_payload += u16.pack(len(pps))
    hvcc_payload += pps

    return box(b"hvcC", hvcc_payload)

# the box will always be dvcC as profile is less than 7
def get_dvmeta_box():
    payload = BitStream()
    
    # Dolby Vision configuration fields
    payload.append("uint:8=1")  # dv_version_major (8 bits)
    payload.append("uint:8=0")  # dv_version_minor (8 bits)
    
    # dv_profile (7 bits) and dv_level (6 bits)
    dv_profile = 5  # Example: Dolby Vision profile 5
    dv_level = 6    # Example: Dolby Vision level 6
    payload.append(f"uint:7={dv_profile}")  # dv_profile (7 bits)
    payload.append(f"uint:6={dv_level}")   # dv_level (6 bits)
    
    # Flags
    rpu_present_flag = 1
    el_present_flag = 0
    bl_present_flag = 1
    dv_bl_signal_compatibility_id = 0  # 4 bits
    
    payload.append(f"uint:1={rpu_present_flag}")  # rpu_present_flag
    payload.append(f"uint:1={el_present_flag}")   # el_present_flag
    payload.append(f"uint:1={bl_present_flag}")   # bl_present_flag
    payload.append(f"uint:4={dv_bl_signal_compatibility_id}")  # dv_bl_signal_compatibility_id
    
    # dv_md_compression (2 bits) + reserved (26 bits)
    dv_md_compression = 0
    payload.append(f"uint:2={dv_md_compression}")  # dv_md_compression
    payload.append("uint:26=0")  # Reserved (26 bits)
    
    # Reserved fields
    payload.append("uint:32=0")  # Reserved (32 bits)
    payload.append("uint:32=0")  # Reserved (32 bits)
    payload.append("uint:32=0")  # Reserved (32 bits)
    payload.append("uint:32=0")  # Reserved (32 bits)

    return box(b"dvcC", payload.bytes)

def get_avcc_box(sps, pps, nal_unit_length_field=4):
    data = parse_avcc_sps(sps)
    avcc_payload = u8.pack(1)
    # avcc_payload += sps[1:4]
    avcc_payload += u8.pack(data['profile'])
    avcc_payload += u8.pack(data['profile_compatibility'])
    avcc_payload += u8.pack(data['level'])
    avcc_payload += u8.pack(0xfc | (nal_unit_length_field - 1))
    avcc_payload += u8.pack(1)  # reserved (0) + number of sps (0000001)
    avcc_payload += u16.pack(len(sps))
    avcc_payload += sps
    avcc_payload += u8.pack(1)  # number of pps
    avcc_payload += u16.pack(len(pps))
    avcc_payload += pps

    return box(b"avcC", avcc_payload)


def extract_box_data(data: bytes, box_sequence: list[bytes]) -> bytes:
    data_reader = io.BytesIO(data)
    while True:
        box_size = u32.unpack(data_reader.read(4))[0]
        box_type = data_reader.read(4)
        if box_type == box_sequence[0]:
            box_data = data_reader.read(box_size - 8)
            if len(box_sequence) == 1:
                return box_data
            return extract_box_data(box_data, box_sequence[1:])
        data_reader.seek(box_size - 8, 1)


def get_track_id(data: bytes) -> int:
    tfhd_data = extract_box_data(data, [b"moof", b"traf", b"tfhd"])
    return u32.unpack(tfhd_data[4:8])[0]
