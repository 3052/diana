def get_hvcc_box(vps: bytes, sps: bytes, pps: bytes, nal_unit_length_field=4):
    data = parse_sps(sps)

    hvcc_payload = u8.pack(1) # Configuration version
    hvcc_payload += u8.pack((data['generalProfileSpace'] << 6) + (0x20 if data['generalTierFlag'] == 1 else 0) | data['generalProfileIdc'])
    hvcc_payload += u32.pack(data['generalProfileCompatibilityFlags']) # general_profile_compatibility_flags
    hvcc_payload += data['constraintBytes'].to_bytes(6, byteorder='big') # general_constraint_indicator_flags
    hvcc_payload += u8.pack(data['generalProfileIdc']) # general_level
    hvcc_payload += u16.pack(0xf000)
    hvcc_payload += u8.pack(0xfc)
    hvcc_payload += u8.pack(0xfc)
    hvcc_payload += u8.pack(0xf8)
    hvcc_payload += u8.pack(0xf8)
    hvcc_payload += u16.pack(0) # average frame rate 
    hvcc_payload += u8.pack((0 << 6) | (0 << 3) | (0 << 2) | (nal_unit_length_field - 1))
    hvcc_payload += u8.pack(0x03)

    # getting into vps sps and pps writing
    hvcc_payload += u8.pack(0x20)
    hvcc_payload += u16.pack(1)
    hvcc_payload += u16.pack(len(vps))
    hvcc_payload += vps

    hvcc_payload += u8.pack(0x21)
    hvcc_payload += u16.pack(1)
    hvcc_payload += u16.pack(len(sps))
    hvcc_payload += sps
    hvcc_payload += u8.pack(0x22)
    hvcc_payload += u16.pack(1)
    hvcc_payload += u16.pack(len(pps))
    hvcc_payload += pps

    return box(b"hvcC", hvcc_payload)  # AVC Decoder Configuration Record
