package playReady

import "encoding/binary"

const (
   HeaderLength  = (4 * 2) + 16 // Assuming SIZEOF(DRM_ID) == 16
   MagicConstant = 0x584D5200   // 'XMR\0'
)

func UuidOrGuid(data []byte) {
   data[0], data[3] = data[3], data[0]
   data[1], data[2] = data[2], data[1]
   data[4], data[5] = data[5], data[4]
   data[6], data[7] = data[7], data[6]
}

func encodePaddedString(val PaddedString) []byte {
   length := uint32(len(val))
   paddedLength := (length + 3) &^ 3
   data := make([]byte, int(4+paddedLength))
   binary.BigEndian.PutUint32(data, length)
   copy(data[4:], val)
   return data
}

func decodePaddedString(data []byte) (PaddedString, int) {
   length := binary.BigEndian.Uint32(data)
   paddedLength := (length + 3) &^ 3
   val := string(data[4 : 4+length])
   return PaddedString(val), int(4 + paddedLength)
}

// AsymmetricEncryptionType is used for encrypting the content key
type AsymmetricEncryptionType uint16

const (
   AsymmetricEncryptionTypeInvalid            AsymmetricEncryptionType = 0x0000
   AsymmetricEncryptionTypeRSA1024            AsymmetricEncryptionType = 0x0001
   AsymmetricEncryptionTypeChainedLicense     AsymmetricEncryptionType = 0x0002
   AsymmetricEncryptionTypeECC256             AsymmetricEncryptionType = 0x0003
   AsymmetricEncryptionTypeECC256WithKZ       AsymmetricEncryptionType = 0x0004
   AsymmetricEncryptionTypeTEETransient       AsymmetricEncryptionType = 0x0005
   AsymmetricEncryptionTypeECC256ViaSymmetric AsymmetricEncryptionType = 0x0006
)

type AuxKey struct {
   Valid       bool
   Entries     uint16
   EntriesList []AuxKeyEntry
}

type AuxKeyEntry struct {
   Location uint32
   Key      [16]byte
}

type ContentKey struct {
   Valid                   bool
   GuidKeyID               []byte
   IGuidKeyID              uint32
   SymmetricCipherType     uint16
   KeyEncryptionCipherType uint16
   CBEncryptedKey          uint16
   EncryptedKeyBuffer      []byte
   IEncryptedKey           uint32
}

type EccDeviceKey struct {
   Valid        bool
   EccCurveType uint16
   IKeyData     uint32
   CBKeyData    uint16
   KeyData      []byte
}

type KeyMaterial struct {
   Valid      bool
   ContentKey ContentKey
   ECCKey     EccDeviceKey
   AuxKey     AuxKey
}

type License struct {
   RightsIdBuffer []byte
   IRightsId      uint32
   Version        uint32
   ContainerOuter OuterContainer
   XMRLic         []byte
   CBXMRLic       uint32
}

type OuterContainer struct {
   Valid         bool
   ContainerKeys KeyMaterial
   Signature     Signature
}

type Signature struct {
   Valid           bool
   Type            uint16
   SignatureBuffer []byte
   ISignature      uint32
   CBSignature     uint16
}

type XmrObject uint16

const (
   XmrObjectInvalid                                       XmrObject = 0x0000
   XmrObjectOuterContainer                                XmrObject = 0x0001
   XmrObjectGlobalPolicyContainer                         XmrObject = 0x0002
   XmrObjectMinimumEnvironmentObject                      XmrObject = 0x0003
   XmrObjectPlaybackPolicyContainer                       XmrObject = 0x0004
   XmrObjectOutputProtectionObject                        XmrObject = 0x0005
   XmrObjectUplinkKidObject                               XmrObject = 0x0006
   XmrObjectExplicitAnalogVideoOutputProtectionContainer  XmrObject = 0x0007
   XmrObjectAnalogVideoOutputConfigurationObject          XmrObject = 0x0008
   XmrObjectKeyMaterialContainer                          XmrObject = 0x0009
   XmrObjectContentKeyObject                              XmrObject = 0x000A
   XmrObjectSignatureObject                               XmrObject = 0x000B
   XmrObjectSerialNumberObject                            XmrObject = 0x000C
   XmrObjectSettingsObject                                XmrObject = 0x000D
   XmrObjectCopyPolicyContainer                           XmrObject = 0x000E
   XmrObjectAllowPlaylistburnPolicyContainer              XmrObject = 0x000F
   XmrObjectInclusionListObject                           XmrObject = 0x0010
   XmrObjectPriorityObject                                XmrObject = 0x0011
   XmrObjectExpirationObject                              XmrObject = 0x0012
   XmrObjectIssuedateObject                               XmrObject = 0x0013
   XmrObjectExpirationAfterFirstuseObject                 XmrObject = 0x0014
   XmrObjectExpirationAfterFirststoreObject               XmrObject = 0x0015
   XmrObjectMeteringObject                                XmrObject = 0x0016
   XmrObjectPlaycountObject                               XmrObject = 0x0017
   XmrObjectGracePeriodObject                             XmrObject = 0x001A
   XmrObjectCopycountObject                               XmrObject = 0x001B
   XmrObjectCopyProtectionObject                          XmrObject = 0x001C
   XmrObjectPlaylistburnCountObject                       XmrObject = 0x001F
   XmrObjectRevocationInformationVersionObject            XmrObject = 0x0020
   XmrObjectRsaDeviceKeyObject                            XmrObject = 0x0021
   XmrObjectSourceidObject                                XmrObject = 0x0022
   XmrObjectRevocationContainer                           XmrObject = 0x0025
   XmrObjectRsaLicenseGranterKeyObject                    XmrObject = 0x0026
   XmrObjectUseridObject                                  XmrObject = 0x0027
   XmrObjectRestrictedSourceidObject                      XmrObject = 0x0028
   XmrObjectDomainIdObject                                XmrObject = 0x0029
   XmrObjectEccDeviceKeyObject                            XmrObject = 0x002A
   XmrObjectGenerationNumberObject                        XmrObject = 0x002B
   XmrObjectPolicyMetadataObject                          XmrObject = 0x002C
   XmrObjectOptimizedContentKeyObject                     XmrObject = 0x002D
   XmrObjectExplicitDigitalAudioOutputProtectionContainer XmrObject = 0x002E
   XmrObjectRingtonePolicyContainer                       XmrObject = 0x002F
   XmrObjectExpirationAfterFirstplayObject                XmrObject = 0x0030
   XmrObjectDigitalAudioOutputConfigurationObject         XmrObject = 0x0031
   XmrObjectRevocationInformationVersion2Object           XmrObject = 0x0032
   XmrObjectEmbeddingBehaviorObject                       XmrObject = 0x0033
   XmrObjectSecurityLevel                                 XmrObject = 0x0034
   XmrObjectCopyToPcContainer                             XmrObject = 0x0035
   XmrObjectPlayEnablerContainer                          XmrObject = 0x0036
   XmrObjectMoveEnablerObject                             XmrObject = 0x0037
   XmrObjectCopyEnablerContainer                          XmrObject = 0x0038
   XmrObjectPlayEnablerObject                             XmrObject = 0x0039
   XmrObjectCopyEnablerObject                             XmrObject = 0x003A
   XmrObjectUplinkKid2Object                              XmrObject = 0x003B
   XmrObjectCopyPolicy2Container                          XmrObject = 0x003C
   XmrObjectCopycount2Object                              XmrObject = 0x003D
   XmrObjectRingtoneEnablerObject                         XmrObject = 0x003E
   XmrObjectExecutePolicyContainer                        XmrObject = 0x003F
   XmrObjectExecutePolicyObject                           XmrObject = 0x0040
   XmrObjectReadPolicyContainer                           XmrObject = 0x0041
   XmrObjectExtensiblePolicyReserved42                    XmrObject = 0x0042
   XmrObjectExtensiblePolicyReserved43                    XmrObject = 0x0043
   XmrObjectExtensiblePolicyReserved44                    XmrObject = 0x0044
   XmrObjectExtensiblePolicyReserved45                    XmrObject = 0x0045
   XmrObjectExtensiblePolicyReserved46                    XmrObject = 0x0046
   XmrObjectExtensiblePolicyReserved47                    XmrObject = 0x0047
   XmrObjectExtensiblePolicyReserved48                    XmrObject = 0x0048
   XmrObjectExtensiblePolicyReserved49                    XmrObject = 0x0049
   XmrObjectExtensiblePolicyReserved4a                    XmrObject = 0x004A
   XmrObjectExtensiblePolicyReserved4b                    XmrObject = 0x004B
   XmrObjectExtensiblePolicyReserved4c                    XmrObject = 0x004C
   XmrObjectExtensiblePolicyReserved4d                    XmrObject = 0x004D
   XmrObjectExtensiblePolicyReserved4e                    XmrObject = 0x004E
   XmrObjectExtensiblePolicyReserved4f                    XmrObject = 0x004F
   XmrObjectRemovalDateObject                             XmrObject = 0x0050
   XmrObjectAuxKeyObject                                  XmrObject = 0x0051
   XmrObjectUplinkxObject                                 XmrObject = 0x0052
   XmrObjectMaximumDefined                                XmrObject = 0x0052
)

type ftlv struct {
   Flags  uint16
   Type   uint16
   Length uint32
   Value  []byte
}

func decodeFtlv(data []byte) (ftlv, int) {
   f := ftlv{}
   f.Flags = binary.BigEndian.Uint16(data)
   n := 2
   f.Type = binary.BigEndian.Uint16(data[n:])
   n += 2
   f.Length = binary.BigEndian.Uint32(data[n:])
   n += 4
   f.Value = data[n:][:f.Length-8]
   n += len(f.Value)
   return f, n
}

// xmr_utils.go
