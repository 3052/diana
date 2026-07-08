package playReady

import (
   "41.neocities.org/diana/playReady/xml"
   "encoding/binary"
   "encoding/hex"
   "errors"
   "fmt"
   "strings"
   "unicode/utf16"
)

const (
   CertHeaderTag = 0x43455254 // "CERT"
   CertVersion   = 0x00000001
)

const (
   ChainHeaderTag = 0x43484149 // "CHAI"
   ChainVersion   = 0x00000001
)

func ParsePro(data []byte) (*xml.WrmHeader, error) {
   if len(data) < 10 {
      return nil, errors.New("data too short for PlayReady Object")
   }
   proLength := binary.LittleEndian.Uint32(data[0:4])
   if proLength > uint32(len(data)) {
      return nil, errors.New("PRO length exceeds data size")
   }
   recordCount := binary.LittleEndian.Uint16(data[4:6])
   var offset uint16 = 6
   for range recordCount {
      if int(offset+4) > len(data) {
         break
      }
      recordType := binary.LittleEndian.Uint16(data[offset : offset+2])
      recordLength := binary.LittleEndian.Uint16(data[offset+2 : offset+4])
      offset += 4
      if int(offset+recordLength) > len(data) {
         return nil, errors.New("record length exceeds data size")
      }
      // Type 1 is the Rights Management (RM) Header which contains the XML
      if recordType == 1 {
         xmlData := data[offset : offset+recordLength]
         if len(xmlData)%2 != 0 {
            return nil, errors.New("invalid UTF-16LE data length")
         }
         u16s := make([]uint16, len(xmlData)/2)
         for j := range u16s {
            u16s[j] = binary.LittleEndian.Uint16(xmlData[j*2 : j*2+2])
         }
         utf8Data := []byte(string(utf16.Decode(u16s)))
         var header xml.WrmHeader
         if err := xml.Unmarshal(utf8Data, &header); err != nil {
            return nil, err
         }
         return &header, nil
      }
      offset += recordLength
   }
   return nil, errors.New("WRMHEADER record not found")
}

type BasicInfo struct {
   Header         ObjectHeader
   CertificateID  CertId
   SecurityLevel  uint32
   Flags          uint32
   Type           uint32
   DigestValue    [32]byte
   ExpirationDate uint32
   ClientID       ClientId
}

type BcertObject uint16

// Object Types
const (
   BcertObjectBasic            BcertObject = 0x0001
   BcertObjectDomain           BcertObject = 0x0002
   BcertObjectPc               BcertObject = 0x0003
   BcertObjectDevice           BcertObject = 0x0004
   BcertObjectFeature          BcertObject = 0x0005
   BcertObjectKey              BcertObject = 0x0006
   BcertObjectManufacturer     BcertObject = 0x0007
   BcertObjectSignature        BcertObject = 0x0008
   BcertObjectSilverlight      BcertObject = 0x0009
   BcertObjectMetering         BcertObject = 0x000a
   BcertObjectExtDataSignKey   BcertObject = 0x000b
   BcertObjectExtDataContainer BcertObject = 0x000c
   BcertObjectExtDataSignature BcertObject = 0x000d
   BcertObjectExtDataHwid      BcertObject = 0x000e
   BcertObjectServer           BcertObject = 0x000f
   BcertObjectSecurityVersion  BcertObject = 0x0010
   BcertObjectSecurityVersion2 BcertObject = 0x0011
)

type CertHeader struct {
   HeaderTag           uint32 // = CertHeaderTag
   Version             uint32 // = CertVersion
   CbCertificate       uint32
   CbCertificateSigned uint32
}

type CertId struct {
   Rgb [16]byte
}

func (c CertId) String() string {
   return hex.EncodeToString(c.Rgb[:])
}

type CertKey struct {
   Type     uint16
   Length   uint16
   Flags    uint32
   Value    []byte
   UsageSet []uint32
}

type Certificate struct {
   Header           CertHeader
   BasicInfo        *BasicInfo
   DeviceInfo       *DeviceInfo
   FeatureInfo      *FeatureInfo
   KeyInfo          *KeyInfo
   ManufacturerInfo *ManufacturerInfo
   SignatureInfo    *SignatureInfo

   RecordOrder    []uint16
   UnknownRecords map[uint16][]UnknownRecord
}

func (c *Certificate) String() string {
   var data []byte
   data = fmt.Appendln(data, &c.ManufacturerInfo.ManufacturerStrings)
   data = fmt.Append(data, "security level: ", c.BasicInfo.SecurityLevel)
   return string(data)
}

type Chain struct {
   Header       ChainHeader
   Certificates []Certificate
}

type ChainHeader struct {
   HeaderTag uint32 // = ChainHeaderTag
   Version   uint32 // = ChainVersion
   CbChain   uint32
   Flags     uint32
   Certs     uint32
}

type ClientId struct {
   Rgb [16]byte
}

func (c ClientId) String() string {
   return hex.EncodeToString(c.Rgb[:])
}

type DeviceInfo struct {
   Header        ObjectHeader
   CbMaxLicense  uint32
   CbMaxHeader   uint32
   MaxChainDepth uint32
}

type FeatureInfo struct {
   Header            ObjectHeader
   NumFeatureEntries uint32
   FeatureSet        []uint32
}

type KeyInfo struct {
   Header  ObjectHeader
   NumKeys uint32
   Keys    []CertKey
}

type ManufacturerInfo struct {
   Header              ObjectHeader
   Flags               uint32
   ManufacturerStrings ManufacturerStrings
}

type ManufacturerStrings struct {
   ManufacturerName PaddedString
   ModelName        PaddedString
   ModelNumber      PaddedString
}

func (m *ManufacturerStrings) String() string {
   var data []byte
   data = fmt.Appendln(data, "manufacturer name:", m.ManufacturerName)
   data = fmt.Append(data, "model number: ", m.ModelNumber)
   return string(data)
}

type ObjectHeader struct {
   Flags    uint16
   Type     uint16
   CbLength uint32
}

type PaddedString string

func (ps PaddedString) String() string {
   return strings.TrimRight(string(ps), "\x00")
}

type SignatureData struct {
   Cb    uint16
   Value []byte
}

type SignatureInfo struct {
   Header          ObjectHeader
   SignatureType   uint16
   SignatureData   SignatureData
   IssuerKeyLength uint32 // bits natively
   IssuerKey       []byte
}

type UnknownRecord struct {
   Flags uint16
   Value []byte
}
