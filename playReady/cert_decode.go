package playReady

import (
   "bytes"
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/sha256"
   "encoding/binary"
   "errors"
   "math/big"
)

func (c *Certificate) decode(data []byte) (int, error) {
   n := 0
   magic := data[0:4]
   if string(magic) != "CERT" {
      return 0, errors.New("failed to find cert magic")
   }

   c.Header.HeaderTag = binary.BigEndian.Uint32(data[n:])
   n += 4
   c.Header.Version = binary.BigEndian.Uint32(data[n:])
   n += 4
   c.Header.CbCertificate = binary.BigEndian.Uint32(data[n:])
   n += 4
   c.Header.CbCertificateSigned = binary.BigEndian.Uint32(data[n:])
   n += 4

   certDataLen := int(c.Header.CbCertificate - 16)
   if len(data[n:]) < certDataLen {
      return 0, errors.New("data too short")
   }
   certData := data[n : n+certDataLen]
   n += certDataLen

   c.UnknownRecords = make(map[uint16][]UnknownRecord)

   var n1 int
   for n1 < len(certData) {
      if len(certData)-n1 < 8 {
         break
      }

      flags := binary.BigEndian.Uint16(certData[n1 : n1+2])
      recType := binary.BigEndian.Uint16(certData[n1+2 : n1+4])
      recLen := binary.BigEndian.Uint32(certData[n1+4 : n1+8])

      if recLen < 8 || n1+int(recLen) > len(certData) {
         break
      }

      valBytes := certData[n1+8 : n1+int(recLen)]
      n1 += int(recLen)

      c.RecordOrder = append(c.RecordOrder, recType)

      headerData := ObjectHeader{Flags: flags, Type: recType, CbLength: recLen}

      switch BcertObject(recType) {
      case BcertObjectBasic:
         c.BasicInfo = &BasicInfo{Header: headerData}
         copy(c.BasicInfo.CertificateID.Rgb[:], valBytes[0:16])
         c.BasicInfo.SecurityLevel = binary.BigEndian.Uint32(valBytes[16:20])
         c.BasicInfo.Flags = binary.BigEndian.Uint32(valBytes[20:24])
         c.BasicInfo.Type = binary.BigEndian.Uint32(valBytes[24:28])
         copy(c.BasicInfo.DigestValue[:], valBytes[28:60])
         c.BasicInfo.ExpirationDate = binary.BigEndian.Uint32(valBytes[60:64])
         if len(valBytes) >= 80 {
            copy(c.BasicInfo.ClientID.Rgb[:], valBytes[64:80])
         }
      case BcertObjectDevice:
         c.DeviceInfo = &DeviceInfo{Header: headerData}
         c.DeviceInfo.CbMaxLicense = binary.BigEndian.Uint32(valBytes[0:4])
         c.DeviceInfo.CbMaxHeader = binary.BigEndian.Uint32(valBytes[4:8])
         c.DeviceInfo.MaxChainDepth = binary.BigEndian.Uint32(valBytes[8:12])
      case BcertObjectFeature:
         c.FeatureInfo = &FeatureInfo{Header: headerData}
         c.FeatureInfo.NumFeatureEntries = binary.BigEndian.Uint32(valBytes[0:4])
         off := 4
         for i := uint32(0); i < c.FeatureInfo.NumFeatureEntries; i++ {
            c.FeatureInfo.FeatureSet = append(c.FeatureInfo.FeatureSet, binary.BigEndian.Uint32(valBytes[off:off+4]))
            off += 4
         }
      case BcertObjectKey:
         c.KeyInfo = &KeyInfo{Header: headerData}
         c.KeyInfo.NumKeys = binary.BigEndian.Uint32(valBytes[0:4])
         off := 4
         for i := uint32(0); i < c.KeyInfo.NumKeys; i++ {
            var kv CertKey
            kv.Type = binary.BigEndian.Uint16(valBytes[off : off+2])
            kv.Length = binary.BigEndian.Uint16(valBytes[off+2 : off+4])
            kv.Flags = binary.BigEndian.Uint32(valBytes[off+4 : off+8])
            off += 8

            kv.Value = make([]byte, 64) // For ECC P256
            copy(kv.Value, valBytes[off:off+64])
            off += 64

            usagesCount := binary.BigEndian.Uint32(valBytes[off : off+4])
            off += 4
            for u := uint32(0); u < usagesCount; u++ {
               kv.UsageSet = append(kv.UsageSet, binary.BigEndian.Uint32(valBytes[off:off+4]))
               off += 4
            }
            c.KeyInfo.Keys = append(c.KeyInfo.Keys, kv)
         }
      case BcertObjectManufacturer:
         c.ManufacturerInfo = &ManufacturerInfo{Header: headerData}
         c.ManufacturerInfo.Flags = binary.BigEndian.Uint32(valBytes[0:4])

         off := 4
         manStr, manLen := decodePaddedString(valBytes[off:])
         c.ManufacturerInfo.ManufacturerStrings.ManufacturerName = manStr
         off += manLen

         modStr, modLen := decodePaddedString(valBytes[off:])
         c.ManufacturerInfo.ManufacturerStrings.ModelName = modStr
         off += modLen

         numStr, _ := decodePaddedString(valBytes[off:])
         c.ManufacturerInfo.ManufacturerStrings.ModelNumber = numStr

      case BcertObjectSignature:
         c.SignatureInfo = &SignatureInfo{Header: headerData}
         c.SignatureInfo.SignatureType = binary.BigEndian.Uint16(valBytes[0:2])
         sigLen := binary.BigEndian.Uint16(valBytes[2:4])
         c.SignatureInfo.SignatureData.Cb = sigLen
         c.SignatureInfo.SignatureData.Value = valBytes[4 : 4+int(sigLen)]

         off := 4 + int(sigLen)
         c.SignatureInfo.IssuerKeyLength = binary.BigEndian.Uint32(valBytes[off : off+4])
         off += 4
         keyBytes := int(c.SignatureInfo.IssuerKeyLength) / 8
         c.SignatureInfo.IssuerKey = valBytes[off : off+keyBytes]
      default:
         c.UnknownRecords[recType] = append(c.UnknownRecords[recType], UnknownRecord{
            Flags: flags,
            Value: valBytes,
         })
      }
   }
   return n, nil
}

func (c *Certificate) verify(pubKey []byte) bool {
   if c.SignatureInfo == nil || !bytes.Equal(c.SignatureInfo.IssuerKey, pubKey) {
      return false
   }

   encodedKey := [65]byte{4}
   copy(encodedKey[1:], pubKey)

   publicKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), encodedKey[:])
   if err != nil {
      return false
   }

   data := c.encode()
   lengthToSig := binary.BigEndian.Uint32(data[12:16])
   signatureDigest := sha256.Sum256(data[:lengthToSig])

   sign := c.SignatureInfo.SignatureData.Value
   r := new(big.Int).SetBytes(sign[:32])
   s := new(big.Int).SetBytes(sign[32:])

   return ecdsa.Verify(publicKey, signatureDigest[:], r, s)
}

// cert_decode.go
