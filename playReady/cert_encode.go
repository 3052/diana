package playReady

import "encoding/binary"

func (c *Certificate) encode() []byte {
   var raw []byte
   var lengthToSignature uint32
   unknownIdx := make(map[uint16]int)

   for _, recType := range c.RecordOrder {
      if BcertObject(recType) == BcertObjectSignature {
         lengthToSignature = uint32(16 + len(raw))
      }

      var valBytes []byte
      flags := uint16(1)

      switch BcertObject(recType) {
      case BcertObjectBasic:
         if c.BasicInfo != nil {
            flags = c.BasicInfo.Header.Flags
            valBytes = make([]byte, 80)
            copy(valBytes[0:16], c.BasicInfo.CertificateID.Rgb[:])
            binary.BigEndian.PutUint32(valBytes[16:20], c.BasicInfo.SecurityLevel)
            binary.BigEndian.PutUint32(valBytes[20:24], c.BasicInfo.Flags)
            binary.BigEndian.PutUint32(valBytes[24:28], c.BasicInfo.Type)
            copy(valBytes[28:60], c.BasicInfo.DigestValue[:])
            binary.BigEndian.PutUint32(valBytes[60:64], c.BasicInfo.ExpirationDate)
            copy(valBytes[64:80], c.BasicInfo.ClientID.Rgb[:])
         }
      case BcertObjectDevice:
         if c.DeviceInfo != nil {
            flags = c.DeviceInfo.Header.Flags
            valBytes = binary.BigEndian.AppendUint32(nil, c.DeviceInfo.CbMaxLicense)
            valBytes = binary.BigEndian.AppendUint32(valBytes, c.DeviceInfo.CbMaxHeader)
            valBytes = binary.BigEndian.AppendUint32(valBytes, c.DeviceInfo.MaxChainDepth)
         }
      case BcertObjectFeature:
         if c.FeatureInfo != nil {
            flags = c.FeatureInfo.Header.Flags
            valBytes = binary.BigEndian.AppendUint32(nil, c.FeatureInfo.NumFeatureEntries)
            for _, feat := range c.FeatureInfo.FeatureSet {
               valBytes = binary.BigEndian.AppendUint32(valBytes, feat)
            }
         }
      case BcertObjectKey:
         if c.KeyInfo != nil {
            flags = c.KeyInfo.Header.Flags
            valBytes = binary.BigEndian.AppendUint32(nil, c.KeyInfo.NumKeys)
            for _, key := range c.KeyInfo.Keys {
               valBytes = binary.BigEndian.AppendUint16(valBytes, key.Type)
               valBytes = binary.BigEndian.AppendUint16(valBytes, key.Length)
               valBytes = binary.BigEndian.AppendUint32(valBytes, key.Flags)
               valBytes = append(valBytes, key.Value...)
               valBytes = binary.BigEndian.AppendUint32(valBytes, uint32(len(key.UsageSet)))
               for _, usage := range key.UsageSet {
                  valBytes = binary.BigEndian.AppendUint32(valBytes, usage)
               }
            }
         }
      case BcertObjectManufacturer:
         if c.ManufacturerInfo != nil {
            flags = c.ManufacturerInfo.Header.Flags
            valBytes = binary.BigEndian.AppendUint32(nil, c.ManufacturerInfo.Flags)
            valBytes = append(valBytes, encodePaddedString(c.ManufacturerInfo.ManufacturerStrings.ManufacturerName)...)
            valBytes = append(valBytes, encodePaddedString(c.ManufacturerInfo.ManufacturerStrings.ModelName)...)
            valBytes = append(valBytes, encodePaddedString(c.ManufacturerInfo.ManufacturerStrings.ModelNumber)...)
         }
      case BcertObjectSignature:
         if c.SignatureInfo != nil {
            flags = c.SignatureInfo.Header.Flags
            valBytes = binary.BigEndian.AppendUint16(nil, c.SignatureInfo.SignatureType)
            valBytes = binary.BigEndian.AppendUint16(valBytes, c.SignatureInfo.SignatureData.Cb)
            valBytes = append(valBytes, c.SignatureInfo.SignatureData.Value...)
            valBytes = binary.BigEndian.AppendUint32(valBytes, c.SignatureInfo.IssuerKeyLength)
            valBytes = append(valBytes, c.SignatureInfo.IssuerKey...)
         }
      default:
         records := c.UnknownRecords[recType]
         idx := unknownIdx[recType]
         valBytes = records[idx].Value
         flags = records[idx].Flags
         unknownIdx[recType]++
      }

      raw = binary.BigEndian.AppendUint16(raw, flags)
      raw = binary.BigEndian.AppendUint16(raw, recType)
      raw = binary.BigEndian.AppendUint32(raw, uint32(len(valBytes)+8))
      raw = append(raw, valBytes...)
   }

   if lengthToSignature == 0 {
      lengthToSignature = uint32(16 + len(raw))
   }

   length := uint32(16 + len(raw))

   data := make([]byte, 16)
   binary.BigEndian.PutUint32(data[0:4], c.Header.HeaderTag)
   binary.BigEndian.PutUint32(data[4:8], c.Header.Version)
   binary.BigEndian.PutUint32(data[8:12], length)
   binary.BigEndian.PutUint32(data[12:16], lengthToSignature)

   return append(data, raw...)
}

// cert_encode.go
