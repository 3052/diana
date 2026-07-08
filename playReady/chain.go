package playReady

import (
   "bytes"
   "crypto/aes"
   "crypto/cipher"
   "crypto/ecdsa"
   "crypto/sha256"
   "encoding/binary"
   "errors"
   "slices"

   "41.neocities.org/diana/playReady/xml"
   "github.com/emmansun/gmsm/padding"
)

func ParseChain(data []byte) (*Chain, error) {
   c := &Chain{}
   if len(data) < 20 {
      return nil, errors.New("chain data too short")
   }

   tag := binary.BigEndian.Uint32(data)
   if tag != ChainHeaderTag {
      return nil, errors.New("failed to find chain magic")
   }
   data = data[4:]

   c.Header.HeaderTag = tag
   c.Header.Version = binary.BigEndian.Uint32(data)
   data = data[4:]

   c.Header.CbChain = binary.BigEndian.Uint32(data)
   data = data[4:]

   c.Header.Flags = binary.BigEndian.Uint32(data)
   data = data[4:]

   certCount := binary.BigEndian.Uint32(data)
   data = data[4:]

   c.Header.Certs = certCount
   c.Certificates = make([]Certificate, certCount)

   for index := uint32(0); index < certCount; index++ {
      var cert Certificate
      bytesRead, err := cert.decode(data)
      if err != nil {
         return nil, err
      }
      c.Certificates[index] = cert
      data = data[bytesRead:]
   }

   return c, nil
}

func (c *Chain) LicenseRequestBytes(signingKey *ecdsa.PrivateKey, kid []byte, contentID string) ([]byte, error) {
   var key xmlKey
   err := key.initialize()
   if err != nil {
      return nil, err
   }

   cipherOutput, err := c.cipherData(&key)
   if err != nil {
      return nil, err
   }

   laRequest, err := newLa(key.PublicKey, cipherOutput, kid, contentID)
   if err != nil {
      return nil, err
   }

   laData, err := xml.Marshal(laRequest)
   if err != nil {
      return nil, err
   }
   laDigest := sha256.Sum256(laData)

   signedInfo := xml.SignedInfo{
      Reference: xml.Reference{ // microsoft.com
         DigestValue: laDigest[:],   // microsoft.com
         Uri:         "#SignedData", // microsoft.com
      },
   }

   signedData, err := xml.Marshal(signedInfo)
   if err != nil {
      return nil, err
   }
   signedDigest := sha256.Sum256(signedData)

   sigR, sigS, err := ecdsa.Sign(nil, signingKey, signedDigest[:])
   if err != nil {
      return nil, err
   }

   var sign [64]byte
   sigR.FillBytes(sign[:32])
   sigS.FillBytes(sign[32:])

   envelope := xml.Envelope{
      Body: xml.Body{ // microsoft.com
         AcquireLicense: &xml.AcquireLicense{ // microsoft.com
            Challenge: xml.OuterChallenge{ // microsoft.com
               Challenge: xml.InnerChallenge{ // microsoft.com
                  La: laRequest, // microsoft.com
                  Signature: xml.Signature{ // microsoft.com
                     SignatureValue: sign[:],    // microsoft.com
                     SignedInfo:     signedInfo, // microsoft.com
                  },
                  XmlNs: "http://schemas.microsoft.com/DRM/2007/03/protocols/messages", // microsoft.com
               },
            },
            XmlNs: "http://schemas.microsoft.com/DRM/2007/03/protocols", // microsoft.com
         },
      },
      Soap: "http://schemas.xmlsoap.org/soap/envelope/", // microsoft.com
   }
   return xml.Marshal(envelope)
}

func (c *Chain) cipherData(key *xmlKey) ([]byte, error) {
   value := xml.Data{
      CertificateChains: xml.CertificateChains{ // microsoft.com
         CertificateChain: c.Bytes(), // microsoft.com
      },
      Features: xml.Features{ // microsoft.com
         Feature: xml.Feature{ // microsoft.com
            Name: "AESCBC", // microsoft.com (SCALABLE)
         },
      },
   }
   data, err := xml.Marshal(value)
   if err != nil {
      return nil, err
   }
   block, err := aes.NewCipher(key.aesKey())
   if err != nil {
      return nil, err
   }
   data = padding.NewPKCS7Padding(aes.BlockSize).Pad(data)
   cipher.NewCBCEncrypter(block, key.aesIv()).CryptBlocks(data, data)
   return append(key.aesIv(), data...), nil
}

func (c *Chain) Bytes() []byte {
   var certsData []byte
   for _, cert := range c.Certificates {
      certsData = append(certsData, cert.encode()...)
   }

   length := uint32(20 + len(certsData))

   data := make([]byte, 20)
   binary.BigEndian.PutUint32(data[0:4], ChainHeaderTag)
   binary.BigEndian.PutUint32(data[4:8], c.Header.Version)
   binary.BigEndian.PutUint32(data[8:12], length)
   binary.BigEndian.PutUint32(data[12:16], c.Header.Flags)
   binary.BigEndian.PutUint32(data[16:20], uint32(len(c.Certificates)))

   return append(data, certsData...)
}

func (c *Chain) verify() bool {
   modelBase := c.Certificates[len(c.Certificates)-1].SignatureInfo.IssuerKey
   for index := len(c.Certificates) - 1; index >= 0; index-- {
      valid := c.Certificates[index].verify(modelBase)
      if !valid {
         return false
      }
      modelBase = c.Certificates[index].KeyInfo.Keys[0].Value
   }
   return true
}

func (c *Chain) GenerateLeaf(modelKey, signingKey, encryptKey *ecdsa.PrivateKey) error {
   if !c.verify() {
      return errors.New("cert is not valid")
   }
   modelPub, err := publicKeyBytes(modelKey)
   if err != nil {
      return err
   }
   if !bytes.Equal(c.Certificates[0].KeyInfo.Keys[0].Value, modelPub) {
      return errors.New("zgpriv not for cert")
   }
   signPub, err := publicKeyBytes(signingKey)
   if err != nil {
      return err
   }
   encPub, err := publicKeyBytes(encryptKey)
   if err != nil {
      return err
   }

   var unsignedCert Certificate
   unsignedCert.Header.HeaderTag = CertHeaderTag
   unsignedCert.Header.Version = CertVersion
   unsignedCert.UnknownRecords = make(map[uint16][]UnknownRecord)

   digest := sha256.Sum256(signPub)

   unsignedCert.RecordOrder = append(unsignedCert.RecordOrder, uint16(BcertObjectBasic))
   unsignedCert.BasicInfo = &BasicInfo{
      Header:         ObjectHeader{Flags: 0, Type: uint16(BcertObjectBasic), CbLength: 88},
      SecurityLevel:  c.Certificates[0].BasicInfo.SecurityLevel,
      Type:           2,
      ExpirationDate: 4294967295,
   }
   copy(unsignedCert.BasicInfo.DigestValue[:], digest[:])

   unsignedCert.RecordOrder = append(unsignedCert.RecordOrder, uint16(BcertObjectDevice))
   unsignedCert.DeviceInfo = &DeviceInfo{
      Header:        ObjectHeader{Flags: 0, Type: uint16(BcertObjectDevice), CbLength: 20},
      CbMaxLicense:  10240,
      CbMaxHeader:   15360,
      MaxChainDepth: 2,
   }

   unsignedCert.RecordOrder = append(unsignedCert.RecordOrder, uint16(BcertObjectFeature))
   unsignedCert.FeatureInfo = &FeatureInfo{
      Header:            ObjectHeader{Flags: 0, Type: uint16(BcertObjectFeature), CbLength: 16},
      NumFeatureEntries: 1,
      FeatureSet:        []uint32{0xD}, // SCALABLE
   }

   unsignedCert.RecordOrder = append(unsignedCert.RecordOrder, uint16(BcertObjectKey))
   keySign := CertKey{
      Type:     1, // ECC 256
      Length:   512,
      Value:    signPub,
      UsageSet: []uint32{1},
   }
   keyEnc := CertKey{
      Type:     1, // ECC 256
      Length:   512,
      Value:    encPub,
      UsageSet: []uint32{2},
   }
   unsignedCert.KeyInfo = &KeyInfo{
      Header:  ObjectHeader{Flags: 0, Type: uint16(BcertObjectKey), CbLength: 180},
      NumKeys: 2,
      Keys:    []CertKey{keySign, keyEnc},
   }

   unsignedCert.RecordOrder = append(unsignedCert.RecordOrder, uint16(BcertObjectManufacturer))
   unsignedCert.ManufacturerInfo = c.Certificates[0].ManufacturerInfo

   unsignedCert.RecordOrder = append(unsignedCert.RecordOrder, uint16(BcertObjectSignature))
   unsignedCert.SignatureInfo = &SignatureInfo{
      Header:          ObjectHeader{Flags: 1, Type: uint16(BcertObjectSignature), CbLength: 82},
      SignatureType:   1,
      SignatureData:   SignatureData{Cb: 64, Value: make([]byte, 64)},
      IssuerKeyLength: uint32(len(modelPub)) * 8, // Bits representation natively
      IssuerKey:       modelPub,
   }

   certData := unsignedCert.encode()
   lengthToSig := binary.BigEndian.Uint32(certData[12:16])
   sigDigest := sha256.Sum256(certData[:lengthToSig])

   sigR, sigS, err := ecdsa.Sign(nil, modelKey, sigDigest[:])
   if err != nil {
      return err
   }

   var sign [64]byte
   sigR.FillBytes(sign[:32])
   sigS.FillBytes(sign[32:])
   unsignedCert.SignatureInfo.SignatureData.Value = sign[:]

   c.Certificates = slices.Insert(c.Certificates, 0, unsignedCert)
   return nil
}
