package playReady

import (
   "bytes"
   "crypto/aes"
   "crypto/ecdsa"
   "encoding/binary"
   "encoding/hex"
   "errors"
   "log"

   "41.neocities.org/diana/playReady/xml"
   "github.com/emmansun/gmsm/cbcmac"
)

// ParseLicense processes XML license data and returns the parsed License object.
func ParseLicense(data []byte) (*License, error) {
   l := &License{}
   var envelope xml.EnvelopeResponse
   err := xml.Unmarshal(data, &envelope)
   if err != nil {
      return nil, err
   }
   if envelope.Body.Fault != nil {
      return nil, errors.New(envelope.Body.Fault.Fault)
   }

   rawXmr := envelope.Body.AcquireLicenseResponse.AcquireLicenseResult.Response.LicenseResponse.Licenses.License
   err = l.decode(rawXmr)
   if err != nil {
      return nil, err
   }
   return l, nil
}

func (l *License) decode(data []byte) error {
   if len(data) < HeaderLength {
      return errors.New("license data too short")
   }

   // Keep full raw XMR for verifying signature locally without rebuilding
   l.XMRLic = data
   l.CBXMRLic = uint32(len(data))

   magic := binary.BigEndian.Uint32(data[0:4])
   if magic != MagicConstant {
      if string(data[:3]) != "XMR" {
         return errors.New("invalid XMR magic keyword")
      }
   }

   l.Version = uint32(binary.BigEndian.Uint16(data[6:8]))

   l.RightsIdBuffer = make([]byte, 16)
   copy(l.RightsIdBuffer, data[8:24])
   l.IRightsId = 8

   // XMR OuterContainer typically begins right after the header, offset by word at 4
   offset := int(binary.BigEndian.Uint16(data[4:6]))
   if offset == 0 || offset < 24 {
      offset = 24
   }

   for offset < len(data) {
      f, n := decodeFtlv(data[offset:])
      if XmrObject(f.Type) == XmrObjectOuterContainer {
         l.ContainerOuter.Valid = true
         l.parseOuterContainer(f.Value)
      }
      offset += n
   }

   return nil
}

func (l *License) parseOuterContainer(data []byte) {
   offset := 0
   for offset < len(data) {
      f, n := decodeFtlv(data[offset:])
      switch XmrObject(f.Type) {
      case XmrObjectKeyMaterialContainer:
         l.ContainerOuter.ContainerKeys.Valid = true
         l.parseKeyMaterialContainer(f.Value)
      case XmrObjectSignatureObject:
         l.ContainerOuter.Signature.Valid = true
         l.ContainerOuter.Signature.Type = binary.BigEndian.Uint16(f.Value[0:2])
         l.ContainerOuter.Signature.CBSignature = binary.BigEndian.Uint16(f.Value[2:4])
         l.ContainerOuter.Signature.SignatureBuffer = f.Value[4:]
      }
      offset += n
   }
}

func (l *License) parseKeyMaterialContainer(data []byte) {
   offset := 0
   for offset < len(data) {
      f, n := decodeFtlv(data[offset:])
      switch XmrObject(f.Type) {
      case XmrObjectContentKeyObject:
         ck := &l.ContainerOuter.ContainerKeys.ContentKey
         ck.Valid = true
         ck.GuidKeyID = f.Value[0:16]
         ck.SymmetricCipherType = binary.BigEndian.Uint16(f.Value[16:18])
         ck.KeyEncryptionCipherType = binary.BigEndian.Uint16(f.Value[18:20])
         ck.CBEncryptedKey = binary.BigEndian.Uint16(f.Value[20:22])
         ck.EncryptedKeyBuffer = f.Value[22:]
      case XmrObjectEccDeviceKeyObject:
         ek := &l.ContainerOuter.ContainerKeys.ECCKey
         ek.Valid = true
         ek.EccCurveType = binary.BigEndian.Uint16(f.Value[0:2])
         ek.CBKeyData = binary.BigEndian.Uint16(f.Value[2:4])
         ek.KeyData = f.Value[4:]
      case XmrObjectAuxKeyObject:
         ak := &l.ContainerOuter.ContainerKeys.AuxKey
         ak.Valid = true
         ak.Entries = binary.BigEndian.Uint16(f.Value[0:2])
         if ak.Entries > 0 {
            ak.EntriesList = make([]AuxKeyEntry, ak.Entries)
            vOff := 2
            for i := 0; i < int(ak.Entries); i++ {
               ak.EntriesList[i].Location = binary.BigEndian.Uint32(f.Value[vOff : vOff+4])
               copy(ak.EntriesList[i].Key[:], f.Value[vOff+4:vOff+20])
               vOff += 20
            }
         }
      }
      offset += n
   }
}

func (c *ContentKey) decrypt(privKey *ecdsa.PrivateKey, aux *AuxKey) ([]byte, error) {
   switch AsymmetricEncryptionType(c.KeyEncryptionCipherType) {
   case AsymmetricEncryptionTypeECC256:
      log.Print("AsymmetricEncryptionTypeECC256")
      return elGamalDecrypt(c.EncryptedKeyBuffer, privKey)
   case AsymmetricEncryptionTypeECC256ViaSymmetric: // scalable
      log.Print("AsymmetricEncryptionTypeECC256ViaSymmetric")
      return c.scalable(privKey, aux)
   }
   return nil, errors.New("cannot decrypt key")
}

func (c *ContentKey) scalable(privKey *ecdsa.PrivateKey, aux *AuxKey) ([]byte, error) {
   if len(c.EncryptedKeyBuffer) < 144 || !aux.Valid || aux.Entries == 0 {
      return nil, errors.New("invalid scalable key data or missing aux keys")
   }

   rootKeyInfo := c.EncryptedKeyBuffer[:144]
   rootKey := rootKeyInfo[128:]
   leafKeys := c.EncryptedKeyBuffer[144:]

   decrypted, err := elGamalDecrypt(rootKeyInfo[:128], privKey)
   if err != nil {
      return nil, err
   }
   var (
      ci [16]byte
      ck [16]byte
   )
   for index := range 16 {
      ci[index] = decrypted[index*2]
      ck[index] = decrypted[index*2+1]
   }

   magicZero, err := hex.DecodeString(magicConstantZero)
   if err != nil {
      return nil, err
   }

   rgbUplinkXkey := xorKey(ck[:], magicZero)
   contentKeyPrime, err := aesEcbEncrypt(rgbUplinkXkey, ck[:])
   if err != nil {
      return nil, err
   }

   auxKeyCalc, err := aesEcbEncrypt(aux.EntriesList[0].Key[:], contentKeyPrime)
   if err != nil {
      return nil, err
   }
   oSecondaryKey, err := aesEcbEncrypt(rootKey, ck[:])
   if err != nil {
      return nil, err
   }
   rgbKey, err := aesEcbEncrypt(leafKeys, auxKeyCalc)
   if err != nil {
      return nil, err
   }
   return aesEcbEncrypt(rgbKey, oSecondaryKey)
}

func (l *License) Decrypt(encryptKey *ecdsa.PrivateKey) ([]byte, error) {
   pubBytes, err := publicKeyBytes(encryptKey)
   if err != nil {
      return nil, err
   }

   if !l.ContainerOuter.ContainerKeys.ECCKey.Valid {
      return nil, errors.New("no device key found in license")
   }
   if !bytes.Equal(l.ContainerOuter.ContainerKeys.ECCKey.KeyData, pubBytes) {
      return nil, errors.New("license response is not for this device")
   }

   ck := &l.ContainerOuter.ContainerKeys.ContentKey
   aux := &l.ContainerOuter.ContainerKeys.AuxKey

   if !ck.Valid {
      return nil, errors.New("no content key object found")
   }

   decryptedKey, err := ck.decrypt(encryptKey, aux)
   if err != nil {
      return nil, err
   }

   if len(decryptedKey) < 32 {
      return nil, errors.New("invalid key length")
   }

   err = l.verify(decryptedKey[:16])
   if err != nil {
      return nil, err
   }

   return decryptedKey[16:32], nil
}

func (l *License) verify(contentIntegrity []byte) error {
   if !l.ContainerOuter.Signature.Valid {
      return errors.New("signature missing")
   }

   // FTLV Header (8) + Sig Header (4: Type + Length) + Signature Bytes
   sigLen := 12 + int(l.ContainerOuter.Signature.CBSignature)

   if len(l.XMRLic) < sigLen {
      return errors.New("license data is shorter than signature")
   }

   data := l.XMRLic[:len(l.XMRLic)-sigLen]

   block, err := aes.NewCipher(contentIntegrity)
   if err != nil {
      return err
   }

   data = cbcmac.NewCMAC(block, aes.BlockSize).MAC(data)
   if !bytes.Equal(data, l.ContainerOuter.Signature.SignatureBuffer) {
      return errors.New("failed to decrypt the keys - mac signature check failed")
   }
   return nil
}

// license.go
