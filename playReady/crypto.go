package playReady

import (
   "41.neocities.org/diana/playReady/xml"
   "crypto/aes"
   "crypto/ecdh"
   "crypto/ecdsa"
   "crypto/elliptic"
   "encoding/hex"
   "errors"
   "filippo.io/nistec"
   "github.com/emmansun/gmsm/cipher"
   
   "time"
)

const magicConstantZero = "7ee9ed4af773224f00b8ea7efb027cbb"

const wmrmPublicKey = "C8B6AF16EE941AADAA5389B4AF2C10E356BE42AF175EF3FACE93254E7B0B3D9B982B27B5CB2341326E56AA857DBFD5C634CE2CF9EA74FCA8F2AF5957EFEEA562"

func GenerateKey() (*ecdsa.PrivateKey, error) {
   return ecdsa.GenerateKey(elliptic.P256(), nil)
}

func ParseRawPrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
   if len(data) < 32 {
      return nil, errors.New("private key data too short")
   }
   return ecdsa.ParseRawPrivateKey(elliptic.P256(), data[:32])
}

func PrivateKeyBytes(key *ecdsa.PrivateKey) ([]byte, error) {
   ecdhKey, err := key.ECDH()
   if err != nil {
      return nil, err
   }
   pubBytes, err := publicKeyBytes(key)
   if err != nil {
      return nil, err
   }
   return append(ecdhKey.Bytes(), pubBytes...), nil
}

func aesEcbEncrypt(data, key []byte) ([]byte, error) {
   block, err := aes.NewCipher(key)
   if err != nil {
      return nil, err
   }
   encData := make([]byte, len(data))
   cipher.NewECBEncrypter(block).CryptBlocks(encData, data)
   return encData, nil
}

func elGamalDecrypt(ciphertext []byte, privKey *ecdsa.PrivateKey) ([]byte, error) {
   c1Bytes := [65]byte{4}
   copy(c1Bytes[1:], ciphertext[:64])
   c1, err := nistec.NewP256Point().SetBytes(c1Bytes[:])
   if err != nil {
      return nil, err
   }

   c2Bytes := [65]byte{4}
   copy(c2Bytes[1:], ciphertext[64:128])
   c2, err := nistec.NewP256Point().SetBytes(c2Bytes[:])
   if err != nil {
      return nil, err
   }

   ecdhKey, err := privKey.ECDH()
   if err != nil {
      return nil, err
   }

   sharedSec, err := nistec.NewP256Point().ScalarMult(c1, ecdhKey.Bytes())
   if err != nil {
      return nil, err
   }

   invSec := nistec.NewP256Point().Negate(sharedSec)
   mPoint := nistec.NewP256Point().Add(c2, invSec)
   return mPoint.Bytes()[1:], nil
}

func elGamalEncrypt(data, pubKey *ecdsa.PublicKey) ([]byte, error) {
   randY := [32]byte{1}

   c1, err := nistec.NewP256Point().ScalarBaseMult(randY[:])
   if err != nil {
      return nil, err
   }

   keyECDH, err := pubKey.ECDH()
   if err != nil {
      return nil, err
   }

   keyPoint, err := nistec.NewP256Point().SetBytes(keyECDH.Bytes())
   if err != nil {
      return nil, err
   }

   sharedSec, err := nistec.NewP256Point().ScalarMult(keyPoint, randY[:])
   if err != nil {
      return nil, err
   }

   dataECDH, err := data.ECDH()
   if err != nil {
      return nil, err
   }

   dataPoint, err := nistec.NewP256Point().SetBytes(dataECDH.Bytes())
   if err != nil {
      return nil, err
   }

   c2 := nistec.NewP256Point().Add(dataPoint, sharedSec)

   return append(c1.Bytes()[1:], c2.Bytes()[1:]...), nil
}

func elGamalKeyGeneration() (*ecdsa.PublicKey, error) {
   uncompressed := [65]byte{4}
   _, err := hex.Decode(uncompressed[1:], []byte(wmrmPublicKey))
   if err != nil {
      return nil, err
   }

   return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed[:])
}

func newLa(pubKey *ecdsa.PublicKey, cipherData, kid []byte, contentId string) (*xml.La, error) {
   genKey, err := elGamalKeyGeneration()
   if err != nil {
      return nil, err
   }
   cipherValue, err := elGamalEncrypt(pubKey, genKey)
   if err != nil {
      return nil, err
   }

   headerData := xml.WrmHeaderData{
      Kid: kid, // microsoft.com
      ProtectInfo: xml.ProtectInfo{ // microsoft.com
         AlgId:  "AESCTR", // microsoft.com
         KeyLen: 16,       // microsoft.com
      },
   }
   if contentId != "" {
      headerData.CustomAttributes = &xml.CustomAttributes{ // 9c9media.com
         ContentId: contentId, // 9c9media.com
      }
   }

   nonce := [16]byte{1} // amazon.com cannot be zero

   return &xml.La{
      ClientInfo: &xml.ClientInfo{ // microsoft.com
         ClientVersion: "10.0.16384.10011", // microsoft.com
      },
      ClientTime: int(time.Now().Unix()), // 9c9media.com
      ContentHeader: xml.ContentHeader{ // microsoft.com
         WrmHeader: xml.WrmHeader{ // microsoft.com
            Data:    headerData,                                                 // microsoft.com
            Version: "4.0.0.0",                                                  // microsoft.com
            XmlNs:   "http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader", // microsoft.com
         },
      },
      EncryptedData: xml.EncryptedData{ // microsoft.com
         CipherData: xml.CipherData{ // microsoft.com
            CipherValue: cipherData, // microsoft.com
         },
         EncryptionMethod: xml.EncryptionMethod{ // microsoft.com
            Algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc", // microsoft.com
         },
         KeyInfo: xml.EncryptedDataInfo{ // microsoft.com
            EncryptedKey: xml.EncryptedKey{ // microsoft.com
               CipherData: xml.CipherData{ // microsoft.com
                  CipherValue: cipherValue, // microsoft.com
               },
               EncryptionMethod: xml.EncryptionMethod{ // microsoft.com
                  Algorithm: "http://schemas.microsoft.com/DRM/2007/03/protocols#ecc256", // microsoft.com
               },
               KeyInfo: xml.EncryptedKeyInfo{ // microsoft.com
                  KeyName: "WMRMServer",                         // microsoft.com
                  XmlNs:   "http://www.w3.org/2000/09/xmldsig#", // microsoft.com
               },
               XmlNs: "http://www.w3.org/2001/04/xmlenc#", // microsoft.com
            },
            XmlNs: "http://www.w3.org/2000/09/xmldsig#", // microsoft.com
         },
         Type:  "http://www.w3.org/2001/04/xmlenc#Element", // microsoft.com
         XmlNs: "http://www.w3.org/2001/04/xmlenc#",        // microsoft.com
      },
      Id:           "SignedData",                                         // microsoft.com
      LicenseNonce: nonce[:],                                             // 9c9media.com
      Version:      "1",                                                  // microsoft.com
      XmlNs:        "http://schemas.microsoft.com/DRM/2007/03/protocols", // microsoft.com
   }, nil
}

func publicKeyBytes(key *ecdsa.PrivateKey) ([]byte, error) {
   ecdhKey, err := key.PublicKey.ECDH()
   if err != nil {
      return nil, err
   }
   // Return 64 bytes (X and Y coordinates) without the 0x04 uncompressed prefix
   return ecdhKey.Bytes()[1:], nil
}

func xorKey(left, right []byte) []byte {
   if len(left) != len(right) {
      panic("slices have different lengths")
   }
   result := make([]byte, len(left))
   for i := 0; i < len(left); i++ {
      result[i] = left[i] ^ right[i]
   }
   return result
}

type xmlKey struct {
   PublicKey *ecdsa.PublicKey
   X         [32]byte
}

func (x *xmlKey) aesIv() []byte {
   return x.X[:16]
}

func (x *xmlKey) aesKey() []byte {
   return x.X[16:]
}

func (x *xmlKey) initialize() error {
   privBytes := [32]byte{1}

   privECDH, err := ecdh.P256().NewPrivateKey(privBytes[:])
   if err != nil {
      return err
   }
   pubBytes := privECDH.PublicKey().Bytes()
   x.PublicKey, err = ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pubBytes)
   if err != nil {
      return err
   }

   copy(x.X[:], pubBytes[1:33])
   return nil
}

// crypto.go
