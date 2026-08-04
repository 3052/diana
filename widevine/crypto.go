package widevine

import (
   "crypto"
   "crypto/rsa"
   "crypto/sha1"
   "crypto/x509"
   "encoding/pem"
   "errors"
   "fmt"
)

func DecodePrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
   block, _ := pem.Decode(pemData)
   if block == nil {
      return nil, errors.New("failed to decode PEM block containing private key")
   }
   key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
   if err == nil {
      rsaKey, ok := key.(*rsa.PrivateKey)
      if !ok {
         return nil, errors.New("key in PEM block is not an RSA private key")
      }
      return rsaKey, nil
   }
   rsaKey, errPkcs1 := x509.ParsePKCS1PrivateKey(block.Bytes)
   if errPkcs1 != nil {
      return nil, fmt.Errorf("failed to parse private key: PKCS#8 (%v), PKCS#1 (%v)", err, errPkcs1)
   }
   return rsaKey, nil
}

func signMessage(requestData []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
   hash := sha1.New()
   hash.Write(requestData)
   hashed := hash.Sum(nil)
   opts := &rsa.PSSOptions{
      SaltLength: rsa.PSSSaltLengthEqualsHash,
      Hash:       crypto.SHA1,
   }
   return rsa.SignPSS(noopReader{}, privateKey, crypto.SHA1, hashed, opts)
}

type noopReader struct{}

func (noopReader) Read(p []byte) (n int, err error) {
   return len(p), nil
}

// crypto.go
