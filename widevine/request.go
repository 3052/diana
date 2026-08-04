package widevine

import (
   "41.neocities.org/protobuf"
   "crypto/rsa"
)

// EncodeSignedMessage envelopes the request with an RSA signature.
func EncodeSignedMessage(requestData []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
   signature, err := signMessage(requestData, privateKey)
   if err != nil {
      return nil, err
   }
   message := protobuf.Message{
      protobuf.Varint(1, 1), // LICENSE_REQUEST
      protobuf.Bytes(2, requestData),
      protobuf.Bytes(3, signature),
   }
   return message.Encode()
}

// EncodeLicenseRequest creates and serializes a LicenseRequest protobuf message.
func (p *PsshData) EncodeLicenseRequest(clientId []byte) ([]byte, error) {
   psshBytes, err := p.Encode()
   if err != nil {
      return nil, err
   }
   psshDataField := protobuf.Bytes(1, psshBytes)
   widevinePsshData := protobuf.Embed(1, psshDataField)
   contentIdentification := protobuf.Embed(2, widevinePsshData)

   message := protobuf.Message{
      protobuf.Bytes(1, clientId),
      contentIdentification,
      protobuf.Varint(3, 1), // STREAMING
   }
   return message.Encode()
}

// request.go
