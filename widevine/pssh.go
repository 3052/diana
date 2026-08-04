package widevine

import "41.neocities.org/protobuf"

// PsshData represents the Widevine-specific protobuf message.
type PsshData struct {
   KeyIds    [][]byte
   ContentId []byte
}

// DecodePsshData parses the protobuf wire format into a PsshData struct.
func DecodePsshData(data []byte) (*PsshData, error) {
   message, err := protobuf.DecodeMessage(data)
   if err != nil {
      return nil, err
   }

   p := &PsshData{}
   it := message.Iterator(2)
   for it.Next() {
      if field := it.Field(); field != nil {
         p.KeyIds = append(p.KeyIds, field.Bytes)
      }
   }
   if field, ok := message.Field(4); ok {
      p.ContentId = field.Bytes
   }
   return p, nil
}

// Encode serializes the PsshData struct into the protobuf wire format.
func (p *PsshData) Encode() ([]byte, error) {
   var message protobuf.Message
   for _, keyId := range p.KeyIds {
      if len(keyId) > 0 {
         message = append(message, protobuf.Bytes(2, keyId))
      }
   }
   if len(p.ContentId) > 0 {
      message = append(message, protobuf.Bytes(4, p.ContentId))
   }
   return message.Encode()
}

// pssh.go
