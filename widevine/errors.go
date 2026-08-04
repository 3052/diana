package widevine

import (
   "41.neocities.org/protobuf"
   "errors"
   "fmt"
)

func decodeErrorFromMessage(message protobuf.Message) error {
   errorCode, ok := message.Field(1)
   if !ok || errorCode == nil {
      return errors.New("widevine license error: unknown code")
   }
   return fmt.Errorf("widevine license error: code %v", errorCode.Numeric)
}

// errors.go
