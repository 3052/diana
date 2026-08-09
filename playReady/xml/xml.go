package xml

import (
   "encoding/base64"
   "encoding/xml"
)

var (
   Marshal   = xml.Marshal
   Unmarshal = xml.Unmarshal
)

type AcquireLicense struct {
   Challenge OuterChallenge `xml:"challenge"`  // microsoft.com
   XmlNs     string         `xml:"xmlns,attr"` // microsoft.com
}

type Body struct {
   AcquireLicense         *AcquireLicense // microsoft.com
   AcquireLicenseResponse *struct {
      AcquireLicenseResult struct {
         Response struct {
            LicenseResponse struct {
               Licenses struct {
                  License Bytes
               }
            }
         }
      }
   }
   Fault *struct {
      Fault string `xml:"faultstring"`
   }
}

type Bytes []byte

func (b Bytes) MarshalText() ([]byte, error) {
   return base64.StdEncoding.AppendEncode(nil, b), nil
}

func (b *Bytes) UnmarshalText(data []byte) error {
   var err error
   *b, err = base64.StdEncoding.AppendDecode(nil, data)
   if err != nil {
      return err
   }
   return nil
}

type CertificateChains struct {
   CertificateChain Bytes `xml:"CertificateChain"` // microsoft.com
}

type CipherData struct {
   CipherValue Bytes `xml:"CipherValue"` // microsoft.com
}

type ContentHeader struct {
   WrmHeader WrmHeader `xml:"WRMHEADER"` // microsoft.com
}

type CustomAttributes struct {
   ContentId string `xml:"CONTENTID"` // 9c9media.com
}

type Data struct {
   CertificateChains CertificateChains `xml:"CertificateChains"` // microsoft.com
   Features          Features          `xml:"Features"`          // microsoft.com
}

type EncryptedData struct {
   EncryptionMethod EncryptionMethod  `xml:"EncryptionMethod"` // microsoft.com
   KeyInfo          EncryptedDataInfo `xml:"KeyInfo"`          // microsoft.com
   CipherData       CipherData        `xml:"CipherData"`       // microsoft.com
   // ATTRIBUTE ORDER MATTERS
   XmlNs string `xml:"xmlns,attr"` // microsoft.com
   Type  string `xml:"Type,attr"`  // microsoft.com
}

type EncryptedDataInfo struct {
   EncryptedKey EncryptedKey `xml:"EncryptedKey"` // microsoft.com
   XmlNs        string       `xml:"xmlns,attr"`   // microsoft.com
}

type EncryptedKey struct {
   EncryptionMethod EncryptionMethod `xml:"EncryptionMethod"` // microsoft.com
   KeyInfo          EncryptedKeyInfo `xml:"KeyInfo"`          // microsoft.com
   CipherData       CipherData       `xml:"CipherData"`       // microsoft.com
   XmlNs            string           `xml:"xmlns,attr"`       // microsoft.com
}

type EncryptedKeyInfo struct {
   KeyName string `xml:"KeyName"`    // microsoft.com
   XmlNs   string `xml:"xmlns,attr"` // microsoft.com
}

type EncryptionMethod struct {
   Algorithm string `xml:"Algorithm,attr"` // microsoft.com
}

type Envelope struct {
   Body    Body     `xml:"soap:Body"`       // microsoft.com
   Soap    string   `xml:"xmlns:soap,attr"` // microsoft.com
   XMLName xml.Name `xml:"soap:Envelope"`   // microsoft.com
}

type EnvelopeResponse struct {
   Body Body
}

type Feature struct {
   Name string `xml:",attr"` // microsoft.com
}

type Features struct {
   Feature Feature `xml:"Feature"` // microsoft.com
}

type InnerChallenge struct {
   La        *La       `xml:"LA"`         // microsoft.com
   Signature Signature `xml:"Signature"`  // microsoft.com
   XmlNs     string    `xml:"xmlns,attr"` // microsoft.com
}

type La struct {
   ClientTime    int64         `xml:"ClientTime"`    // peacocktv.com
   Version       string        `xml:"Version"`       // microsoft.com
   ContentHeader ContentHeader `xml:"ContentHeader"` // microsoft.com
   LicenseNonce  Bytes         `xml:"LicenseNonce"`  // 9c9media.com
   EncryptedData EncryptedData `xml:"EncryptedData"` // microsoft.com
   XMLName       xml.Name      `xml:"LA"`            // microsoft.com
   // ATTRIBUTE ORDER MATTERS
   XmlNs string `xml:"xmlns,attr"` // microsoft.com
   Id    string `xml:"Id,attr"`    // microsoft.com
}

type OuterChallenge struct {
   Challenge InnerChallenge `xml:"Challenge"` // microsoft.com
}

type ProtectInfo struct {
   KeyLen int    `xml:"KEYLEN"` // microsoft.com
   AlgId  string `xml:"ALGID"`  // microsoft.com
}

type Reference struct {
   DigestValue Bytes  `xml:"DigestValue"` // microsoft.com
   Uri         string `xml:"URI,attr"`    // microsoft.com
}

type Signature struct {
   SignedInfo     SignedInfo `xml:"SignedInfo"`     // microsoft.com
   SignatureValue Bytes      `xml:"SignatureValue"` // microsoft.com
}

type SignedInfo struct {
   Reference Reference `xml:"Reference"`  // microsoft.com
   XmlNs     string    `xml:"xmlns,attr"` // microsoft.com
}

type WrmHeader struct {
   Data WrmHeaderData `xml:"DATA"` // microsoft.com
   // ATTRIBUTE ORDER MATTERS
   XmlNs   string `xml:"xmlns,attr"`   // microsoft.com
   Version string `xml:"version,attr"` // microsoft.com
}

type WrmHeaderData struct {
   ProtectInfo      ProtectInfo       `xml:"PROTECTINFO"`      // microsoft.com
   CustomAttributes *CustomAttributes `xml:"CUSTOMATTRIBUTES"` // 9c9media.com
   Kid              Bytes             `xml:"KID"`              // microsoft.com
}

// xml/xml.go
