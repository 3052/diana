package playReady

import (
   "bytes"
   "encoding/hex"
   "io"
   "log"
   "net/http"
   "os"
   "testing"
)

var key_tests = []struct {
   content_id string
   key        string
   key_id     string
   transform  func([]byte) ([]byte, error)
   url        string
}{
   {
      key_id:     "10000000000000000000000000000000",
      content_id: "",
      transform:  func(payload []byte) ([]byte, error) { return payload, nil },
      url:        "https://test.playready.microsoft.com/service/rightsmanager.asmx?cfg=ck:AAAAAAAAAAAAAAAAAAAAAA==,ckt:AES128BitCBC",
      key:        "00000000000000000000000000000000",
   },
   {
      key_id:     "10000000000000000000000000000000",
      content_id: "",
      transform:  func(payload []byte) ([]byte, error) { return payload, nil },
      url:        "https://test.playready.microsoft.com/service/rightsmanager.asmx?cfg=ck:AAAAAAAAAAAAAAAAAAAAAA==",
      key:        "00000000000000000000000000000000",
   },
}

func TestKey(t *testing.T) {
   paths := getPaths("ignore/SL2000")
   data, err := os.ReadFile(paths.devCert)
   if err != nil {
      t.Fatal(err)
   }
   chain_data, err := ParseChain(data)
   if err != nil {
      t.Fatal(err)
   }
   data, err = os.ReadFile(paths.zPrivSig)
   if err != nil {
      t.Fatal(err)
   }
   signingKey, err := ParseRawPrivateKey(data)
   if err != nil {
      t.Fatal(err)
   }
   data, err = os.ReadFile(paths.zPrivEncr)
   if err != nil {
      t.Fatal(err)
   }
   encrypt_key, err := ParseRawPrivateKey(data)
   if err != nil {
      t.Fatal(err)
   }
   for _, test := range key_tests {
      kid, err := hex.DecodeString(test.key_id)
      if err != nil {
         t.Fatal(err)
      }
      UuidOrGuid(kid)
      payload, err := chain_data.LicenseRequestBytes(
         signingKey, kid, test.content_id,
      )
      if err != nil {
         t.Fatal(err)
      }
      reqData, err := test.transform(payload)
      if err != nil {
         t.Fatal(err)
      }

      req, err := http.NewRequest("POST", test.url, bytes.NewReader(reqData))
      if err != nil {
         t.Fatal(err)
      }
      t.Log(req.URL)

      // Scope the defer strictly to the response lifecycle
      func() {
         resp, err := http.DefaultClient.Do(req)
         if err != nil {
            t.Fatal(err)
         }
         defer resp.Body.Close()

         respData, err := io.ReadAll(resp.Body)
         if err != nil {
            t.Fatal(err)
         }
         if resp.StatusCode != http.StatusOK {
            t.Fatalf("StatusCode %v respData %q", resp.StatusCode, string(respData))
         }
         license_data, err := ParseLicense(respData)
         if err != nil {
            t.Fatal(err)
         }
         // key
         key, err := license_data.Decrypt(encrypt_key)
         if err != nil {
            t.Fatal(err)
         }
         if hex.EncodeToString(key) != test.key {
            t.Fatal("key")
         }
         // key ID DO THIS AFTER KEY
         UuidOrGuid(
            license_data.ContainerOuter.ContainerKeys.ContentKey.GuidKeyID,
         )
         key_id := hex.EncodeToString(
            license_data.ContainerOuter.ContainerKeys.ContentKey.GuidKeyID,
         )
         if key_id != test.key_id {
            t.Fatal("key ID")
         }
      }()
   }
}

func write_file(name string, data []byte) error {
   log.Println("WriteFile", name)
   return os.WriteFile(name, data, os.ModePerm)
}

func getPaths(baseDir string) testPaths {
   return testPaths{
      groupCert: baseDir + "/bgroupcert.dat",
      zPriv:     baseDir + "/zgpriv.dat",
      devCert:   baseDir + "/bdevcert.dat",
      zPrivEncr: baseDir + "/zprivencr.dat",
      zPrivSig:  baseDir + "/zprivsig.dat",
   }
}

func TestChain(t *testing.T) {
   directories := []string{"ignore/SL2000", "ignore/SL3000"}
   for _, baseDir := range directories {
      paths := getPaths(baseDir)
      data, err := os.ReadFile(paths.groupCert)
      if err != nil {
         t.Fatal(err)
      }
      chain_data, err := ParseChain(data)
      if err != nil {
         t.Fatal(err)
      }
      data, err = os.ReadFile(paths.zPriv)
      if err != nil {
         t.Fatal(err)
      }
      modelKey, err := ParseRawPrivateKey(data)
      if err != nil {
         t.Fatal(err)
      }
      signingKey, err := GenerateKey()
      if err != nil {
         t.Fatal(err)
      }
      encrypt_key, err := GenerateKey()
      if err != nil {
         t.Fatal(err)
      }
      err = chain_data.GenerateLeaf(modelKey, signingKey, encrypt_key)
      if err != nil {
         t.Fatal(err)
      }
      err = write_file(paths.devCert, chain_data.Bytes())
      if err != nil {
         t.Fatal(err)
      }
      data, err = PrivateKeyBytes(encrypt_key)
      if err != nil {
         t.Fatal(err)
      }
      err = write_file(paths.zPrivEncr, data)
      if err != nil {
         t.Fatal(err)
      }
      data, err = PrivateKeyBytes(signingKey)
      if err != nil {
         t.Fatal(err)
      }
      err = write_file(paths.zPrivSig, data)
      if err != nil {
         t.Fatal(err)
      }
   }
}

type testPaths struct {
   groupCert string
   zPriv     string
   devCert   string
   zPrivEncr string
   zPrivSig  string
}
