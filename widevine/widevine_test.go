package widevine

import (
   "bytes"
   "encoding/base64"
   "encoding/json"
   "fmt"
   "net/http"
   "net/url"
   "os"
   "testing"
)

const playback_envelope = "MDJ8Cm0KBHBlbnYSJDIzZGU5ZDdiLTM4Y2UtNDU5Ni04ZjI3LTQxMTkzM2Q3Njc4YhoUYTJ6K3BwX2VuYytzX3BtZlNkelEgASgBUgsIkdK70QYQhcntC1oLCOXPu9EGEKnl6gtiCwjBprzRBhCp5eoLWhAoe6by101IgoUGFYZjT3aSYkjeCOSSmx7N5GSfZBC7YgNX6ftq0v3QoJq+3ixonKXipHG2FDHcKfU1TFVzPIZPDg9eukSqMFcNSABg55hVlzDyaWYTlIp1YulqwAs8ntJQdC/wlo38LFVioJUW56urprhc8sP+nOr0Z+f3apEfJwETEWSzyZzYl6C44+ZHC1qxnPFc73jaGy0+iWrJYh48La4zNYDAxKpr4p++DkxV2B6yzhqOOvTWA1ZNFu7wENRHjf7u6PWSigGxzPun/EoOrbPuRki8CL6db8KC79FF9kEd7oHnBcHZvvnkuATJuyyxGhCULFnUAzyM6R0mvuaPPF3Bo4kxuigCjU/lu20XaKIhgogF2hq+AxWseg4IxK1HG+pG81QN4vDHx6e6K8vjERXfuBdL7sC2TIPuHmqyUWtyb21eUeFgjtmIbJ/pMybOBxMwgj3H4azuyvFISZru7F9ojooJxV8HMtTQjQJ2+/uyokQnllodeTc4eaXJGBIpGqq8Pcw2R1j5Z4TKBI80RDMhd4MOLbEfROmx8p95iAxq3U7LH+/k25xMyc3QMTk03NIF1G3M8sPrbDeLi/N++phxI8x8HZOdAG4Q8y2kJQYaZBd5MjOVsaPj3s6yocZSYmA9/4bNeTC85B/30h+0tRkm4rZD89+zIdOFeu+C7TB9dAjaPLZTY5r2WE9eeQwhVHh5HtSR1JxO5GZHgTDf6iqUGLr3bVgRgM3srND9RYj/+uRBOKpKXI/mmyWlDycpA2Fn7tbZbxr/N1RD545QiiZiQj0FAWJiLI5LGGIdTvCuw/JNWwL8Vqj2jQpQfO/BF1kFnqrabP0n/qxXOmQVkwaabX2jBpwq6qz3AyB5pX5RCbI7lJTqYDMe5UVV9CyiAvEWarbLhvMaHwbp6u2rhmwpvp/LmgHihgR0z1IV+alAI3oJ2U4JeOQjFAcOF//J52MsLMbD4G+qP0N8Sss993BWIcbBVrenp4200BEhxi8ZZqfhUvmifUSo6SHIJ/694WxT9QgbmzS3HkjFxcBU8FwNwUR0fgZ5a8eF2WXvP1TtU0FuCpPlh4FLfyWE5eSPF+GQYTm8y3p02b9KuSEh+v51TjSRSz8LLW3TV7M4ae4lVslglT6Zw/8ND1Mf+muNV9BZmFmCbrOBL3rXKtp1S5IRAF/TCQsI4MkCcyU8WkI1XJblJKc+cRaF7oDaqrCqa+kLLzflm/Am6Cc7/odNqG3ThpzxrHP4HV7veQROAsDsHX9lUCRrL7GOns+Am829ZHZIYvPGc2uIyt5PkIjmp4lfqD4/sdMVD8ti/yI0eQ7QIw/9L2OWgQAPwBFuxKShtObf+kOOVqwxWRmRQgUuq4MBqw+ve3F/MskzA1sKGbMrFXi1msXgr0ZkVedxxMefX9bv+CbhClx/RJsLpmWbE/dusIe5HNzqk9nEOHtGjH6AsPQYLEYu4gZpjx5kSlgCl5xHOSecjawD/k/KyhCPoAxltUKZO8GZIC6/E9SPA6B+pd6qQr45jb1J+07X+MgfOTKzpFkqBBCHjVH3wnRGBLiuin4lQNxgy4f1utaFN+XHdIrEn80WTGP+q5zsOQPJ6AcaaAXakhHpgCx8ZNotCAelkLafUwFuxHD7bnv6OM1KRPg6iXCF5X0NpICS+w7wPsfaODWp4YjmPU1l+kgXeR/s1EP0HgRRiuWb5FY2sMta3gUcQJMEedN+gi6Bf4dAd/3VVNggRV7MIlEu5EB7MSmC6pAQzSmX515wXPeFPpVfU0XRIqSgd6Ic0Sgus+hZH5xTs3W0L9sMmke72yQ1x43Rmaa7C3xGyON/DGdIbM2C2JBCR5nKlrrJ+Sgj7ki9rSMXjPfSaDLad680WRx4hSPMk8VAqjdRBebodd2ywhwyE58lrrRlkTpTyxaXc+ws+LovETItJWgVh6V9RcHxeWPLBYIjPoNBDsiqWnLTGWy60P9ioFHdgshAVFGkcoj0L7LKMFoXN1v8X3Ro+q5g9nyee6KErGxO/ka+c4jcyKN6ea6e2p+8+85Ss7LeZOAes7edMsN/pqOw9O7monZGkyh8wIC2/f/UUPpNmHIgjOYiaRImhwIEK6++t+BUHZdLOq6TX6UC74CoioHLC18="

func TestLicense(t *testing.T) {
   // read private key
   pemData, err := os.ReadFile("device_private_key")
   if err != nil {
      t.Fatal(err)
   }
   privateKey, err := DecodePrivateKey(pemData)
   if err != nil {
      t.Fatal(err)
   }

   // read client ID
   clientId, err := os.ReadFile("device_client_id_blob")
   if err != nil {
      t.Fatal(err)
   }

   // decode PSSH data
   psshRaw, err := base64.StdEncoding.DecodeString(
      "CAESENlROAqEW0/uqlhMioe8fWMaBmFtYXpvbiI1Y2lkOjB4YUQ4bzJPUm9XYTluZHFSVjlqRGc9PSwyVkU0Q29SYlQrNnFXRXlLaDd4OVl3PT0qAlNEMgA=",
   )
   if err != nil {
      t.Fatal(err)
   }
   pssh, err := DecodePsshData(psshRaw)
   if err != nil {
      t.Fatal(err)
   }

   // build license request
   requestData, err := pssh.EncodeLicenseRequest(clientId)
   if err != nil {
      t.Fatal(err)
   }

   // sign the request
   signedData, err := EncodeSignedMessage(requestData, privateKey)
   if err != nil {
      t.Fatal(err)
   }

   // build the HTTP request
   challenge := base64.StdEncoding.EncodeToString(signedData)
   body := map[string]any{
      "includeHdcpTestKey": true,
      "licenseChallenge":   challenge,
      "playbackEnvelope":   playback_envelope,
   }
   bodyData, err := json.Marshal(body)
   if err != nil {
      t.Fatal(err)
   }

   reqURL := &url.URL{
      Scheme: "https",
      Host:   "ab8mt4dd97et.na.api.amazonvideo.com",
      Path:   "/playback/drm-vod/GetWidevineLicense",
   }
   q := url.Values{}
   q.Set("deviceID", "uuidcbb2f9705f13437e9e515622dce02106")
   q.Set("deviceTypeID", "A2SNKIF736WF4T")
   q.Set("gascEnabled", "false")
   q.Set("marketplaceID", "ATVPDKIKX0DER")
   q.Set("uxLocale", "en-US")
   q.Set("firmware", "1")
   q.Set("titleId", "amzn1.dv.gti.28b85d90-1338-720b-4be7-3247683a7624")
   reqURL.RawQuery = q.Encode()

   req, err := http.NewRequest("POST", reqURL.String(), bytes.NewReader(bodyData))
   if err != nil {
      t.Fatal(err)
   }
   req.Header.Set("Accept", "*/*")
   req.Header.Set("Authorization", "Bearer Atna|EwMDIODjqerb1s19VY8TleIkKR1BEOKexzrLTQXgCGXp0J6itgvkzWwku0_bpHh98e4DXYIDwzGDHgMa2gKlxn5vZsCbc8gJX5f4KgyRzEE-P1hJhKD7t__EQ5WkD-RDOkZ85U9i8JFlv1OyNFF8R67eRToH6e67S1Jv5TmzHo3_JeF3B6iR4KUPj4-Lv1qeSJvmb_xAzuWxjLu0kXdVh934lbGNbdj_dmo7S6ZfiIbGfxJ9_2QnW3_tyC7ONmRUuX8RkPyYvunUcFY8Bxpon-ZjXE2ju5xL1O_weRRku2ehOHBiuLt73sPfqpOSKUK4mO3EsK2BXYUT0qruoZAePhhIrA_iezaUA-M7Dq5nO9ivoIb6pCQFRO0dfKQXjKQmcdplXXFTw1WtyXmGk8dJ28kDmZejh5Muxf4o-Uvp1f_tBKrbuYoXt0MHUjLwtXLIXV1MGZU")
   req.Header.Set("Content-Type", "text/plain")
   req.Header.Set("User-Agent", "Android/google/sdk_gphone_x86/generic_x86_arm:11/RSR1.240422.006/12134477:userdebug/dev-keys, Ignition X/15.5.2026042820-android, Google")

   // send request
   resp, err := http.DefaultClient.Do(req)
   if err != nil {
      t.Fatal(err)
   }
   defer resp.Body.Close()

   fmt.Println("Status:", resp.Status)
   if resp.StatusCode != http.StatusOK {
      t.Fatal("expected 200 OK, got", resp.Status)
   }
}
