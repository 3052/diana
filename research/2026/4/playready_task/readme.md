# playready task

~~~
bgroupcert.dat
zgpriv.dat

bdevcert.dat
zprivencr.dat
zprivsig.dat
~~~

https://apkmirror.com/apk/amazon-mobile-llc/amazon-prime-video

~~~c
DX_STORE_PLAYREADY_CERTIFICATE_TEMPLATE  = 0x400,   // PlayReady model certificate template used to generate the final device certificate - "bgroupcert.dat"
DX_STORE_PLAYREADY_MODEL, // PlayReady private key of the model cert and is used to sign the final device certificate - "zgpriv.dat"

DX_STORE_PLAYREADY_CERTIFICATE, // PlayReady device certificate - "bdevcert.dat"
DX_STORE_PLAYREADY_DEVICE_ENCRYPT, // PlayReady private device encryption key - "zprivencr.dat"
DX_STORE_PLAYREADY_DEVICE_SIGN, // PlayReady private device signing key - "zprivsig.dat"
~~~

<https://github.com/Danile71/android_kernel_zte_run4g_mod/blob/master/mediatek/frameworks/opt/playready/include/DxDrmDefines.h>

~~~c
#define PR_DRM_DCT_PLAYREADY_TEMPLATE  "bgroupcert"
#define PR_DRM_DKT_PLAYREADY_MODEL  "zgpriv"

#define PR_DRM_DCT_PLAYREADY    "bdevcert"
#define PR_DRM_DKT_PLAYREADY_DEVICE_ENCRYPT  "zprivencr"
#define PR_DRM_DKT_PLAYREADY_DEVICE_SIGN  "zprivsig"
~~~
