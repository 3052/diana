#include <sw_types.h>
#include <sw_debug.h>
#include <sw_string_functions.h>
#include <sw_mem_functions.h>
#include <sw_user_heap.h>
#include <sw_user_app_api.h>
#include <sw_shared_memory.h>
#include <sw_user_meson.h>

#include <otz_id.h>
#include <otz_common.h>

#include <task_control.h>
#include <playready_task.h>

#include "otz_tee_crypto_api.h"

typedef struct {
        uint32_t seconds;
        uint32_t milli_seconds;
}TEE_Time;

void TEE_GetSystemTime( TEE_Time* time );

#define PLAYREADY_DBG sw_printf
#define PLAYREADY_ERR sw_printf
#define PLAYREADY_MEM_LEN_MAX          (256 * 1024)
#define CTR_MODE_CONTEXT                        (32)
#define ALIGN1024(x) (((x) + 1024) & ~1024)
#define RESERVED_MEMORY (128*1024)

int PLAYREADY_MEM_LEN_V=PLAYREADY_MEM_LEN_MAX;




#define PR_DRM_DCT_PLAYREADY    "bdevcert"
#define PR_DRM_DCT_PLAYREADY_LEN    (8)

#define PR_DRM_DKT_PLAYREADY_DEVICE_SIGN  "zprivsig"
#define PR_DRM_DKT_PLAYREADY_DEVICE_SIGN_LEN   (8) 

#define PR_DRM_DKT_PLAYREADY_DEVICE_ENCRYPT  "zprivencr"
#define PR_DRM_DKT_PLAYREADY_DEVICE_ENCRYPT_LEN (9) 

#define PR_DRM_DKT_PLAYREADY_MODEL  "zgpriv"
#define PR_DRM_DKT_PLAYREADY_MODEL_LEN  (6) 

#define PR_DRM_DKT_PLAYREADY_PRIV_KEY  "zgpriv_protected"
#define PR_DRM_DKT_PLAYREADY_PRIV_KEY_LEN  (16)

#define PR_DRM_DCT_PLAYREADY_TEMPLATE  "bgroupcert"
#define PR_DRM_DCT_PLAYREADY_TEMPLATE_LEN  (10) 
#define NTT
#ifndef NTT
#define PR_DRM_KF_PLAYREADY    "PlayReadykeybox"
#define PR_DRM_KF_PLAYREADY_LEN    (15)
#else
#define PR_DRM_KF_PLAYREADY    "nfprkeybox25"
#define PR_DRM_KF_PLAYREADY_LEN    (12)
#endif

#define PR_STORAGE_SIZE           (16*1024)
#define CRYPT_AES_KEY "key for certkey"
#define DRM_AESKEY                   001
#define DRM_AESKEYID               002

const char* IV_NULL="NOIV MAYCLEARDATA";
const char* PUB_NULL="NUL";




#define PR_DRM_KEYFILE_NAME "prkeyfile"
#define PR_DRM_KEYFILE_SIZE  sizeof(DRM_KEYFILE_CONTEXT)
static DRM_KEYFILE_CONTEXT* f_pKeyFile;
static int pr_keyfile_id;
static void *pr_keyfile_ptr;
TEE_OperationHandle  hw_opt_global=NULL;




static unsigned char *goutput_handle=NULL;
static DRM_AES_KEY aesKey;
static  DRM_ENCRYPTED_KEY oEncKey;


//static unsigned char clear_certkey[PR_STORAGE_SIZE];
static unsigned int vdec_dec_addr = NULL;
static unsigned int vdec_this_frame = NULL;

#define PRWMV_DEBUG 0
#if PRWMV_DEBUG
#define PRWMV_DBG(x, ...) sw_printf(x, ## __VA_ARGS__)
#define PRWMV_TRACEPR(format, ...) sw_printf("SW: %s L%d " format, __func__, __LINE__, ## __VA_ARGS__)
#define PRWMV_TRACE() sw_printf("SW: %s L%d\n", __func__, __LINE__);
char sbuf[1024*4];
#else
#define PRWMV_DBG(x, ...)
#define PRWMV_TRACEPR(format, ...)
#define PRWMV_TRACE()
#endif

#define PRWMV_ERR(x, ...) sw_printf(x, ## __VA_ARGS__)


#define HWCIPHER_ENABLE   0
enum media_type_id{
            AUDIO_TYPE=0,//sw
            VIDEO_TYPE,//hw
};

#if PRWMV_DEBUG
void hex_dump_internal(char *buf, int size)
{
    int len, i, j, c;
	int off=0;
	int printed=0;

#undef fprintf
#define PRINT(...) do {\
		printed= snprintf(sbuf+off,1024*4-off, __VA_ARGS__); \
		if(printed>0) off+=printed;\
		} while(0)

    for(i=0;i<size;i+=16) {
        len = size - i;
        if (len > 16)
            len = 16;
        PRINT("%08x: ", i);
        for(j=0;j<16;j++) {
            if (j < len)
                PRINT(" %02x", buf[i+j]);
            else
                PRINT("   ");
        }
        PRINT(" ");
        for(j=0;j<len;j++) {
            c = buf[i+j];
            if (c < ' ' || c > '~')
                c = '.';
            PRINT("%c", c);
        }
        PRINT("\n");
    }
	if(off >0 && off<1024*4){
		sbuf[off]='\0';
		sw_printf("%s\n",sbuf);
	}
#undef PRINT
}
#endif

typedef enum {
    DRM_LEVEL1     = 1,
    DRM_LEVEL2     = 2,
    DRM_LEVEL3     = 3,
    DRM_NONE       = 4,
} drm_level_t;

typedef struct drm_info {
    drm_level_t drm_level;
	int drm_flag;
	int drm_hasesdata;
	int drm_priv;
          unsigned int drm_pktsize;
	unsigned int drm_pktpts;
	unsigned int drm_phy;
	unsigned int drm_vir;
	unsigned int drm_remap;
	int data_offset;
	int extpad[8];
} drminfo_t;

//32 B
struct NativeSecDecryptContext {
    DRM_BYTE ivec[20];
    DRM_DWORD encSize;
    DRM_DWORD clrSize;
    DRM_DWORD offset;
};

#define PR_HW_OPT_NAME "prhwkey"
#define PR_HW_OPT_SIZE  DRM_AES_KEYSIZE_128

static int pr_hw_opt_id;
static void *pr_hw_opt_ptr;


static void *playready_hw_opt_get(void)
{
	int ret = 0;
	int shm_id = -1;
	int inited = 0;
	void *shm_addr = NULL;

	shm_id = shm_create(PR_HW_OPT_NAME, PR_HW_OPT_SIZE, shm_flag_read|shm_flag_write);
	if (shm_id <= 0) {
		inited = 1;
		shm_id = shm_create(PR_HW_OPT_NAME, PR_HW_OPT_SIZE, shm_flag_create|shm_flag_read|shm_flag_write);
		if (shm_id <= 0) {
			sw_printf("SW: PR create hw option FAILED.\n");
			pr_hw_opt_id = -1;
			pr_hw_opt_ptr = NULL;
			return NULL;
		}
	}

	shm_addr = shm_attach(shm_id, NULL/*SHM_AT_ADDR+shm_id*PAGE_SIZE*/, shm_flag_read|shm_flag_write);
    //sw_printf("+++++++shm_attach hw opt , addr %x, id %d\n", shm_addr, shm_id);
	if (!shm_addr) {
		sw_printf("SW: shm_attach error.\n");
		pr_hw_opt_id = -1;
		pr_hw_opt_ptr = NULL;
		return NULL;
	} else {
		if (inited) {
			sw_printf("SW: PR create hw option, addr=0x%x\n", shm_addr);
			sw_memset(shm_addr, 0x0, PR_HW_OPT_SIZE);
		}
		pr_hw_opt_id = shm_id;
		pr_hw_opt_ptr = shm_addr;
	}

	return pr_hw_opt_ptr;
}

static void playready_hw_opt_release(void)
{
	if (pr_hw_opt_id <= 0 || !pr_hw_opt_ptr) {
		sw_printf("SW: PR release hw option FAILED.\n");
		return;
	}
	shm_detach(pr_hw_opt_id, pr_hw_opt_ptr);
    //sw_printf("+++++++++++++shm_detach hw opt key , addr %x, id %d\n", pr_hw_opt_ptr, pr_hw_opt_id);
	pr_hw_opt_id = -1;
	pr_hw_opt_ptr = NULL;

	return;
}

#define SHM_AT_ADDR     0x101000
#define PAGE_SIZE       0x1000

 DRM_KEYFILE_CONTEXT* playready_keyfile_context_get(void)
{
         return  f_pKeyFile;
#if 0
	shm_id = shm_create(PR_DRM_KEYFILE_NAME, PR_DRM_KEYFILE_SIZE, shm_flag_read|shm_flag_write);
	if (shm_id <= 0) {
		inited = 1;
		sw_printf("SW: PR create keyfile context size %d .\n",PR_DRM_KEYFILE_SIZE);
		
		shm_id = shm_create(PR_DRM_KEYFILE_NAME, PR_DRM_KEYFILE_SIZE, shm_flag_create|shm_flag_read|shm_flag_write);
		if (shm_id <= 0) {
			sw_printf("SW: PR create keyfile context FAILED shm_id %d .\n",shm_id);
			pr_keyfile_id = -1;
			pr_keyfile_ptr = NULL;
			return NULL;
		}
	}

	shm_addr = shm_attach(shm_id, NULL/*SHM_AT_ADDR+shm_id*PAGE_SIZE*/, shm_flag_read|shm_flag_write);
         //sw_printf("========shm_attach keyfile, addr %x, id %d\n", shm_addr, shm_id);
	if (!shm_addr) {
		sw_printf("SW: shm_attach error.\n");
		pr_keyfile_id = -1;
		pr_keyfile_ptr = NULL;
		return NULL;
	} else {
		if (inited) {
			sw_printf("SW: playready_keyfile_context_get, name %s addr=0x%x\n", PR_DRM_KEYFILE_NAME, shm_addr);
			sw_memset(shm_addr, 0x0, PR_DRM_KEYFILE_SIZE);
		}
		pr_keyfile_id = shm_id;
		pr_keyfile_ptr = shm_addr;
	}
	sw_printf("SW: playready_keyfile_context_get, name %s addr=0x%x inited %d \n", PR_DRM_KEYFILE_NAME, shm_addr,inited);
	return pr_keyfile_ptr;
#endif	
	
}

 void playready_keyfile_context_release(void)
{

#if 0
	if (pr_keyfile_id <= 0 || !pr_keyfile_ptr) {
		sw_printf("SW: PR release keyfile FAILED.\n");
		return;
	}
	shm_detach(pr_keyfile_id, pr_keyfile_ptr);
    //sw_printf("===============shm_detach keyfile, addr %x, id %d\n", pr_keyfile_ptr, pr_keyfile_id);
	pr_keyfile_id = -1;
	pr_keyfile_ptr = NULL;
#endif
	return;
	
}

#define PR_CONTENT_KEY_NAME "prcontentkey"
#define PR_CONTENT_KEY_SIZE  sizeof(AES_KEY)

static int pr_content_key_id;
static void *pr_content_key_ptr;

static void *playready_content_key_get(void)
{
	int ret = 0;
	int shm_id = -1;
	int inited = 0;
	void *shm_addr = NULL;

	shm_id = shm_create(PR_CONTENT_KEY_NAME, PR_CONTENT_KEY_SIZE, shm_flag_read|shm_flag_write);
	if (shm_id <= 0) {
		inited = 1;
		shm_id = shm_create(PR_CONTENT_KEY_NAME, PR_CONTENT_KEY_SIZE, shm_flag_create|shm_flag_read|shm_flag_write);
		if (shm_id <= 0) {
			sw_printf("SW: PR create content key FAILED. shm_id=0x%x\n",shm_id);
			pr_content_key_id = -1;
			pr_content_key_ptr = NULL;
			return NULL;
		}
	}

	shm_addr = shm_attach(shm_id, NULL/*SHM_AT_ADDR+shm_id*PAGE_SIZE*/, shm_flag_read|shm_flag_write);
    //sw_printf("+++++++shm_attach content key , addr %x, id %d\n", shm_addr, shm_id);
	if (!shm_addr) {
		sw_printf("SW: shm_attach error.\n");
		pr_content_key_id = -1;
		pr_content_key_ptr = NULL;
		return NULL;
	} else {
		if (inited) {
			sw_printf("SW: PR create content key, name %s  addr=0x%x\n", PR_CONTENT_KEY_NAME,shm_addr);
			sw_memset(shm_addr, 0x0, PR_CONTENT_KEY_SIZE);
		}
		pr_content_key_id = shm_id;
		pr_content_key_ptr = shm_addr;
	}
	return pr_content_key_ptr;
}

static void playready_content_key_release(void)
{
	if (pr_content_key_id <= 0 || !pr_content_key_ptr) {
		sw_printf("SW: PR release content key FAILED.\n");
		return;
	}
	shm_detach(pr_content_key_id, pr_content_key_ptr);
          //sw_printf("+++++++++++++shm_detach content key , addr %x, id %d\n", pr_content_key_ptr, pr_content_key_id);
	pr_content_key_id = -1;
	pr_content_key_ptr = NULL;

	return;
}

int cmd_OEM_TEE_hal(void *req_buf, sw_uint req_buf_len,
        void *res_buf, sw_uint res_buf_len,
        struct otzc_encode_meta *meta_data,
        sw_uint *ret_res_buf_len)
{
    unsigned int  in_data_len=0;
    unsigned int  out_data_len=0;
    unsigned int  es_data_len=0;
    unsigned char *in=NULL;
    unsigned char *PlayReadyIV=NULL;
    unsigned char *out=NULL;
    unsigned char *out_buf=NULL;
    int offset = 0, pos = 0, mapped = 0, type, out_len=0;


   DRM_BYTE           *pbReq;
   DRM_DWORD        cbReq;
   DRM_DWORD        cbRsp;
   DRM_BYTE           *pbRsp;

   int method_id=-1;
   int f_eKeyType=-1;
    while (offset <= req_buf_len) {
        if(decode_data(req_buf, meta_data, 
                    &type, &offset, &pos, &mapped, (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        else {
            if(type != OTZ_ENC_UINT32)
            {
                return SMC_EINVAL_ARG;
            }
            method_id = *((sw_uint*)out_buf);
        }
        if(decode_data(req_buf, meta_data, 
                    &type, &offset, &pos, &mapped, (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        else {
            if(type != OTZ_ENC_UINT32)
            {
                return SMC_EINVAL_ARG;
            }
            f_eKeyType = *((sw_uint*)out_buf);
        }		
        if(decode_data(req_buf, meta_data, &type, &offset, &pos, &mapped,
                    (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        if(type != OTZ_ENC_ARRAY && (type != OTZ_MEM_REF)) {
            return SMC_EINVAL_ARG;
        }
        cbReq=out_len;		
        pbReq=out_buf;
        break;
    }
    
	
    offset = 0, pos = OTZ_MAX_REQ_PARAMS;
	
    while (offset <= res_buf_len) {
        if(decode_data(res_buf, meta_data, &type, &offset, &pos, &mapped, 
                    (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        if ((type != OTZ_ENC_ARRAY) && (type != OTZ_MEM_REF)) { 
            return SMC_EINVAL_ARG;
        }
        pbRsp = out_buf;
        cbRsp=out_len;		
        break;
    }
	
    DRM_Hal_MethodRequest( method_id, f_eKeyType,  pbReq, cbReq, pbRsp,&cbRsp )  ;
    //PLAYREADY_DBG("return method_Id 0x%x  f_eKeyType0x%x  cb=0x%x\n",method_id,f_eKeyType,cbRsp);		
    if(update_response_len(meta_data, pos, cbRsp)) {
        PLAYREADY_DBG("cmd_OEM_TEE_hal  update_response_len %d\n", __LINE__);        		
        return SMC_EINVAL_ARG;
    }
    *ret_res_buf_len = cbRsp;	
  		
    return 0;
}

int cmd_OEM_TEE_entrypoint(void *req_buf, sw_uint req_buf_len,
        void *res_buf, sw_uint res_buf_len,
        struct otzc_encode_meta *meta_data,
        sw_uint *ret_res_buf_len)
{
#if 0
    unsigned int  in_data_len=0;
    unsigned int  out_data_len=0;
    unsigned int  es_data_len=0;
    unsigned char *in=NULL;
    unsigned char *PlayReadyIV=NULL;
    unsigned char *out=NULL;
    unsigned char *out_buf=NULL;
    int offset = 0, pos = 0, mapped = 0, type, out_len=0;


   DRM_BYTE           *pbReq;
   DRM_DWORD        cbReq;
   DRM_DWORD        cbRsp;
   DRM_BYTE           *pbRsp;
   
   // PLAYREADY_DBG("cmd_OEM_TEE_entrypoin t%d res%d\n",req_buf_len,res_buf_len);
    while (offset <= req_buf_len) {
        /* decode buf length */
        if(decode_data(req_buf, meta_data, 
                    &type, &offset, &pos, &mapped, (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        else {
            if(type != OTZ_ENC_UINT32)
            {
                return SMC_EINVAL_ARG;
            }
            cbReq = *((sw_uint*)out_buf);
        }
        /* decode encbuffer */
        if(decode_data(req_buf, meta_data, &type, &offset, &pos, &mapped,
                    (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        if(type != OTZ_ENC_ARRAY && (type != OTZ_MEM_REF)) {
            return SMC_EINVAL_ARG;
        }
        pbReq=out_buf;
        break;
    }


    offset = 0, pos = OTZ_MAX_REQ_PARAMS;
    while (offset <= res_buf_len) {
        if(decode_data(res_buf, meta_data, &type, &offset, &pos, &mapped, 
                    (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        if ((type != OTZ_ENC_ARRAY) && (type != OTZ_MEM_REF)) { 
            return SMC_EINVAL_ARG;
        }
        pbRsp = out_buf;
        cbRsp=out_len;		
        break;
    }
    DRM_TEE_STUB_HandleMethodRequest(cbReq,pbReq, &cbRsp,pbRsp );
    if(update_response_len(meta_data, pos, cbRsp)) {
        return SMC_EINVAL_ARG;
    }
    *ret_res_buf_len = cbRsp;
#endif		
    return 0;
}

int oem_tee_contentkey_build (DRM_BYTE   * rgbKey)
{   
    PLAYREADY_ERR("oem_tee_contentkey_build\n");
    
	//sw_printf("rgbKey0-7[0x%x] [0x%x] [0x%x] [0x%x] [0x%x] [0x%x] [0x%x] [0x%x] \n",rgbKey[0],rgbKey[1],rgbKey[2],rgbKey[3],rgbKey[4],rgbKey[5],rgbKey[6],rgbKey[7]);
	//sw_printf("rgbKey8-15[0x%x] [0x%x] [0x%x] [0x%x] [0x%x] [0x%x] [0x%x] [0x%x] \n",rgbKey[8],rgbKey[9],rgbKey[10],rgbKey[11],rgbKey[12],rgbKey[13],rgbKey[14],rgbKey[15]);  	
#if HWCIPHER_ENABLE
    DRM_BYTE *  hw_opt=NULL;    	
     hw_opt = (DRM_BYTE *)playready_hw_opt_get(); 
     if(hw_opt)
         sw_memcpy((void *)hw_opt,rgbKey,DRM_AES_KEYSIZE_128);  	
     playready_hw_opt_release(); 
#else
     AES_KEY* content_key;
     content_key = (AES_KEY *)playready_content_key_get();
     AES_set_encrypt_key(rgbKey, 128, content_key);
     playready_content_key_release();
 #endif     	 
     return 0;
}

int cmd_load_KF(void *req_buf, sw_uint req_buf_len,
        void *res_buf, sw_uint res_buf_len,
        struct otzc_encode_meta *meta_data,
        sw_uint *ret_res_buf_len)
{
    //PLAYREADY_ERR("2.5 cmd_load_KF\n");
    unsigned int  out_data_len=0;
    unsigned int  storage_type;
    unsigned int result;
    unsigned char *out;
    unsigned char *out_buf;
    int offset = 0, pos = 0, mapped = 0, type, out_len=0;
    unsigned char * certkey=NULL;
	
    offset = 0, pos = OTZ_MAX_REQ_PARAMS;
    while (offset
            <= res_buf_len) {
        if(decode_data(res_buf, meta_data, &type, &offset, &pos, &mapped,
                    (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        if (type != OTZ_ENC_UINT32) {
            return SMC_EINVAL_ARG;
        }
        certkey=(unsigned char *) malloc(PR_STORAGE_SIZE);	
        if(certkey)
            result = sw_storage_read(PR_DRM_KF_PLAYREADY, PR_DRM_KF_PLAYREADY_LEN, certkey, PR_STORAGE_SIZE, &out_data_len);  
        if (result != 0) {
            out_data_len = 0;
            PLAYREADY_DBG("SW: cmd_load_KF, read storage fail\n");    
        } else {
           *((sw_uint*)out_buf) = out_data_len;
        }
        break;
    }

     f_pKeyFile = (unsigned char *) malloc(PR_DRM_KEYFILE_SIZE);
     if(f_pKeyFile==NULL){
	   PLAYREADY_ERR("SW: cmd_load_KF,  playready_keyfile_context_get fail\n"); 
	   return 0;
     } 	
     f_pKeyFile->cbKeyfileBuffer = out_data_len;
     f_pKeyFile->pbKeyfileBuffer = (f_pKeyFile->rgbKeyfileBuffer + sizeof( f_pKeyFile->rgbKeyfileBuffer ));
     f_pKeyFile->pbKeyfileBuffer -= out_data_len;
     /*sw_printf("[cmd_load_KF] f_pKeyFile->pbKeyfileBuffer %x, size %d, kf %x\n",
                    f_pKeyFile->pbKeyfileBuffer,
                    sizeof( f_pKeyFile->rgbKeyfileBuffer ),
                    clear_certkey);*/
     sw_memcpy(f_pKeyFile->pbKeyfileBuffer, certkey,out_data_len);
     result=DRM_KF_Parse(
               f_pKeyFile->pOEMContext,
               f_pKeyFile->rgbParserStack,
               sizeof(f_pKeyFile->rgbParserStack ),
               f_pKeyFile->pbKeyfileBuffer,
               f_pKeyFile->cbKeyfileBuffer,
               1,
               &f_pKeyFile->keyfile);
    f_pKeyFile->fInited = TRUE;
    f_pKeyFile->fLoaded = TRUE;


     if(result!=0)
          PLAYREADY_ERR("SW: cmd_load_KF, load keyfile fail result=0x%x\n",result);    
     else
          PLAYREADY_ERR("SW: cmd_load_KF, load  %s parser keyfile len=0x%x\n",PR_DRM_KF_PLAYREADY,out_data_len);	  
     if(certkey){
	 free(certkey);
	 certkey=NULL;
      }
	return 0;
}

int cmd_KF_getCert(void *req_buf, sw_uint req_buf_len,
        void *res_buf, sw_uint res_buf_len,
        struct otzc_encode_meta *meta_data,
        sw_uint *ret_res_buf_len)
{
    unsigned int  out_data_len=0;
    unsigned int  cert_type;
    unsigned int result;
    unsigned char *out;
    unsigned char *out_buf;
    int offset = 0, pos = 0, mapped = 0, type, out_len=0;

   
    while (offset <= req_buf_len) {
        /* decode type */
        if(decode_data(req_buf, meta_data,
                    &type, &offset, &pos, &mapped, (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        else {
            if(type != OTZ_ENC_UINT32) {
                return SMC_EINVAL_ARG;
            }
            cert_type = *((sw_uint*)out_buf);
        }
        break;
    }

    offset = 0, pos = OTZ_MAX_REQ_PARAMS;
    while (offset <= res_buf_len) {
        if(decode_data(res_buf, meta_data, &type, &offset, &pos, &mapped,
                    (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        if ((type != OTZ_ENC_ARRAY) && (type != OTZ_MEM_REF)) {
            return SMC_EINVAL_ARG;
        }
        out = out_buf;
        break;
    }
    //PLAYREADY_DBG("cert_type=%d out_len=%d \n",cert_type,out_len);

   if(f_pKeyFile==NULL){
   	PLAYREADY_DBG("SW: cmd_KF_getCert,  playready_keyfile_context_get fail\n");
	*ret_res_buf_len = out_data_len;
	return 0;
   }
    result=DRM_KF_GetCertificate (f_pKeyFile, cert_type,  &out,   &out_data_len);


    if(out_data_len!=0){
        if(update_response_len(meta_data, pos, out_data_len)) {
            PLAYREADY_DBG("SW: cmd_KF_getCert, update_response_len failed\n"); 
            return SMC_EINVAL_ARG;
        } 
    }
    *ret_res_buf_len = out_data_len;

    return 0;
}

int cmd_KF_getKey(void *req_buf, sw_uint req_buf_len,
        void *res_buf, sw_uint res_buf_len,
        struct otzc_encode_meta *meta_data,
        sw_uint *ret_res_buf_len)
 {
   //PLAYREADY_ERR("cmd_KF_getKey\n");
    unsigned char *Pub=NULL;
    unsigned char *Piv=NULL;
    unsigned char *out=NULL;
    unsigned char *out_buf=NULL;
    int offset = 0, pos = 0, mapped = 0, type, out_len=0;
    unsigned int  cert_type;
    unsigned int  pub_len=0;
    unsigned int  out_data_len=0;
   
    while (offset <= req_buf_len) {
        /* decode  type */
        if(decode_data(req_buf, meta_data, 
                    &type, &offset, &pos, &mapped, (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        else {
            if(type != OTZ_ENC_UINT32)
            {
                return SMC_EINVAL_ARG;
            }
            cert_type = *((sw_uint*)out_buf);
        }        /* decode  length */
        if(decode_data(req_buf, meta_data, 
                    &type, &offset, &pos, &mapped, (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        else {
            if(type != OTZ_ENC_UINT32)
            {
                return SMC_EINVAL_ARG;
            }
            pub_len = *((sw_uint*)out_buf);
        }
		
        /* decode encbuffer */
        if(decode_data(req_buf, meta_data, &type, &offset, &pos, &mapped,
                    (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        if(type != OTZ_ENC_ARRAY && (type != OTZ_MEM_REF)) {
            return SMC_EINVAL_ARG;
        }
        Pub=out_buf;
        if(sw_memcmp(Pub,PUB_NULL,sw_strlen(PUB_NULL))==0)
            Pub=NULL;
        break;
    }


    offset = 0, pos = OTZ_MAX_REQ_PARAMS;
    while (offset <= res_buf_len) {
        if(decode_data(res_buf, meta_data, &type, &offset, &pos, &mapped, 
                    (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        if ((type != OTZ_ENC_ARRAY) && (type != OTZ_MEM_REF)) { 
            return SMC_EINVAL_ARG;
        }
        Piv = out_buf;
        break;
    }

    if(f_pKeyFile==NULL){
   	PLAYREADY_DBG("SW: cmd_KF_getKey ,  playready_keyfile_context_get  fail\n");
	*ret_res_buf_len = out_data_len;
	return 0;
   }
    sechal_DRM_KF_GetPrivateKey (f_pKeyFile,cert_type,Pub,pub_len-4,Piv, &out_data_len);


    if(update_response_len(meta_data, pos, out_data_len)) {
        return SMC_EINVAL_ARG;
    }
    *ret_res_buf_len = out_data_len;
    return 0;
}

int cmd_ECC256KEYPAIR(void *req_buf, sw_uint req_buf_len,
        void *res_buf, sw_uint res_buf_len,
        struct otzc_encode_meta *meta_data,
        sw_uint *ret_res_buf_len, sw_uint svc_cmd_id)
{
    PLAYREADY_DBG("cmd_ECC256KEYPAIR\n");
#if 0
    unsigned char *out_buf;
    unsigned char *out;
    int offset = 0, pos = 0, mapped = 0, type, out_len=0;
    unsigned char *rgbEncKeys;
    unsigned char *pubkey;
    int enckeylen=0;
    DRM_DWORD     cbDecKey    = ECC_P256_INTEGER_SIZE_IN_BYTES;
    AES_KEY enckey;
    unsigned char ivec[AES_BLOCK_SIZE] = { 0 };
    unsigned char ecount_buf[AES_BLOCK_SIZE]= { 0 };
    unsigned int  num=0;
    unsigned char  key[ECC_P256_INTEGER_SIZE_IN_BYTES]={0};

    while (offset <= req_buf_len) {
        /* decode buf length */
        if(decode_data(req_buf, meta_data, 
                    &type, &offset, &pos, &mapped, (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        else {
            if(type != OTZ_ENC_UINT32)
                return SMC_EINVAL_ARG;

            enckeylen = *((sw_uint*)out_buf);
        }

        /* decode pubkey */
        if(decode_data(req_buf, meta_data, &type, &offset, &pos, &mapped,
                    (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        if((type != OTZ_ENC_ARRAY) && (type != OTZ_MEM_REF)) {
            return SMC_EINVAL_ARG;
        }
        pubkey=out_buf;
        break;
    }    
    offset = 0, pos = OTZ_MAX_REQ_PARAMS;
    while (offset <= res_buf_len) {
        if(decode_data(res_buf, meta_data, &type, &offset, &pos, &mapped, 
                    (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        if ((type != OTZ_ENC_ARRAY) && (type != OTZ_MEM_REF)) { 
            return SMC_EINVAL_ARG;
        }
        out = out_buf;
        break;
    }

    f_pKeyFile = playready_keyfile_context_get();
   //GetDeviceECC256KeyPair(f_pKeyFile,1,pubkey,ECC_P256_POINT_SIZE_IN_BYTES,&oEncKey);
   //DRM_BBX_KF_DecryptKey(NULL, &oEncKey, 0, ( DRM_BYTE * )key, &cbDecKey);
    AES_set_encrypt_key((const unsigned char*)CRYPT_AES_KEY, sizeof(CRYPT_AES_KEY)*8,&enckey);
    AES_ctr128_encrypt(key, out,ECC_P256_INTEGER_SIZE_IN_BYTES,&enckey,ivec,ecount_buf,&num);
    sw_memset(key,0,sizeof (key));
        
	playready_keyfile_context_release();
    if(update_response_len(meta_data, pos, cbDecKey)) {
            PLAYREADY_DBG("SW: cmd_ECC256KEYPAIR, update_response_len failed\n");	
            return SMC_EINVAL_ARG;
        }
    *ret_res_buf_len = cbDecKey;
#endif
    return 0;
}

int cmd_decryt_contentkey(void *req_buf, sw_uint req_buf_len,
        void *res_buf, sw_uint res_buf_len,
        struct otzc_encode_meta *meta_data,
        sw_uint *ret_res_buf_len, sw_uint svc_cmd_id)
{
    PLAYREADY_DBG("cmd_decryt_contentkey\n");
#if 0	
    playready_data_t playready_data;
    unsigned char *out_buf;	
    int offset = 0, pos = 0, mapped = 0, type, out_len=0;
    unsigned char *rgbEncKeys;
    unsigned char *pubkey;
    int enckeylen=0;
    DRM_BYTE     rgbDecKeys[ ECC_P256_PLAINTEXT_SIZE_IN_BYTES]  = { 0 };
    DRM_BYTE   f_pbKeyBuff[DRM_AES_KEYSIZE_128 ] = { 0 };
    DRM_DWORD f_pcbKey=DRM_AES_KEYSIZE_128;
    AES_KEY* content_key;
    DRM_BYTE *  hw_opt;
    unsigned char * stream=NULL;	
		
    PRWMV_TRACE();
    sw_memset(&playready_data, 0, sizeof(playready_data_t));
    while (offset <= req_buf_len) {
        /* decode buf length */
        if(decode_data(req_buf, meta_data, 
                    &type, &offset, &pos, &mapped, (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        else {
            if(type != OTZ_ENC_UINT32)
                return SMC_EINVAL_ARG;

            enckeylen = *((sw_uint*)out_buf);
        }

        /* decode pubkey */
        if(decode_data(req_buf, meta_data, &type, &offset, &pos, &mapped,
                    (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        if((type != OTZ_ENC_ARRAY) && (type != OTZ_MEM_REF)) {
            return SMC_EINVAL_ARG;
        }
        pubkey=out_buf;

        /* decode EncKey */
        if(decode_data(req_buf, meta_data, &type, &offset, &pos, &mapped,
                    (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        if((type != OTZ_ENC_ARRAY) && (type != OTZ_MEM_REF)) {
            return SMC_EINVAL_ARG;
        }
        rgbEncKeys=out_buf;
        break;
    }
    f_pKeyFile = playready_keyfile_context_get();
    //Playready_Api_decryt_contentkey(f_pKeyFile,rgbEncKeys, enckeylen,pubkey,rgbDecKeys);
    DRM_BYT_CopyBytes( f_pbKeyBuff,
                           0,
                           rgbDecKeys,
                           DRM_AES_KEYSIZE_128,
                           f_pcbKey );
   playready_keyfile_context_release();
    stream=(unsigned char * )playready_stream_get();
    if(*stream!=HLS) {// MSS use hw
        PLAYREADY_DBG("cmd_decryt_contentkey option for MSS\n");		
        hw_opt = (DRM_BYTE *)playready_hw_opt_get(); 		
        sw_memcpy((void *)hw_opt,(const void *)f_pbKeyBuff,DRM_AES_KEYSIZE_128);  	
        playready_hw_opt_release();
    }
    else{// hls use openssl
        content_key = (AES_KEY *)playready_content_key_get();
        Playready_Api_SetKeyTabEnc(f_pbKeyBuff, DRM_AES_KEYSIZE_128, content_key);
        playready_content_key_release();
    }
    playready_stream_release();	
#endif
    return 0;
}

int cmd_decryt_RC4_contentkey(void *req_buf, sw_uint req_buf_len,
        void *res_buf, sw_uint res_buf_len,
        struct otzc_encode_meta *meta_data,
        sw_uint *ret_res_buf_len, sw_uint svc_cmd_id)
{
#if 0
    playready_data_t playready_data;
    unsigned char *out_buf;
    int offset = 0, pos = 0, mapped = 0, type, out_len=0;
    unsigned char *rgbEncKeys;
    unsigned char *pubkey;
    unsigned char *contentKey=NULL;
    int enckeylen=0, pubkeylen = 0;
    unsigned char *rgbDecKeys;
    DRM_DWORD f_pcbKey=DRM_AES_KEYSIZE_128;

    sw_memset(&playready_data, 0, sizeof(playready_data_t));
    while (offset <= req_buf_len) {
        /* decode buf length */
        if(decode_data(req_buf, meta_data,
                    &type, &offset, &pos, &mapped, (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        else {
            if(type != OTZ_ENC_UINT32)
                return SMC_EINVAL_ARG;

            pubkeylen = *((sw_uint*)out_buf);
        }

        /* decode pubkey */
        if(decode_data(req_buf, meta_data, &type, &offset, &pos, &mapped,
                    (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        if((type != OTZ_ENC_ARRAY) && (type != OTZ_MEM_REF)) {
            return SMC_EINVAL_ARG;
        }
        pubkey=out_buf;

                /* decode EncKey */
        if(decode_data(req_buf, meta_data, &type, &offset, &pos, &mapped,
                    (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        if((type != OTZ_ENC_ARRAY) && (type != OTZ_MEM_REF)) {
            return SMC_EINVAL_ARG;
        }
        rgbEncKeys=out_buf;
        break;
    }

    f_pKeyFile = playready_keyfile_context_get();
    //Playready_Api_decryt_RC4contentkey(f_pKeyFile,rgbEncKeys, pubkeylen,pubkey,rc4_contentkey);
    vdec_this_frame = vdec_dec_addr = sw_get_vdec_addr();
#endif	
    return 0;
}


int cmd_decryt_RC4_audio(void *req_buf, sw_uint req_buf_len,
        void *res_buf, sw_uint res_buf_len,
        struct otzc_encode_meta *meta_data,
        sw_uint *ret_res_buf_len, sw_uint svc_cmd_id)
{
#if 0

    unsigned int  in_data_len=0;
    unsigned int  out_data_len=0;
    unsigned int  es_data_len=0;
    unsigned char *in=NULL;
    unsigned char *out=NULL;
    unsigned char *out_buf=NULL;
    int offset = 0, pos = 0, mapped = 0, type, out_len=0;

    //PLAYREADY_DBG("cmd_decryt_RC4_audio\n");
    while (offset <= req_buf_len) {
        /* decode buf length */
        if(decode_data(req_buf, meta_data,
                    &type, &offset, &pos, &mapped, (void**)&out_buf, &out_len)) {
            PLAYREADY_DBG("cmd_decryt_RC4_audio error %d\n", __LINE__);
            return SMC_EINVAL_ARG;
        }
        else {
            if(type != OTZ_ENC_UINT32)
            {
                PLAYREADY_DBG("cmd_decryt_RC4_audio error %d\n", __LINE__);
                return SMC_EINVAL_ARG;
            }

            es_data_len = *((sw_uint*)out_buf);
        }
        /* decode encbuffer */
        if(decode_data(req_buf, meta_data, &type, &offset, &pos, &mapped,
                    (void**)&out_buf, &out_len)) {
            PLAYREADY_DBG("cmd_decryt_RC4_audio error %d\n", __LINE__);
            return SMC_EINVAL_ARG;
        }
        if(type != OTZ_ENC_ARRAY && (type != OTZ_MEM_REF)) {
            PLAYREADY_DBG("cmd_decryt_RC4_audio error %d\n", __LINE__);
            return SMC_EINVAL_ARG;
        }
        in = out_buf;
        break;
    }

    offset = 0, pos = OTZ_MAX_REQ_PARAMS;
    while (offset <= res_buf_len) {
        if(decode_data(res_buf, meta_data, &type, &offset, &pos, &mapped,
                    (void**)&out_buf, &out_len)) {
            PLAYREADY_DBG("cmd_decryt_RC4_audio error %d\n", __LINE__);
            return SMC_EINVAL_ARG;
        }
        if ((type != OTZ_ENC_ARRAY) && (type != OTZ_MEM_REF)) {
            PLAYREADY_DBG("cmd_decryt_RC4_audio error %d\n", __LINE__);
            return SMC_EINVAL_ARG;
        }
        out = out_buf;
        break;
    }

    sw_memcpy(out, in, es_data_len);
    //Playready_Api_decryt_RC4(out, es_data_len);
    out_data_len=es_data_len;

    if(update_response_len(meta_data, pos, out_data_len)) {
        PLAYREADY_DBG("cmd_decryt_RC4_audio error %d\n", __LINE__);
        return SMC_EINVAL_ARG;
    }
    *ret_res_buf_len = out_data_len;
    //PLAYREADY_DBG("SW: pr_decryt_audio() in=0x%x, out=0x%x, enc_len=0x%x, resp_len=0x%x\n", in, out, es_data_len, res_buf_len);
#endif
    return 0;
}

int cmd_decryt_RC4_video(void *req_buf, sw_uint req_buf_len,
        void *res_buf, sw_uint res_buf_len,
        struct otzc_encode_meta *meta_data,
        sw_uint *ret_res_buf_len, sw_uint svc_cmd_id)
{
#if 0

    unsigned int  in_data_len=0;
    unsigned int  out_data_len=0;
    unsigned int  es_data_len=0;
    unsigned int  buf_offset = 0;
    unsigned char *in=NULL;
    unsigned char *out=NULL;
    unsigned char *out_buf=NULL;
    int offset = 0, pos = 0, mapped = 0, type, out_len=0;

    while (offset <= req_buf_len) {
        /* decode buf length */
        if(decode_data(req_buf, meta_data,
                    &type, &offset, &pos, &mapped, (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        else {
            if(type != OTZ_ENC_UINT32)
            {
                return SMC_EINVAL_ARG;
            }

            es_data_len = *((sw_uint*)out_buf);
        }
        /* decode offset */
        if(decode_data(req_buf, meta_data,
                    &type, &offset, &pos, &mapped, (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        else {
            if(type != OTZ_ENC_UINT32)
            {
                return SMC_EINVAL_ARG;
            }

            buf_offset = *((sw_uint*)out_buf);
        }
        /* decode encbuffer */
        if(decode_data(req_buf, meta_data, &type, &offset, &pos, &mapped,
                    (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        if(type != OTZ_ENC_ARRAY && (type != OTZ_MEM_REF)) {
            return SMC_EINVAL_ARG;
        }
        in = out_buf;
        break;
    }

    offset = 0, pos = OTZ_MAX_REQ_PARAMS;
    while (offset <= res_buf_len) {
        if(decode_data(res_buf, meta_data, &type, &offset, &pos, &mapped,
                    (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        if (type != OTZ_ENC_UINT32) {
            return SMC_EINVAL_ARG;
        }
        break;
    }
    if(buf_offset == 0){
        if(vdec_dec_addr >= sw_get_vdec_addr()+sw_get_vdec_size()-RESERVED_MEMORY)
            vdec_dec_addr = sw_get_vdec_addr();
        vdec_dec_addr = ((unsigned int)vdec_dec_addr+256)&0xffffff00;
        vdec_this_frame = vdec_dec_addr;
    }
    //sw_printf("vdec addr %x, len %x, buf_offset %x\n", vdec_dec_addr, es_data_len, buf_offset);
    sw_memcpy(vdec_dec_addr, in, es_data_len);
    //Playready_Api_decryt_RC4((DRM_BYTE*)vdec_dec_addr, es_data_len);
    *((sw_uint*)out_buf) = vdec_this_frame;
    vdec_dec_addr += es_data_len;
    //PLAYREADY_DBG("vdec_dec_addr[%d] %x, decrypt video size %d\n",
    //        buf_offset, vdec_dec_addr+buf_offset, es_data_len);
#endif	
    return 0;
}

int cmd_decryt_ts(void *req_buf, sw_uint req_buf_len,
        void *res_buf, sw_uint res_buf_len,
        struct otzc_encode_meta *meta_data,
        sw_uint *ret_res_buf_len)
{
    unsigned int  i;
    unsigned int  cbSecCtx=0;
    struct NativeSecDecryptContext *pSecCtx=NULL;
    unsigned char *in=NULL;
    unsigned char *out_buf=NULL;
    unsigned int in_len=0, sec_num = 0, buf_off = 0;
    int offset = 0, pos = 0, mapped = 0, type, out_len=0;
    int res = 0;
    static AES_KEY *content_key;
    DRM_BYTE *  hw_opt;
    //PRWMV_TRACE();

    if (res < 0){
        PLAYREADY_DBG("SW: cmd_decryt_video, video stream not point to protected memory\n");
        return SMC_ERROR;
    }

    while (offset <= req_buf_len) {
        /* decode NativeSecDecryptContext */
        if(decode_data(req_buf, meta_data, &type, &offset, &pos, &mapped,
                    (void**)&out_buf, &out_len))
            return SMC_EINVAL_ARG;
        if((type != OTZ_ENC_ARRAY) && (type != OTZ_MEM_REF))
            return SMC_EINVAL_ARG;
        pSecCtx = out_buf;
       
        /* decode NativeSecDecryptContext length */
        if(decode_data(req_buf, meta_data,
                    &type, &offset, &pos, &mapped, (void**)&out_buf, &out_len))
            return SMC_EINVAL_ARG;
        else {
            if(type != OTZ_ENC_UINT32)
                return SMC_EINVAL_ARG;
            cbSecCtx = *((sw_uint*)out_buf);
        }

        /* decode data buffer */
        if(decode_data(req_buf, meta_data, &type, &offset, &pos, &mapped,
                    (void**)&out_buf, &out_len))
            return SMC_EINVAL_ARG;
        if((type != OTZ_ENC_ARRAY) && (type != OTZ_MEM_REF))
            return SMC_EINVAL_ARG;
        in = out_buf;

        /* decode data size*/
        if(decode_data(req_buf, meta_data,
                    &type, &offset, &pos, &mapped, (void**)&out_buf, &out_len))
            return SMC_EINVAL_ARG;
        else {
            if(type != OTZ_ENC_UINT32)
                return SMC_EINVAL_ARG;
            in_len = *((sw_uint*)out_buf);
        }
        break;
    }

    //PRWMV_TRACE();
     goutput_handle = sw_get_vdec_addr();
    //sw_printf("[decyptoTS] pSecCtx %x, cbSecCtx %d, in %x, in_len %d, sec_num %d\n",
    //                pSecCtx, cbSecCtx, in, in_len, sec_num);

#if HWCIPHER_ENABLE

    hw_opt = (DRM_BYTE  *)playready_hw_opt_get();

    if(pSecCtx->clrSize > 0){
        sw_memcpy((sw_short_int*)(goutput_handle), in, pSecCtx->clrSize);
    }
    if(pSecCtx->encSize > 0){
        if(hw_opt_global==NULL){
            playready_cipher_start(&hw_opt_global,NULL,hw_opt,DRM_AES_KEYSIZE_128);
            PLAYREADY_DBG("[%s:%d]HW cipher start\n", __FUNCTION__, __LINE__);
        }
        if(hw_opt_global){
            if (pSecCtx->encSize > 8192)
                decrypt_type = VIDEO_TYPE;
            playready_cipher_setiv(hw_opt_global,pSecCtx->ivec, decrypt_type);
            playready_cipher_ctr_process(hw_opt_global,
                in + pSecCtx->clrSize,
                (sw_uint)pSecCtx->encSize,
                (sw_short_int*)(goutput_handle + pSecCtx->clrSize),
                (sw_uint *)&pSecCtx->encSize);
        }else{
            PLAYREADY_DBG("[%s:%d]HW cipher no TEE_OperationHandle \n", __FUNCTION__, __LINE__);
        }
     }
    playready_hw_opt_release();

#else
    sec_num = cbSecCtx/sizeof(struct NativeSecDecryptContext);
    content_key = (AES_KEY *)playready_content_key_get();

    for(i = 0; i < sec_num; i++, pSecCtx++){
        //sw_printf("[decyptoTS] pSecCtx %x, cbSecCtx %d, in %x, in_len %d, sec_num %d,buf_off %d, clr %d, enc %d\n",
        //                pSecCtx, cbSecCtx, in, in_len, sec_num, buf_off, pSecCtx->clrSize, pSecCtx->encSize);
        if(buf_off + pSecCtx->clrSize + pSecCtx->encSize > in_len)
            sw_printf("[decyptoTS] BUG [%d + %d + %d > %d]\n",
                        pSecCtx->offset, pSecCtx->clrSize,
                        pSecCtx->encSize, in_len);
        
        if(pSecCtx->clrSize > 0){
            sw_memcpy((sw_short_int*)(goutput_handle + pSecCtx->offset), in + buf_off, pSecCtx->clrSize);
        }
        if(pSecCtx->encSize > 0)
            Playready_Api_decryptTS(in + buf_off + pSecCtx->clrSize,
                        pSecCtx->encSize,
                        pSecCtx->ivec,
                        CTR_MODE_CONTEXT,
                        (sw_short_int*)(goutput_handle + pSecCtx->offset + pSecCtx->clrSize),
                        content_key);
        buf_off += (pSecCtx->encSize + pSecCtx->clrSize);
    }
    playready_content_key_release();
#endif	
    return 0;
}
int cmd_decryt_video(void *req_buf, sw_uint req_buf_len,
        void *res_buf, sw_uint res_buf_len,
        struct otzc_encode_meta *meta_data,
        sw_uint *ret_res_buf_len)
{
	//PLAYREADY_DBG("cmd_decryt_video\n");
    unsigned int  out_data_len=0;
    unsigned int  enc_data_len=0;
    unsigned char *PlayReadyIV=NULL;
    unsigned char *in=NULL;
    unsigned char *out_buf=NULL;
    unsigned int clear_data_len=0;
    unsigned int output_offset=0;
    int offset = 0, pos = 0, mapped = 0, type, out_len=0;
    int res = 0;
    AES_KEY* content_key;
    DRM_BYTE *  hw_opt;	
   unsigned int output_handle;

    while (offset <= req_buf_len) {
        /* decode buf length */
        if(decode_data(req_buf, meta_data, 
                    &type, &offset, &pos, &mapped, (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        else {
            if(type != OTZ_ENC_UINT32)
            {
                return SMC_EINVAL_ARG;
            }

            enc_data_len = *((sw_uint*)out_buf);
        }
        /* decode iv */
        if(decode_data(req_buf, meta_data, &type, &offset, &pos, &mapped,
                    (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        if((type != OTZ_ENC_ARRAY) && (type != OTZ_MEM_REF)) {
            return SMC_EINVAL_ARG;
        }
        PlayReadyIV = out_buf;
        if(sw_memcmp(PlayReadyIV,IV_NULL,sw_strlen(IV_NULL))==0)
            PlayReadyIV=NULL;
        if(out_buf)
            in = out_buf + CTR_MODE_CONTEXT;

        /* decode clear data size */
        if(decode_data(req_buf, meta_data, 
                    &type, &offset, &pos, &mapped, (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        else {
            if(type != OTZ_ENC_UINT32)
            {
                return SMC_EINVAL_ARG;
            }

            clear_data_len = *((sw_uint*)out_buf);
        }

        /* decode output Offset value.a*/ 
        if(decode_data(req_buf, meta_data, 
                    &type, &offset, &pos, &mapped, (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        else {
            if(type != OTZ_ENC_UINT32)
            {
                return SMC_EINVAL_ARG;
            }
            output_offset = *((sw_uint*)out_buf);
        }
        /* decode output Offset value.b*/         		
        if(decode_data(req_buf, meta_data, 
                    &type, &offset, &pos, &mapped, (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        else {
            if(type != OTZ_ENC_UINT32)
            {
                return SMC_EINVAL_ARG;
            }
            output_handle = *((sw_uint*)out_buf);
        }
        break;
    }

   if( output_handle!=sw_get_vdec_addr()&&output_handle!=(sw_get_vdec_addr()+400*1024))  	
       PLAYREADY_DBG("video output_handle may need check 0x%x\n", output_handle);			
   if(output_handle!=goutput_handle)
   	goutput_handle=output_handle;
    
    if((clear_data_len>0)&&(output_offset<=(PLAYREADY_MEM_LEN_V-clear_data_len))&&in)
        sw_memcpy((sw_short_int*)(goutput_handle+output_offset), in, clear_data_len);

    if((enc_data_len>0)&&((output_offset+clear_data_len)<=(PLAYREADY_MEM_LEN_V-enc_data_len))&&in){
#if  HWCIPHER_ENABLE
       hw_opt = (DRM_BYTE *)playready_hw_opt_get();
       if(hw_opt_global==NULL){
            playready_cipher_start(&hw_opt_global,NULL,hw_opt,DRM_AES_KEYSIZE_128);
	   PLAYREADY_DBG("[%s:%d]HW cipher start\n", __FUNCTION__, __LINE__);   		
        }
        if(hw_opt_global){ 
            playready_cipher_setiv(hw_opt_global,PlayReadyIV,VIDEO_TYPE);
            playready_cipher_ctr_process(hw_opt_global,in+clear_data_len,enc_data_len,(sw_short_int*)(goutput_handle+output_offset+clear_data_len),&enc_data_len);
	  //PLAYREADY_DBG("[%s:%d]HW cipher \n", __FUNCTION__, __LINE__);  		
        }else{           
	   PLAYREADY_DBG("[%s:%d]HW cipher no TEE_OperationHandle \n", __FUNCTION__, __LINE__);			 
        }    		
        playready_hw_opt_release(); 		
#else  
        content_key = (AES_KEY *)playready_content_key_get(); 		
        Playready_Api_decrypt(in+clear_data_len,
                enc_data_len,
                PlayReadyIV,
                CTR_MODE_CONTEXT,
                (sw_short_int*)(goutput_handle+output_offset+clear_data_len),
                content_key);
       
        playready_content_key_release();		
#endif
    }
   
    return 0;
}

int cmd_decryt_audio(void *req_buf, sw_uint req_buf_len,
        void *res_buf, sw_uint res_buf_len,
        struct otzc_encode_meta *meta_data,
        sw_uint *ret_res_buf_len)
{
    unsigned int  in_data_len=0;
    unsigned int  out_data_len=0;
    unsigned int  es_data_len=0;
    unsigned char *in=NULL;
    unsigned char *PlayReadyIV=NULL;
    unsigned char *out=NULL;
    unsigned char *out_buf=NULL;
    int offset = 0, pos = 0, mapped = 0, type, out_len=0;
    AES_KEY* content_key;
   DRM_BYTE *  hw_opt;
   
    //PLAYREADY_DBG("cmd_decryt_audio\n");
    while (offset <= req_buf_len) {
        /* decode buf length */
        if(decode_data(req_buf, meta_data, 
                    &type, &offset, &pos, &mapped, (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        else {
            if(type != OTZ_ENC_UINT32)
            {
                return SMC_EINVAL_ARG;
            }

            es_data_len = *((sw_uint*)out_buf);
        }
        /* decode encbuffer */
        if(decode_data(req_buf, meta_data, &type, &offset, &pos, &mapped,
                    (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        if(type != OTZ_ENC_ARRAY && (type != OTZ_MEM_REF)) {
            return SMC_EINVAL_ARG;
        }
        PlayReadyIV=out_buf;
        if(out_buf)
            in = out_buf+CTR_MODE_CONTEXT;
        break;
    }


    offset = 0, pos = OTZ_MAX_REQ_PARAMS;
    while (offset <= res_buf_len) {
        if(decode_data(res_buf, meta_data, &type, &offset, &pos, &mapped, 
                    (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        if ((type != OTZ_ENC_ARRAY) && (type != OTZ_MEM_REF)) { 
            return SMC_EINVAL_ARG;
        }
        out = out_buf;
        break;
    }
    //sw_printf("dump in size %d\n", es_data_len);
    //hex_dump_internal(in, 16);
    //sw_printf("dump iv\n");
    //hex_dump_internal(PlayReadyIV, 32);

    
#if  HWCIPHER_ENABLE  
    hw_opt = (DRM_BYTE *)playready_hw_opt_get();
    if(hw_opt_global==NULL){
        playready_cipher_start(&hw_opt_global,NULL,hw_opt,DRM_AES_KEYSIZE_128);
        if(hw_opt_global)
        PLAYREADY_DBG("[%s:%d]HW cipher start hw_opt_global=0x%x\n", __FUNCTION__, __LINE__,hw_opt_global);   		
    }
   if(hw_opt_global){
        playready_cipher_setiv(hw_opt_global,PlayReadyIV,AUDIO_TYPE);
        playready_cipher_ctr_process(hw_opt_global,in,es_data_len,out,&es_data_len);
    }
    else{         
         PLAYREADY_DBG("[%s:%d]HW cipher no TEE_OperationHandle \n", __FUNCTION__, __LINE__);		   
    }
    playready_hw_opt_release();	
#else
    content_key = (AES_KEY *)playready_content_key_get();
    Playready_Api_decrypt(in, es_data_len,PlayReadyIV, CTR_MODE_CONTEXT,out, content_key);
    playready_content_key_release();	
#endif    
    
    //sw_printf("dump out\n");
    //hex_dump_internal(out, 16);

    out_data_len=es_data_len;
    if(update_response_len(meta_data, pos, out_data_len)) {
        return SMC_EINVAL_ARG;
    }
    *ret_res_buf_len = out_data_len;
    //PLAYREADY_DBG("SW: pr_decryt_audio() in=0x%x, out=0x%x, enc_len=0x%x, resp_len=0x%x\n", in, out, es_data_len, res_buf_len);
    return 0;
}
int cmd_free_HW_Operation(void *req_buf, sw_uint req_buf_len,
        void *res_buf, sw_uint res_buf_len,
        struct otzc_encode_meta *meta_data,
        sw_uint *ret_res_buf_len)
{
    PLAYREADY_ERR("cmd_free_HW_Operation\n");
    unsigned int  storage_type;
    unsigned int result=SMC_SUCCESS;
    unsigned char *out;
    unsigned char *out_buf;
    int offset = 0, pos = 0, mapped = 0, type, out_len=0;
    DRM_BYTE *  hw_opt;	

    offset = 0, pos = OTZ_MAX_REQ_PARAMS;
    while (offset
            <= res_buf_len) {
        if(decode_data(res_buf, meta_data, &type, &offset, &pos, &mapped,
                    (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        if (type != OTZ_ENC_UINT32) {
            return SMC_EINVAL_ARG;
        }
#if HWCIPHER_ENABLE  
        hw_opt = (DRM_BYTE  *)playready_hw_opt_get();
        result=playready_cipher_done(hw_opt_global);
        hw_opt_global=NULL;		
        playready_hw_opt_release();	
#endif	
        if (result != 0) {
            PLAYREADY_DBG("SW: cmd_free_HW_Operation  fail\n");    
        } else {
           *((sw_uint*)out_buf) = result;
        }
        break;
    }
   if(f_pKeyFile){
       free(f_pKeyFile);
       f_pKeyFile=NULL;
   }
     if(result!=0)
          PLAYREADY_ERR("SW: cmd_free_HW_Operation,  fail result=0x%x\n",result);    
     return 0;
}

/**
 * @brief Test the wi dev ine operations
 *
 * This function tests the functiona lit y of widevine 
 *
 * @param req_buf: Virtual address of t he request buffer
 * @param req_buf_len: Requ est buffer length
 * @param res_buf: Virtual address of th e response buffer
 * @param res_buf_len: Respo nse buffer length
 * @param meta_data: Virtual address of the meta data of the encoded data
 * @param ret_res_buf_len: Return length of the response buffer
 *
 * @return  SMC return codes:
 * SMC_SUCCESS: API processed successfully. \n
 * SMC_*: An implementation-defined error code for any other error.
 */
int cmd_alloc_secure_mem(void *req_buf,
        sw_uint req_buf_len,
        void *res_buf,
        sw_uint res_buf_len,
        struct otzc_encode_meta *meta_data,
        sw_uint *ret_res_buf_len)
{
    PLAYREADY_DBG("SW: cmd_alloc_secure_mem, req_buf_len:%x,res_buf_len:%x\n", req_buf_len, res_buf_len);
    unsigned char *out_buf;
    int offset = 0, pos = 0, mapped = 0,type, out_len=0;
    int data_size = 0;
    static unsigned char *data_address = NULL;
    static int secure_mem_len = PLAYREADY_MEM_LEN_MAX;
    while (offset <= req_buf_len) {
        /* decode buf length */
        if(decode_data(req_buf, meta_data,
                    &type, &offset, &pos, &mapped, (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        else {
            if(type != OTZ_ENC_UINT32)
                return SMC_EINVAL_ARG;

            data_size = *((sw_uint*)out_buf);
        }
        break;
    }

    if(data_size > secure_mem_len) {
        secure_mem_len = data_size;
    }
            
    if (secure_mem_len >= sw_get_vdec_size()) {
        PLAYREADY_DBG("SW: alloc_secure_mem: size:%x too large!!!\n", data_size);
        return SMC_EINVAL_ARG;
    }

    if(!data_address) {
        data_address = sw_get_vdec_addr();
    }

    PLAYREADY_DBG("SW: cmd_alloc_secure_mem:data_address:%x,size:%x,secure_mem_len:%x\n", data_address, data_size, secure_mem_len);

    offset = 0, pos = OTZ_MAX_REQ_PARAMS;
    while (offset
            <= res_buf_len) {
        if(decode_data(res_buf, meta_data, &type, &offset, &pos, &mapped,
                    (void**)&out_buf, &out_len)) {
            return SMC_EINVAL_ARG;
        }
        if (type != OTZ_ENC_UINT32) {
            return SMC_EINVAL_ARG;
        }
        *((sw_uint*)out_buf) = data_address;
        break;
    }
    return 0;
}

int process_otz_playready_svc(sw_uint svc_cmd_id, void *req_buf, sw_uint req_buf_len, 
        void *resp_buf, sw_uint res_buf_len,
        struct otzc_encode_meta *meta_data, sw_uint *ret_res_buf_len)
{
    int ret_val = SMC_ERROR;

    //sw_printf("[process_otz_playready_svc] svc_cmd_id %d\n", svc_cmd_id);

    switch (svc_cmd_id) {
       case OTZ_PLAYREADY_CMD_ID_ALLOC_SECURE_MEM:
            ret_val = cmd_alloc_secure_mem(req_buf,req_buf_len,
                    resp_buf,res_buf_len,meta_data,ret_res_buf_len);	
            break;
       case OTZ_PLAYREADY_CMD_ID_AID_DECRYPT:
            ret_val = cmd_decryt_audio(req_buf,req_buf_len,
                    resp_buf,res_buf_len,meta_data,ret_res_buf_len);
            break;
       case OTZ_PLAYREADY_CMD_ID_VID_DECRYPT:
            ret_val = cmd_decryt_video(req_buf,req_buf_len,
                    resp_buf,res_buf_len,meta_data,ret_res_buf_len);
            break;
 
       case OTZ_PLAYREADY_CMD_ID_KF_LOAD:
            ret_val = cmd_load_KF(req_buf,req_buf_len,
                    resp_buf,res_buf_len,meta_data,ret_res_buf_len);	
            break;
       case OTZ_PLAYREADY_CMD_ID_KF_GETCERT:
            ret_val = cmd_KF_getCert(req_buf,req_buf_len,
                    resp_buf,res_buf_len,meta_data,ret_res_buf_len);	
            break;
       case OTZ_PLAYREADY_CMD_ID_KF_GETPRIVKEY:
            ret_val = cmd_KF_getKey(req_buf,req_buf_len,
                    resp_buf,res_buf_len,meta_data,ret_res_buf_len);	
            break;
       case OTZ_PLAYREADY_CMD_ID_ECC256KEYPAIR:
            ret_val = cmd_ECC256KEYPAIR(req_buf,req_buf_len,
                    resp_buf,res_buf_len,meta_data,ret_res_buf_len,svc_cmd_id);
            break;
       case OTZ_PLAYREADY_CMD_ID_DECRYPT_CONTENTKEY:
            ret_val = cmd_decryt_contentkey(req_buf,req_buf_len,
                    resp_buf,res_buf_len,meta_data,ret_res_buf_len,svc_cmd_id);
            break;
       case OTZ_PLAYREADY_CMD_ID_DECRYPT_RC4_CONTENTKEY:
            ret_val = cmd_decryt_RC4_contentkey(req_buf,req_buf_len,
                    resp_buf,res_buf_len,meta_data,ret_res_buf_len,svc_cmd_id);
            break;
       case OTZ_PLAYREADY_CMD_ID_CPHR_DECRYPT_AUDIO:
            ret_val = cmd_decryt_RC4_audio(req_buf,req_buf_len,
                    resp_buf,res_buf_len,meta_data,ret_res_buf_len,svc_cmd_id);
            break;
       case OTZ_PLAYREADY_CMD_ID_CPHR_DECRYPT_VIDEO:
            ret_val = cmd_decryt_RC4_video(req_buf,req_buf_len,
                    resp_buf,res_buf_len,meta_data,ret_res_buf_len,svc_cmd_id);
            break;
       case OTZ_PLAYREADY_CMD_ID_CPHR_DECRYPT_TS:
            ret_val = cmd_decryt_ts(req_buf,req_buf_len,
                    resp_buf,res_buf_len,meta_data,ret_res_buf_len);
            break;
       case OTZ_PLAYREADY_CMD_ID_FREE_HW_OPERATION:
            ret_val = cmd_free_HW_Operation(req_buf,req_buf_len,
                    resp_buf,res_buf_len,meta_data,ret_res_buf_len);	
            break;		
       case OTZ_PLAYREADY_CMD_ID_OEM_TEE_HAL_TRANSPORT:
            ret_val = cmd_OEM_TEE_hal(req_buf,req_buf_len,
                    resp_buf,res_buf_len,meta_data,ret_res_buf_len);
            break;			
        default:
            ret_val = SMC_EOPNOTSUPP;
            break;
    }

    return ret_val;
}

/**
 * @brief playready task entry point
 *
 * This function implements the commands to test the rtc operations
 *
 * @param task_id: task identifier
 * @param tls: Pointer to task local storage
 */

void playready_task(int task_id, sw_tls* tls)
{
	task_init(task_id, tls);
    tls->ret_val = process_otzapi(task_id, tls);
	task_exit(task_id, tls);
	tee_panic("playready task -hangs\n");
}
