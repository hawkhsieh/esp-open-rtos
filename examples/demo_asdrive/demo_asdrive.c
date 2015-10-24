/* http_get_mbedtls - HTTPS version of the http_get example, using mbed TLS.
 *
 * Retrieves a JSON response from the howsmyssl.com API via HTTPS over TLS v1.2.
 *
 * Validates the server's certificate using the root CA loaded (in PEM format) in cert.c.
 *
 * Adapted from the ssl_client1 example in mbedtls.
 *
 * Original Copyright (C) 2006-2015, ARM Limited, All Rights Reserved, Apache 2.0 License.
 * Additions Copyright (C) 2015 Angus Gratton, Apache 2.0 License.
 */
#include "espressif/esp_common.h"
#include "esp/uart.h"

#include <string.h>

#include "FreeRTOS.h"
#include "task.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"
#include "lwip/api.h"

#include "ssid_config.h"

/* mbedtls/config.h MUST appear before all other mbedtls headers, or
   you'll get the default config.

   (Although mostly that isn't a big problem, you just might get
   errors at link time if functions don't exist.) */
#include "mbedtls/config.h"

#include "mbedtls/net.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"


#include "syslog.h"
#include <mbedtls/aes.h>
#include "mbedtls/base64.h"
#include <ctype.h>
#include "stdio.h"
#include "math.h"
#define AES_BLOCK_SIZE 16


#define WEB_SERVER "api.dch.dlink.com"
#define WEB_PORT "443"


#define MAX_SESSION_NUM 1
#define FUNCTION_NAME_LEN 16
#define MAX_MIII_LOG_BUF  256 //512byte
#define MAX_CONFIG_STR_SIZE 512
#define LINEAR_DEFAULT_BUF_LEN 512   //On Heap
//#define STACK_REQUEST_HEADER_BUF 512
//#define AES_IN_DATA_BUF_MAX 256
#define BIND_AGENT_BODY_LEN 512
#define HTTP_REQUEST_MAXLEN 600

/* Root cert for howsmyssl.com, stored in cert.c */
extern const char *server_root_cert;

/* MBEDTLS_DEBUG_C disabled by default to save substantial bloating of
 * firmware, define it in
 * examples/http_get_mbedtls/include/mbedtls/config.h if you'd like
 * debugging output.
 */
#ifdef MBEDTLS_DEBUG_C


/* Increase this value to see more TLS debug details,
   0 prints nothing, 1 will print any errors, 4 will print _everything_
*/
#define DEBUG_LEVEL 4

static void my_debug(void *ctx, int level,
                     const char *file, int line,
                     const char *str)
{
    ((void) level);

    /* Shorten 'file' from the whole file path to just the filename

       This is a bit wasteful because the macros are compiled in with
       the full _FILE_ path in each case, so the firmware is bloated out
       by a few kb. But there's not a lot we can do about it...
    */
    char *file_sep = rindex(file, '/');
    if(file_sep)
        file = file_sep+1;

    logprintf("%s:%04d: %s", file, line, str);
}
#endif

xTaskHandle xHandle;


void printHunk( char *data , int data_size , int chunk_size)
{
    int last=0;
    int cutat=chunk_size;
    while( data_size>cutat ){
        char tmp;
        tmp=data[cutat];
        if (cutat>=data_size)
            halt("printHunk: last(%d)>=data_size(%d)\n",last,data_size);
        data[cutat]=0;
        if (last>=data_size)
            halt("printHunk: last(%d)>=data_size(%d)\n",last,data_size);
        printf("%s",&data[last]);
        data[cutat]=tmp;
        last = cutat;
        cutat += chunk_size;
    }
    printf("%s\n+++total=%d+++\n",&data[last],data_size);
}

#define SECUIRTY_REQ
#if defined (SECUIRTY_REQ)
/*
    .domainname="dch.dlink.com:443",
    .country_code="WW",
    .agent_version="",
*/


static int AES_initAES(char *key , mbedtls_aes_context *ctx , int mode )
{
    int aes_key_bit,key_len;
    key_len = strlen(key);
    aes_key_bit = key_len*8;

    if ( mode == MBEDTLS_AES_ENCRYPT){
        if (mbedtls_aes_setkey_enc(ctx, (unsigned char*)key, aes_key_bit) < 0) {

            logprintf("AES enc init fail \n");
            goto ERROR;
        }
    }else{
        if (mbedtls_aes_setkey_dec(ctx, (unsigned char*)key, aes_key_bit) < 0) {

            logprintf("AES enc init fail \n");
            goto ERROR;
        }
    }
    return 0;
ERROR:
    return -1;
}

static char* llocAESBuf(size_t in_size,size_t *out_size)
{
    size_t remain_size;
    char *out_addr;

    *out_size = in_size;
    remain_size = in_size % AES_BLOCK_SIZE;

    if (remain_size != 0){

        if (in_size < AES_BLOCK_SIZE)
            *out_size = AES_BLOCK_SIZE;
        else {

            int add_size = AES_BLOCK_SIZE - remain_size;
            *out_size += add_size;
        }
    }

    out_addr = malloc((*out_size)+1);
    bzero(out_addr, (*out_size)+1);

    logprintf("AES in size %d out_size %d \n", in_size, *out_size);

    return out_addr;

}

typedef struct
{
    char *data_point;
    int data_length;
    size_t alloc_size;
}aes_data_st;

aes_data_st runAESEncrypt(char *in_addr,size_t in_size,char *iv,int mode)
{
    size_t out_size;
    char *out_addr;
    aes_data_st aes_data;
    bzero(&aes_data,sizeof(aes_data_st));
    char *align_in_addr = malloc(in_size);

    bzero(align_in_addr, in_size);
    memcpy(align_in_addr, in_addr, in_size);

    out_addr = llocAESBuf(in_size, &out_size);

    mbedtls_aes_context aes_key;
    AES_initAES( "8b57e5181d4af2c8" , &aes_key , mode);

    unsigned char const_iv[16];

    memcpy(const_iv,iv,16);
    int ret;
    ret = mbedtls_aes_crypt_cbc( &aes_key ,mode ,out_size,(unsigned char *)const_iv,(unsigned char *)align_in_addr,(unsigned char *)out_addr );
    if (ret)
        logprintf("[ERROR] mbedtls_aes_crypt_cbc failed=%d\n",ret);

    aes_data.data_point = out_addr;
    aes_data.data_length = out_size;
    aes_data.alloc_size = out_size;

    free(align_in_addr);
    return aes_data;
}

static size_t base64encode(const unsigned char *input, size_t input_length, unsigned char *output, size_t output_length)
{
    size_t written_len;
    int ret;
    ret = mbedtls_base64_encode( output, output_length , &written_len , input , input_length );
    if (ret)
        logprintf("[ERROR] mbedtls_base64_encode failed ret=%d,written_len=%d\n",ret,written_len);

    if ( written_len > output_length )
        halt( "base64encode: written_len(%d) > output_length(%d)\n" ,written_len , output_length);

    return written_len;
}

static char* AES_runAESEnc(char *in_addr,size_t in_size,char *iv)
{
    aes_data_st aes_data;
    aes_data = runAESEncrypt(in_addr, in_size, iv, MBEDTLS_AES_ENCRYPT);

    int base64_enc_text_size=(int)((double)aes_data.alloc_size * 1.5 )+1;
    char *base64_enc_text = malloc( base64_enc_text_size );
    bzero(base64_enc_text,base64_enc_text_size);
    logprintf("AES encrypt but length:%d and iv:%s \n", in_size, iv);

    base64encode((unsigned char*) aes_data.data_point, aes_data.alloc_size, (unsigned char*) base64_enc_text, base64_enc_text_size );

    if ( base64_enc_text[base64_enc_text_size-1] != 0 )
    {
        halt("base64_enc_text[%d] not 0\n" , base64_enc_text_size-1);
    }
    free(aes_data.data_point);

    return base64_enc_text;
}


char* Aes_getRandIv(int iv_len)
{
    int i = 0;
    char *retval = (char*) malloc(iv_len+1);

    srand((unsigned int)&i);
    for (i=0; i<iv_len; i++) {
        retval[i] = (rand() % 255)+1;
    }

    retval[i] = 0;
    return retval;
}



char toHex(char code)
{
    static char hex[] = "0123456789ABCDEF";
    return hex[code & 15];
}

static char* Http_urlEncode (unsigned char *str)
{
    int buf_len=strlen((char *)str) * 3 + 1;
    unsigned char *pstr = str, *buf = malloc( buf_len ), *pbuf = buf;
    int i=0;
    while (*pstr) {
        if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~'){
            pbuf[i++] = *pstr;
        }else{
            pbuf[i++]='%';
            pbuf[i++] = toHex(*pstr >> 4);
            pbuf[i++] = toHex(*pstr & 15);
        }
        pstr++;

    }
    if ( i >= buf_len )
        halt( "Http_urlEncode overflow i=%d,buf_len=%d\n", i , buf_len );

    pbuf[i] = '\0';

    return (char*)buf;
}


static int getBingAgentBody(char *body,int body_len)
{
    int len = 0,buf_len = 0, did_len = 0;
    char *iv = NULL,*url_encode_iv = NULL,*p = NULL;
    char *did,*mac,*brand,*model,*fw_ver,*hw_ver,*second_id;
    time_t time_stamp=1445586574;
    unsigned char base64_iv[32],*encrypt_p = NULL;
    char *buf = malloc( BIND_AGENT_BODY_LEN );


    did = "b7e15a006ea42c4246486863a96a5589";
    mac = "02:42:ac:11:00:3c";
    brand = "D-Link";
    model = "DSP-W110";
    fw_ver = "1.11";
    hw_ver = "A1";
    second_id = "57b671c4158153a1110c32cf69653112";

  //  time_stamp = time(NULL);

    iv = Aes_getRandIv(16);
    base64encode((unsigned char*)iv, strlen(iv), base64_iv, sizeof(base64_iv));
    url_encode_iv = Http_urlEncode(base64_iv);


    did_len = strlen(did);

    if (did_len == 0) {

         buf_len = snprintf(buf, BIND_AGENT_BODY_LEN ,
                 "mac=%s&dch_id=%s&"
                 "brand=%s&model=%s&"
                 "firmware_version=%s&"
                 "hardware_version=%s&"
                 "agent_version=%s&"
                 "time=%d", mac, second_id, brand, model, fw_ver, hw_ver, "1.0.17", (int)time_stamp);

    }
    else {

        buf_len = snprintf(buf, BIND_AGENT_BODY_LEN ,
                       "did=%s&mac=%s&"
                       "dch_id=%s&"
                       "brand=%s&model=%s&"
                       "firmware_version=%s&"
                       "hardware_version=%s&"
                       "agent_version=%s&"
                       "time=%d", did, mac, second_id, brand, model, fw_ver, hw_ver, "1.0.17", (int)time_stamp);

    }

//    logprintf("++++body++++\n");
//    printHunk( buf , buf_len , LOGBUF_LENGTH );

    encrypt_p = (unsigned char*)AES_runAESEnc(buf, buf_len, iv);
    free(buf);
    free(iv);

    logprintf("++++base64 p++++\n");
    printHunk( (char *)encrypt_p , strlen((char *)encrypt_p) , LOGBUF_LENGTH );

    logprintf("++++base64 url_encode_iv++++\n");
    printHunk( (char *)url_encode_iv , strlen((char *)url_encode_iv) , LOGBUF_LENGTH );


    p = Http_urlEncode(encrypt_p);

    if (did_len  == 0)
        len = snprintf(body, body_len, "p=%s&iv=%s\r\n\r\n", p, url_encode_iv);
    else
        len = snprintf(body, body_len, "did=%s&p=%s&iv=%s\r\n\r\n", did, p, url_encode_iv);

    free(url_encode_iv);
    free(encrypt_p);
    free(p);

    return len;

}
#endif


int Network_getInBoundIp(int in_bound_fd,char *ip,int *port)
{
    struct sockaddr_in sin;
    socklen_t len = sizeof(sin);
    if (getpeername(in_bound_fd, (struct sockaddr *)&sin, &len) == -1)
        errnologprintf( "FD :%d\n",in_bound_fd);
    else
    {
        strncpy( ip , inet_ntoa(sin.sin_addr) , INET_ADDRSTRLEN );
        *port = sin.sin_port;
        return 0;
    }

    return -1;
}


typedef struct{

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_x509_crt cacert;
    mbedtls_ssl_config conf;

}TLSConnect;

void TLSConnect_Free( TLSConnect *conn , mbedtls_net_context *fd )
{
    mbedtls_ssl_session_reset(&conn->ssl);
    mbedtls_net_free( fd );

}

int TLSConnect_Init( TLSConnect *conn )
{
    const char *pers = "ssl_client1";
    int ret;
    /*
     * 0. Initialize the RNG and the session data
     */
    mbedtls_ssl_init(&conn->ssl);
    mbedtls_x509_crt_init(&conn->cacert);
    mbedtls_ctr_drbg_init(&conn->ctr_drbg);
    logprintf("\n  . Seeding the random number generator...");

    mbedtls_ssl_config_init(&conn->conf);

    mbedtls_entropy_init(&conn->entropy);
    if((ret = mbedtls_ctr_drbg_seed(&conn->ctr_drbg, mbedtls_entropy_func, &conn->entropy,
                                    (const unsigned char *) pers,
                                    strlen(pers))) != 0)
    {
        logprintf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        while(1) {} /* todo: replace with abort() */
    }

    logprintf(" ok\n");

    /*
     * 0. Initialize certificates
     */
    logprintf("  . Loading the CA root certificate ...");

    ret = mbedtls_x509_crt_parse(&conn->cacert, (uint8_t*)server_root_cert, strlen(server_root_cert)+1);
    if(ret < 0)
    {
        logprintf(" failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret);
        while(1) {} /* todo: replace with abort() */
    }

    logprintf(" ok (%d skipped)\n", ret);

    /* Hostname set here should match CN in server certificate */
    if((ret = mbedtls_ssl_set_hostname(&conn->ssl, WEB_SERVER)) != 0)
    {
        logprintf(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        while(1) {} /* todo: replace with abort() */
    }

    /*
     * 2. Setup stuff
     */
    logprintf("  . Setting up the SSL/TLS structure...");

    if((ret = mbedtls_ssl_config_defaults(&conn->conf,
                                          MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        logprintf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }

    logprintf(" ok\n");

    /* OPTIONAL is not optimal for security, in this example it will print
       a warning if CA verification fails but it will continue to connect.
    */
    mbedtls_ssl_conf_authmode(&conn->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&conn->conf, &conn->cacert, NULL);
    mbedtls_ssl_conf_rng(&conn->conf, mbedtls_ctr_drbg_random, &conn->ctr_drbg);
#ifdef MBEDTLS_DEBUG_C
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
    mbedtls_ssl_conf_dbg(&conn->conf, my_debug, stdout);
#endif

    if((ret = mbedtls_ssl_setup(&conn->ssl, &conn->conf)) != 0)
    {
        logprintf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    /* Wait until we can resolve the DNS for the server, as an indication
       our network is probably working...
    */
    logprintf("Waiting for server DNS to resolve... ");
    err_t dns_err;
    ip_addr_t host_ip;
    do {
        vTaskDelay(500 / portTICK_RATE_MS);
        dns_err = netconn_gethostbyname(WEB_SERVER, &host_ip);
    } while(dns_err != ERR_OK);
    logprintf("Internet is ok!!\n");
    return 0;

exit:
    TLSConnect_Free( conn , 0 );
    return -1;
}

int TLSConnect_SendReq( TLSConnect *conn , char *request , int request_len , char *response , int response_len )
{
    int ret=0;
    logprintf("HTTP get task starting...\n");

    uint32_t flags;
    mbedtls_net_context server_fd;


        mbedtls_net_init(&server_fd);
        logprintf("heap = %u\n", xPortGetFreeHeapSize());
        /*
         * 1. Start the connection
         */
        logprintf("  . Connecting to %s:%s...\n", WEB_SERVER, WEB_PORT);

        if((ret = mbedtls_net_connect(&server_fd, "54.64.145.83",
                                      WEB_PORT, MBEDTLS_NET_PROTO_TCP)) != 0)
        {
            logprintf(" failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
            goto exit;
        }

        logprintf(" ok\n");

        mbedtls_ssl_set_bio(&conn->ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

        /*
         * 4. Handshake
         */
        logprintf("  . Performing the SSL/TLS handshake...\n");

        while((ret = mbedtls_ssl_handshake(&conn->ssl)) != 0)
        {
            if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            {
                logprintf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret);
                goto exit;
            }
        }

        logprintf(" ok\n");

        /*
         * 5. Verify the server certificate
         */
        logprintf("  . Verifying peer X.509 certificate...\n");

        /* In real life, we probably want to bail out when ret != 0 */
        if((flags = mbedtls_ssl_get_verify_result(&conn->ssl)) != 0)
        {
            char vrfy_buf[512];

            logprintf(" failed\n");

            mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);

            logprintf("%s\n", vrfy_buf);
        }
        else
            logprintf(" ok\n");

        /*
         * 3. Write the GET request
         */
        logprintf("  > Write to server:\n");
#if 0
        char ip[INET_ADDRSTRLEN];
        int port;
        Network_getInBoundIp( server_fd.fd , ip , &port);
        logprintf("connect to %s:%d\n",ip,port);
#endif
        while((ret = mbedtls_ssl_write(&conn->ssl, (const unsigned char *)request, request_len)) <= 0)
        {
            if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            {
                logprintf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
                goto exit;
            }
        }

//        logprintf("++++request(%d bytes written)++++\n",ret);
//        printHunk( (char*)request , ret , LOGBUF_LENGTH );

        /*
         * 7. Read the HTTP response
         */
        logprintf("  < Read from server:\n");

        do
        {
            ret = mbedtls_ssl_read(&conn->ssl, (unsigned char *)response, response_len );

            if(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
                continue;

            if(ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                ret = 0;
                break;
            }

            if(ret < 0)
            {
                logprintf("failed\n  ! mbedtls_ssl_read returned %d\n\n", ret);
                break;
            }

            if(ret == 0)
            {
                logprintf("\n\nEOF\n\n");
                break;
            }

            ret=0;break;
        } while(1);

        mbedtls_ssl_close_notify(&conn->ssl);

    exit:

        TLSConnect_Free( conn , &server_fd );

#if 0
        int countdown;
        for(countdown = successes ? 3 : 1; countdown >= 0; countdown--) {
            logprintf("%d... ", countdown);
            vTaskDelay(1000 / portTICK_RATE_MS);
        }
        logprintf("\nStarting again!\n");
#endif
    return ret;

}

void sleep( int second )
{
    vTaskDelay( second / portTICK_RATE_MS);
}



void http_get_task(void *param)
{
    char * restrict request = malloc(HTTP_REQUEST_MAXLEN);
#if defined(SECUIRTY_REQ)
    char *body = malloc(512);
    int body_len=getBingAgentBody(body,512);
    int request_len=snprintf( request , HTTP_REQUEST_MAXLEN ,
    "POST /agent/bind HTTP/1.1\r\n"\
    "Host: api.dch.dlink.com:443\r\n"\
    "Content-Type: application/x-www-form-urlencoded\r\n"\
    "Content-Length: %d\r\n\r\n%s" , body_len , body );
    free(body);

    logprintf("request_len=%d\n",request_len);
#else
    strcpy(request,"GET /ok.html HTTP/1.1\r\nHost: api.dch.dlink.com\r\n\r\n");
    int request_len=strlen(request);
#endif

    unsigned char response[512];
    memset(response, 0, sizeof(response));


    TLSConnect *conn=malloc(sizeof(TLSConnect));
    int successes = 0, failures = 0;

    if ( TLSConnect_Init( conn ) )
         halt("TLSConnect_Init\n");

    while(1){

        int ret;
        ret = TLSConnect_SendReq( conn , request , request_len , (char *)response , sizeof(response) );

        if(ret != 0)
        {
            char error_buf[100];
            mbedtls_strerror(ret, error_buf, 100);
            logprintf("\n\nLast error was: %d - %s\n\n", ret, error_buf);
            failures++;
        } else {
            successes++;

            logprintf("++++request(%d bytes read)++++\n",ret);
            printHunk( (char*)response , ret , LOGBUF_LENGTH );
        }

        logprintf("successes = %d failures = %d\n", successes, failures);
    }
}

void user_init(void)
{
    SyslogDial("54.169.15.38",514);

    uart_set_baud(0, 115200);
    logprintf("SDK version:%s\n", sdk_system_get_sdk_version());

    struct sdk_station_config config = {
        .ssid = WIFI_SSID,
        .password = WIFI_PASS,
    };

    /* required to call wifi_set_opmode before station_set_config */
    sdk_wifi_set_opmode(STATION_MODE);
    sdk_wifi_station_set_config(&config);

    xTaskCreate(&http_get_task, (signed char *)"get_task", 2048 ,  NULL , 2, &xHandle );
}
