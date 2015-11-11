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


#include "log_control.h"
//#include "start_link.h"
//#include "rly_client.h"
#include "build_request.h"
#include "fetch_response.h"
#include "memory.h"
#include "asdResponse.h"
#include "asdUART.h"
#include "asdGPIO.h"
#include "asdJson.h"
#include "string_utility.h"
#include "fsm.h"
#include <inttypes.h>


#define AES_BLOCK_SIZE 16

#define HTTP
//#define WEB_SERVER "api.dch.dlink.com"
#define WEB_SERVER "api.astra.miiicasa.com"

#define WEB_PORT "80"

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

/*
    .domainname="dch.dlink.com:443",
    .country_code="WW",
    .agent_version="",
*/

typedef struct{

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_x509_crt cacert;
    mbedtls_ssl_config conf;

}TLSConnect;


typedef struct{
    FSM fsm;
    transition *trans;
    char http_buf[HTTP_REQUEST_MAXLEN];
    TLSConnect conn;
#ifdef HTTP
    int socket_fd;
#endif
    char *app_data;
}HTTPS;

typedef struct
{
    FSM fsm;
    char *relay_server;
    char *p;
    char *iv;
    HTTPS https;
}Linkd;




int HTTPConnect_Write( int socket_fd , char *data ,int data_len )
{
    int len = write(socket_fd, data, data_len);
    if ( len < 0) {
        errnologprintf("write");
        close(socket_fd);
    }

    return len;
}


int TLSConnect_Write( TLSConnect *conn , char *data ,int data_len )
{
    int ret;
    while((ret = mbedtls_ssl_write( &conn->ssl, (const unsigned char *)data, data_len)) <= 0)
    {
        if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            logprintf("mbedtls_ssl_write=%d\n\n", ret);
            break;
        }
    }
    return ret;
}

void TLSConnect_Free( TLSConnect *conn , mbedtls_net_context *fd )
{
    mbedtls_ssl_session_reset(&conn->ssl);
    mbedtls_net_free( fd );
/*
    mbedtls_x509_crt_free( &conn->cacert );
    mbedtls_ssl_free( &conn->ssl );
    mbedtls_ssl_config_free( &conn->conf );
    mbedtls_ctr_drbg_free( &conn->ctr_drbg );
    mbedtls_entropy_free( &conn->entropy );*/
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
    mbedtls_ssl_config_init(&conn->conf);
    mbedtls_entropy_init(&conn->entropy);

    if((ret = mbedtls_ctr_drbg_seed(&conn->ctr_drbg, mbedtls_entropy_func, &conn->entropy,
                                    (const unsigned char *) pers,
                                    strlen(pers))) != 0)
    {
        halt("mbedtls_ctr_drbg_seed=%d\n", ret);
    }

    /*
     * 0. Initialize certificates
     */
    logprintf("Load CA\n");

    ret = mbedtls_x509_crt_parse(&conn->cacert, (uint8_t*)server_root_cert, strlen(server_root_cert)+1);
    if(ret < 0)
    {
        halt("mbedtls_x509_crt_parse=-0x%x\n", -ret);
    }

    /* Hostname set here should match CN in server certificate */
    if((ret = mbedtls_ssl_set_hostname(&conn->ssl, WEB_SERVER)) != 0)
    {
        halt("mbedtls_ssl_set_hostname=%d\n", ret);
    }

    /*
     * 2. Setup stuff
     */
    logprintf("Set SSL/TLS\n");

    if((ret = mbedtls_ssl_config_defaults(&conn->conf,
                                          MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        errprintf("mbedtls_ssl_config_defaults=%d\n", ret);
        goto exit;
    }

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
        errprintf("mbedtls_ssl_setup=%d\n", ret);
        goto exit;
    }

    /* Wait until we can resolve the DNS for the server, as an indication
       our network is probably working...
    */
    logprintf("resolving...\n");
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

#ifdef HTTP
int HTTPConnect_SendReq( HTTPS *https , char *url , char *request , int request_len , char *response , int response_len )
{
    int ret=-1;
    const struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM,
    };
    struct addrinfo *res;

    int err = getaddrinfo( url, WEB_PORT, &hints, &res);

    if(err != 0 || res == NULL) {
        printf("DNS x err=%d res=%p\r\n", err, res);
        if(res)
            freeaddrinfo(res);
        vTaskDelay(1000 / portTICK_RATE_MS);
        goto END;
    }
    /* Note: inet_ntoa is non-reentrant, look at ipaddr_ntoa_r for "real" code */
    struct in_addr *addr = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
    printf( "%s=%s\r\n",url, inet_ntoa(*addr));

    int s = socket(res->ai_family, res->ai_socktype, 0);
    if(s < 0) {
        printf("... Failed to allocate socket.\r\n");
        freeaddrinfo(res);
        vTaskDelay(1000 / portTICK_RATE_MS);
        goto END;
    }

    if(connect(s, res->ai_addr, res->ai_addrlen) != 0) {
        close(s);
        freeaddrinfo(res);
        printf("... socket connect failed.\r\n");
        vTaskDelay(4000 / portTICK_RATE_MS);
        goto END;
    }

    freeaddrinfo(res);

    if (write(s, request, request_len) < 0) {
        printf("... socket send failed\r\n");
        close(s);
        vTaskDelay(4000 / portTICK_RATE_MS);
        goto END;
    }
    int len=0;
    https->socket_fd=s;
    do{
        ret = recv( s, &response[len] , response_len-len,0);
        if ( ret < 0 )
            break;

        len += ret;
        response[len]=0;

        if (https->trans){
            if ( run_fsm( &https->fsm , https->trans , &response , https ,0,0) == 0 )
                break;
        }
        else
            break;

    }while( ret >= 0 );
    ret = len;
    close(s);
END:
    return ret;

}
#endif
int TLSConnect_SendReq( HTTPS *https , char *url , char *request , int request_len , char *response , int response_len )
{
    int ret=0,len=0;
    uint32_t flags;
    mbedtls_net_context server_fd;

        mbedtls_net_init(&server_fd);
        /*
         * 1. Start the connection
         */
        logprintf("Connect to %s:" WEB_PORT "\n", url );
        logprintf("heap=%u\n", xPortGetFreeHeapSize());

        if((ret = mbedtls_net_connect(&server_fd, url ,
                                      WEB_PORT, MBEDTLS_NET_PROTO_TCP)) != 0)
        {
            errprintf("mbedtls_net_connect=%d\n", ret);
            goto exit;
        }

        mbedtls_ssl_set_bio(&https->conn.ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

        /*
         * 4. Handshake
         */
        logprintf("mbedtls_ssl_handshake,heap=%u\n", xPortGetFreeHeapSize());

        int retry=3;
        while((ret = mbedtls_ssl_handshake(&https->conn.ssl)) != 0 && retry-- )
        {
            if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            {
                logprintf("mbedtls_ssl_handshake=-0x%x\n", -ret);
                sleep(1);
                continue;
            }
        }
        /*
         * 5. Verify the server certificate
         */
        logprintf("Verifying X.509 cert\n");

        /* In real life, we probably want to bail out when ret != 0 */
        if((flags = mbedtls_ssl_get_verify_result(&https->conn.ssl)) != 0)
        {
            char vrfy_buf[512];

            errprintf(" failed\n");

            mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);

            logprintf("%s\n", vrfy_buf);
        }

        /*
         * 3. Write the GET request
         */
#if 0
        char ip[INET_ADDRSTRLEN];
        int port;
        Network_getInBoundIp( server_fd.fd , ip , &port);
        logprintf("connect to %s:%d\n",ip,port);
#endif
        logprintf("<<<(%d)\n", request_len);

        while((ret = mbedtls_ssl_write(&https->conn.ssl, (const unsigned char *)request, request_len)) <= 0)
        {
            if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            {
                errprintf("mbedtls_ssl_write=%d\n", ret);
                goto exit;
            }
        }
//        logprintf("++++request(%d bytes written)++++\n",ret);
//        printHunk( (char*)request , ret , LOGBUF_LENGTH );

        /*
         * 7. Read the HTTP response
         */
        do
        {
            logprintf("heap=%u\n", xPortGetFreeHeapSize());
#define NULL_CHAR 1
            ret = mbedtls_ssl_read(&https->conn.ssl, (unsigned char *)&response[len], response_len-len-NULL_CHAR );

            logprintf(">>>(%d)\n", ret );

            if(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
                continue;

            if(ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                ret = 0;
                break;
            }

            if(ret < 0)
            {
                errprintf("mbedtls_ssl_read=%d\n\n", ret);
                break;
            }

            if(ret == 0)
            {
                logprintf("\n\nEOF\n\n");
                break;
            }

            len += ret;
            response[len]=0;

            if (https->trans){
                if ( run_fsm( &https->fsm , https->trans , &response , https ,0,0) == 0 )
                    break;
            }
            else
                break;

        } while(1);

        mbedtls_ssl_close_notify(&https->conn.ssl);

    exit:
        TLSConnect_Free( &https->conn , &server_fd );

        if ( ret < 0 ){
            char error_buf[100];
            mbedtls_strerror(ret, error_buf, 100);
            errprintf("mbedtls: %s\n", ret, error_buf);
        }else
            ret=len;

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

unsigned int sleep( unsigned int second )
{
    vTaskDelay( second*1000 / portTICK_RATE_MS);
    return 0;
}



String getJson( void *data  )
{
    String json_string;
    bzero(&json_string,sizeof(String));
    char *json = strchr((char*)data,'{');
    char *end_json = strrchr((char*)data,'}');
    if ( end_json ) *(end_json+1)=0;
    else{
        goto ERROR;
    }
    STRING_LinkString(&json_string , json , strlen(json));
ERROR:
    return json_string;
}


typedef struct{
    char *p;
    char *iv;
    char *status;
    char *errmsg;
    char *errno_json;
    char *relay_server;
}EncryptResponse;

int EncryptResponse_Assign(char **data, void *globol_context , void *local_context )
{
    KeyValue *key_value = (KeyValue *)globol_context;
    EncryptResponse *agent_bind = (EncryptResponse*)asdJsonFSM_GetData(data);

    if ( strcmp( key_value->key , "p") == 0 ){
        agent_bind->p=key_value->value;
    }else if( strcmp( key_value->key , "status") == 0 ){
        agent_bind->status = key_value->value;
    }else if( strcmp( key_value->key , "iv") == 0 ){
        agent_bind->iv = key_value->value;
    }else if( strcmp( key_value->key , "relay_server") == 0 ){
        agent_bind->relay_server = key_value->value;
    }

    return 0;
}




int LinkdEncryptRequest( HTTPS *https , char *http_buf , int http_buf_len, EncryptResponse *response )
{
    printHunk( (char *)http_buf , http_buf_len , LOGBUF_LENGTH );

    int ret;
#ifdef HTTP
    ret = HTTPConnect_SendReq( https , WEB_SERVER , http_buf , http_buf_len , (char *)http_buf , HTTP_REQUEST_MAXLEN );
#else
    ret = TLSConnect_SendReq( https , "54.64.145.83" , http_buf , http_buf_len , (char *)http_buf , HTTP_REQUEST_MAXLEN );
#endif
    if(ret <= 0){
        halt("tls failed\n");
    }

    printHunk( (char*)http_buf , ret , LOGBUF_LENGTH );

    transition perform_trans={0, FUNCTION(EncryptResponse_Assign),   1,-1, ACCEPT };
    String http_buf_json = getJson( http_buf );
    if ( http_buf_json.point == 0 ){
        errprintf("no json\n" );
        return -1;
    }
    char *agent_bind_keys[] = { "p","status","iv","relay_server",0};
    asdJsonFSM_Parse( &http_buf_json , response , &perform_trans , agent_bind_keys );

    return 0;
}

#define http_request_header_fmt "%s HTTP/1.1\r\n"\
                                "Host: " WEB_SERVER "\r\n"\
                                "Content-Type: application/x-www-form-urlencoded\r\n"\
                                "Content-Length: %d\r\n\r\n%s"

int agent_bind(char **data, void *globol_context , void *local_context )
{
    Linkd *linkd_inst=(Linkd *)*data;

    char *body = malloc(512);
    int body_len=getBingAgentBody(body,512);
    int http_buf_len=snprintf( linkd_inst->https.http_buf , HTTP_REQUEST_MAXLEN ,
                               http_request_header_fmt , "POST /agent/bind" , body_len , body );
    free(body);

    EncryptResponse agent_bind_json;
    bzero(&agent_bind_json,sizeof(EncryptResponse));

    if ( LinkdEncryptRequest( &linkd_inst->https ,linkd_inst->https.http_buf , http_buf_len ,&agent_bind_json) ){
        errprintf("resp err\n");
        return -1;
    }

    logprintf("p:%s\n",agent_bind_json.p);
    logprintf("status:%s\n",agent_bind_json.status);

    return 0;
}




int get_relay(char **data, void *globol_context , void *local_context )
{

    Linkd *linkd_inst=(Linkd *)*data;
    logprintf("POST /agent/v2/relay/get\n");
    logprintf("rs=%p,p=%p,iv=%p\n",linkd_inst->relay_server,linkd_inst->p , linkd_inst->iv);

    free( linkd_inst->relay_server );linkd_inst->relay_server=0;
    free( linkd_inst->p );linkd_inst->p=0;
    free( linkd_inst->iv );linkd_inst->iv=0;

    char *body = malloc(512);
    int body_len=getRelayBody(body,512);
    int http_buf_len=snprintf( linkd_inst->https.http_buf , HTTP_REQUEST_MAXLEN ,
                               http_request_header_fmt , "POST /agent/v2/relay/get", body_len , body );

    free(body);
    EncryptResponse response;
    bzero(&response,sizeof(EncryptResponse));

    if ( LinkdEncryptRequest( &linkd_inst->https ,linkd_inst->https.http_buf , http_buf_len ,&response) )
    {
        return -1;
    }

    logprintf("status:%s\n",response.status);
    logprintf("p:%s\n",response.p);
    logprintf("iv:%s\n",response.iv);
    logprintf("relay_server:%s\n",response.status);

    linkd_inst->p = strdup(response.p);
    linkd_inst->iv = strdup(response.iv);
    linkd_inst->relay_server = strdup(response.relay_server);

    return 0;
}


#if 0

typedef struct {
    char *http_string;
    int http_string_len;
    int content_len;
    char *body;
}HttpContent;

/*
int HttpFirst(char **data, void *globol_context , void *local_context )
{
    logprintf( "+++++++ HttpFirst +++++++\n");
    HttpContent *content=(HttpContent *)globol_context;
    content->http_string_len = strlen(*data);
    content->http_string = *data;
    return 0;
}

int HttpContentLength(char **data, void *globol_context , void *local_context )
{
    logprintf( "+++++++ HttpContentLength +++++++\n");
#define CONTENT_LENGTH "ContentLength: "
    HttpContent *content=(HttpContent *)globol_context;
    char *content_length_str = strstr_bmh( *data , content->http_string_len ,CONTENT_LENGTH,sizeof(CONTENT_LENGTH)-1);
    if ( content->content_len == 0 )
        return -1;

    content_length_str += sizeof(CONTENT_LENGTH)-1;
    content->content_len = atoi( content_length_str);

    return 0;
}

int HttpNoBody(char **data, void *globol_context , void *local_context )
{
    HttpContent *content=(HttpContent *)globol_context;

    if ( content->body == 0 )
        return 0;
    else
        return -1;
}

int HttpGet(char **data, void *globol_context , void *local_context )
{
    logprintf( "+++++++ HttpGet +++++++\n");

    logprintf( "data=%s\n",*data);
    if ( memcmp( *data, "GET" , 3) == 0 )
    {
        return 0;
    }else
        return -1;
}

int HttpCompleteBody(char **data, void *globol_context , void *local_context )
{
    logprintf( "+++++++ HttpCompleteBody +++++++\n");
    HttpContent *content=(HttpContent *)globol_context;

    if ( content->body == 0 )
        return -1;

    if ( strlen( content->body ) == content->content_len )
        return 0;
    else
        return -1;

}


int HttpBody(char **data, void *globol_context , void *local_context )
{
    logprintf( "+++++++ HttpBody +++++++\n");
    HttpContent *content=(HttpContent *)globol_context;
#define CRLFCRLF "\r\n\r\n"
    char *crlfcrlf = strstr_bmh( *data , strlen(*data) , CRLFCRLF ,sizeof(CRLFCRLF)-1);
    if ( crlfcrlf == 0 )
        return -1;

    content->body = crlfcrlf + sizeof(CRLFCRLF)-1;
    return 0;
}
*/

#endif


#if 0
static String asdUART_WriteAPI( HTTPS *https,String *json , String *first_line )
{
    UARTData uart_data;
    bzero(&uart_data,sizeof(UARTData));

    if ( asdUART_ParseFirstLine( first_line , &uart_data ) )
        return -1;
//    int s=asdUART_GetSession( &uart_data );
//    if ( s == -1 )
//        return -1;
    transition write_transition[]={
        {0, FUNCTION(asdUARTData_Assign), -1,-1, ACCEPT },
        {-1}
    };
    asdJsonFSM_Parse( json , &uart_data , write_transition , post_uart );

    int len;
    for(len=0;len<uart_data.size;len++){
        putchar(uart_data.buf[len]);
    }

    logprintf("read_size=%d\n",uart_data.read_size);

    for(len=0;len<uart_data.read_size;len++)
    {
        uart_data.buf[len] = getchar();
    }

    uart_data.size=uart_data.read_size;

    String response;
    response = asdUARTData_Response( https , &uart_data );
    free(uart_data.buf);
    return response;

}
#endif


int HttpProcessData(char **data, void *globol_context , void *local_context )
{

    HTTPS *https=(HTTPS *)globol_context;
    char *request=*data;
    String response;
    bzero(&response,sizeof(String));
    int len=strlen(*data);

    printHunk( request , len  , HTTP_REQUEST_MAXLEN );

    char *lf=strchr(request,'\n');
    if ( lf == 0 ){
        response = asdResponse_400( "No first line" );
        goto END;
    }
    *(lf-1)=0; //Mark the first line
    char *header= lf+1;

    char *uri=strchr(request,' ');
    if (uri==0){
        response = asdResponse_400( "no 1st space" );
        goto END;
    }

    uri += 1;
    int uri_len=strlen(uri);

    String first_line;
    STRING_LinkString(&first_line , request , strlen(request) );
    char *method = request;

#define nobody "no body"
#define nouri "no uri"

#if 0
#define ACCESS_CONTROL "Access-Control-Request-Method: "
    if ( strncmp( request, "OPTION" ,4 ) == 0 ){

        char *access_control = strstr_bmh( header , strlen(header) , ACCESS_CONTROL , sizeof(ACCESS_CONTROL ) -1);
        if ( access_control == 0 ){
            response = asdResponse_400( "no method" );
            goto END;
        }

        method = access_control + sizeof(ACCESS_CONTROL ) -1;
    }
#endif

    char *version;
    version=strstr_bmh(uri,uri_len,"/v1_0_0/",sizeof("/v1_0_0/")-1);
    if ( version == 0 ){
        response = asdResponse_400( "no version" );
        goto END;
    }

    char *path=version+sizeof("/v1_0_0/")-1;
    int path_len=strlen(path);

    logprintf( "======path:%s\n",path);


    if ( strncmp( method, "POST" ,4 ) == 0 ){
        String json_string=getJson(header);

        if ( strstr_bmh(uri,uri_len,"/uart/config?",sizeof("/uart/config?")-1) )
        {
            if ( json_string.point ){
                response = asdUART_ConfigAPI( &json_string );
            }else{
                return -1;
            }
        }
        else if( strstr_bmh(uri,uri_len,"uart?",sizeof("uart?")-1) )
        {
            if ( json_string.point ){
                response = asdUART_WriteAPI( &json_string , &first_line , 1234 );
            }else{
                return -1;
            }
        }else if ( strstr_bmh(uri,uri_len,"gpio/config?",sizeof("gpio/config/")-1) )
        {
            if ( json_string.point ){
                response = asdGPIO_ConfigAPI( &json_string );
            }else{
                return -1;
            }
        }
        else if( strstr_bmh(uri,uri_len,"gpio?",sizeof("gpio?")-1) )
        {
            response = asdGPIO_WriteAPI( &json_string );
        }else
            response = asdResponse_400( nouri );

    }else{
        if( strstr_bmh(uri,uri_len,"uart?",sizeof("uart?")-1) )
        {
            response = asdUART_ReadAPI( &first_line , 0 );
            //        if( strstr_bmh(request,len,"GET /uart?wait=true",sizeof("GET /uart?wait=true")-1) == 0 )
            //            Api_closeSession(id);

        }else if( strstr_bmh(uri,uri_len,"gpio/",sizeof("gpio/")-1) ){

            response = asdGPIO_ReadAPI( &first_line );
        }else
            response = asdResponse_400( nouri );
    }
END:
#ifdef HTTP
    HTTPConnect_Write( https->socket_fd , response.point , response.length );
#else
    TLSConnect_Write( &https->conn , response.point , response.length );
#endif
    STRING_FreeString( &response );
    return 0;
}

int rs_connect(char **data, void *globol_context , void *local_context )
{
#define CONNECT2 "POST /connect2"
    Linkd *linkd_inst=(Linkd *)*data;
    logprintf("[%s] " CONNECT2 "\n",linkd_inst->relay_server);

    char *did = "b7e15a006ea42c4246486863a96a5589";
    char *http_buf=linkd_inst->https.http_buf;
    int http_buf_len=snprintf( http_buf , HTTP_REQUEST_MAXLEN ,
                               CONNECT2 " HTTP/1.1\r\n"\
                               "Host: %s\r\n"\
                               "Content-Type: application/json\r\n\r\n"\
                               "{\"p\":\"%s\",\"iv\":\"%s\"", linkd_inst->relay_server , linkd_inst->p , linkd_inst->iv );

    printHunk( (char *)http_buf , http_buf_len , LOGBUF_LENGTH );

    int ret;
    char *column = strchr(linkd_inst->relay_server,':');
    if (column) *column=0;

    bzero(&linkd_inst->https.fsm,sizeof(FSM));

    transition trans[]={
        {0, FUNCTION(HttpProcessData),    1,-1, ACCEPT },
        {-1}
    };

    bzero(&linkd_inst->https.fsm,sizeof(FSM));
    linkd_inst->https.trans = trans;

//    HttpContent relay;
//    bzero(&relay,sizeof(HttpContent));
//    linkd_inst->https.app_data = (void*)&relay;
#ifdef HTTP
    ret = HTTPConnect_SendReq(&linkd_inst->https ,
                              linkd_inst->relay_server ,
                              http_buf ,
                              http_buf_len ,
                              (char *)http_buf ,
                              HTTP_REQUEST_MAXLEN );
#else
    ret = TLSConnect_SendReq( &linkd_inst->https ,
                              linkd_inst->relay_server ,
                              http_buf ,
                              http_buf_len ,
                              (char *)http_buf ,
                              HTTP_REQUEST_MAXLEN );
#endif
    if (ret>=0)
        return 0;
    else
        return -1;
}

int supervisor(char **data, void *globol_context , void *local_context )
{
    return 0;
}

typedef enum{
 //   AGENT_BIND,
    SERIVCE_GET_RELAY,
    RS_CONNECT,
    RS_SUPERVISOR
}LinkdStatus;




void http_get_task(void *param)
{
    Linkd *linkd_inst;
    linkd_inst=malloc(sizeof(Linkd));
    bzero( linkd_inst , sizeof(Linkd) );

    if ( TLSConnect_Init( &linkd_inst->https.conn ) )
        halt("TLSConnect_Init\n");

//    linkd_inst->http_buf = malloc(HTTP_REQUEST_MAXLEN);
//    linkd_inst->conn=malloc(sizeof(TLSConnect));


const transition linkd_transition[] = {
//    {AGENT_BIND, FUNCTION(agent_bind),       AGENT_BIND,AGENT_BIND, ACCEPT },

//    {AGENT_BIND, FUNCTION(agent_bind),       SERIVCE_GET_RELAY,AGENT_BIND, ACCEPT },
    {SERIVCE_GET_RELAY, FUNCTION(get_relay), RS_CONNECT       ,RS_CONNECT, ACCEPT },
    {RS_CONNECT, FUNCTION(rs_connect),       RS_CONNECT       ,SERIVCE_GET_RELAY, ACCEPT },
   // {RS_SUPERVISOR, FUNCTION(supervisor),    RS_SUPERVISOR    ,SERIVCE_GET_RELAY, ACCEPT },
    {-1}
};

    run_fsm( &linkd_inst->fsm  , (transition*)linkd_transition , (char**)&linkd_inst , NULL , NULL, NULL);


#if defined TEST
    while(1){

#if 1
        int successes = 0, failures = 0;

        char *body = malloc(512);
        int body_len=getBingAgentBody(body,512);
        int http_buf_len=snprintf( http_buf , HTTP_REQUEST_MAXLEN ,
                                  "POST /agent/bind HTTP/1.1\r\n"\
                                  "Host: api.dch.dlink.com:443\r\n"\
                                  "Content-Type: application/x-www-form-urlencoded\r\n"\
                                  "Content-Length: %d\r\n\r\n%s" , body_len , body );
        free(body);

        logprintf("request_len=%d\n",http_buf_len);
#else
        strcpy(http_buf,"GET /ok.html HTTP/1.1\r\nHost: api.dch.dlink.com\r\n\r\n");
        int http_buf_len=strlen(http_buf);
#endif
        logprintf("heap=%u\n", xPortGetFreeHeapSize());

        int ret;
        ret = TLSConnect_SendReq( conn , http_buf , http_buf_len , (char *)http_buf , http_buf_len );

        logprintf("heap=%u\n", xPortGetFreeHeapSize());


        if(ret <= 0){
            failures++;
        } else {
            successes++;

            logprintf("++++request(%d bytes read)++++\n",ret);
            printHunk( (char*)http_buf , ret , LOGBUF_LENGTH );
        }

        logprintf("successes = %d failures = %d\n", successes, failures);
    }
#endif
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

    xTaskCreate(&http_get_task, (signed char *)"get_task", 1500 ,  NULL , 2, &xHandle );
}
