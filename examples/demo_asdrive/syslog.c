/* Very basic example that just demonstrates we can run at all!
 */
#include "espressif/esp_common.h"
#include "espressif/sdk_private.h"
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"

#include <lwip/sockets.h>
#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "string.h"
#include "syslog.h"

Syslog *syslogInst;

int SyslogSend( char *data , int size )
{
    int ret;
    ret = sendto(syslogInst->socket, data , size,0,(struct sockaddr *)&syslogInst->servaddr,sizeof(struct sockaddr_in));
    if ( ret < 0 ){
        locprintf( "sendto failed\n");
    }

    return ret;
}

Syslog *SyslogDial( char *ip , int port )
{
    int sockfd;
    syslogInst = (Syslog *)malloc(sizeof(Syslog));
    if (syslogInst==0){
        locprintf( "malloc failed\n");
        return 0;
    }
    memset(syslogInst,0,sizeof(Syslog));
    sockfd=socket(AF_INET,SOCK_DGRAM,0);

    syslogInst->socket = sockfd;
    syslogInst->servaddr.sin_family = AF_INET;
    syslogInst->servaddr.sin_addr.s_addr=inet_addr(ip);
    syslogInst->servaddr.sin_port=htons(port);
    syslogInst->port = port;
    strcpy( syslogInst->ip , ip );

    return syslogInst;
}


#if 0

void task1(void *pvParameters)
{
    int count=0;
    char sendline[20];

    while(1) {
        sprintf( sendline , "Hello[%d]\n",count++ );
        logprintf( "%s" , sendline);
        vTaskDelay(1000 / portTICK_RATE_MS);
    }
}

void task2(void *pvParameters)
{
    printf("Hello from task 2!\r\n");
    xQueueHandle *queue = (xQueueHandle *)pvParameters;
    while(1) {
        uint32_t count;
        if(xQueueReceive(*queue, &count, 1000)) {
            printf("Got %lu\n", count);
        } else {
            printf("No msg :(\n");
        }
    }
}

static xQueueHandle mainqueue;

void user_init(void)
{
    syslogInst = SyslogDial("54.169.15.38",514);
    uart_init( BIT_RATE_115200 , BIT_RATE_115200 );
    printf("SDK version:%s\n", sdk_system_get_sdk_version());

    struct sdk_station_config config = {
        .ssid = "hawknetgear",
        .password = "53345405"
    };

    /* required to call wifi_set_opmode before station_set_config */
    sdk_wifi_set_opmode(STATION_MODE);
    sdk_wifi_station_set_config(&config);

//    mainqueue = xQueueCreate(10, sizeof(uint32_t));
    xTaskCreate(task1, (signed char *)"tsk1", 1024, &mainqueue, 2, NULL);
//    xTaskCreate(task2, (signed char *)"tsk2", 256, &mainqueue, 2, NULL);
}
#endif
