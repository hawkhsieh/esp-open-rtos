
#include "espressif/esp_common.h"
#include "esp/uart.h"

#include <string.h>

#include <FreeRTOS.h>
#include <task.h>
#include <ssid_config.h>

#include <espressif/esp_sta.h>
#include <espressif/esp_wifi.h>

#include <semphr.h>

#include "asdrive.h"
#include "asdLog.h"
#include "platform.h"

void user_init(void)
{
    uart_set_baud(0, 115200);
    printf("SDK version:%s\n", sdk_system_get_sdk_version());

    Platform_Init();

    Platform_PrintHeap("booting");

    xTaskCreate(&astraLenServ, (int8_t *)"astraLenServ", 400 , NULL, 1, NULL);
    xTaskCreate(&astraClient, (int8_t *)"astraClient", 1000, NULL, 1, NULL);
}
