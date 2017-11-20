
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
#include "asdConfig.h"
#include "asdState.h"
#include "version.h"

//#include "rboot-bigflash.c"

void user_init(void)
{
    uart_set_baud(0, 115200);

    printf("gitver=%s\n",SRC_VERSION);

    Config_Init();
    setLogLevel(atoi(Config_getLog())); //boot
    Platform_PrintHeap("booting");

    xTaskCreate(&astraClient, "astraClient", 1200, NULL, 1, NULL);
}
