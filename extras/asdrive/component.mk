# args for passing into compile rule generation
asdrive_MAIN = $(asdrive_ROOT)asdrive

INC_DIRS +=$(asdrive_MAIN)/fsm/src/
INC_DIRS +=$(asdrive_MAIN)/jsmn/
INC_DIRS +=$(asdrive_MAIN)/SocketToRelay/
INC_DIRS +=$(asdrive_MAIN)/SocketToRelay/ev
INC_DIRS +=$(asdrive_MAIN)/SocketToRelay/linkd
INC_DIRS +=$(asdrive_MAIN)/SocketToRelay/string_utility
INC_DIRS +=$(asdrive_MAIN)/SocketToRelay/system
INC_DIRS +=$(asdrive_MAIN)/SocketToRelay/ssl
INC_DIRS +=$(asdrive_MAIN)/SocketToRelay/log_control
INC_DIRS +=$(asdrive_MAIN)/SocketToRelay/http_parser
INC_DIRS +=$(asdrive_MAIN)/SocketToRelay/md5encrypt
INC_DIRS +=$(asdrive_MAIN)/SocketToRelay/network
INC_DIRS +=$(asdrive_MAIN)/SocketToRelay/api
INC_DIRS +=$(asdrive_MAIN)/SocketToRelay/web_api
INC_DIRS +=$(asdrive_MAIN)/SocketToRelay/config
INC_DIRS +=$(asdrive_MAIN)/SocketToRelay/aes_encrypt
INC_DIRS +=$(asdrive_MAIN)/SocketToRelay/relayd/client

#asdrive_SRC_FILES += $(asdrive_MAIN)/asdJson.o
#asdrive_SRC_FILES += $(asdrive_MAIN)/asdUART.o
#asdrive_SRC_FILES += $(asdrive_MAIN)/asdResponse.o
#asdrive_SRC_FILES += $(asdrive_MAIN)/fsm/src/fsm.o
#asdrive_SRC_FILES += $(asdrive_MAIN)/jsmn/jsmn.o
#asdrive_SRC_FILES += $(asdrive_MAIN)/log.o
#asdrive_SRC_FILES += $(asdrive_MAIN)/json.o
#asdrive_SRC_FILES += $(asdrive_MAIN)/buf.o
#asdrive_SRC_FILES += $(asdrive_MAIN)/rs232.o
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/config/config.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/ev/ev_action.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/ev/ev_init.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/http_parser/http_parser.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/linkd/linkd_timer.c
#asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/linkd/linkd_session.o
#asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/linkd/linkd_linear_buf.o
#asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/linkd/linkd_io.o
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/linkd/linkd.c
#asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/linkd/linkd_config.o
#asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/linkd/linkd_file.o
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/md5encrypt/base64.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/network/network_link.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/relayd/client/rly_client.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/relayd/client/rly_ctrl.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/string_utility/string_utility.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/system/allocMonitor.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/system/array.c
#asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/system/system_utility.o
#asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/web_api/web_api.o
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/log_control/log_control.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/ssl/ssl_connect.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/aes_encrypt/aes_encrypt.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/api/out_api.c
#asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/web_api/start_link.o

asdrive_CFLAGS += -D__ESP8266__ -DLWIP_IPV4 -DLWIP_IPV6 -DNO_shm $(CFLAGS)

$(eval $(call component_compile_rules,asdrive))
