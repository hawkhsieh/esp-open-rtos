# args for passing into compile rule generation
asdrive_MAIN = $(asdrive_ROOT)src

asdrive_INC_DIR = $(asdrive_MAIN) $(asdrive_MAIN)/fsm/src/ $(asdrive_MAIN)/jsmn/ $(asdrive_MAIN)/SocketToRelay/ $(asdrive_MAIN)/SocketToRelay/ev $(asdrive_MAIN)/SocketToRelay/linkd $(asdrive_MAIN)/SocketToRelay/string_utility $(asdrive_MAIN)/SocketToRelay/system $(asdrive_MAIN)/SocketToRelay/ssl $(asdrive_MAIN)/SocketToRelay/log_control $(asdrive_MAIN)/SocketToRelay/http_parser $(asdrive_MAIN)/SocketToRelay/md5encrypt $(asdrive_MAIN)/SocketToRelay/api $(asdrive_MAIN)/SocketToRelay/web_api $(asdrive_MAIN)/SocketToRelay/config $(asdrive_MAIN)/SocketToRelay/aes_encrypt

asdrive_SRC_FILES = $(asdrive_MAIN)/asdUART.c
asdrive_SRC_FILES += $(asdrive_MAIN)/asdJson.c
asdrive_SRC_FILES += $(asdrive_MAIN)/asdResponse.c
asdrive_SRC_FILES += $(asdrive_MAIN)/fsm/src/fsm.c
asdrive_SRC_FILES += $(asdrive_MAIN)/jsmn/jsmn.c
asdrive_SRC_FILES += $(asdrive_MAIN)/log.c
asdrive_SRC_FILES += $(asdrive_MAIN)/json.c
asdrive_SRC_FILES += $(asdrive_MAIN)/buf.c
asdrive_SRC_FILES += $(asdrive_MAIN)/rs232.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/config/config.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/ev/ev_action.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/ev/ev_init.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/http_parser/http_parser.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/linkd/linkd_timer.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/linkd/linkd_session.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/linkd/linkd_linear_buf.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/linkd/linkd_io.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/linkd/linkd_config.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/linkd/linkd.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/linkd/linkd_file.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/md5encrypt/base64.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/network/network_link.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/relayd/client/rly_client.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/relayd/client/rly_ctrl.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/string_utility/string_utility.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/system/allocMonitor.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/system/array.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/system/system_utility.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/web_api/web_api.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/log_control/log_control.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/ssl/ssl_connect.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/aes_encrypt/aes_encrypt.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/api/out_api.c
asdrive_SRC_FILES += $(asdrive_MAIN)/SocketToRelay/web_api/start_link.c

asdrive_CFLAGS = $(CFLAGS) -D__ESP8266__

$(eval $(call component_compile_rules,asdrive))
