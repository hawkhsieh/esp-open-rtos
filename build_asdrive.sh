rsync -av --exclude=".git" --exclude="SocketToRelay/soc/esp8266/esp-open-rtos" --exclude="SocketToRelay/soc/esp8266/esp-open-sdk" --exclude="SocketToRelay/wolfssl" ../../../../ ./extras/asdrive/asdrive
#make -C ./demo_asdrive V=1
make -C ./demo_asdrive $1
