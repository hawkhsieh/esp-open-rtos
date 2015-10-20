rsync -av --exclude=".git" --exclude="SocketToRelay/soc/esp8266/esp-open-rtos" --exclude="SocketToRelay/soc/esp8266/esp-open-sdk" --exclude="SocketToRelay/wolfssl" ../../../../ ./extras/asdrive/asdrive
sudo PATH=$PATH make flash -j4 -C ./examples/demo_asdrive ESPPORT=/dev/ttyUSB0
#make -C ./demo_asdrive V=1
make -C ./demo_asdrive $1
