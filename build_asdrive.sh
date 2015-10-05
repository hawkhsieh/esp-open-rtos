rsync -av --exclude=".git" --exclude="asdrive/soc" --exclude="asdrive/wolfssl" ../../../../asdrive ./extras/asdrive
make -C ./demo_asdrive V=1
