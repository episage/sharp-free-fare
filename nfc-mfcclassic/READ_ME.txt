//command mingw64 to compile mifare dll 64 bits

MAIN_FILE=mifare
LIBNFC=libnfc
CFLAGS=`pkg-config --cflags ${LIBNFC}`
CFLAGS_LIBNFC=`pkg-config --cflags libnfc | cut -d ' ' -f 1`/${LIBNFC}
 
x86_64-w64-mingw32-gcc -shared -Wl,--allow-multiple-definition ./${MAIN_FILE}.c ./libnfc.lib ${CFLAGS} ${CFLAGS_LIBNFC} -o ./${MAIN_FILE}_x64.dll