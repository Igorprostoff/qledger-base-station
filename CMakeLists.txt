cmake_minimum_required(VERSION 3.7)

# set the project name
project(QServer)
include(Findpigpio.cmake)
find_package(pigpio REQUIRED)
# This command attempts to find the library, REQUIRED argument is optional
find_package(PostgreSQL REQUIRED)

include_directories(./include ${pigpio_INCLUDE_DIR} ${pigpio_INCLUDE_DIRS}) 
# add the executable

add_executable(QServer
    main.c
    mymap.h
    block.h
    configparse.h
    include/lora/LoRa.c
    include/lora/LoRa.h
)


target_link_libraries(QServer m ${pigpio_LIBRARY} ${pigpiod_if_LIBRARY} ${pigpio_LIBS} ${pigpiod_if2_LIBRARY} ${PostgreSQL_LIBRARIES} pigpio pthread -lmysqlclient -lmbedtls -lmbedx509 -lmbedcrypto)
add_compile_options(-I/usr/include/mysql -L/usr/lib64/mysql -lmysqlclient -Wall -fpic -lpigpio -lrt -pthread -lm -lmbedtls -lmbedx509 -lmbedcrypto)
