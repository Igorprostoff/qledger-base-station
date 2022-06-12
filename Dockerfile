FROM raspbian/stretch:latest
RUN apt update && apt install -y pigpio && apt install -y default-libmysqlclient-dev && apt install -y sudo && apt install -y cmake && apt install -y libmbedtls-dev && apt install -y g++ && apt install -y libmbedtls10 && apt install -y libpq-dev && apt install -y postgresql-server-dev-all
RUN mkdir /project
RUN mkdir /project/include
ADD ./include /project/include
ADD ./*.h /project/
ADD ./*.c /project/
ADD ./Makefile /project/Makefile
ADD ./CMakeLists.txt /project/CMakeLists.txt
ADD ./config_file /project/config_file
WORKDIR /project
ADD ./Findpigpio.cmake /project/Findpigpio.cmake
ADD ./Findpigpio.cmake /usr/share/cmake-3.7/Modules/Findpigpio.cmake
RUN ls /usr/include/postgresql/
RUN cmake CMakeLists.txt && make
USER root
ENTRYPOINT ["/project/QServer" ]