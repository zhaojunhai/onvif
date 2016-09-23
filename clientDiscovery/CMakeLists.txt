cmake_minimum_required(VERSION 3.0)

project (ONVIF_CLIENT_DISCOVERY)

ADD_DEFINITIONS(-g)
INCLUDE_DIRECTORIES(/usr/share/gsoap/import/)
add_executable(client clientDiscovery.cpp soapC.cpp soapClient.cpp)
TARGET_LINK_LIBRARIES(client gsoap++)
