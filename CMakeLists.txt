cmake_minimum_required(VERSION 3.16)

set(_project_name deauth)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

project(${_project_name} C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

set(THREADS_PREFER_PTHREAD_FLAG ON)

find_package(Threads REQUIRED)
link_libraries(Threads::Threads)

find_package ( LibNL REQUIRED )
include_directories(${LibNL_INCLUDE_DIR})
link_libraries (${LibNL_LIBRARIES})

find_library(LibTins_LIBRARY NAMES tins)
if (LibTins_LIBRARY)
    message("Found libtins libraries: ${LibTins_LIBRARY}")
else (LibTins_LIBRARY)
    message(FATAL_ERROR "Libtins not found")
endif (LibTins_LIBRARY)
link_libraries (${LibTins_LIBRARY})

find_library(PCAP_LIBRARY NAMES pcap)
if (PCAP_LIBRARY)
    message("Found pcap libraries: ${PCAP_LIBRARY}")
else (PCAP_LIBRARY)
    message(FATAL_ERROR "pcap not found")
endif (PCAP_LIBRARY)
link_libraries (${PCAP_LIBRARY})

find_library(YAML_CPP_LIBRARY NAMES yaml-cpp)
if (YAML_CPP_LIBRARY)
    message("Found yaml-cpp libraries: ${YAML_CPP_LIBRARY}")
else (YAML_CPP_LIBRARY)
    message(FATAL_ERROR "yaml-cpp not found")
endif (YAML_CPP_LIBRARY)
link_libraries(${YAML_CPP_LIBRARY})

include_directories("${CMAKE_SOURCE_DIR}/include")

add_executable (deauth src/deauth.cpp src/80211Wrapper.cpp)
add_executable (emp src/emp.cpp src/80211Wrapper.cpp)
