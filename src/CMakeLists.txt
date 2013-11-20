# Set up include directories
set(PROJ_INCLUDES "${CMAKE_SOURCE_DIR}/include")
set(PROJ_DEPS "${CMAKE_SOURCE_DIR}/dep")
#set(Boost_USE_STATIC_LIBS ON)
#find_package(Boost 1.54 REQUIRED COMPONENTS program_options filesystem)
#include_directories(${PROJ_INCLUDES} ${Boost_INCLUDE_DIR})

#ext
include_directories(${PROJ_INCLUDES} ${PROJ_DEPS})

# List of source files for compilation
set(SOURCES pcap.cpp
            device.cpp
            error.cpp
            pcap_types.cpp
            utility.cpp)

# Binary output directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY  "${CMAKE_SOURCE_DIR}/lib")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG  "${CMAKE_SOURCE_DIR}/lib/debug")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE  "${CMAKE_SOURCE_DIR}/lib/release")


add_library (core OBJECT ${SOURCES})
add_library (${PROJECT_NAME} STATIC $<TARGET_OBJECTS:core>)
