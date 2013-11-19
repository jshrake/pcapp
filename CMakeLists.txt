cmake_minimum_required(VERSION 2.8.8)

project(pcap_cpp)
#Add the project's cmake directory to the module path


# Build all project dependencies
add_subdirectory(dep)

#compiler settings for project
set(CMAKE_CXX_FLAGS "-Wall -Werror -Wextra -std=c++11 -stdlib=libc++ ${CMAKE_CXX_FLAGS}")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_DEBUG} -g -O0 -DGL_DEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_RELEASE} -O5")

# Build the project executable
add_subdirectory(src)

# Testing with the Google Test framework
enable_testing()
set(GTEST_TARGET "test_pcap")
set(PROJECT_TEST_NAME "test_${CMAKE_PROJECT_NAME}")
add_custom_target(${GTEST_TARGET} 
  COMMAND "${CMAKE_CURRENT_BINARY_DIR}/test/${PROJECT_TEST_NAME}"
COMMENT "Running unit tests with Google Test Framework" VERBATIM)
add_subdirectory(test)

#Documentation generation with Doxygen
find_package(Doxygen)
if (DOXYGEN_FOUND)
	set(DOXYGEN_TARGET "doc")
	add_custom_target(${DOXYGEN_TARGET}
	COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_SOURCE_DIR}/doc/Doxyfile
	COMMENT "Generating API Documentation with Doxygen" VERBATIM)
endif()	
