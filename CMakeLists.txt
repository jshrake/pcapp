cmake_minimum_required(VERSION 2.8.8)

project(pcapp)
#Add the project's cmake directory to the module path


# Build all project dependencies
add_subdirectory(dep)

#compiler settings for project
set(CMAKE_CXX_FLAGS "-Wall -Werror -Wextra -std=c++11 -stdlib=libc++ ${CMAKE_CXX_FLAGS}")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_DEBUG} -g -O0 -DGL_DEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_RELEASE} -O3")

# Testing with the Google Test framework
enable_testing()
add_subdirectory(test)

#Documentation generation with Doxygen
find_package(Doxygen)
if (DOXYGEN_FOUND)
	set(DOXYGEN_TARGET "doc")
	add_custom_target(${DOXYGEN_TARGET}
	COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_SOURCE_DIR}/doc/Doxyfile
	COMMENT "Generating API Documentation with Doxygen" VERBATIM)
endif()
