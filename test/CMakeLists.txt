include_directories(${CMAKE_SOURCE_DIR}/dep/googletest/include ${CMAKE_SOURCE_DIR}/include)
link_directories(${CMAKE_SOURCE_DIR}/dep/libpcap ${CMAKE_SOURCE_DIR}/lib)

set(SRCFILES
  pcap_tests.cpp
  )

add_executable(${PROJECT_TEST_NAME} ${SRCFILES})
target_link_libraries(${PROJECT_TEST_NAME} gtest gtest_main pcap ${PROJECT_NAME})
add_test(${PROJECT_TEST_NAME} ${PROJECT_TEST_NAME})
add_dependencies(${GTEST_TARGET} ${PROJECT_TEST_NAME})
