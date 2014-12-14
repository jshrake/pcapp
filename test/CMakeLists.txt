set(PROJECT_TEST_NAME "${PROJECT_NAME}-test")
set(PCAP_TEST_TARGET "ctest")
add_custom_target(${PCAP_TEST_TARGET}
  COMMAND "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_TEST_NAME}"
COMMENT "Running unit tests with Google Test Framework" VERBATIM)
include_directories(${PROJECT_SOURCE_DIR}/dep/googletest/include ${PROJECT_SOURCE_DIR}/include)

set(SRCFILES
  pcap_tests.cpp
  device_tests.cpp
  )

add_executable(${PROJECT_TEST_NAME} ${SRCFILES})
target_link_libraries(${PROJECT_TEST_NAME} gtest gtest_main pcap)
add_test(${PROJECT_TEST_NAME} ${PROJECT_TEST_NAME})
add_dependencies(${PCAP_TEST_TARGET} ${PROJECT_TEST_NAME})