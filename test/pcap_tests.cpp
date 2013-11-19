#include "gtest/gtest.h"
#include <pcap_cpp/pcap.hpp>

namespace pcap_tests {

TEST(pcap_tests, create_test) {
  auto device = libpcap::create("en0");
  EXPECT_TRUE(device);
}

} //namespace test_vector
