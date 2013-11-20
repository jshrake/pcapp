#include <pcap_cpp/utility.hpp>

namespace libpcap {
std::string qtos(const bpf_u_int32 q) {
  const auto one = q & 0xff;
  const auto two = (q >> 8) & 0xff;
  const auto three = (q >> 16) & 0xff;
  const auto four = (q >> 24) & 0xff;
  return std::to_string(one) + "." + std::to_string(two) + "." +
         std::to_string(three) + "." + std::to_string(four);
}
}
