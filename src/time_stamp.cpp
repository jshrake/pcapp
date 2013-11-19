#include <pcap_cpp/time_stamp.hpp>
#include <iostream>
namespace libpcap {
std::ostream &operator<<(std::ostream &os, const time_stamp &tstamp) {
  os << pcap_tstamp_type_val_to_name(static_cast<int>(tstamp));
  return os;
}
}