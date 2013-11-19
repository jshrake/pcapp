#include <libpcap++/pcap_error.hpp>

namespace libpcap {

pcap_error::pcap_error(const std::string &msg) : std::runtime_error{ msg } {}

pcap_error::pcap_error(pcap_t *source)
    : pcap_error{ error_string(source) } {}

pcap_already_activated_error::pcap_already_activated_error(pcap_t *source)
    : pcap_error{ "Capture source already activated\n" +
                  error_string(source) } {}

std::string error_string(const pcap_error_buffer &error_buffer) {
  return "pcap error: " +
         std::string{ error_buffer.cbegin(), error_buffer.cend() }
  +"\n";
}

std::string error_string(pcap_t *source) {
  return std::string{ "pcap error: " }
  +pcap_geterr(source) + "\n";
}

std::string warning_string(pcap_t *source) {
  return std::string{ "pcap warning: " }
  +pcap_geterr(source) + "\n";
}

}
