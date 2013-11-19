#pragma once
#include <pcap/pcap.h>

#include <array>
#include <stdexcept>
#include <string>

namespace libpcap {
using pcap_error_buffer = std::array<char, PCAP_ERRBUF_SIZE>;
struct pcap_error : public std::runtime_error {
  pcap_error(const std::string &msg);
  pcap_error(pcap_t *source);
};

struct pcap_already_activated_error : public pcap_error {
  pcap_already_activated_error(pcap_t *source);
};

std::string error_string(const pcap_error_buffer &error_buffer);
std::string error_string(pcap_t *source);
std::string warning_string(pcap_t *source);
}
