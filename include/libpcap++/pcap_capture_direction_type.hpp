#pragma once
#include <pcap/pcap.h>

namespace libpcap {
enum class capture_direction {
  received = PCAP_D_IN, sent = PCAP_D_OUT, both = PCAP_D_INOUT
};
}
