#pragma once
#include <pcap/pcap.h>
#include <iosfwd>
#include <memory>
#include <vector>

namespace libpcap {

using unique_pcap_t = std::unique_ptr<pcap_t, decltype(&pcap_close)>;
using unique_bpf_program = std::unique_ptr<bpf_program, decltype(&pcap_freecode)>;

enum class time_stamp {
  host = PCAP_TSTAMP_HOST, host_low_prec = PCAP_TSTAMP_HOST_LOWPREC,
  host_high_prec = PCAP_TSTAMP_HOST_HIPREC, adapter = PCAP_TSTAMP_ADAPTER,
  adapter_unsynced = PCAP_TSTAMP_ADAPTER_UNSYNCED
};

enum class capture_direction {
  received = PCAP_D_IN, sent = PCAP_D_OUT, both = PCAP_D_INOUT
};

std::ostream &operator<<(std::ostream &os, const time_stamp &tstamp); 
}

