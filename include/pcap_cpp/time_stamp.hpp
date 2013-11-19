#pragma once
#include <pcap/pcap.h>

namespace libpcap {
enum class time_stamp_type {
  host = PCAP_TSTAMP_HOST, host_low_prec = PCAP_TSTAMP_HOST_LOWPREC,
  host_high_prec = PCAP_TSTAMP_HOST_HIPREC, adapter = PCAP_TSTAMP_ADAPTER,
  adapter_unsynced = PCAP_TSTAMP_ADAPTER_UNSYNCED
};
}
