#pragma once
#include <pcap/pcap.h>
#include <string>
namespace libpcap {

std::string qtos(const bpf_u_int32 q);

}
