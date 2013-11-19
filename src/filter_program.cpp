#include <libpcap++/pcap_filter_program.hpp>
#include <libpcap++/pcap.hpp>

namespace libpcap {
filter_program::filter_program(pcap_t *device, const std::string expression,
                               const bool optimize, const bpf_u_int32 ip)
: device_{device}, expression_{expression}, optimize_{optimize}, ip_{ip} {
  program_ = libpcap::compile_filter(device, expression, optimize, ip);
}

filter_program::filter_program(const filter_program &program)
  : filter_program{program.device_, program.expression_, program.optimize_, program.ip_} {
}

filter_program::filter_program(filter_program &&program)
    : device_{ program.device_ }, expression_{ std::move(program.expression_) },
      optimize_{ program.optimize_ }, ip_{ program.ip_ },
      program_{ program.program_ } {
  program.program_ = nullptr;
}

filter_program &filter_program::operator=(const filter_program &program) {
  filter_program tmp{program};
  swap(tmp);
  return *this;
}

filter_program &filter_program::operator=(filter_program &&program) {
  filter_program tmp{std::move(program)};
  swap(tmp);
  return *this;
}

filter_program::~filter_program() {
  if (program_) {
    pcap_freecode(program_);
  }
}

void filter_program::swap(filter_program &other) {
  using std::swap;
  swap(device_, other.device_);
  swap(expression_, other.expression_);
  swap(optimize_, other.optimize_);
  swap(ip_, other.ip_);
  swap(program_, other.program_);
}

}
