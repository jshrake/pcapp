#pragma once
#include <pcap/pcap.h>
#include <string>

namespace libpcap {
class filter_program {
public:
  filter_program() = default;
  filter_program(pcap_t *device, const std::string expression,
                 const bool optimize, const bpf_u_int32 ip);
  ~filter_program();
  filter_program(const filter_program &program);
  filter_program(filter_program &&program);
  filter_program &operator=(const filter_program &program);
  filter_program &operator=(filter_program &&program);
  void swap(filter_program &other);
  const std::string &expression() { return expression_; }
  bpf_program *get() const { return program_; }

private:
  pcap_t *device_ = nullptr;
  std::string expression_{};
  bool optimize_{};
  bpf_u_int32 ip_{};
  bpf_program *program_ = nullptr;
};

}
