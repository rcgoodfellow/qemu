#include "hw/ipmi/lan.h"
#include "qemu/log.h"
  
uint8_t*
check_ipmi_packet(const uint8_t *buf, size_t *len, request_callback *cb)
{
  qemu_log("ipmi-lan not implemented :/\n");
  return NULL;
}
