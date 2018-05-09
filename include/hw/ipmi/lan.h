#pragma once
#include "qemu/osdep.h"
#include "net/eth.h"
#include "net/net.h"

#define IPMI_UDP_PORT 623
#define IPMI_RING_SIZE 3
#define PACKED __attribute__ ((__packed__))

/*-----------------------------------------------------------------------------
 *
 * ipmi packet structures
 *
 *---------------------------------------------------------------------------*/

/* 
 * rcmp
 */
struct rcmp_hdr {
  uint8_t version,
          reserved,
          sequence,
          class;
} PACKED;


/*
 * ipmi 1.5
 */
struct ipmi_15_hdr {
  uint8_t   auth_format;
  uint32_t  session_id,
            session_seq;
  uint8_t   payload_len;
} PACKED;

struct ipmi_15_footer {
  uint8_t   pad_length,
            next_hdr;
} PACKED;

struct ipmi_15_pkt {
  struct ipmi_15_hdr     header;
  uint8_t                *payload;
  struct ipmi_15_footer  footer;
} PACKED;

struct ipmi_15_full_pkt {
  struct eth_header   eth;
  struct ip_header    ip;
  struct udp_header   udp;
  struct rcmp_hdr     rcmp;
  struct ipmi_15_pkt  ipmi;
} PACKED;

#define IPMI_15_PKT()    \
  {                      \
    .header = {0,0,0,0}, \
    .payload = NULL,     \
    .footer = {0,0}      \
  };


/* 
 * ipmi 2.0 
 */
struct ipmi_20_hdr {
  uint8_t   auth_format,
            payload_type;
  uint32_t  session_id,
            session_seq;
  uint8_t   payload_len;
} PACKED;

/*
 *  ipmi request
 */
struct ipmi_request_hdr {
  uint8_t rsaddr,
          netfn_rsl,
          checksum,
          rqaddr,
          seq_rql,
          cmd;
} PACKED;

struct ipmi_request_footer {
  uint8_t checksum;
} PACKED;

struct ipmi_request {
  struct ipmi_request_hdr     hdr;
  uint8_t                     *payload;
  struct ipmi_request_footer  footer;
} PACKED;

/*
 *  ipmi response
 */

struct ipmi_response_hdr {
  uint8_t rqaddr,
          netfn_rql,
          checksum,
          rsaddr,
          seq_rsl,
          cmd;
} PACKED;

struct ipmi_response_footer {
  uint8_t checksum;
} PACKED;

struct ipmi_response {
  struct ipmi_response_hdr      hdr;
  uint8_t                       *payload;
  struct ipmi_response_footer   footer;
} PACKED;

/*
 *  impi network functions
 */
enum {
  IPMI_CHASSIS_REQUEST,
  IPMI_CHASSIS_RESPONSE,
  IPMI_BRIDGE_REQUEST,
  IPMI_BRIDGE_RESPONSE,
  IPMI_SENSOR_EVENT_REQUEST,
  IPMI_SENSOR_EVENT_RESPONSE,
  IPMI_APP_REQUEST,
  IPMI_APP_RESPONSE,
  IPMI_FIRMWARE_REQUEST,
  IPMI_FIRMWARE_RESPONSE,
  IPMI_STORAGE_REQUEST,
  IPMI_STORAGE_RESPONSE,
  IPMI_TRANSPORT_REQUEST,
  IPMI_TRANSPORT_RESPONSE,
};

/*-----------------------------------------------------------------------------
 *
 * ipmi command structures
 *
 *---------------------------------------------------------------------------*/

/*
 *  app:get_channel_auth
 */
#define IPMI_APP_GET_AUTH 0x38

struct channel_auth_req {
  uint8_t channel_number,
          max_priv_lvl;
} PACKED;

struct ipmi_channel_auth_capabilities {
  uint8_t channel_number,
          auth_support,
          status,
          extended,
          oem_id,
          oem_aux;
} PACKED;

struct ipmi_get_auth_response {
  struct ipmi_response_hdr                hdr;
  uint8_t                                 completion_code;
  struct ipmi_channel_auth_capabilities   data;
  uint8_t                                 checksum;
} PACKED;

uint8_t *check_ipmi_packet(const uint8_t *buf, size_t *len);
void ipmi_15_free_full_pkt(struct ipmi_15_full_pkt *);
static inline int ipmi_15_fp_len(const struct ipmi_15_full_pkt *pkt) {
  return ntohs(pkt->ip.ip_len) + sizeof(struct eth_header);
}

/*
 *  chassis
 */
enum {
  IPMI_CHASSIS_CAPABILITIES,
  IPMI_CHASSIS_STATUS,
  IPMI_CHASSIS_CONTROL
};

enum {
  IPMI_POWER_DOWN,
  IPMI_POWER_UP,
  IPMI_POWER_CYCLE,
  IPMI_HARD_RESET,
  IPMI_PULSE_DIAG,
  IPMI_SOFT_ACPI_SHUTDOWN,
};
