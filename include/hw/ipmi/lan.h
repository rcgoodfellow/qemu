#pragma once
#include "qemu/osdep.h"
#include "net/eth.h"
#include "net/net.h"

#define IPMI_UDP_PORT 623
#define IPMI_RING_SIZE 3
#define PACKED __attribute__ ((__packed__))
#define UNUSED(x) (void)x;

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
  //0x0E - 0x2B RESERVED
  IPMI_GROUP_EXTENSION_REQUEST = 0x2C,
  IPMI_GROUP_EXTENSION_RESPONSE,
  IPMI_OEM_GROUP_REQUEST,
  IPMI_OEM_GROUP_RESPONSE,
  IPMI_CONTROLLER_SPECIFIC_OEM_GROUP_REQUEST,
  IPMI_CONTROLLER_SPECIFIC_OEM_GROUP_RESPONSE
};

/*
 *  chassis enums
 */
enum {
  IPMI_CHASSIS_CAPABILITIES,
  IPMI_CHASSIS_STATUS,
  IPMI_CHASSIS_CONTROL
};

/*
 *  power control enums
 */
enum {
  IPMI_POWER_DOWN,
  IPMI_POWER_UP,
  IPMI_POWER_CYCLE,
  IPMI_HARD_RESET,
  IPMI_PULSE_DIAG,
  IPMI_SOFT_ACPI_SHUTDOWN,
};

/*-----------------------------------------------------------------------------
 *
 * ipmi command structures
 *
 *---------------------------------------------------------------------------*/
#define IPMI_CMD_RESPONSE(datatype)       \
struct datatype##_response {              \
  struct ipmi_response_hdr hdr;           \
  uint8_t completion_code;                \
  struct datatype data;                   \
  uint8_t checksum;                       \
} PACKED;

struct ipmi_basic_cmd_response {
  struct ipmi_response_hdr hdr;
  uint8_t completion_code;
  uint8_t checksum;
} PACKED;

/*
 *  app:get_channel_auth
 */
#define IPMI_APP_GET_AUTH 0x38

struct ipmi_channel_auth_req {
  uint8_t channel_number,
          max_priv_lvl;
} PACKED;

struct ipmi_get_auth {
  uint8_t channel_number,
          auth_support,
          status,
          extended,
          oem_id,
          oem_aux;
} PACKED;

IPMI_CMD_RESPONSE(ipmi_get_auth);

/*
 *  app:get_session_challenge
 */
#define IPMI_APP_GET_SESSION_CHALLENGE 0x39

struct ipmi_session_challenge_req {
  uint8_t authtype;
  uint8_t username[16];
} PACKED;

struct ipmi_session_challenge {
  uint32_t session_id;
  uint8_t challenge[16];
}PACKED;

IPMI_CMD_RESPONSE(ipmi_session_challenge);

/*
 *  app:activate_session
 */
#define IPMI_APP_ACTIVATE_SESSION 0x3A

struct ipmi_session_activate_req {
  uint8_t authtype,
          max_priv_lvl,
          challenge[16];
  uint32_t seq;
} PACKED;

struct ipmi_session_activate {
  uint8_t authtype;
  uint32_t session_id,
           seq;
  uint8_t max_priv_lvl;
} PACKED;

IPMI_CMD_RESPONSE(ipmi_session_activate);

/*
 *  app:set_session_priv_lvl
 */
#define IPMI_APP_SET_SESSION_PRIV_LVL 0x3B

struct ipmi_set_session_priv_lvl_req {
  uint8_t req_priv_lvl;
} PACKED;

struct ipmi_set_session_priv_lvl {
  uint8_t new_priv_lvl;
} PACKED;

IPMI_CMD_RESPONSE(ipmi_set_session_priv_lvl);

/*
 *  app:get_device_id
 */
#define IPMI_APP_GET_DEVICE_ID 0x01

struct ipmi_get_device_id {
  uint8_t device_id,
          device_revision,
          firmware_revision_major,
          firmware_revision_minor,
          additional_device_support,
          manufacturer_id[3];
  uint16_t product_id;
} PACKED;

IPMI_CMD_RESPONSE(ipmi_get_device_id);

/*
 *  app:close_session
 */
#define IPMI_APP_CLOSE_SESSION 0x3C

struct ipmi_close_session_req {
  uint32_t session_id;
} PACKED;


/*
 *  chassis:get_status
 */

struct ipmi_get_chassis_status {
  uint8_t current_power_state,
          last_power_event,
          misc_chassis_state;
} PACKED;

IPMI_CMD_RESPONSE(ipmi_get_chassis_status);


/*-----------------------------------------------------------------------------
 *
 * helper functions
 *
 *---------------------------------------------------------------------------*/

typedef void (*request_callback)(void);

uint8_t *check_ipmi_packet(const uint8_t *buf, size_t *len, 
    request_callback *cb);
void ipmi_15_free_full_pkt(struct ipmi_15_full_pkt *);
static inline int ipmi_15_fp_len(const struct ipmi_15_full_pkt *pkt) {
  return ntohs(pkt->ip.ip_len) + sizeof(struct eth_header);
}

void do_cycle(void);

