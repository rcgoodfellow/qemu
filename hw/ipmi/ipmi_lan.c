#include <string.h>
#include "hw/ipmi/lan.h"
#include "qemu/log.h"
#include "net/net.h"
#include "net/eth.h"

static inline struct rcmp_hdr 
read_rcmp_hdr(const uint8_t *buf)
{
  struct rcmp_hdr h = {
    .version =  ldub_p(buf),
    .sequence = ldub_p(buf + 2),
    .class =    ldub_p(buf + 3)
  };
  return h;
}

static inline struct ipmi_20_hdr 
read_ipmi_20_hdr(const uint8_t *buf)
{
  struct ipmi_20_hdr h = {
    .auth_format =    ldub_p( buf + 0  ),
    .payload_type = ldl_be_p( buf + 1  ),
    .session_id =   ldl_be_p( buf + 2  ),
    .session_seq =  ldl_be_p( buf + 6  ),
    .payload_len =    ldub_p( buf + 10 )
  };
  return h;
}

static inline struct ipmi_15_hdr 
read_ipmi_15_hdr(const uint8_t *buf)
{
  struct ipmi_15_hdr h = {
    .auth_format =    ldub_p( buf + 0  ),
    .session_id =   ldl_be_p( buf + 2  ),
    .session_seq =  ldl_be_p( buf + 6  ),
    .payload_len =    ldub_p( buf + 10 )
  };
  return h;
}

static inline struct ipmi_request_hdr 
read_ipmi_request_hdr(const uint8_t *buf)
{
  struct ipmi_request_hdr h = {
    .rsaddr    = ldub_p(buf + 0),
    .netfn_rsl = ldub_p(buf + 1),
    .checksum  = ldub_p(buf + 2),
    .rqaddr    = ldub_p(buf + 3),
    .seq_rql   = ldub_p(buf + 4),
    .cmd       = ldub_p(buf + 5)
  };
  return h;
}

static void ipmi_free_pkt(struct ipmi_15_pkt *pkt)
{
  free(pkt->payload);
}

void ipmi_15_free_full_pkt(struct ipmi_15_full_pkt *pkt)
{
  ipmi_free_pkt(&pkt->ipmi);
  free(pkt);
}

static inline uint8_t checksum(const uint8_t *data, size_t size) 
{
  uint8_t ck = 0;
  for(size_t i=0; i<size; i++) {
    ck = (ck + data[i]) % 256;
  }
  return ck;
}

static bool
handle_app_request(const struct ipmi_request_hdr *req, const uint8_t *data,
    struct ipmi_15_pkt *pkt)
{
  qemu_log("got APP REQUEST\n");
  switch(req->cmd) {
    case IPMI_APP_GET_AUTH:
    {
      qemu_log("got AUTH CAPABILITY REQUEST\n");

      const struct channel_auth_req *cr = (struct channel_auth_req*)(data);

      struct ipmi_get_auth_response r = {
        .hdr = {
          .rqaddr = 0x20,
          .netfn_rql = 0x07 << 2,
          .rsaddr = req->rsaddr,
          .seq_rsl = 0,
          .rqaddr = req->rqaddr,
          .cmd = req->cmd,
        },
        .completion_code = 0x00,
        .data = {
          .channel_number = cr->channel_number,
          .auth_support = 0x00, //no auth support atm.
          .status = 0b0011000,  //no per message auth
                                //no user auth
                                //no anonymus user support
          .extended = 0,
          .oem_id = 0,
          .oem_aux = 0
        }
      };
      r.hdr.checksum = checksum(&r.hdr.rqaddr, 2);
      r.checksum = checksum(&r.hdr.rsaddr, 4 + sizeof(r.data));

      pkt->header.payload_len = sizeof(r);
      pkt->payload = malloc(sizeof(r));
      memcpy(pkt->payload, &r, sizeof(r));
      qemu_log("IPMI payload send: "
          "rsaddr=%x "
          "netfn=%x "
          "checksum=%x "
          "rqaddr=%x "
          "pseq=%x "
          "cmd=%x\n",
          r.hdr.rsaddr, r.hdr.netfn_rql, r.hdr.checksum, r.hdr.rqaddr, r.hdr.seq_rsl, r.hdr.cmd);
      return true;
    }
    default:
      qemu_log("got UNKOWN APP REQUEST\n");
      return false;
  }
}

static bool
handle_chassis_request(const struct ipmi_request_hdr *req, const uint8_t *data,
    struct ipmi_15_pkt *pkt)
{
  switch(req->cmd) {
    case IPMI_CHASSIS_STATUS:
      qemu_log("got CHASSIS STATUS request\n");
      //TODO implement
      return false;
      break;
    case IPMI_CHASSIS_CONTROL: {
      qemu_log("got CHASSIS control request\n");
      switch(req->cmd) {
        case IPMI_POWER_DOWN:
          qemu_log("got IPMI_POWER_DOWN\n");
          break;
        case IPMI_POWER_UP:
          qemu_log("got IPMI_POWER_UP\n");
          break;
        case IPMI_POWER_CYCLE:
          qemu_log("got IPMI_POWER_CYCLE\n");
          break;
        case IPMI_HARD_RESET:
          qemu_log("got IPMI_POWER_RESET\n");
          break;
        case IPMI_PULSE_DIAG:
          qemu_log("got IPMI_PULSE_DIAG\n");
          break;
        case IPMI_SOFT_ACPI_SHUTDOWN:
          qemu_log("got IPMI_SOFT_ACPI_SHUTDOWN\n");
          break;
        default:
          qemu_log("got unsupported chassis control command %x\n", 
              req->cmd);
      }
      //TODO create response
      return false;
    }
    default:
      qemu_log("got unsupported chassis request %x\n", req->cmd);
      return false;
  }
}

static bool 
handle_ipmi_request(const uint8_t *pkt_in, struct ipmi_15_pkt *pkt_out)
{
  qemu_log("ipmi-lan: recv'd ipmi packet\n");

  /* read IPMI header */
  struct ipmi_15_hdr ipmi = read_ipmi_15_hdr(pkt_in);
  if(ipmi.auth_format) {
    qemu_log("ipmi: only AUTH=NONE supported at this time\n");
    return false;
  }

  /* read IPMI payload */
  size_t payload_start = sizeof(struct ipmi_15_hdr);
  struct ipmi_request_hdr req = read_ipmi_request_hdr(pkt_in + payload_start);
  uint8_t netfn = (req.netfn_rsl & 0xfc) >> 2;
  qemu_log("netfn: %x\n", netfn);
  qemu_log("IPMI payload: "
      "rsaddr=%x "
      "netfn=%x "
      "checksum=%x "
      "rqaddr=%x "
      "pseq=%x "
      "cmd=%x\n",
      req.rsaddr, netfn, req.checksum, req.rqaddr, req.seq_rql, req.cmd);

  const uint8_t *data = pkt_in + payload_start + sizeof(struct ipmi_request_hdr);

  switch(netfn) {
    case IPMI_APP_REQUEST:
      return handle_app_request(&req, data, pkt_out);

    case IPMI_CHASSIS_REQUEST:
      return handle_chassis_request(&req, data, pkt_out);
    default: 
      qemu_log("got unimplemented function %x\n", netfn);
      return false;
  }
}

/*
 * TODO XXX - These are in net/checksum & net/eth - but not exported for all 
 *            machine types
 */

static inline uint32_t 
checksum_add_cont(int len, uint8_t *buf, int seq)
{
  uint32_t sum1 = 0, sum2 = 0;
  int i;

  for (i = 0; i < len - 1; i += 2) {
    sum1 += (uint32_t)buf[i];
    sum2 += (uint32_t)buf[i + 1];
  }
  if (i < len) {
    sum1 += (uint32_t)buf[i];
  }

  if (seq & 1) {
    return sum1 + (sum2 << 8);
  } else {
    return sum2 + (sum1 << 8);
  }
}

static inline uint32_t
checksum_add(int len, uint8_t *buf)
{
  return checksum_add_cont(len, buf, 0);
}

static inline uint16_t 
checksum_finish(uint32_t sum)
{
  while (sum>>16)
    sum = (sum & 0xFFFF)+(sum >> 16);
  return ~sum;
}

static inline uint16_t 
checksum_tcpudp(uint16_t length, uint16_t proto,
    uint8_t *addrs, uint8_t *buf)
{
  uint32_t sum = 0;

  sum += checksum_add(length, buf);         // payload
  sum += checksum_add(8, addrs);            // src + dst address
  sum += proto + length;                    // protocol & length
  return checksum_finish(sum);
}

static inline uint32_t
calc_ip4_pseudo_hdr_csum(struct ip_header *iphdr,
                             uint16_t csl,
                             uint32_t *cso)
{
    struct ip_pseudo_header ipph;
    ipph.ip_src = iphdr->ip_src;
    ipph.ip_dst = iphdr->ip_dst;
    ipph.ip_payload = cpu_to_be16(csl);
    ipph.ip_proto = iphdr->ip_p;
    ipph.zeros = 0;
    *cso = sizeof(ipph);
    return checksum_add(*cso, (uint8_t *) &ipph);
}

/* end XXX */

//static struct ipmi_15_full_pkt*
static uint8_t*
create_ipmi_response(
    const struct eth_header *eth_origin,
    const struct ip_header *ip_origin,
    const struct udp_header *udp_origin,
    const struct rcmp_hdr *rcmp,
    const struct ipmi_15_pkt *ipkt,
    size_t *len)
{
  struct eth_header eth;
  memcpy(&eth.h_dest[0], &eth_origin->h_source[0], sizeof(eth.h_dest));
  memcpy(&eth.h_source[0], &eth_origin->h_dest[0], sizeof(eth.h_source));
  eth.h_proto = eth_origin->h_proto;

  struct ip_header ip;
  static uint16_t ip_id = 0;
  uint16_t ip_len;
  ip.ip_ver_len = ip_origin->ip_ver_len;
  ip.ip_tos = ip_origin->ip_tos;
  ip_len = 
    sizeof(struct ip_header) + 
    sizeof(struct udp_header) +
    sizeof(struct rcmp_hdr) +
    sizeof(struct ipmi_15_pkt) +
    ipkt->header.payload_len;
  ip.ip_len = htons(ip_len);
  ip.ip_id = htons(ip_id++);
  ip.ip_off = 0;
  ip.ip_ttl = 255;
  ip.ip_p = ip_origin->ip_p;
  ip.ip_src = ip_origin->ip_dst;
  ip.ip_dst = ip_origin->ip_src;
  ip.ip_sum = 0;

  ip.ip_sum = htons(checksum_finish(checksum_add(20, (uint8_t*)&ip)));
  
  struct udp_header udp; 
  udp.uh_sport = udp_origin->uh_dport;
  udp.uh_dport = udp_origin->uh_sport;
  udp.uh_ulen = htons(ip_len - sizeof(struct ip_header));
  udp.uh_sum = 0;

  *len = sizeof(eth) + ip_len;
  uint8_t *blob = malloc(*len);
  size_t i = 0;
  memcpy(blob+i, &eth, sizeof(eth));
  i += sizeof(eth);
  memcpy(blob+i, &ip, sizeof(ip));
  i += sizeof(ip);
  memcpy(blob+i, &udp, sizeof(udp));
  i += sizeof(udp);
  memcpy(blob+i, rcmp, sizeof(struct rcmp_hdr));
  i += sizeof(struct rcmp_hdr);
  memcpy(blob+i, &ipkt->header, sizeof(ipkt->header));
  i += sizeof(ipkt->header);
  memcpy(blob+i, ipkt->payload, ipkt->header.payload_len);
  i += ipkt->header.payload_len;
  memcpy(blob+i, &ipkt->footer, sizeof(ipkt->footer));

  struct ip_header *ip_p = (struct ip_header*)blob+sizeof(eth);
  struct udp_header *udp_p = (struct udp_header*)blob+sizeof(eth)+sizeof(udp);
  udp_p->uh_sum = htons(checksum_tcpudp(
      ip_len - sizeof(struct ip_header), ip.ip_p, 
      (uint8_t*)&ip_p->ip_src, 
      (uint8_t*)udp_p
  ));
  
  free(ipkt->payload);

  return blob;
}

//struct ipmi_15_full_pkt* 
uint8_t*
check_ipmi_packet(const uint8_t *buf, size_t *len)
{
  /* read the ip header, if proto is not UDP - not an ipmi packet */
  struct eth_header *eth = PKT_GET_ETH_HDR(buf);
  uint32_t eth_sz = eth_get_l2_hdr_length(buf);
  struct ip_header *ip = PKT_GET_IP_HDR(buf);
  if(ip->ip_p != IP_PROTO_UDP) {
    return NULL;
  }
  uint8_t ihl = 0x0fu & ip->ip_ver_len;
  size_t ip_sz = ihl*4;
  struct udp_header *udp = (struct udp_header*)( ((uint8_t*)ip) + ip_sz );

  /* read the udp destination port, if not 632 - not an ipmi packet
   * TODO: also deal with port 624
   */
  uint16_t dstp = lduw_be_p(buf + eth_sz + ip_sz + 2);
  if(dstp != IPMI_UDP_PORT) {
    return NULL;
  }

  /* read RMCP header */
  size_t rcmp_start = eth_sz + ip_sz + sizeof(udp_header);
  struct rcmp_hdr rcmp = read_rcmp_hdr(buf + rcmp_start);

  /* detect ipmi packet */
  if( rcmp.version  == IPMI_RCMP_VERSION && 
      rcmp.sequence == IPMI_RCMP_SEQUENCE &&
      rcmp.class    == IPMI_RCMP_CLASS ) 
  {
    size_t ipmi_start = rcmp_start + sizeof(struct rcmp_hdr);
    struct ipmi_15_pkt ipkt = IPMI_15_PKT();
    bool ok = handle_ipmi_request(buf + ipmi_start, &ipkt);
    if(ok) {
      return create_ipmi_response(eth, ip, udp, &rcmp, &ipkt, len);
    }
  }

  /* detect asf packet */
  else if( rcmp.version == IPMI_RCMP_VERSION &&
           rcmp.sequence < IPMI_RCMP_SEQUENCE &&
           rcmp.class == ASF_RCMP_CLASS ) 
  {
    qemu_log("ipmi-lan: recv'd asf packet\n");
    return NULL;
  }

  /* if we're here - we got a malformed packet */
  else 
  {
    //XXX remove this, if we get a malformed ipmi packet don't fret just forward
    qemu_log("?: packet targets IPMI port, but is not IPMI\n");
    qemu_log("version %x\n", rcmp.version);
    qemu_log("sequence %x\n", rcmp.sequence);
    qemu_log("class %x\n", rcmp.class);
  }

  return NULL;

}
