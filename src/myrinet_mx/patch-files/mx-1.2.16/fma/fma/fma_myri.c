/*
 * Routines for dealing with the Myricom setup
 */
#include <stdio.h>
#include <stdlib.h>

#include "lf_os_specific.h"

#include "libfma.h"
#include "lf_fms_comm.h"
#include "lf_scheduler.h"
#include "lf_channel.h"
#include "lf_xbar32.h"
#include "lf_myri_packet.h"
#include "lf_fma_flags.h"
#include "lf_fabric.h"
#include "lf_lag.h"
#include "libmyri.h"

#include "fma.h"
#include "fma_myri.h"
#include "fma_myrioe.h"
#include "fma_myri_packet.h"
#include "fma_fms.h"
#include "fma_map.h"
#include "fma_probe.h"
#include "fma_fabric.h"
#include "fma_standalone.h"
#include "fma_tunnel.h"
#include "fma_map_fabric.h"
#include "fma_settings.h"
#include "fma_proxy.h"
#include "fma_raw_proxy.h"

/*
 * Internal prototypes
 */
static int fma_init_nic(int nic_id, int nic_handle);
static int fma_init_nic_mom(int nic_id, int nic_handle);
static void fma_mom_get_event(struct lf_channel *chp);
static void fma_myrinet_ready(void);
static void fma_start_nic_query(struct fma_nic_info *nip);
static void fma_query_nic(void *vnip);
static void fma_proxy_msg_from_fms(struct fma_nic_info *nip,
  int port, struct fma_proxy_fms_to_fma *msg);
static void fma_remote_log(struct fma_log_msg *pkt);

/*
 * Initialize variables for Myricom setup
 */
void
fma_init_myri_vars()
{
  int i;

  /* Some one-time config checks */
  if (sizeof(struct fma_nic_verify_scout_opaque_data)
      > MYRI_NIC_SCOUT_OPAQUE_SIZE) {
    fprintf(stderr,
	"sizeof(struct fma_nic_verify_scout_opaque_data)=%d, max is %d\n",
	(int) sizeof(struct fma_nic_verify_scout_opaque_data),
	MYRI_NIC_SCOUT_OPAQUE_SIZE);
    exit(1);
  }
  if (sizeof(struct fma_nic_map_scout_opaque_data)
      > MYRI_NIC_SCOUT_OPAQUE_SIZE) {
    fprintf(stderr,
	"sizeof(struct fma_nic_map_scout_opaque_data)=%d, max is %d\n",
	(int) sizeof(struct fma_nic_map_scout_opaque_data),
	MYRI_NIC_SCOUT_OPAQUE_SIZE);
    exit(1);
  }
  if (sizeof(struct fma_nic_reply_opaque_data) > MYRI_NIC_REPLY_OPAQUE_SIZE) {
    fprintf(stderr, "sizeof(struct fma_nic_reply_opaque_data)=%d, max is %d\n",
	(int) sizeof(struct fma_nic_reply_opaque_data),
	MYRI_NIC_REPLY_OPAQUE_SIZE);
    exit(1);
  }

  LF_CALLOC(A.myri, struct fma_myri, 1);
  LF_CALLOC(A.myri->nic_info, struct fma_nic_info *, FMA_MAX_NICS);

  /* create empty probe list */
  LF_CALLOC(A.myri->probe_anchors, struct fma_probe_desc, FMA_PROBE_HASH_SIZE);
  for (i=0; i<FMA_PROBE_HASH_SIZE; ++i) {
    struct fma_probe_desc *anchor;

    anchor = A.myri->probe_anchors + i;

    anchor->pd_next = anchor;
    anchor->pd_prev = anchor;
  }

  /* create empty verify list */
  LF_CALLOC(A.myri->verify_anchor, struct fma_probe_desc, 1);
  A.myri->verify_anchor->user_next = A.myri->verify_anchor;
  A.myri->verify_anchor->user_prev = A.myri->verify_anchor;

  /* Initialize serial numbers */
  A.myri->probe_serial = 1;
  A.myri->bfs_serial = 1;

  return;

 except:
  fma_perror_exit(1);
}

/*
 * Initialize Myrinet interfaces.
 * Figure out how many NICs, what is running on them, and get
 * information about these NICs
 */
int
fma_init_myri()
{
  int n;
  int rc;
  int nic_handle;
  int max_ports;
  int num_2g;
  struct fma_myri *mp;
  struct fma_nic_info *nip;
  struct fma_nic_reply_opaque_data *rodp;
  char *cp;

  mp = A.myri;

  /* Tell everyone we are a full-blown FMA */
  A.my_fma_flags |= FMA_FLAG_CAN_ROUTE
		    | FMA_FLAG_IS_GATEWAY
		    | FMA_FLAG_CAN_VERIFY
		    | FMA_FLAG_CAN_DO_MOE
		    | FMA_FLAG_CAN_DISTRIBUTE;

  /*
   * See if we have a LAG_ID specified in the environment.
   * If so, all of our NICs will share this LAG_ID
   */
  cp = getenv("FM_LAG_ID");
  if (cp != NULL) {
    lf_string_to_lag_id(cp, A.my_lag_id);
    A.my_fma_flags |= FMA_FLAG_CAN_DO_LAG;
  }

  /*
   * See how many NICs we can open
   */
  num_2g = 0;
  for (n=0; n<FMA_MAX_NICS; ++n) {

    /* if we can open the NIC, allocate a struct for it */
    nic_handle = myri_open(n);
    if (nic_handle != -1) {
      rc = fma_init_nic(n, nic_handle);
      if (rc != 0) LF_ERROR(("Error initializing NIC"));

      /* count how many 2G NICs we open */
      if (mp->nic_info[n]->myri_info.speed == MYRI_SPEED_2G) {
	++num_2g;
      }

    /* If we got a busy error opening this NIC, something is running that
     * needs to be killed - exit!
     */
    } else if (errno == EBUSY) {
      LF_ERROR(("NIC is busy - please free it!"));
    }
  }
  if (mp->fma_num_nics == 0) {
    LF_ERROR(("No NICs opened!"));
  }

  /* If we have any MoM NICs, we get a bonus to our mapping level */
  if (mp->myri_num_nics > 0) {
    A.map_level += FMA_MOM_LEVEL_BONUS;
  }

  /* If we have any MoE NICs, report it in flags */
  if (mp->moe_num_nics > 0) {
    A.my_fma_flags |= FMA_FLAG_HAS_MOE;
  }


  /* If no 2G NICs are present, we may assume there are no ID-less xbars */
  if (num_2g == 0) {
    A.xbar_types = FMA_XT_ID_ONLY;
    if (A.debug) fma_log("10G NICs only, assuming all xbars have IDs");
  }

  /*
   * Now set up the static part of NIC reply
   */
  max_ports = 0;
  for (n=0; n<mp->fma_num_nics; ++n) {

    nip = mp->nic_info[n];

    /* keep track of max ports on any of our NICs */
    if (nip->myri_info.num_ports > max_ports) {
      max_ports = nip->myri_info.num_ports;
    }

    if (nip->ni_net_type != MYRI_NT_MYRINET) continue;

    /* fill in the dynamic part of the struct */
    LF_CALLOC(rodp, struct fma_nic_reply_opaque_data, 1);
    nip->nic_reply_data = rodp;
    rodp->fma_protocol_16 = htons(FMA_PROTOCOL_VERSION);
    rodp->host_nic_id_16 = htons(nip->nic_id);
    LF_MAC_COPY(rodp->max_mac_addr, A.myri->my_max_mac);
    memset(rodp->nr_lag_id, 0, sizeof(rodp->nr_lag_id));
    strncpy((char *)rodp->nr_hostname, A.local_hostname,
	sizeof(rodp->nr_hostname)-1);
  }

  /* fill in dynamic part also */
  fma_force_update_nic_reply_info();

  /* start with a random map session ID */
  mp->map_session_id = lf_random();

  /* Compute "nic_ports" which is used to allocate arrays here and there */
  mp->nic_ports = mp->fma_num_nics * max_ports;
  mp->local_max_nic_ports = max_ports;

  return 0;

 except:
  return -1;
}

/*
 * Allocate a structure for this NIC and record information about it.
 * Also create a channel for monitoring this NIC
 */
static int
fma_init_nic(
  int nic_id,
  int nic_handle)
{
  enum myri_net_type net_type;
  int rc;

  rc = myri_get_net_type(nic_handle, &net_type);
  if (rc != 0) {
    LF_ERROR(("Error getting network type"));
  }

  /* Call the right init routine based on network type */
  if (net_type == MYRI_NT_MYRINET) {
    return fma_init_nic_mom(nic_id, nic_handle);
  } else if (net_type == MYRI_NT_ETHERNET) {
    return fma_init_nic_moe(nic_id, nic_handle);
  } else {
    LF_ERROR(("Unknown net_type %d", net_type));
  }

 /* we should not get here */
 except:
  return -1;
}

/*
 * NIC init code for Myrinet-over-Myrinet
 */
static int
fma_init_nic_mom(
  int nic_id,
  int nic_handle)
{
  struct fma_nic_info *nip;
  struct fma_myri *mp;
  struct lf_channel *chp;
  int rc;
  int i;

  nip = NULL;
  chp = NULL;
  mp = A.myri;

  /* allocate and save a struct for this NIC */
  LF_CALLOC(nip, struct fma_nic_info, 1);
  mp->nic_info[mp->fma_num_nics] = nip;

  /* fill in fields */
  nip->nic_handle = nic_handle;
  nip->nic_id = nic_id;
  nip->nic_index = mp->fma_num_nics;
  nip->ni_net_type = MYRI_NT_MYRINET;

  /* get Myrinet information for NIC */
  rc = myri_get_nic_info(nic_handle, &nip->myri_info);
  if (rc == -1) LF_ERROR(("Getting NIC info for nic_id"));

  /* We only support just so many routes */
  if (nip->myri_info.num_routes > FMA_MAX_NUM_ROUTES) {
    nip->myri_info.num_routes = FMA_MAX_NUM_ROUTES;
  }

  /* allocate a few small arrays */
  LF_CALLOC(nip->sf_ports, int, nip->myri_info.num_ports);
  LF_CALLOC(nip->sf_port_index, int, nip->myri_info.num_ports);
  LF_CALLOC(nip->sf_verifiers, int, nip->myri_info.num_ports);
  LF_CALLOC(nip->sf_ver_index, int, nip->myri_info.num_ports);

  /* print a nice message for each NIC found */
  fma_log("NIC %d: MoM %s s/n=%s %d ports, speed=%dG", nic_id,
      nip->myri_info.product_id,
      nip->myri_info.serial_no,
      nip->myri_info.num_ports,
      nip->myri_info.speed==MYRI_SPEED_2G?2:10);
  fma_log("       mac = " LF_MAC_FORMAT, LF_MAC_ARGS(nip->myri_info.mac_addr));

  /* save MAX mac address on this host */
  if (LF_MAC_CMP(nip->myri_info.mac_addr, mp->my_max_mac) > 0) {
    LF_MAC_COPY(mp->my_max_mac, nip->myri_info.mac_addr);
  }

  /* allocate space for counters */
  LF_CALLOC(nip->last_counters, struct myri_nic_counters,
            nip->myri_info.num_ports);

  /* See if we need to set the hostname for the NIC */
  fma_check_nic_hostname(nic_handle);

  /* allocate channel for this NIC */
  LF_CALLOC(chp, struct lf_channel, 1);
  nip->chp = chp;

  /* fill in the channel */
  chp->fd = myri_fd(nic_handle);
  chp->hangup_rtn = fma_nic_hangup;
  chp->context = nip;

  /* add this channel to poll queue */
  if (lf_add_channel(chp) != 0) {
    LF_FREE(chp);
    LF_ERROR(("Adding channel"));
  }

  /* register callback for events */
  lf_channel_receive(chp, NULL, 0, fma_mom_get_event);

  /* start a query of each interface */
  for (i=0; i<nip->myri_info.num_ports; ++i) {

    fma_start_direct_probe(nip, i);
    ++mp->queries_in_progress;
  }

  ++mp->fma_num_nics;	/* increase num_nics once everything has succeeded */
  ++mp->myri_num_nics;	/* count MoM NICs */

  return 0;

 except:
  LF_FREE(nip);
  LF_FREE(chp);
  return -1;
}

/*
 * The Myrinet is now ready to use
 */
static void
fma_myrinet_ready()
{
  int rc;

  /* First try to start up FMS mode. */
  rc = fma_fms_myrinet_ready();

  /* FMS startup failed, go standalone */
  if (rc != 0) {
    fma_enter_standalone_mode();
  }
}

/*
 * A query has completed, update count and set ready flag if all done
 */
void
fma_note_query_completion()
{
  struct fma_myri *mp;

  mp = A.myri;

  /* sanity-check the count */
  if (mp->queries_in_progress <= 0) {
    LF_ERROR(("query completed with none in progress!"));
  }

  /* If nothing left in progress, Myrinet is now ready! */
  if (--mp->queries_in_progress <= 0) {
    fma_myrinet_ready();
  }
  return;

 except:
  fma_perror_exit(1);
}

/*
 * Find NIC info given ID
 */
struct fma_nic_info *
find_nip_by_id(
  int nic_id)
{
  struct fma_myri *mp;
  struct fma_nic_info *nip;
  int n;

  mp = A.myri;
  for (n=0; n<mp->fma_num_nics; ++n) {
    nip = mp->nic_info[n];
    if (nip->nic_id == nic_id) {
      return nip;
    }
  }
  return NULL;
}

/*
 * Got a hangup on the NIC fd - just ignore it I guess
 */
void
fma_nic_hangup(
  struct lf_channel *chp)
{
}

/*
 * Time to read an event from the NIC in Myri-over-Myri mode
 */
static void
fma_mom_get_event(
  struct lf_channel *chp)
{
  struct fma_nic_info *nip;
  struct myri_event *mep;
  int rc;

  nip = chp->context;		/* get pointer to NIC info */

  /* get the next event for this NIC */
  rc = myri_next_event(nip->nic_handle, &mep, 0);
  if (rc != 0) {
    fma_log ("myri_next_event():%s", strerror (errno));
    LF_ERROR(("Error getting event from NIC"));
  }

  switch (mep->type) {
    case MYRI_EVENT_RAW_RECV_COMPLETE:
      fma_myri_handle_recv(nip, mep->d.raw_recv.port,
	  mep->d.raw_recv.rxbuf, mep->d.raw_recv.rx_len, NULL);
      break;

    case MYRI_EVENT_RAW_SEND_COMPLETE:
      fma_myri_send_complete(mep->d.raw_send.context);
      break;

    case MYRI_EVENT_ERROR:
      fma_myri_error(nip, mep->d.error.error);
      break;

    case MYRI_EVENT_NO_EVENT:
      fma_log("No event when there should have been one!?");
      exit(1);
      break;

    default:
      break;
  }
  myri_release_event(mep);
  return;

 except:
  fma_perror_exit(1);
}

/*
 * Send the Myrinet info to the FMS
 */
int
fma_send_myri_info()
{
  struct fma_fms_host_msg *msg;
  struct fma_myri *mp;
  int msglen;
  int num_nics;
  int rc;
  int n;

  mp = A.myri;

  /* fill in the message header */
  num_nics = mp->fma_num_nics;

  msglen = FMA_FMS_HOST_MSG_SIZE(num_nics);

  /* build message for FMS */
  LF_CALLOC(msg, struct fma_fms_host_msg, msglen);

  /* if there is any NIC info, pass it along */
  msg->nic_cnt_32 = htonl(num_nics);
  for (n=0; n<num_nics; ++n) {
    struct fma_fms_nic *ffn;
    struct fma_nic_info *nip;
    int i;

    ffn = msg->nic_array + n;
    nip = mp->nic_info[n];

    ffn->nic_id_16 = htons(nip->nic_id);
    memcpy(ffn->mac_addr, nip->myri_info.mac_addr, sizeof(lf_mac_addr_t));
    strcpy(ffn->product_id, nip->myri_info.product_id);
    strcpy(ffn->serial_no, nip->myri_info.serial_no);

    ffn->num_active_ports_32 = htonl(nip->myri_info.num_ports);

    /* copy over connection data */
    for (i=0; i<nip->myri_info.num_ports; ++i) {
      ffn->xbar_id_32[i] = htonl(nip->ni_xbar_id[i]);
      ffn->xbar_port_32[i] = htonl(nip->ni_xbar_port[i]);
    }
  }

  /* Fill in some host info */
  msg->fw_type_32 = htonl(myri_firmware_type());
  msg->fma_flags_32 = htonl(A.my_fma_flags);

  /* send the header and the message */
  rc = fma_fms_send(FMA_FMS_HOST_MSG, msg, msglen, TRUE, fma_free, msg);
  if (rc != 0) LF_ERROR(("error sending myri information"));

  return 0;

 except:
  LF_FREE(msg);
  return -1;

}

/*
 * Handle an incoming Myrinet packet
 * sender_mac is only valid if the message came through a tunnel
 */
void
fma_myri_handle_recv(
  struct fma_nic_info *nip,
  int port,
  struct lf_myri_packet_hdr *pkt,
  int length,
  lf_mac_addr_t sender_mac)
{
  int type;
  int subtype;
  int typesubtype;
  struct fma_myri_packet *fmapkt;
  int rc;

  /* shortcut the cast later on */
  fmapkt = (struct fma_myri_packet *)pkt;

  /* make sure it is long enough to make sense - must have type and subtype */
  if (length < sizeof(pkt->type_16) + sizeof(pkt->subtype_16)) {
    return;
  }

  type = htons(pkt->type_16);

  /* Possible MoE packet? */
  if (type == MYRI_TYPE_ETHER || type == MYRI_TYPE_MX) {
    moe_check_mom_packet(nip, port, (struct mome_pkt_hdr *)pkt, length);
    return;
  }

#if 0
  if (type != FMA_PACKET_TYPE && type != MYRI_PACKET_TYPE) {
    if (type != 0x21) {
      fma_log("NIC %d rejecting packet type 0x%x", nip->nic_id, type);
    }
    return;
  }
#endif

  /*
   * Handle the packet based on type and subtype
   * We define a couple of macros to allow to make one big switch for 
   * both packet types.
   */
#define MYRI_TYPE(S) ((MYRI_PACKET_TYPE<<16)|(S))
#define FMA_TYPE(S) ((FMA_PACKET_TYPE<<16)|(S))

  subtype = htons(pkt->subtype_16);
  typesubtype = (type << 16) | subtype;

  switch (typesubtype) {

    case MYRI_TYPE(MYRI_SUBTYPE_NIC_SCOUT):
      fma_got_nic_scout(nip, port, (struct myri_nic_scout *)pkt, length);
      break;

    /* Got response to NIC probe */
    case MYRI_TYPE(MYRI_SUBTYPE_NIC_SCOUT_REPLY):
      fma_got_nic_scout_resp(nip, port,
	  (struct myri_nic_scout_reply *)pkt, length);
      break;

    /* XBAR scout returned */
    case FMA_TYPE(FMA_SUBTYPE_XBAR_SCOUT):
    case FMA_TYPE(FMA_SUBTYPE_TAGGED_XBAR_SCOUT):
      fma_got_xbar_scout_pkt(nip, port,
	  (struct fma_xbar_scout_pkt *) pkt, length);
      break;

    /* got an ACK from a tunnel packet */
    case FMA_TYPE(FMA_SUBTYPE_FMA_TUNNEL_ACK):
      fma_tunnel_got_ack(fmapkt);
      break;

    /* got a tunnel message start packet */
    case FMA_TYPE(FMA_SUBTYPE_FMA_TUNNEL_START):
      fma_tunnel_got_start(nip, port, fmapkt, fma_mom_generic_raw_send);
      break;

    /* got a tunnel message body packet */
    case FMA_TYPE(FMA_SUBTYPE_FMA_TUNNEL_BODY):
      fma_tunnel_got_body(fmapkt);
      break;

    /* xbar compare response */
    case FMA_TYPE(FMA_SUBTYPE_XBAR_COMPARE):
      fma_mf_got_compare_resp(nip, port, (struct fma_xbar_compare_pkt *)pkt);
      break;

    /* tagged xbar mapping packet */
    case FMA_TYPE(FMA_SUBTYPE_TAGGED_XBAR_MAP):
      fma_mf_got_tagged_xbar_resp(nip, port, (struct fma_xbar_scout_pkt *)pkt);
      break;

    /* xbar mapping packet */
    case FMA_TYPE(FMA_SUBTYPE_XBAR_MAP):
      fma_mf_got_xbar_resp(nip, port, (struct fma_xbar_scout_pkt *)pkt);
      break;

    /* no-op used for syncing */
    case MYRI_TYPE(MYRI_SUBTYPE_NO_OP):
      break;

    case FMA_TYPE(FMA_SUBTYPE_PROXY_CLIENT_ID_REQUEST):
      fma_got_proxy_client_id_request(nip, port, fmapkt);
      break;

    case FMA_TYPE(FMA_SUBTYPE_PROXY_CLIENT_ID_REPLY):
      fma_got_proxy_client_id_reply(fmapkt);
      break;

    /* Take this message and forward it to FMS */
    case FMA_TYPE(FMA_SUBTYPE_PROXY_FMA_TO_FMS):
      fma_proxy_msg_to_fms(nip, port, &fmapkt->u.proxy_fma_to_fms);
      break;

    /* A message for this FMA from FMS forwarded by another FMA */
    case FMA_TYPE(FMA_SUBTYPE_PROXY_FMS_TO_FMA):
      fma_proxy_msg_from_fms(nip, port, &fmapkt->u.proxy_fms_to_fma);
      break;
      
    case FMA_TYPE(FMA_SUBTYPE_TOPO_MAP):
      if (A.run_state == FMA_RUN_STANDALONE) {
	if (length > 0) {

	  /* Load this topo map */
	  fma_standalone_load_map(&fmapkt->u.topo_map,
	      length - sizeof(struct lf_myri_packet_hdr));

	} else {
	  fma_log("Ignoring zero-length map from peer");
	}
      } else {
	fma_log("Ignoring topo_map from peer while not standalone");
      }
      break;

    case FMA_TYPE(FMA_SUBTYPE_MAP_FABRIC):
      fma_peer_remap_request((struct fma_map_request *)fmapkt, sender_mac);
      break;

    case FMA_TYPE(FMA_SUBTYPE_DIST_DONE):
      fma_remote_map_dist_done((struct fma_dist_done_msg *)fmapkt, sender_mac);
      break;

    case FMA_TYPE(FMA_SUBTYPE_MOE_PEER_LIST):
      moe_got_peer_list((struct moe_peer_list_pkt *)fmapkt, sender_mac);
      break;

    case FMA_TYPE(FMA_SUBTYPE_LOG_MSG):
      fma_remote_log((struct fma_log_msg *)fmapkt);
      break;

    default:
#ifndef _WIN32
      rc = fma_rp_handle_myri_packet(pkt, length);
      /* Comment out to prevent fma.log build up. 
      if (rc == 0) {
	fma_log("Unknown type/subtype: %x/%x", type, subtype);
      } */
#endif
      break;
  }
}

/*
 * Provide a mechanism for getting a callback when a send completes
 */
int
fma_myri_raw_send(
  int nic_id,
  int port,
  void *route,
  int route_len,
  void *txbuf,
  int txlen,
  void (*callback_rtn)(void *),
  void *context)
{
  int rc;
  struct fma_myri_send_callback *scp;

  /* If callback specified, save it away */
  if (callback_rtn != NULL) {

    /* allocate and fill in a send callback record */
    LF_CALLOC(scp, struct fma_myri_send_callback, 1);
    scp->callback_rtn = callback_rtn;
    scp->context = context;

  /* otherwise, no context is used for send */
  } else {
    scp = NULL;
  }

  /* do the send */
  rc = myri_raw_send(nic_id, port, route, route_len,
			 txbuf, txlen, scp);

  /* If error, free the callback record */
  if (rc != 0) {
    LF_FREE(scp);
  }
  return rc;

 except:
  fma_perror_exit(1);
  return -1;
}

void
fma_myri_send_complete(
  struct fma_myri_send_callback *scp)
{
  /* make the callback and free the record */
  if (scp != NULL) {
    scp->callback_rtn(scp->context);
    LF_FREE(scp);
  }
}

/*
 * Send a no-op packet and perform callback when complete.  This is useful
 * for triggering a callback after a long sequence of sends.
 */
int
fma_myri_sync_callback(
  int nic_id,
  int port,
  void (*callback_rtn)(void *),
  void *context)
{
  struct lf_myri_packet_hdr pkt;
  unsigned char route[1];
  int rc;

  pkt.type_16 = htons(MYRI_PACKET_TYPE);
  pkt.subtype_16 = htons(MYRI_SUBTYPE_NO_OP);

  route[0] = LF_DELTA_TO_ROUTE(0);

  rc = fma_myri_raw_send(nic_id, port, route, 1, &pkt, sizeof(pkt),
      			 callback_rtn, context);
  return rc;
}

/*
 * On some systems, we need to set the initial hostname for this NIC
 */
void
fma_check_nic_hostname(
  int nic_handle)
{
#if defined _WIN32 || defined __APPLE__
  int rc;
  lf_string_t name;
  char *cp;

  /* get the current hostname */
  rc = myri_get_hostname(nic_handle, name);
  if (rc == -1) LF_ERROR(("Error getting NIC hostname"));

  /* See if it is "localhost" or "localhost:*" */
  cp = strchr(name, ':');
  if (cp != NULL) *cp = '\0';

  /* If currently "localhost", set it to the real hostname */
  if (strcmp(name, "localhost") == 0) {
    rc = myri_set_dflt_hostname(nic_handle, A.local_hostname);
    if (rc == -1) LF_ERROR(("Error setting default hostname"));
  }
  return;

 except:
  fma_perror_exit(1);
#endif
}

/*
 * Got an error from a Myrinet NIC
 */
void
fma_myri_error(
  struct fma_nic_info *nip,
  enum myri_error_type error)
{
  fma_log("NIC %d reports error %d", nip->nic_id, error);

  if (A.run_state != FMA_RUN_STANDALONE) {
    fma_fms_report_nic_error(nip->nic_id, error);
  }

  fma_exit(1);		/* not much else to do, really */
}

/*
 * start or restart all NIC queries
 */
void
fma_start_nic_queries()
{
  struct fma_myri *mp;
  int n;

  mp = A.myri;
  for (n=0; n<mp->fma_num_nics; ++n) {
    if (mp->nic_info[n]->ni_net_type != MYRI_NT_MYRINET) continue;
    fma_start_nic_query(mp->nic_info[n]);
  }
}

/*
 * Start the scheduled NIC queries.
 * This queries the counters to get a baseline, then schedules the first
 * read to take place after nic_query_interval has elapsed.
 */
static void
fma_start_nic_query(
  struct fma_nic_info *nip)
{
  int p;
  struct fma_settings *asp;
  int rc;

  asp = A.settings;

  /* do baseline reads */
  for (p=0; p<nip->myri_info.num_ports; ++p) {
    rc = myri_get_nic_counters(nip->nic_handle, p, nip->last_counters + p);
    if (rc != 0) {
      LF_ERROR(("Error reading NIC counters"));
    }
  }

  /* cancel any pending query */
  if (nip->nic_query_timer != NULL) {
    lf_remove_event(nip->nic_query_timer);
  }

  /* Schedule the first query */
  if (asp->nic_query_interval > 0) {
    nip->nic_query_timer = lf_schedule_event(fma_query_nic, nip,
				       asp->nic_query_interval);
    if (nip->nic_query_timer == NULL) {
      LF_ERROR(("Error scheduling nic query task"));
    }
  }
  return;

 except:
  fma_perror_exit(1);
}

/*
 * Perform a NIC query
 */
static void
fma_query_nic(
  void *vnip)
{
  struct fma_nic_info *nip;
  struct myri_nic_counters counters;
  struct fma_settings *asp;
  int rc;
  int p;

  nip = vnip;
  asp = A.settings;
  nip->nic_query_timer = NULL;

  /* read counters for each NIC */
  for (p=0; p<nip->myri_info.num_ports; ++p) {
    int badcrcs;

    /* read current counter values */
    rc = myri_get_nic_counters(nip->nic_handle, p, &counters);
    if (rc != 0) {
      LF_ERROR(("Error reading NIC counters"));
    }

    /* check badcrc delta versus threshold */
    badcrcs = counters.badcrcs - nip->last_counters[p].badcrcs;
    if (badcrcs > asp->nic_badcrc_threshold) {
      fma_fms_nic_badcrc(nip->nic_id, p, badcrcs);
    }

    /* save this set of counters */
    nip->last_counters[p] = counters;
  }

  /* Schedule the next query */
  if (asp->nic_query_interval > 0) {
    nip->nic_query_timer = lf_schedule_event(fma_query_nic, nip,
				       asp->nic_query_interval);
    if (nip->nic_query_timer == NULL) {
      LF_ERROR(("Error scheduling nic query task"));
    }
  }
  return;

 except:
  fma_perror_exit(1);
}

/*
 * A message for this NIC from the FMS forwarded through another FMA
 */
static void
fma_proxy_msg_from_fms(
  struct fma_nic_info *nip,
  int port,
  struct fma_proxy_fms_to_fma *msg)
{
  int type;
  int length;

  type = ntohl(msg->h.msg_type_32);
  length = ntohl(msg->h.length_32);
  if (A.debug > 1) fma_log("Handling proxied message, type = %d", type);
  fma_handle_message(type, length, (union lf_fma_message *)msg->data);
}

/*
 * Schedule an update of the NIC reply data to happen right now
 */
void
fma_force_update_nic_reply_info()
{
  struct fma_myri *mp;

  mp = A.myri;

  /* cancel any existing scheduled run */
  if (mp->fma_nic_reply_info_task != NULL) {
    lf_remove_event(mp->fma_nic_reply_info_task);
    mp->fma_nic_reply_info_task = NULL;
  }

  /* run update now */
  fma_update_nic_reply_info(NULL);
}

/*
 * Fill in the scout reply information to enable the NIC to auto-reply
 */
void
fma_update_nic_reply_info(
  void *v)
{
  struct fma_nic_reply_opaque_data *rodp;
  struct fma_myri *mp;
  struct fma_nic_info *nip;
  int rc;
  int n;

  mp = A.myri;

  /* clear event handle */
  mp->fma_nic_reply_info_task = NULL;

  for (n=0; n<mp->fma_num_nics; ++n) {

    nip = mp->nic_info[n];
    if (nip->ni_net_type != MYRI_NT_MYRINET) continue;

    /* fill in the dynamic part of the struct */
    rodp = nip->nic_reply_data;
    rodp->fma_flags_32 = htonl(A.my_fma_flags);
    rodp->level_8 = A.stand->my_level;
    rodp->map_version_32 = htonl(A.map_info->mi_map_version);
    rodp->my_unique_id_32 = htonl(nip->nic_unique_id);
    LF_MAC_COPY (rodp->mapper_mac_addr, A.map_info->mi_mapper_mac_addr);

    /* insert our LAG_ID if we are running LACP */
    if (A.my_fma_flags & FMA_FLAG_CAN_DO_LAG) {
      lf_lag_copy(rodp->nr_lag_id, A.my_lag_id);
    }

    rc = myri_set_nic_reply_info(nip->nic_handle, rodp, sizeof(*rodp));
    if (rc != 0) {
      LF_ERROR(("Error setting NIC reply info"));
    }
  }

  /* re-schedule update to occur periodically so the NIC knows we are awake */
  mp->fma_nic_reply_info_task = lf_schedule_event(fma_update_nic_reply_info,
      NULL, FMA_SET_NIC_REPLY_INFO_PERIOD);
  if ( mp->fma_nic_reply_info_task == NULL) {
    LF_ERROR(("Error re-arming nic_reply_info task"));
  }

  return;

 except:
  fma_perror_exit(1);
}

/*
 * Generic RAW send for MoM->MoM
 */
int
fma_mom_generic_raw_send(
  struct fma_generic_send_info *gsip,
  void *pkt,
  int pkt_len,
  void (*callback)(void *),
  void *context)
{
  return fma_myri_raw_send(gsip->gsi_nip->nic_handle, gsip->gsi_port,
                     gsip->gsi_route, gsip->gsi_route_len,
                     pkt, pkt_len, callback, context);
}

/*
 * Log a message requested by a remote node
 */
static void
fma_remote_log(
    struct fma_log_msg *pkt)
{
  fma_log("%s reports: %s", fma_mac_to_hostname(pkt->req_mac_addr), pkt->msg);
}
