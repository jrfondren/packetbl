#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netfilter.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <syslog.h>

const uint8_t c_nfqnl_copy_packet = NFQNL_COPY_PACKET;
const int c_nfqa_cfg_f_fail_open = NFQA_CFG_F_FAIL_OPEN;
const int c_nfqa_cfg_f_gso = NFQA_CFG_F_GSO;
const int c_nf_accept = NF_ACCEPT;
const int c_nf_drop = NF_DROP;
const int c_af_inet = AF_INET;
const int c_time_t_size = sizeof(time_t);
const int c_log_notice = LOG_NOTICE;
const int c_log_err = LOG_ERR;
