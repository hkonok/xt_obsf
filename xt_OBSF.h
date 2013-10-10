#ifndef _LINUX_NETFILTER_XT_OBSF_H
#define _LINUX_NETFILTER_XT_OBSF_H 1

#define XT_OBSF_MAX_KEY_LEN 32
#define IP_HDR_LEN 20
#define UDP_HDR_LEN 8
#define RTP_HDR_LEN 12
#define TOT_HDR_LEN 40

#define G729 18 // Macro for recognizing G729 packets as RTP payload type 18
#define MAX 15 //this is for the option like yes/no enable/disable

/* Declared by konok */
#define MY_PRIME 51
#define SKB_ARRAY_SIZE 20
#define PS_CLEAN_TIME 300

/* Declared by Taufique */
#define HASH_PRIME 1999
#define MAX_BUFF_SIZE 300

#define PAD_LEN 10 /* Adjust it for changing padding from the server
			Otherwise the server will always pad PAD_LEN bytes */

/* These are the flags we will encounter
 * in writing the main target function and
 * other related functions
 */

enum {
	XT_OBSF_PKT_SIP 		= 1<<0,
	XT_OBSF_PKT_RTP 		= 1<<1,
	XT_OBSF_ENC_ENABLED_SIP		= 1<<2,
	XT_OBSF_ENC_ENABLED_RTP		= 1<<3,
	XT_OBSF_PAD_ENABLED_RTP		= 1<<4,
	XT_OBSF_PTIME_ENABLED_RTP	= 1<<5,
	XT_OBSF_ENC_ENC_SIP 		= 1<<6,
	XT_OBSF_ENC_DEC_SIP 		= 1<<7,
	XT_OBSF_ENC_ENC_RTP 		= 1<<8,
	XT_OBSF_ENC_DEC_RTP 		= 1<<9,
	XT_OBSF_PAD_APAD		= 1<<10,
	XT_OBSF_PAD_RPAD		= 1<<11,
	
};

/*
 * struct rtphdr: the RTP header structure
 *
 *
 * Only needed in kernel space
 */

#if defined(__KERNEL__)

struct rtphdr {

#if defined(__BIG_ENDIAN_BITFIELD)
	__u8 version:2;
	__u8 padding:1;
	__u8 hdr_xtnsn:1;
	__u8 csrc_count:4;
	__u8 marker:1;
	__u8 pt:7;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	__u8 csrc_count:4;
	__u8 hdr_xtnsn:1;
	__u8 padding: 1;
	__u8 version:2;
	__u8 pt:7;
	__u8 marker:1;
#else
#error "please fix <asm/byteorder.h>"
#endif

	__u16 sequence:16;

	__u32 ts;
	__u32 ssrc;
};
#endif


/* The STRUCTURE xt_OBSF_tginfo
 * flags --> flags we set
 * sip_key --> sip encryption key
 * rtp_key --> rtp_encryption key
 * sip_key_len --> length of the sip encryption key (without null)
 * rtp_key_len --> length of the rtp encryption key (without null)
 * pad_len --> length of padding (if 0, padding will be avoided)
 * merge_ptime --> ptime we are looking for merging.
 * split_ptime --> the ptime at which packets will be splitted
 */

struct xt_OBSF_tginfo{
	__u16	flags;
	__u8	sip_key[XT_OBSF_MAX_KEY_LEN];
	__u8	rtp_key[XT_OBSF_MAX_KEY_LEN];
	__u8	sip_key_len;
	__u8	rtp_key_len;
	__u16	merge_ptime;
	__u8	split_ptime;
	struct xt_obsf_priv *priv;

	char	pkt_type[MAX];
	char	enc_en_or_disable[MAX];
	char	enc_path[MAX];
	char	pad_en_or_disable[MAX];
	char	ptime_en_or_disable[MAX];
	char	pad_path[MAX];
};

#endif /* _LINUX_NETFILTER_XT_OBSF_H */
