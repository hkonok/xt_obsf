#include <stdio.h>
#include <xtables.h>
#include <linux/netfilter/x_tables.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "xt_OBSF.h"

enum {
	O_OBSF_PKT=1,
	O_OBSF_ENC,
	O_OBSF_RTP_KEY,
	O_OBSF_RTP_KEY_LEN,
	O_OBSF_SIP_KEY,
	O_OBSF_SIP_KEY_LEN,
	O_OBSF_ENC_PATH,
	O_OBSF_PAD,
	O_OBSF_PAD_PATH,
	O_OBSF_PTIME,
	O_OBSF_SP_TIME,
	O_OBSF_LP_TIME,
};

static void OBSF_help(void)
{

}


static const struct xt_option_entry OBSF_opts[] = {
		{
			.name="pkt",
			.id=O_OBSF_PKT,
			.type=XTTYPE_STRING,
			.flags=XTOPT_PUT,
			XTOPT_POINTER(struct xt_OBSF_tginfo,pkt_type),
		},
		{
			.name="encryption",
			.id= O_OBSF_ENC,
			.type=XTTYPE_STRING,
			.flags=XTOPT_PUT,
			XTOPT_POINTER(struct xt_OBSF_tginfo,enc_en_or_disable),
		},
		{
			.name="rtp_key",
			.id=O_OBSF_RTP_KEY,
			.type=XTTYPE_STRING,
			.flags=XTOPT_PUT,
			XTOPT_POINTER(struct xt_OBSF_tginfo,rtp_key),
		},
		{
			.name="sip_key",
			.id=O_OBSF_SIP_KEY,
			.type=XTTYPE_STRING,
			.flags=XTOPT_PUT,
			XTOPT_POINTER(struct xt_OBSF_tginfo,sip_key),
		},
		{
			.name="rtp_key_len",
			.id=O_OBSF_RTP_KEY_LEN,
			.type=XTTYPE_UINT8,
			.flags=XTOPT_PUT,
			XTOPT_POINTER(struct xt_OBSF_tginfo,rtp_key_len),
		},
		{
			.name="sip_key_len",
			.id=O_OBSF_SIP_KEY_LEN,
			.type=XTTYPE_UINT8,
			.flags=XTOPT_PUT,
			XTOPT_POINTER(struct xt_OBSF_tginfo,sip_key_len),
		},
		{
			.name="enc_path",
			.id=O_OBSF_ENC_PATH,
			.type=XTTYPE_STRING,
			.flags=XTOPT_PUT,
			XTOPT_POINTER(struct xt_OBSF_tginfo,enc_path),
		},
		{
			.name="pad",
			.id=O_OBSF_PAD,
			.type=XTTYPE_STRING,
			.flags=XTOPT_PUT,
			XTOPT_POINTER(struct xt_OBSF_tginfo,pad_en_or_disable),
		},
		{
			.name="pad_path",
			.id=O_OBSF_PAD_PATH,
			.type=XTTYPE_STRING,
			.flags=XTOPT_PUT,
			XTOPT_POINTER(struct xt_OBSF_tginfo,pad_path),

		},
		{
			.name="ptime",
			.id=O_OBSF_PTIME,
			.type=XTTYPE_STRING,
			.flags=XTOPT_PUT,
			XTOPT_POINTER(struct xt_OBSF_tginfo,ptime_en_or_disable),
		},
		{
			.name="sptime",
			.id=O_OBSF_SP_TIME,
			.type=XTTYPE_UINT8,
			.flags=XTOPT_PUT,
			XTOPT_POINTER(struct xt_OBSF_tginfo,split_ptime),
		},
		{
			.name="lptime",
			.id=O_OBSF_LP_TIME,
			.type=XTTYPE_UINT16,
			.flags=XTOPT_PUT,
			XTOPT_POINTER(struct xt_OBSF_tginfo,merge_ptime),
		},

		XTOPT_TABLEEND,
};

static void OBSF_parse(struct xt_option_call *cb)
{
	struct xt_OBSF_tginfo *info = cb->data;
	xtables_option_parse(cb);

	switch(cb->entry->id) {

	case O_OBSF_PKT:
	{
		printf("%s\n",info->pkt_type);
		printf("%d\n",info->flags);
		if(!strcmp(info->pkt_type,"sip"))
			info->flags |= XT_OBSF_PKT_SIP;
		else if(!strcmp(info->pkt_type,"rtp"))
			info->flags |= XT_OBSF_PKT_RTP;
		printf("%d\n",info->flags);
		break;
	}

	case O_OBSF_ENC:
	{
		printf("%s\n",info->enc_en_or_disable);
		printf("%d\n",info->flags);
		if((!strcmp(info->enc_en_or_disable,"yes")) && (!strcmp(info->pkt_type,"sip")) )
			info->flags |= XT_OBSF_ENC_ENABLED_SIP;
		else if((!strcmp(info->enc_en_or_disable,"yes")) && (!strcmp(info->pkt_type,"rtp")) )
			info->flags |= XT_OBSF_ENC_ENABLED_RTP;

		printf("%d\n",info->flags);
		break;
	}

	case O_OBSF_RTP_KEY:
	{
		printf("%s\n",info->rtp_key);
		break;
	}

	case O_OBSF_RTP_KEY_LEN:
	{
		printf("%d\n",info->rtp_key_len);
		break;
	}

	case O_OBSF_ENC_PATH:
	{
		printf("%s\n",info->enc_path);
		//for sip & enc enable
		if( (!strcmp(info->pkt_type,"sip")) && (!strcmp(info->enc_path,"encrypt")) && (!strcmp(info->enc_en_or_disable,"yes")) )
			info->flags |= XT_OBSF_ENC_ENC_SIP;

		else if( (!strcmp(info->pkt_type,"sip")) && (!strcmp(info->enc_path,"decrypt")) && (!strcmp(info->enc_en_or_disable,"yes")) )
			info->flags |= XT_OBSF_ENC_DEC_SIP;

		//for rtp & enc enable
		else if( (!strcmp(info->pkt_type,"rtp")) && (!strcmp(info->enc_path,"encrypt")) && (!strcmp(info->enc_en_or_disable,"yes")) )
			info->flags |= XT_OBSF_ENC_ENC_RTP;

		else if( (!strcmp(info->pkt_type,"rtp")) && (!strcmp(info->enc_path,"decrypt")) && (!strcmp(info->enc_en_or_disable,"yes")) )
			info->flags |= XT_OBSF_ENC_DEC_RTP;

		break;
	}

	case O_OBSF_PAD:
	{
		printf("%s\n",info->pad_en_or_disable);
		printf("%d\n",info->flags);
		if(!strcmp(info->pad_en_or_disable,"enable"))
			info->flags |= XT_OBSF_PAD_ENABLED_RTP;
		printf("%d\n",info->flags);
		break;
	}
	
	case O_OBSF_PAD_PATH:
	{
		//printf("%d\n",info->pad_len);
		//break;
		printf("%s\n",info->pad_path);
		printf("%d\n",info->flags);
		if(!strcmp(info->pad_path,"apad"))
			info->flags |= XT_OBSF_PAD_APAD;
		else if(!strcmp(info->pad_path,"rpad"))
			info->flags |= XT_OBSF_PAD_RPAD;
		printf("%d\n",info->flags);
		break;

	}

	case O_OBSF_PTIME:
	{
		printf("%s\n",info->ptime_en_or_disable);
		printf("%d\n",info->flags);
		if(!strcmp(info->ptime_en_or_disable,"enable"))
			info->flags |= XT_OBSF_PTIME_ENABLED_RTP;
		printf("%d\n",info->flags);
		break;
	}

	case O_OBSF_SP_TIME:
	{
		printf("%d\n",info->split_ptime);
		break;
	}

	case O_OBSF_LP_TIME:
	{
		printf("%d\n",info->merge_ptime);
		break;
	}


	}
}


static void OBSF_print(const void *ip,
		       const struct xt_entry_target *target, int numeric)
{
}


static void OBSF_save(const void *ip, const struct xt_entry_target *target)
{

}

static struct xtables_target obsf_target = {
				.family  = NFPROTO_UNSPEC,
				.name    = "OBSF",
				.version = XTABLES_VERSION,
				.size    = XT_ALIGN(sizeof(struct xt_OBSF_tginfo)),
				.userspacesize = XT_ALIGN(sizeof(struct xt_OBSF_tginfo) - sizeof(struct xt_obsf_priv *)),
				.help = OBSF_help,
				.print = OBSF_print,
				.save = OBSF_save,
				.x6_options = OBSF_opts,
				.x6_parse=OBSF_parse,
};

static void _init(void)
{
	xtables_register_target(&obsf_target);
}
