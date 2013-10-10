/* This is xt_OBSF.c */

#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/jhash.h>
#include <linux/mm.h>
#include <linux/err.h>
#include <linux/init.h>
#include <asm/byteorder.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/timer.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/ip.h>
#include <net/udp.h>
#include <net/route.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <net/snmp.h>
#include <net/protocol.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <net/raw.h>
#include <net/checksum.h>
#include <net/xfrm.h>
#include <linux/mroute.h>
#include <linux/netlink.h>
#include <linux/route.h>

#include "xt_OBSF.h"

struct xt_obsf_priv {
	struct crypto_blkcipher *tfm_sip;
	struct crypto_blkcipher *tfm_rtp;

	struct xt_OBSF_tginfo *info;
};

/*
 *structure for the list
 */
struct ps_data
{
	__u32 saddr,daddr,dest,ssrc;
	__u32 ts;
	__u16 sequence:16;
	unsigned long current_t;
	struct list_head list;
};

struct queue_data {
        unsigned int saddr;
        unsigned int daddr;
        unsigned int source;
        unsigned int dest;
        unsigned int ssrc;
        unsigned int buff_ptr;
        unsigned char buffer[MAX_BUFF_SIZE];
        struct timeval tim; /* Last time when data entered queue */
        struct tm parsed_tim; /* Parsed value of timeval struct */
        unsigned int timestamp;
        unsigned int sequence;
        struct queue_data *next;
        struct queue_data *prev;
};

/* Array of queues. Actually hash table */
struct queue_data table[HASH_PRIME];

/* task_stuct is needed to multithread */
static struct task_struct *ts;
unsigned int DPTIME = 100;


/*
 * for array of  list
 */
static struct  ps_data *ps_list;
/*
 *for sample input
 */
static struct  ps_data inp;

/* This is necessary for sending the inward packets to the
 * upper layers. ip_rcv_finish() is modified here to get
 * rid of it. */

int sysctl_ip_early_demux __read_mostly = 1;

/*
 * Hashing on five numbers
 * used jhash function of kernel api
 */

static unsigned int hash_it(unsigned int saddr, unsigned int daddr,
                                unsigned int source, unsigned int dest,
                                unsigned int ssrc)
{
        unsigned int ret = HASH_PRIME;
        ret += ((jhash_2words(saddr, daddr, HASH_PRIME) % HASH_PRIME) *
                (jhash_2words(source, dest, HASH_PRIME) % HASH_PRIME) *
                (jhash_2words(saddr, ssrc, HASH_PRIME) % HASH_PRIME)) % HASH_PRIME;
        return (ret % HASH_PRIME);
}


/*
 * Searches in a certain index of hash table for a data
 * returns NULL if not found else returns pointer of that element in the table
 */

struct queue_data * search_table(unsigned int hash_index, struct queue_data *new_data)
{
        /* Taking a new queue pointer. Which will be pointing to the queue represented
         * by new_data at last. */
        struct queue_data *ret;
        /* First initializing it with first queue on the list */
        ret = table[hash_index].next;
        /* Iterating through the list to find the desired queue */
        while(ret != NULL) {
                /* Checking if current queue matches our criteria */
                if(ret->saddr == new_data->saddr &&
                        ret->daddr == new_data->daddr &&
                        ret->dest == new_data->dest &&
                        ret->ssrc == new_data->ssrc) {
                        /* It matched. So I can return it */
                        return ret;
                }
                /* It didn't match so I need to go to next queue */
                ret = ret->next;
        }

        /* No queue matched out criteria. Because if it matched it would have not
         * come this far. It would have returned before.
         * So I need to return a NULL. Now value of 'ret' is NULL.
         * I can return 'ret'
         */
        return ret;
}


/*
 * Two parameters: hash table index of the queue, pointer to the new queue which will be inserted
 * It will insert new queue at first of the linked list of queues to do it in O(1)[constant] complexity
 */

void insert_data(unsigned int hash_index, struct queue_data *new_data)
{
        /* Setting 'next' pointer of the new queue to the first queue in the list */
        new_data->next = table[hash_index].next;
        new_data->prev = &table[hash_index];
        /* Resetting 'next' pointer of the hash table element of given index to the new queue */
        table[hash_index].next = new_data;
        if(new_data->next != NULL) new_data->next->prev = new_data;
}


/*
 * Two parameters: where to keep, what to keep.
 * Provided above two parameters this function will add
 * data from new_data->buffer to the end of ptr->buffer
 */

void save_data(struct queue_data *ptr, struct queue_data *new_data)
{
        /* Copying data from new_data->buffer to ptr->buffer */
        memcpy(ptr->buffer+ptr->buff_ptr, new_data->buffer, new_data->buff_ptr);
        /* Copying time */
        ptr->tim = new_data->tim;
        ptr->parsed_tim = new_data->parsed_tim;
        /* Adjusting ptr->buff_ptr after copying */
        ptr->buff_ptr += new_data->buff_ptr;
}


/*
 * struct queue_data pointer have to be passed as parameter
 * It will get first DPTIME amount of data
 * from the buffer of provided queue_data and return it.
 */

void get_data(struct queue_data *ptr, unsigned char * temp)
{
        /* Sequence no is increased by 1 */
        ptr->sequence += 1;

        /* Time stamp is increased by DPTIME*8 */
        ptr->timestamp += DPTIME * 8;

        /* temp is taken to copy data of new pkt */
        //unsigned char temp[DPTIME];

        /* Data of new pkt is copied to temp from buffer. */
        memcpy(temp, ptr->buffer, DPTIME);

        /* Buffer is shifting its data forward
         * beacause first DPTIME data of buffer is copied
         * and no longer necessary.
         */
        memcpy(ptr->buffer, ptr->buffer+DPTIME, ptr->buff_ptr-DPTIME);

        /* Adjusting buff_ptr. Reducing DPTIME from current value.
         * Because first DPTIME is gone now.*/
        ptr->buff_ptr -= DPTIME;
}


/*
 * Returns 1 if difference between t1 and t2 is greater than 5 sec
 * Else 0
 */

static int diff_time_more_than_five_sec(struct tm t1, struct tm t2)
{
        if(t1.tm_year == t2.tm_year){
                int t1_sec = t1.tm_sec + t1.tm_min * 60 + t1.tm_hour * 3600 + t1.tm_yday * 86400;
                int t2_sec = t2.tm_sec + t2.tm_min * 60 + t2.tm_hour * 3600 + t2.tm_yday * 86400;
                if((t1_sec - t2_sec) > 5) return 1;
                else return 0;
        }
        else {
                return 0;
        }
        return 0;
}

/*
 * This function will collect garbage from hash table
 */

static int garbage_collector(void * ptr)
{
        int i = 0;
	while(1){
                i %=  HASH_PRIME;
                struct timeval t;
                struct tm broken;
                do_gettimeofday(&t);
                time_to_tm(t.tv_sec, 0, &broken);

                struct queue_data *temp = table[i].next;
                while(temp != NULL){
                        if(diff_time_more_than_five_sec(broken, temp->parsed_tim)){
                                temp->prev->next = temp->next;
                                if(temp->next != NULL) temp->next->prev = temp->prev;
                                struct queue_data *tt = temp;
                                temp = temp->next;
                                kfree(tt);
                        }
                        else{
                                temp = temp->next;
                        }
                }

                msleep(1);
                if(kthread_should_stop()) return 0;
                i++;
        }
}

/*
 * This function takes an checks if new packet is to be queued
 * or send. Takes an sk_buff as input and returns a queue pointer
 * if several packets are to be marged and sent. Otherwise returns NULL.
 */

static struct queue_data * pkt_queue(struct sk_buff *skb)
{
        /* Declaring necessary variables necessary for queing */
        struct iphdr *iph;
        struct udphdr *udph;
        struct rtphdr *rtph;
        unsigned char *data;
        unsigned int hash_index;
        unsigned int data_len;
        struct queue_data *new_data;
        struct queue_data *ptr;

        /* Parsing skb for all headers and data. */
        iph = (struct iphdr *) skb_header_pointer(skb, 0, 0, NULL);
        udph = (struct udphdr *) skb_header_pointer(skb, IP_HDR_LEN, 0, NULL);
        rtph = (struct rtphdr *) skb_header_pointer(skb, IP_HDR_LEN + UDP_HDR_LEN, 0, NULL);
        data = (unsigned char *) skb_header_pointer(skb, TOT_HDR_LEN, 0, NULL);
        data_len = skb->len - TOT_HDR_LEN;

        /* Getting hash index by hashing on five values */
        hash_index = hash_it(iph->saddr, iph->daddr, 54321, udph->dest, rtph->ssrc);

        /* Allocating and initializing a new queue.
         * If a queue corresponding to it already exists then it's data will
         * copied and this queue will be dropped.
         * Else this queue will be inserted to the hash table that manages the queues.
         */
	new_data = (struct queue_data *)kmalloc(sizeof(struct queue_data), GFP_ATOMIC);
        new_data->saddr = iph->saddr;
        new_data->daddr = iph->daddr;
        new_data->source = udph->source;
        new_data->dest = udph->dest;
        new_data->buff_ptr = data_len;
        memcpy(new_data->buffer, data, data_len);
        do_gettimeofday(&(new_data->tim));
        time_to_tm(new_data->tim.tv_sec, 0, &(new_data->parsed_tim));
        new_data->timestamp = rtph->ts;
        new_data->sequence = ntohs(rtph->sequence);
	new_data->ssrc = rtph->ssrc;
        new_data->next = NULL;
        new_data->prev = NULL;

        /* Search result of finding corresponding queue will be kept in this pointer.
         * If no queue found it will contain NULL.
         * Else if any queue found it will contain pointer to that queue
         */
	ptr = search_table(hash_index, new_data);

        /* Checking if found or not. */
        if(ptr == NULL){
                /* No queue found in the table. So it need to be inserted. */
                insert_data(hash_index, new_data);
                /*
		 * Checking if this queue has data greater than DPTIME.
                 * Though it won't happen at first insertion of queue data, it is taken for safety measure.
                 * If it exceeds DPTIME returning '0' as indicator. Else it is returning '1'.
                 */
                if(new_data->buff_ptr >= DPTIME){
                        return new_data;
                }
                else{
                        return NULL;
                }
        }
        else {
                /* A corresponding queue found. So saving data from this queue to that queue.*/
                save_data(ptr, new_data);
                /* 'new_data' need to be freed. Because new_data->buffer is already copied to respective queue
                 * and it no longer have any use
                 */
                kfree(new_data);
                if(ptr->buff_ptr >= DPTIME) {
                        return ptr;
                }
                else {
                        return NULL;
                }
        }
}

static inline bool ip_rcv_options(struct sk_buff *skb)
{
	struct ip_options *opt;
	const struct iphdr *iph;
	struct net_device *dev = skb->dev;

	if (skb_cow(skb, skb_headroom(skb))) {
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INDISCARDS);
		goto drop;
	}

	iph = ip_hdr(skb);
	opt = &(IPCB(skb)->opt);
	opt->optlen = iph->ihl*4 - sizeof(struct iphdr);

	if (ip_options_compile(dev_net(dev), opt, skb)) {
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INHDRERRORS);
		goto drop;
	}

	if (unlikely(opt->srr)) {
		struct in_device *in_dev = __in_dev_get_rcu(dev);

		if (in_dev) {
			if (!IN_DEV_SOURCE_ROUTE(in_dev)) {
			}
		}

		if (ip_options_rcv_srr(skb))
			goto drop;
	}

	return false;
drop:
	return true;
}

/* Modified ip_rcv_finish() --> ip_rcv_pkt() */

static int ip_rcv_pkt(struct sk_buff *skb)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct rtable *rt;

	if (sysctl_ip_early_demux && !skb_dst(skb)) {
		const struct net_protocol *ipprot;
		int protocol = iph->protocol;
	}

	/*
	 *	Initialise the virtual path cache for the packet. It describes
	 *	how the packet travels inside Linux networking.
	 */
	if (!skb_dst(skb)) {
		int err = ip_route_input_noref(skb, iph->daddr, iph->saddr,
					       iph->tos, skb->dev);
		if (unlikely(err)) {
			if (err == -EXDEV)
				NET_INC_STATS_BH(dev_net(skb->dev),
						 LINUX_MIB_IPRPFILTER);
			goto drop;
		}
	}

	if (iph->ihl > 5 && ip_rcv_options(skb))
		goto drop;

	rt = skb_rtable(skb);
	if (rt->rt_type == RTN_MULTICAST) {
		IP_UPD_PO_STATS_BH(dev_net(rt->dst.dev), IPSTATS_MIB_INMCAST,
				skb->len);
	} else if (rt->rt_type == RTN_BROADCAST)
		IP_UPD_PO_STATS_BH(dev_net(rt->dst.dev), IPSTATS_MIB_INBCAST,
				skb->len);

	return dst_input(skb);

drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}

/*
 * wraper function for list
 * to init the arry of list
 */

static void init_ps_list(struct ps_data *ptr,int n)
{
	int i;
	for(i=0;i<n;i++)
	{
		ptr[i].saddr = ptr[i].daddr = ptr[i].dest = ptr[i].ssrc = 0;
		INIT_LIST_HEAD(&ps_list[i].list);
	}
}

/*
 * add a new element to the tail of the list
 */

int ps_list_is_equal(struct ps_data *a,struct ps_data *b)
{
	return (a->saddr == b->saddr && a->daddr == b->daddr && a->dest == b->dest && a->ssrc == b->ssrc);
}

static void add_ps_list(struct ps_data *ptr,struct ps_data *var)
{
	struct ps_data *tmp;
	tmp=kmalloc(sizeof(struct ps_data),GFP_KERNEL);
	tmp->saddr = var->saddr;
	tmp->daddr = var->daddr;
	tmp->dest = var->dest;
	tmp->ssrc = var->ssrc;
	tmp->sequence = tmp->ts = -1;
	list_add_tail(&(tmp->list),&(ptr->list));
}

/*
 *shear for a match in the list (ip & port)
 */

static struct ps_data * search_ps_list(struct ps_data *ptr,struct ps_data *var)
{
	struct ps_data *tmp;
	list_for_each_entry(tmp,&(ptr->list),list)
	{

		if(ps_list_is_equal(tmp,var))
			return tmp;
	}
	return NULL;
}

/*
 *delete all an elemnt from the list
 *with ip=var.ip and port=var.port
 */

static int delete_ps_list_element(struct ps_data *ptr,struct ps_data *var)
{
	struct ps_data *tmp;
	tmp=search_ps_list(ptr,var);
	if(tmp)
	{
		list_del(&(tmp->list));
		kfree(tmp);
		return 1;
	}
	return 0;
}

static void ps_clean_list(struct ps_data *ptr){
	int i;
	struct ps_data *tmp1,*tmp2;

	for(i = 0; i < MY_PRIME ; i++){
		list_for_each_entry_safe(tmp1,tmp2,&(ptr[i].list),list){
			if(time_before(jiffies, tmp1->current_t)){
				list_del(&(tmp1->list));
				kfree(tmp1);
				printk(KERN_INFO "\none element has been freed.\n");
			}
		}
	}
}

/*
 *delete all the elements in the list
 */

static void delete_ps_list(struct ps_data *ptr)
{
	struct ps_data *tmp1,*tmp2;
	list_for_each_entry_safe(tmp1,tmp2,&(ptr->list),list)
	{
		list_del(&(tmp1->list));
		kfree(tmp1);
	}
}

static void ps_clean_all_list_element(struct ps_data *ptr)
{
	int i;
	for(i = 0 ; i < MY_PRIME ; i++){
		delete_ps_list(&ptr[i]);
	}
}


/*
 *returns a hashing index for the hash map
 */

static u32 ps_hash_func(struct ps_data *var)
{
	return ( jhash_2words(var->saddr,var->daddr,MY_PRIME)%MY_PRIME * jhash_2words(var->dest,var->ssrc,MY_PRIME)%MY_PRIME ) % MY_PRIME;
}

/*
 *maintens a hash map
 */

static struct ps_data * ps_hash_map(struct ps_data *ptr,struct ps_data *var)
{
	int idx;
	struct ps_data *tmp;
	idx=(int)ps_hash_func(var);
	tmp=search_ps_list(&ptr[idx],var);
	if(tmp==NULL)
	{
		add_ps_list(&ptr[idx],var);
		tmp = search_ps_list(&ptr[idx], var);
		return tmp;
	}
	else {
		return tmp;
	}
}

static void split_pkt(struct sk_buff *skb, struct sk_buff ** splited_skb,const struct xt_OBSF_tginfo *info) {
	int i;
	unsigned char *data,*new_data;
	unsigned int data_len, current_data_len;
	int offset, len;
	struct ps_data *maped_info, inp;
	struct iphdr *iph, *new_iph;
	struct udphdr *udph, *new_udph;
	struct rtphdr *rtph, *new_rtph;


	iph = (struct iphdr *) skb_header_pointer(skb, 0, 0, NULL);
	udph = (struct udphdr *) skb_header_pointer(skb, IP_HDR_LEN, 0, NULL);
	rtph = (struct rtphdr *) skb_header_pointer(skb, IP_HDR_LEN + UDP_HDR_LEN, 0, NULL);
	inp.saddr = ntohl(iph->saddr);
	inp.daddr = ntohl(iph->daddr);
	inp.dest = ntohl(udph->dest);
	inp.ssrc = ntohl(rtph->ssrc);

	data_len = skb->len - TOT_HDR_LEN;
	
	maped_info = ps_hash_map(ps_list,&inp);
	if(maped_info->sequence == -1 || maped_info->ts == -1)
	{
		maped_info->sequence = ntohs(rtph->sequence);
	}
	maped_info->ts = ntohl(rtph->ts) - data_len*8 + info->split_ptime*8;


	maped_info->current_t = jiffies + PS_CLEAN_TIME*HZ;

	data = (unsigned char *) skb_header_pointer(skb,TOT_HDR_LEN, 0, NULL);

	for(i=0, current_data_len = data_len; current_data_len >= info->split_ptime ; i++, current_data_len -= info->split_ptime )
	{
		splited_skb[i] = skb_copy(skb, GFP_ATOMIC);
		new_data = (unsigned char *) skb_header_pointer(splited_skb[i], TOT_HDR_LEN, 0, NULL);
		memcpy(new_data, data + i*info->split_ptime, info->split_ptime);
		memset(new_data + info->split_ptime, 0, data_len - info->split_ptime);

		new_iph = (struct iphdr *) skb_header_pointer(splited_skb[i], 0, 0, NULL);
		new_udph = (struct udphdr *) skb_header_pointer(splited_skb[i], IP_HDR_LEN, 0, NULL);
		new_rtph = (struct rtphdr *) skb_header_pointer(splited_skb[i], IP_HDR_LEN + UDP_HDR_LEN, 0, NULL);
		splited_skb[i]->tail -= (data_len - info->split_ptime);

		/*
		 * chage length
		 */

		splited_skb[i]->len = skb->len - (data_len - info->split_ptime );
		new_iph->tot_len = htons( ntohs(iph->tot_len) - (data_len - info->split_ptime) );
		new_udph->len = htons( ntohs(udph->len) - (data_len - info->split_ptime) );

		/*
		 * iph checksum
		 */

		new_iph->check = 0;
		ip_send_check (new_iph);

		/*
		 * Rulling out the upd checksum
		 */

		new_udph->check = 0;

		/*
		 * ts & sequence number calculation
		 */

		new_rtph->sequence = htons(maped_info->sequence);
		maped_info->sequence++;
		new_rtph->ts = htonl(maped_info->ts);
		maped_info->ts += info->split_ptime*8;

	}
	if(current_data_len > 0)
	{

		splited_skb[i] = skb_copy(skb, GFP_ATOMIC);
		new_data = (unsigned char *) skb_header_pointer(splited_skb[i], TOT_HDR_LEN, 0, NULL);
		memcpy(new_data, data + i*info->split_ptime, current_data_len);
		memset(new_data + current_data_len, 0, data_len - current_data_len);

		new_iph = (struct iphdr *) skb_header_pointer(splited_skb[i], 0, 0, NULL);
		new_udph = (struct udphdr *) skb_header_pointer(splited_skb[i], IP_HDR_LEN, 0, NULL);
		new_rtph = (struct rtphdr *) skb_header_pointer(splited_skb[i], IP_HDR_LEN + UDP_HDR_LEN, 0, NULL);
		splited_skb[i]->tail -= (data_len - current_data_len);
		/*
		 * chage length
		 */
		splited_skb[i]->len = skb->len - (data_len - current_data_len );
		new_iph->tot_len = htons( ntohs(iph->tot_len) - (data_len - current_data_len) );
		new_udph->len = htons( ntohs(udph->len) - (data_len - current_data_len) );
		/*
		 * iph checksum
		 */
		new_iph->check = 0;
		ip_send_check (new_iph);
		/*
		 * updh checksum
		 */
		new_udph->check = 0;
		offset = skb_transport_offset(splited_skb[i]);
		len = splited_skb[i]->len - offset;
		new_udph->check = ~csum_tcpudp_magic((new_iph->saddr), (new_iph->daddr), len, IPPROTO_UDP, 0);

		/*
		 * ts & sequence number calculation
		 */
		new_rtph->sequence = htons(maped_info->sequence);
		maped_info->sequence++;
		new_rtph->ts = htonl(maped_info->ts);
		maped_info->ts += current_data_len*8;
		i++;

	}
	splited_skb[i] = NULL;
}

/*
 * cleanup function
 *
 */

static struct task_struct *ps_thread;

int ps_clean_up_fn(void *vp) {
	unsigned long j0,j1;
	int delay = PS_CLEAN_TIME*HZ;
	while(1){
		j0 = jiffies;
		j1 = j0 + delay;
		while (time_before(jiffies, j1)){
			if(kthread_should_stop())
				return 0;
			schedule();
		}
		ps_clean_list(ps_list);
		if(kthread_should_stop())
			return 0;
	}
	return 0;
}

int ps_thread_init (void) {
    char  our_thread[20]="ps_clean_thread";

    ps_thread = kthread_create(ps_clean_up_fn,NULL,our_thread);
    if((ps_thread))
        {
		wake_up_process(ps_thread);
        }

    return 0;
}

/* The padding function */

void pad_data(struct sk_buff *skb)
{
	struct iphdr *iph;
	struct udphdr *udph;
	struct rtphdr *rtph;
	unsigned char *data;
	unsigned int data_len;

	iph = (struct iphdr *) skb_header_pointer(skb, 0, 0, NULL);
	udph = (struct udphdr *) skb_header_pointer(skb, IP_HDR_LEN, 0, NULL);
	rtph = (struct rtphdr *) skb_header_pointer(skb, IP_HDR_LEN + UDP_HDR_LEN, 0, NULL);
	data = (unsigned char *) skb_header_pointer(skb, TOT_HDR_LEN, 0, NULL);
	data_len = skb->len - TOT_HDR_LEN;

	if ((rtph->version == 2) && (rtph->pt == G729)) {

		struct sk_buff *newskb;
		struct iphdr *newiph;
		struct udphdr *newudph;
		unsigned char *newdata;
		unsigned int newdata_len;

		newskb = skb_copy_expand(skb, 16, 512, GFP_ATOMIC);
		newiph = (struct iphdr *) skb_header_pointer(newskb, 0, 0, NULL);
		newudph = (struct udphdr *) skb_header_pointer(newskb, IP_HDR_LEN, 0, NULL);
		newdata = (unsigned char *) skb_header_pointer(newskb, IP_HDR_LEN +  UDP_HDR_LEN, 0, NULL);
		newdata_len = data_len + RTP_HDR_LEN;

		__u8 pad_len = PAD_LEN;
		unsigned char extra_data[pad_len];
		int i;

		for (i=0; i<pad_len; i++) {
			extra_data[i] = i;
		}

		extra_data[0] = pad_len;

		unsigned char *temp;
		unsigned int temp_len;

		temp_len = newdata_len + pad_len;

		temp = kmalloc(sizeof(char) * temp_len, GFP_KERNEL);
		memcpy(temp, extra_data, pad_len);

		unsigned char *ptr;
		ptr = temp + pad_len;
		memcpy(ptr, newdata, newdata_len);

		skb_put(newskb, pad_len);
		memcpy(newdata, temp, temp_len);

		newiph->tot_len = htons(ntohs(newiph->tot_len) + pad_len);
		newudph->len = htons(ntohs(newudph->len) + pad_len);

		newiph->check = 0;
		ip_send_check(newiph);
		newudph->check = 0;

		struct sk_buff *tempskb = skb_copy(skb, GFP_ATOMIC);
		*tempskb = *skb;
		*skb = *newskb;
		*newskb = *tempskb;

		kfree_skb(newskb);
		kfree(temp);
	}
}

/* The depadding function */

static void dpad_data(struct sk_buff *skb)
{
	struct iphdr *iph;
	struct udphdr *udph;
	struct rtphdr *rtph;
	unsigned char *data;
	unsigned int data_len;

	iph = (struct iphdr *) skb_header_pointer(skb, 0, 0, NULL);
	udph = (struct udphdr *) skb_header_pointer(skb, IP_HDR_LEN, 0, NULL);
	data = (unsigned char *) skb_header_pointer(skb, IP_HDR_LEN + UDP_HDR_LEN, 0, NULL);
	data_len = skb->len - IP_HDR_LEN - UDP_HDR_LEN;

	unsigned char *temp;
	unsigned int  pad_len;
	unsigned char *ptr;
	unsigned int temp_len;

	pad_len = data[0];

	if (pad_len < data_len) {
		temp_len = data_len - pad_len;
	}
	else temp_len = data_len + pad_len;

	if (temp_len < data_len) {
		temp = kmalloc(sizeof(char) * temp_len, GFP_KERNEL);

		ptr = &data[pad_len];
		memcpy(temp, ptr, temp_len);

		rtph = (struct rtphdr *) temp;

		if ((rtph->version == 2) && (rtph->pt == G729)) {
			memcpy(data, temp, temp_len);

			skb->len = skb->len - pad_len;
			skb->tail = skb->tail - pad_len;

			iph->tot_len = htons(ntohs(iph->tot_len) - pad_len);
			udph->len = htons(ntohs(udph->len) - pad_len);

			iph->check = 0;
			ip_send_check(iph);
			udph->check = 0;
		}
		kfree(temp);
	}
	else {
	}
}

/* The encrypt_data function */
static inline void encrypt_data(struct sk_buff *skb, struct xt_OBSF_tginfo *info)
{
	struct iphdr *iph;
	struct udphdr *udph;
	unsigned char *data;
	unsigned int data_len;

	iph = (struct iphdr *) skb_header_pointer(skb, 0, 0, NULL);
	udph = (struct udphdr *) skb_header_pointer(skb, IP_HDR_LEN, 0, NULL);
	data = (unsigned char *) skb_header_pointer(skb, IP_HDR_LEN + UDP_HDR_LEN, 0, NULL);
	data_len = skb->len - IP_HDR_LEN - UDP_HDR_LEN;

	struct blkcipher_desc desc;
	struct scatterlist sg;
	unsigned int iv_len;

	if (info->flags & XT_OBSF_PKT_SIP) {
		iv_len = crypto_blkcipher_ivsize(info->priv->tfm_sip);

		__u8 iv[iv_len];

		memset(iv, 0xff, iv_len);

		crypto_blkcipher_set_iv(info->priv->tfm_sip, iv, iv_len);
		crypto_blkcipher_setkey(info->priv->tfm_sip, info->sip_key, info->sip_key_len);

		desc.tfm = info->priv->tfm_sip;
		desc.flags = 0;
	}
	else if (info->flags & XT_OBSF_PKT_RTP) {
		iv_len = crypto_blkcipher_ivsize(info->priv->tfm_rtp);

		__u8 iv[iv_len];

		memset(iv, 0xff, iv_len);

		crypto_blkcipher_set_iv(info->priv->tfm_rtp, iv, iv_len);
		crypto_blkcipher_setkey(info->priv->tfm_rtp, info->rtp_key, info->rtp_key_len);

		desc.tfm = info->priv->tfm_rtp;
		desc.flags = 0;
	}

	sg_init_one(&sg, data, data_len);
	crypto_blkcipher_encrypt(&desc, &sg, &sg, data_len);

	iph->check = 0;
	ip_send_check(iph);
	udph->check = 0;
}

/* The decrypt_data function */
static inline void decrypt_data(struct sk_buff *skb, struct xt_OBSF_tginfo *info)
{
	struct iphdr *iph;
	struct udphdr *udph;
	unsigned char *data;
	unsigned int data_len;

	iph = (struct iphdr *) skb_header_pointer(skb, 0, 0, NULL);
	udph = (struct udphdr *) skb_header_pointer(skb, IP_HDR_LEN, 0, NULL);
	data = (unsigned char *) skb_header_pointer(skb, IP_HDR_LEN + UDP_HDR_LEN, 0, NULL);
	data_len = skb->len - IP_HDR_LEN - UDP_HDR_LEN;

	struct blkcipher_desc desc;
	struct scatterlist sg;
	unsigned int iv_len;

	if (info->flags & XT_OBSF_PKT_SIP) {
		iv_len = crypto_blkcipher_ivsize(info->priv->tfm_sip);

		__u8 iv[iv_len];

		memset(iv, 0xff, iv_len);

		crypto_blkcipher_set_iv(info->priv->tfm_sip, iv, iv_len);
		crypto_blkcipher_setkey(info->priv->tfm_sip, info->sip_key, info->sip_key_len);

		desc.tfm = info->priv->tfm_sip;
		desc.flags = 0;
	}
	else if (info->flags & XT_OBSF_PKT_RTP) {
		iv_len = crypto_blkcipher_ivsize(info->priv->tfm_rtp);

		__u8 iv[iv_len];

		memset(iv, 0xff, iv_len);

		crypto_blkcipher_set_iv(info->priv->tfm_rtp, iv, iv_len);
		crypto_blkcipher_setkey(info->priv->tfm_rtp, info->rtp_key, info->rtp_key_len);

		desc.tfm = info->priv->tfm_rtp;
		desc.flags = 0;
	}

	sg_init_one(&sg, data, data_len);
	crypto_blkcipher_decrypt(&desc, &sg, &sg, data_len);

	iph->check = 0;
	ip_send_check(iph);
	udph->check = 0;
}

/*
 * Call this checksumming function only if you are sure the
 * module will be loaded on a VM. Otherwise ignore it.
 * So, before building the module, take care about the
 * machine, if VM, then leave alone the code, but if it is
 * on main machine, then comment out the lines which contains
 * the following function --> udp4_hwcsum();
 */

void udp4_hwcsum(struct sk_buff *skb, __be32 src, __be32 dst)
{
	struct udphdr *uh = udp_hdr(skb);
	struct sk_buff *frags = skb_shinfo(skb)->frag_list;
	int offset = skb_transport_offset(skb);
	int len = skb->len - offset;
	int hlen = len;
	__wsum csum = 0;

	if (!frags) {
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct udphdr, check);
		uh->check = ~csum_tcpudp_magic(src, dst, len, IPPROTO_UDP, 0);
	} else {
		do {
			csum = csum_add(csum, frags->csum);
			hlen -= frags->len;
		} while ((frags = frags->next));

		csum = skb_checksum(skb, offset, hlen, csum);
		skb->ip_summed = CHECKSUM_NONE;
		uh->check = csum_tcpudp_magic(src, dst, len, IPPROTO_UDP, csum);

	if (uh->check == 0)
		uh->check = CSUM_MANGLED_0;
	}
}

/*
 * This is obsf_tg --> The target function.
 * When new packet is got according to the rule, this function is invoked
 * at first.
 */

static unsigned int obsf_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct iphdr	*iph;
	struct udphdr	*udph;
	struct rtphdr	*rtph;
	unsigned char	*data;
	unsigned int	data_len;

	const struct xt_OBSF_tginfo *info = (void *) par->targinfo;

	if (skb_linearize (skb) < 0)
		return NF_DROP;
	
	iph = (struct iphdr *) skb_header_pointer(skb, 0, 0, NULL);
	udph = (struct udphdr *) skb_header_pointer(skb, IP_HDR_LEN, 0, NULL);

	/* Checking for SIP packet */
	if (info->flags & XT_OBSF_PKT_SIP){
		data = (unsigned char *) skb_header_pointer(skb, IP_HDR_LEN + UDP_HDR_LEN, 0, NULL);
		data_len = skb->len - IP_HDR_LEN - UDP_HDR_LEN;

		/* For INWARD SIP Packets */
		if (par->hooknum == NF_INET_PRE_ROUTING) {
			if (info->flags & XT_OBSF_ENC_ENABLED_SIP){
				if (info->flags & XT_OBSF_ENC_DEC_SIP) {
					// Call the DECRYPTION engine appropriately
					decrypt_data(skb, info);
				}
			}
		}
		/* For OUTWARD SIP packets */
		else if (par->hooknum == NF_INET_LOCAL_OUT) {
			if (info->flags & XT_OBSF_ENC_ENABLED_SIP) {
				if (info->flags & XT_OBSF_ENC_ENC_SIP) {
					// Call the ENCRYPTION engine appropriately
					encrypt_data(skb, info);
					udp4_hwcsum(skb, iph->saddr, iph->daddr); // Comment out if on Real machine
				}
			}
		}
	}
	else if(info->flags & XT_OBSF_PKT_RTP){ /* Checking for RTP packet */

		/* For INWARD RTP packets in PRE_ROUTING */
		if (par->hooknum == NF_INET_PRE_ROUTING) {
			if (info->flags & XT_OBSF_ENC_ENABLED_RTP){
				if (info->flags & XT_OBSF_ENC_DEC_RTP){
					// Call the DECRYPTION engine appropriately
					decrypt_data(skb, info);
				}
			}

			rtph = (struct rtphdr *) skb_header_pointer (skb, IP_HDR_LEN + UDP_HDR_LEN, 0, NULL);
			data = (unsigned char *) skb_header_pointer (skb, TOT_HDR_LEN, 0, NULL);
			data_len = skb->len - TOT_HDR_LEN;

			if (info->flags & XT_OBSF_PAD_ENABLED_RTP) {
				if (info->flags & XT_OBSF_PAD_RPAD) {
					// Call the DEPADDING function appropriately
					dpad_data(skb);
				}
			}

			if (rtph->pt == G729) {
				if (info->flags & XT_OBSF_PTIME_ENABLED_RTP) {
					// Call the splitting function and adjust the conditions!
					struct sk_buff *splited_skb[15];
					split_pkt(skb,splited_skb,info);

					int i;
					for(i=0; splited_skb[i]!=NULL ; i++);

					int small_len;
					small_len = i;

					for (i=0; i<small_len; i++){
						ip_rcv_pkt(splited_skb[i]);
					}
					return NF_DROP;
				}
			}
		}
		/* For OUTWARD RTP packets */
		else if (par->hooknum == NF_INET_LOCAL_OUT) {
			rtph = (struct rtphdr *) skb_header_pointer(skb, IP_HDR_LEN + UDP_HDR_LEN, 0, NULL);
			data = (unsigned char *) skb_header_pointer(skb, TOT_HDR_LEN, 0, NULL);
			data_len = skb->len - TOT_HDR_LEN;

			/* Padding and ptime modification will work only on g729 packets */
			if(rtph->pt ==  G729) {
				if (info->flags & XT_OBSF_PTIME_ENABLED_RTP) {
					// Call the merging function and adjust the conditions!
					struct queue_data * ptr = pkt_queue(skb);

					if(ptr == NULL){
						return NF_DROP;
					}
					else{
						unsigned char * temp = (unsigned char * ) kmalloc(300 * sizeof(char), GFP_ATOMIC);
						get_data(ptr, temp);

						struct sk_buff *newskb;
						struct iphdr *newiph;
						struct udphdr *newudph;
						struct rtphdr *newrtph;
						unsigned char *newdata;

						newskb = skb_copy_expand(skb, 16, TOT_HDR_LEN + DPTIME + 100,GFP_ATOMIC);
						newiph = (struct iphdr *) skb_header_pointer(newskb, 0, 0, NULL);
						newudph = (struct udphdr *) skb_header_pointer(newskb, IP_HDR_LEN, 0, NULL);
						newrtph = (struct rtphdr *) skb_header_pointer(newskb, IP_HDR_LEN + UDP_HDR_LEN, 0, NULL);
						newdata = (unsigned char *) skb_header_pointer(newskb, TOT_HDR_LEN, 0, NULL);

						newrtph->sequence = htons(ptr->sequence - 1);

						skb_put(newskb, DPTIME - (skb->len - TOT_HDR_LEN));
						memcpy(newdata, temp, DPTIME);

						newiph->tot_len = htons(DPTIME + TOT_HDR_LEN);
						newudph->len = htons(DPTIME + UDP_HDR_LEN + RTP_HDR_LEN);


						/* Calculation of IP header checksum */
						newiph->check = 0;
						ip_send_check (newiph);

						/* Calculation of UDP checksum */
						newudph->check = 0;
						udp4_hwcsum(newskb, newiph->saddr, newiph->daddr);
						// Comment out the above line if on real machine

						struct sk_buff *tempskb = skb_copy(newskb, GFP_ATOMIC);

						*tempskb = *skb;
						*skb = *newskb;
						*newskb = *tempskb;

						iph = skb_header_pointer(skb, 0, 0, NULL);
						udph = skb_header_pointer(skb, IP_HDR_LEN, 0, NULL);
						rtph = skb_header_pointer(skb, IP_HDR_LEN + UDP_HDR_LEN, 0, NULL);
						data = skb_header_pointer(skb, TOT_HDR_LEN, 0, NULL);
						data_len = DPTIME;

						kfree_skb(newskb);
						kfree(temp);

					}
				}

				if (info->flags & XT_OBSF_PAD_ENABLED_RTP) {
					if (info->flags & XT_OBSF_PAD_APAD) {
						pad_data(skb);
						iph = (struct iphdr *) skb_header_pointer(skb, 0, 0, NULL);
						udp4_hwcsum(skb, iph->saddr, iph->daddr);
						// Comment out the last line if on real machine
					}
				}
			}

			if (info->flags & XT_OBSF_ENC_ENABLED_RTP) {
				if (info->flags & XT_OBSF_ENC_ENC_RTP) {
					// Call the ENCRYPTION engine appropriately
					encrypt_data(skb, info);
					iph = (struct iphdr *) skb_header_pointer(skb, 0, 0, NULL);
					udp4_hwcsum(skb, iph->saddr, iph->daddr);
					// Comment out the last line if on real machine
				}
			}
		}
	}

	return NF_ACCEPT;
}

static int obsf_tg_check(const struct xt_tgchk_param *par)
{
	struct xt_OBSF_tginfo *info = (void *) par->targinfo;
	/* Allocate and initialize private data structure */
	struct xt_obsf_priv *priv = kzalloc(sizeof(*priv), GFP_KERNEL);

	DPTIME = info->merge_ptime;

	if (info->flags & XT_OBSF_ENC_ENABLED_SIP) {
		if (info->flags & (XT_OBSF_ENC_ENC_SIP | XT_OBSF_ENC_DEC_SIP)) {
			printk(KERN_ALERT "SIP encryption enabled.\n");
			priv->tfm_sip = crypto_alloc_blkcipher("ecb(arc4)", 0, CRYPTO_ALG_ASYNC);

			if (priv->tfm_sip != NULL) {
				printk(KERN_ALERT "tfm_sip allocation done successfully\n");
				unsigned char *name = crypto_blkcipher_name (priv->tfm_sip);
				printk(KERN_ALERT "SIP encryption algorithm name: %s\n", name);
				crypto_blkcipher_alg(priv->tfm_sip)->ivsize = 256;
			}
			else
				printk(KERN_ALERT "tfm_sip allocation failed.\n");
		}
	}

	else if (info->flags & XT_OBSF_ENC_ENABLED_RTP) {
		if (info->flags & (XT_OBSF_ENC_ENC_RTP | XT_OBSF_ENC_DEC_RTP)) {
			printk(KERN_ALERT "RTP encryption enabled.\n");
			priv->tfm_rtp = crypto_alloc_blkcipher("ecb(arc4)", 0, CRYPTO_ALG_ASYNC);

			if (priv->tfm_rtp != NULL) {
				printk(KERN_ALERT "tfm_rtp allocation done successfully\n");
				unsigned char *name = crypto_blkcipher_name (priv->tfm_rtp);
				printk(KERN_ALERT "RTP encryption algorithm name: %s\n", name);
				crypto_blkcipher_alg(priv->tfm_rtp)->ivsize = 256;
			}
			else
				printk(KERN_ALERT "tfm_rtp allocation failed.\n");
		}
	}

	info->priv = priv;
	priv->info = info;

	return 0;

	/* failover */

	fail_sip:
	if (priv) {
		if (priv->tfm_sip)
			crypto_free_blkcipher(priv->tfm_sip);
		kfree(priv);
	}
	info->priv = NULL;
	return -ENOMEM;

	fail_rtp:
	if (priv) {
		if (priv->tfm_rtp)
			crypto_free_blkcipher(priv->tfm_rtp);
		kfree(priv);
	}
	info->priv = NULL;
	return -ENOMEM;
}

static struct xt_target obsf_tg_reg __read_mostly = {

		.name		= "OBSF",
		.revision	= 0,
		.family		= NFPROTO_IPV4,
		.proto		= IPPROTO_UDP,
		.table		= "mangle",
		.hooks		= (1 << NF_INET_LOCAL_IN) |
				  (1 << NF_INET_PRE_ROUTING) |
				  (1 << NF_INET_LOCAL_OUT) |
				  (1 << NF_INET_POST_ROUTING),
		.target		= obsf_tg,
		.checkentry	= obsf_tg_check,
		.targetsize	= sizeof(struct xt_OBSF_tginfo),
		.me		= THIS_MODULE,
};

static int __init obsf_tg_init(void)
{
	// Module initialization
	ps_list = kmalloc(sizeof(struct ps_data)*MY_PRIME, GFP_KERNEL);
	init_ps_list(ps_list,MY_PRIME);
	ps_thread_init();

	int i;
	for(i = 0; i < HASH_PRIME; i++){
		table[i].next = NULL;
	}
	ts = kthread_run(&garbage_collector, NULL, "Garbage collector thread");
	/* Threads are already initialized above */

	printk(KERN_ALERT "\n\nOBSF module loaded\n\n");
	return xt_register_target(&obsf_tg_reg);
}

static void __exit obsf_tg_exit(void)
{
	// For cleaning threads in splitting rtp packets
	kthread_stop(ps_thread);
	ps_clean_all_list_element(ps_list);

	// For cleaning threads in merging rtp packets
	kthread_stop(ts);
	int i = 0;
	while(i < HASH_PRIME){
		struct queue_data *temp = table[i].next;
		while(temp != NULL){
			temp->prev->next = temp->next;
			temp->next->prev = temp->prev;
			struct queue_data *tt = temp;
			temp = temp->next;
			kfree(tt);
		}
		i++;
	}

	// Module unloading
	printk(KERN_ALERT "\n\nOBSF module unloaded\n\n");
	xt_unregister_target(&obsf_tg_reg);
}

module_init(obsf_tg_init);
module_exit(obsf_tg_exit);

MODULE_AUTHOR("Bansberry Server Team: Konok, Arif, Ovi");
MODULE_DESCRIPTION("Xtables: obsfuscation of UDP traffic");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_OBSF");
MODULE_ALIAS("ip6t_OBSF");
