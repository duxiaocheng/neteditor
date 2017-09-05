/* NetfilterQueue Demo
 *
 * Usage:
 * =====
 *    # make
 *    # iptables -I OUTPUT -p udp --dport 50001 -j NFQUEUE --queue-num 0
 *    # ./nf_queue_test
 *    [server]# nc -u -l 50001
 *    [client]# nc -u 10.9.245.200 50001
 *    hello world
 *    change # this package will be change to hack!
 *    bad # this pakcage will be filted!
 *    # iptables -D OUTPUT -p udp --dport 50001 -j NFQUEUE --queue-num 0
 *
 * Reference:
 * =========
 *    http://netfilter.org/projects/libnetfilter_queue/
 *    http://blog.csdn.net/cheng_fangang/article/details/10960221
 *    https://git.netfilter.org/libnetfilter_queue/
 *    http://blog.csdn.net/prahs/article/details/55259094
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <asm/byteorder.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/ip.h>
#include <linux/udp.h>

#ifdef __LITTLE_ENDIAN
#define IPQUAD(addr)                           \
  ((unsigned char *)&addr)[0],                 \
  ((unsigned char *)&addr)[1],                 \
  ((unsigned char *)&addr)[2],                 \
  ((unsigned char *)&addr)[3]
#else
#define IPQUAD(addr)                           \
  ((unsigned char *)&addr)[3],                 \
  ((unsigned char *)&addr)[2],                 \
  ((unsigned char *)&addr)[1],                 \
  ((unsigned char *)&addr)[0]
#endif

/* dump memory data in the hex format */
static void dump_data(const void* data, size_t len)
{
  unsigned int i = 0;
  unsigned int j = 0;
  const unsigned char *pdata = (const unsigned char *)data;
  const int max_ch_of_line = 16;
  for (i = 0; i < len; i += max_ch_of_line) {
    char buf_0x[128] = {0};
    char buf_ch[128] = {0};
    for (j = 0; j < max_ch_of_line; j++) {
      snprintf(buf_0x + strlen(buf_0x), sizeof(buf_0x) - strlen(buf_0x) - 1, 
          "%02x ", (*pdata & 0xff)); /* avoid 0xffffff09 */
      snprintf(buf_ch + strlen(buf_ch), sizeof(buf_ch) - strlen(buf_ch) - 1, 
          "%c", *pdata > 31 && *pdata <= 'z' ? *pdata : '.');
      pdata++;
    }
    printf("0x%x: %s %s\n", (pdata - 16), buf_0x, buf_ch);
    if (0 != i && i % 512 == 0) {
      printf("\n");
    }
  }
}

static u_int16_t checksum(u_int32_t init, u_int8_t *addr, size_t count){
  /* Compute Internet Checksum for "count" bytes
   * beginning at location "addr".
   */
  u_int32_t sum = init;

  while( count > 1 ) {
    /* This is the inner loop */
    sum += ntohs(* (u_int16_t*) addr);
    addr += 2;
    count -= 2;
  }
  /* Add left-over byte, if any */
  if( count > 0 )
    sum += * (u_int8_t *) addr;

  /* Fold 32-bit sum to 16 bits */
  while (sum>>16)
    sum = (sum & 0xffff) + (sum >> 16);

  return (u_int16_t)~sum;
}

static u_int16_t ip_checksum(struct iphdr* iphdrp) {
  return checksum(0, (u_int8_t*)iphdrp, iphdrp->ihl<<2);
}

static void set_ip_checksum(struct iphdr* iphdrp) {
  iphdrp->check = 0;
  iphdrp->check = htons(checksum(0, (u_int8_t*)iphdrp, iphdrp->ihl<<2));
}

static void set_udp_checksum(struct iphdr* iphdrp, struct udphdr* udphdrp) {
  size_t udplen = ntohs(udphdrp->len);
  u_int32_t cksum = 0;

  cksum += ntohs((iphdrp->saddr >> 16) & 0x0000ffff);
  cksum += ntohs(iphdrp->saddr & 0x0000ffff);
  cksum += ntohs((iphdrp->daddr >> 16) & 0x0000ffff);
  cksum += ntohs(iphdrp->daddr & 0x0000ffff);
  cksum += iphdrp->protocol & 0x00ff;
  cksum += udplen;

  udphdrp->check = 0;
  udphdrp->check = htons(checksum(cksum, (u_int8_t*)udphdrp, udplen));
}

static u_int32_t print_pkt (struct nfq_data *tb)
{
  int id = 0;
  struct nfqnl_msg_packet_hdr *ph;
  u_int32_t mark,ifi;
  char name[64] = {0};
  int ret;
  unsigned char *data;

  ph = nfq_get_msg_packet_hdr(tb);
  if (ph) {
    id = ntohl(ph->packet_id);
    printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
  }

  struct nfqnl_msg_packet_hw *hw = nfq_get_packet_hw(tb);
  if (hw) {
    printf(" %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x ",
        hw->hw_addr[0], hw->hw_addr[1], hw->hw_addr[2], hw->hw_addr[3],
        hw->hw_addr[4], hw->hw_addr[5], hw->hw_addr[6], hw->hw_addr[7]);
  }

  mark = nfq_get_nfmark(tb);
  if (mark)
    printf("mark=%u ", mark);

  ifi = nfq_get_indev(tb);
  if (ifi) {
    printf("indev=%u,%u ", ifi, nfq_get_physindev(tb));
  }

  ifi = nfq_get_outdev(tb);
  if (ifi) {
    printf("outdev=%u,%u ", ifi, nfq_get_physoutdev(tb));
  }

  ret = nfq_get_payload(tb, &data);
  if (ret >= 0)
    printf("payload_len=%d ", ret);
  fputc('\n', stdout);

  return id;
}

static size_t change_payload(struct iphdr* iphdrp, struct udphdr* udphdrp, const char* newdata)
{
    void *user_data = udphdrp + 1;
    size_t user_len = ntohs(udphdrp->len) - 8;

    printf("change udp user data!\n");
    const size_t newlen = strlen(newdata);
    const ssize_t difflen = newlen - user_len;
    if (newlen > user_len) {
      printf(" warning: new data len:%u is greater than old len:%u\n", newlen, user_len);
      printf("   peer end maybe can not receive this package!\n");
    }

    iphdrp->tot_len = htons(ntohs(iphdrp->tot_len) + difflen);
    set_ip_checksum(iphdrp);

    strncpy(user_data, newdata, newlen);
    udphdrp->len = htons(ntohs(udphdrp->len) + difflen);
    set_udp_checksum(iphdrp, udphdrp);

    dump_data(user_data, newlen);
    return newlen;
  }

static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
    struct nfq_data *nfa, void *data)
{
  (void)nfmsg;
  (void)data;
  u_int32_t id = 0;
  struct nfqnl_msg_packet_hdr *ph;
  unsigned char *pdata = NULL;
  int pdata_len;
  int verdict = NF_ACCEPT;

  // show package info
  print_pkt(nfa);

  ph = nfq_get_msg_packet_hdr(nfa);
  if (ph) {
    id = ntohl(ph->packet_id);
  }

  pdata_len = nfq_get_payload(nfa, (unsigned char**)&pdata);
  if(pdata_len == -1){
    pdata_len = 0;
  }

  struct iphdr *iphdrp = (struct iphdr *)pdata;

  printf("ip len %d, %d %u.%u.%u.%u ->", pdata_len, iphdrp->ihl<<2, IPQUAD(iphdrp->saddr));
  printf(" %u.%u.%u.%u %s", IPQUAD(iphdrp->daddr), getprotobynumber(iphdrp->protocol)->p_name);
  printf(" ipsum 0x%04x(%s)\n", ntohs(iphdrp->check), 0 == ip_checksum(iphdrp) ? "True" : "False");

  // change TTL
  printf("change ip ttl from %d to 32!\n", iphdrp->ttl);
  iphdrp->ttl = 32;
  set_ip_checksum(iphdrp);

  if (iphdrp->protocol == IPPROTO_UDP) {
    const size_t UDP_HEAD_LEN = 8;
    struct udphdr *udphdrp = (struct udphdr*)((u_int8_t*)iphdrp + (iphdrp->ihl<<2));
    printf("udp len %d, source %d -> dest %d\n", ntohs(udphdrp->len), ntohs(udphdrp->source), ntohs(udphdrp->dest));
    void *user_data = udphdrp + 1;
    size_t user_len = ntohs(udphdrp->len) - UDP_HEAD_LEN;
    dump_data(user_data, user_len);

    // change user payload
    if (strstr(user_data, "change")) {
      change_payload(iphdrp, udphdrp, "hack!\n");
    }

    // filter
    if (strstr(user_data, "bad")) {
      printf("this package will be dropped!\n");
      verdict = NF_DROP;
    }
  }

  return nfq_set_verdict_mark(qh, id, verdict, 1, (u_int32_t)pdata_len, pdata);
}

int main(int argc, char **argv){
  struct nfq_handle *h;
  struct nfq_q_handle *qh;
  struct nfnl_handle *nh;
  int fd;
  int rv;
  char buf[4096];

  h = nfq_open();
  if (!h) {
    perror("nfq_open error: ");
    exit(1);
  }

  if (nfq_unbind_pf(h, AF_INET) < 0) {
    perror("nfq_unbind_pf error: ");
    exit(1);
  }

  if (nfq_bind_pf(h, AF_INET) < 0) {
    perror("nfq_bind_pf error: ");
    exit(1);
  }

  int qid = 0;
  if(argc == 2){
    qid = atoi(argv[1]);
  }
  printf("binding this socket to queue %d\n", qid);
  qh = nfq_create_queue(h, qid, &callback, NULL);
  if (!qh) {
    perror("nfq_create_queue errror: ");
    exit(1);
  }

  if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
    perror("nfq_set_mode error: ");
    exit(1);
  }

  nh = nfq_nfnlh(h);
  fd = nfnl_fd(nh);

  while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
    nfq_handle_packet(h, buf, rv);
  }

  /* never reached */
  nfq_destroy_queue(qh);
  nfq_close(h);
  exit(0);
}

/* # ./nf_queue_test
 * binding this socket to queue 0
 * hw_protocol=0x0800 hook=3 id=1 outdev=2,0 payload_len=40 
 * ip len 40, 20 10.9.245.198 -> 10.9.245.200 udp ipsum 0x6ef1(True)
 * change ip ttl from 64 to 32!
 * udp len 20, source 34724 -> dest 50001
 * 0xd9c6bc00: 68 65 6c 6c 6f 20 77 6f 72 6c 64 0a 00 00 00 00  hello world.....
 * hw_protocol=0x0800 hook=3 id=2 outdev=2,0 payload_len=35 
 * ip len 35, 20 10.9.245.198 -> 10.9.245.200 udp ipsum 0x677a(True)
 * change ip ttl from 64 to 32!
 * udp len 15, source 34724 -> dest 50001
 * 0xd9c6bc00: 63 68 61 6e 67 65 0a 6f 72 6c 64 0a 00 00 00 00  change.orld.....
 * change udp user data!
 * 0xd9c6bc00: 68 61 63 6b 21 0a 0a 6f 72 6c 64 0a 00 00 00 00  hack!..orld.....
 * hw_protocol=0x0800 hook=3 id=3 outdev=2,0 payload_len=32 
 * ip len 32, 20 10.9.245.198 -> 10.9.245.200 udp ipsum 0x6375(True)
 * change ip ttl from 64 to 32!
 * udp len 12, source 34724 -> dest 50001
 * 0xd9c6bc00: 62 61 64 0a 21 0a 0a 6f 72 6c 64 0a 00 00 00 00  bad.!..orld.....
 * this package will be dropped!
 */

