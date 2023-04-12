#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac)
{
    // 判断数据包是否合法
    if (buf->len < sizeof(ip_hdr_t)) return;
    ip_hdr_t *ip_hdr_in = (ip_hdr_t *)buf->data;
    if (ip_hdr_in->version != IP_VERSION_4 ||
        ip_hdr_in->hdr_len < 5 ||
        swap16(ip_hdr_in->total_len16) > buf->len) return;
    // 检验校验和，不一致则丢弃，一致则恢复校验和字段
    uint16_t checksum_received = ip_hdr_in->hdr_checksum16;
    ip_hdr_in->hdr_checksum16 = 0;
    if (checksum_received != checksum16((uint16_t *)ip_hdr_in, ip_hdr_in->hdr_len * IP_HDR_LEN_PER_BYTE)) return;
    ip_hdr_in->hdr_checksum16 = checksum_received;
    // 检验数据包目标IP是否为本机IP
    if (memcmp(ip_hdr_in->dst_ip, net_if_ip, NET_IP_LEN) != 0) return;
    // 判断数据包是否存在填充，若是则剔除填充
    if (buf->len > swap16(ip_hdr_in->total_len16)) buf_remove_padding(buf, buf->len - swap16(ip_hdr_in->total_len16));
    // 识别协议，合法的包括ICMP=1,TCP=6,UDP=17，否则发送ICMP协议不可达
    if (ip_hdr_in->protocol == NET_PROTOCOL_UDP ||
        //ip_hdr_in->protocol == NET_PROTOCOL_TCP ||
        ip_hdr_in->protocol == NET_PROTOCOL_ICMP){
        // 去除IP报头，向上层传递数据包
        buf_remove_header(buf, ip_hdr_in->hdr_len * IP_HDR_LEN_PER_BYTE);
        net_in(buf, ip_hdr_in->protocol, ip_hdr_in->src_ip);
    } else {
        icmp_unreachable(buf, ip_hdr_in->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }
}

/**
 * @brief 处理一个要发送的ip分片
 * 
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    // 添加IP报头空间
    buf_add_header(buf, sizeof(ip_hdr_t));
    ip_hdr_t *ip_hdr_out = (ip_hdr_t *)buf->data;
    // 填充IP报头
    ip_hdr_out->version = IP_VERSION_4;
    ip_hdr_out->hdr_len = sizeof(ip_hdr_t) / IP_HDR_LEN_PER_BYTE;
    ip_hdr_out->tos = 0;
    ip_hdr_out->total_len16 = swap16(buf->len);
    ip_hdr_out->id16 = swap16(id);
    ip_hdr_out->flags_fragment16 = mf ? swap16(IP_MORE_FRAGMENT | (offset >> 3)) : swap16(offset >> 3);
    ip_hdr_out->ttl = IP_DEFALUT_TTL;
    ip_hdr_out->protocol = protocol;
    memcpy(ip_hdr_out->dst_ip, ip, NET_IP_LEN);
    memcpy(ip_hdr_out->src_ip, net_if_ip, NET_IP_LEN);
    // 校验和先填0，计算出结果后再填入字段
    ip_hdr_out->hdr_checksum16 = 0;
    ip_hdr_out->hdr_checksum16 = checksum16((uint16_t *)ip_hdr_out, sizeof(ip_hdr_t));
    // 发送封装好的数据包
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 * 
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{   
    int fragment_size = ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t);
    static int id = 0;
    int offset = 0;
    buf_t ip_buf;
    
    while (buf->len > fragment_size) {
        // 分片发送，每片数据长度为MTU - IP报头长度
        buf_init(&ip_buf, fragment_size);
        memcpy(ip_buf.data, buf->data, fragment_size);
        ip_fragment_out(&ip_buf, ip, protocol, id, offset * fragment_size ,1);
        offset++;
        // 剔除已发送部分
        buf_remove_header(buf, fragment_size);
    }
    // 发送占用不满的数据包（或分片最后剩余部分）
    buf_init(&ip_buf, buf->len);
    memcpy(ip_buf.data, buf->data, buf->len);
    ip_fragment_out(&ip_buf, ip, protocol, id, offset * fragment_size, 0);
    id++;
}

/**
 * @brief 初始化ip协议
 * 
 */
void ip_init()
{
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}