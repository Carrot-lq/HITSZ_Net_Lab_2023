#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"
#include "sys/time.h"

map_t ip_defrag_map;

/**
 * @brief 将node插入queue对应位置中
 * 
 * @param queue 已按offset排序的ipq链表
 * @param node 待插入的ipq节点
 * 
 * @return 返回插入后队列头节点
*/
ipq_t* ip_defrag_insert(ipq_t *queue, ipq_t *node)
{
    // 若节点offset比queue起点还小，头插
    if (node->offset < queue->offset) {
        node->next = queue;
        return node;
    }
    // 寻找到node应该在的位置
    ipq_t *p = queue;
    while (p->next != NULL) {
        if (p->next->offset > node->offset) break;
        p = p->next;
    }
    // 插入node
    node->next = p->next;
    p->next = node;
    return queue;
}

/**
 * @brief 将已集齐所有分片的ipq链表组合为完整数据包向上层发送
 * 
 * @param queue 已按offset排序的所有分片到齐的ipq链表
*/
void ip_defrag(ipq_t *queue, int len, uint8_t protocol, uint8_t *src_ip)
{
    // 准备数据包
    buf_t buf;
    buf_init(&buf, len);
    // 依次将队中节点数据复制到包中
    ipq_t *p = queue;
    while (p->next != NULL) {
        memcpy(buf.data + p->offset, p->data, p->len);
        p = p->next;
    }
    memcpy(buf.data + p->offset, p->data, p->len);
    // 向上层传递
    net_in(&buf, protocol, src_ip);
}

/**
 * @brief 判断链表是否已集齐所有分片
 * 
 * @param queue 已按offset排序的所有分片到齐的ipq链表
 * 
 * @return 集齐返回整个数据包长度，反之为0
*/
int is_defrag_over(ipq_t *queue)
{
    int len = 0;
    ipq_t *p = queue;
    // 第一个结点offset需为0
    if (p->offset != 0) return 0;
    // 每个节点offset需等于上一个节点offset与len之和
    while (p->next != NULL) {
        if (p->next->offset != p->offset + p->len) return 0;
        len += p->len;
        p = p->next;
    }
    len += p->len;
    // 最后一个节点mf不为1
    if (p->mf > 0) return 0;
    return len;
}

/**
 * @brief 传入分片的IP数据包，若分片到齐则重组并传至上层；维护
 * 
 * @param buf_frag 已去除IP报头的数据包
 */
void ip_frag_in(buf_t *buf_frag, uint8_t *src_ip, net_protocol_t protocol, uint16_t id, uint16_t offset, int mf)
{
    // 为传入的分片新建节点
    ipq_t *new_node = (ipq_t *)malloc(sizeof(ipq_t));
    new_node->data = (uint8_t *)malloc(buf_frag->len);
    memcpy(new_node->data, buf_frag->data, buf_frag->len);
    new_node->len = buf_frag->len;
    new_node->offset = offset;
    new_node->mf = mf;
    new_node->next = NULL;
    gettimeofday(&new_node->time, NULL);

    // 查找id是否已有分片
    ipq_t *ip_defrag_queue = (ipq_t *)map_get(&ip_defrag_map, &id);
    if (ip_defrag_queue == NULL) {
        // 收到的为该id第一个分片，新建ipq队列装入map
        map_set(&ip_defrag_map, &id, new_node);
        // 存入map会复制数据，清理node所占空间（但data所未被复制，其空间不可清理）
        free(new_node);
    } else {
        // 不为第一个分片，将节点插入队列
        ipq_t *queue = ip_defrag_insert(ip_defrag_queue, new_node);
        // 判断queue中是否集齐了该数据包的所有分片
        int len = is_defrag_over(queue);
        if (len > 0) {
            // 若是，重组完整的数据包并传入上层，并清理queue占用空间(除队头外，其会在map_delete得到删除)
            ip_defrag(queue, len, protocol, src_ip);
            ipq_t *p = queue->next, *next;
            while (p != NULL) {
                next = p->next;
                free(p->data);
                free(p);
                p = next;
            }
            free(queue->data);
            map_delete(&ip_defrag_map, &id);
        } else {
            // 否则将queue存入map
            map_set(&ip_defrag_map, &id, queue);
        }
    }
    
}


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
    uint16_t hdr_len = ip_hdr_in->hdr_len * IP_HDR_LEN_PER_BYTE;
    uint16_t id = swap16(ip_hdr_in->id16);
    uint16_t total_len = swap16(ip_hdr_in->total_len16);
    uint16_t flags_fragment = swap16(ip_hdr_in->flags_fragment16);
    if (ip_hdr_in->version != IP_VERSION_4 ||
        hdr_len < sizeof(ip_hdr_t) ||
        total_len > buf->len) return;
    // 检验校验和，不一致则丢弃，一致则恢复校验和字段
    uint16_t checksum_received = ip_hdr_in->hdr_checksum16;
    ip_hdr_in->hdr_checksum16 = 0;
    if (checksum_received != checksum16((uint16_t *)ip_hdr_in, hdr_len)) return;
    ip_hdr_in->hdr_checksum16 = checksum_received;
    // 检验数据包目标IP是否为本机IP
    if (memcmp(ip_hdr_in->dst_ip, net_if_ip, NET_IP_LEN) != 0) return;
    // 判断数据包是否存在填充，若是则剔除填充
    if (buf->len > total_len) buf_remove_padding(buf, buf->len - total_len);
    // 识别协议，合法的包括ICMP=1,TCP=6,UDP=17，否则发送ICMP协议不可达
    if (ip_hdr_in->protocol == NET_PROTOCOL_UDP ||
        ip_hdr_in->protocol == NET_PROTOCOL_TCP ||
        ip_hdr_in->protocol == NET_PROTOCOL_ICMP) {
        // 判断是否分片（MF为1或offset不为0），若分片则交由分片处理函数
        int mf = flags_fragment & IP_MORE_FRAGMENT;
        int offset = (flags_fragment & 0x1fff)<< 3;
        buf_remove_header(buf, hdr_len);
        if (mf > 0 || offset > 0) {
            ip_frag_in(buf, ip_hdr_in->src_ip, ip_hdr_in->protocol, id, offset, mf);
        } else {
            net_in(buf, ip_hdr_in->protocol, ip_hdr_in->src_ip);
        }
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
    int offset = 0; // 已发送的分片数，实际字节偏移量需乘fragment_size
    buf_t ip_buf;
    
    while (buf->len > fragment_size) {
        // 分片发送，每片数据长度为MTU - IP报头长度（本实验中IP报头始终为20bytes）
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
    map_init(&ip_defrag_map, sizeof(uint16_t), sizeof(ipq_t), 0, 0, NULL);
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}