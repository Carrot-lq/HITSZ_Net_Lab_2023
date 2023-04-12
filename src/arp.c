#include <string.h>
#include <stdio.h>
#include "net.h"
#include "arp.h"
#include "ethernet.h"
/**
 * @brief 初始的arp包
 * 
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = constswap16(ARP_HW_ETHER),
    .pro_type16 = constswap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 * 
 */
map_t arp_table;

/**  
 * @brief arp buffer，<ip,buf_t>的容器
 * 
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 * 
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp)
{
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 * 
 */
void arp_print()
{
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 * 
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip)
{
    // 初始化txbuf
    buf_init(&txbuf, sizeof(arp_pkt_t));
    // 填写ARP报头
    arp_pkt_t arp_pkt = arp_init_pkt;
    arp_pkt.opcode16 = swap16(ARP_REQUEST); // 操作类型为请求，APR_REQUEST
    memcpy(arp_pkt.target_ip, target_ip, NET_IP_LEN);
    // 发送ARP报文
    memcpy(txbuf.data, &arp_pkt, sizeof(arp_pkt));
    uint8_t broadcast_mac[NET_MAC_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    ethernet_out(&txbuf, broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 * 
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac)
{
    // 初始化txbuf
    buf_init(&txbuf, sizeof(arp_pkt_t));
    // 填写ARP报头
    arp_pkt_t arp_pkt = arp_init_pkt;
    arp_pkt.opcode16 = swap16(ARP_REPLY); // 操作类型为响应，ARP_REPLY
    memcpy(arp_pkt.target_mac, target_mac, NET_MAC_LEN);
    memcpy(arp_pkt.target_ip, target_ip, NET_IP_LEN);
    // 发送ARP报文
    memcpy(txbuf.data, &arp_pkt, sizeof(arp_pkt));
    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac)
{
    // 判断数据包是否合法
    if (buf->len < sizeof(arp_pkt_t)) return;
    arp_pkt_t *arp_pkt_in = (arp_pkt_t *)buf->data;
    if (arp_pkt_in->hw_type16 != swap16(ARP_HW_ETHER) ||
        arp_pkt_in->pro_type16 != swap16(NET_PROTOCOL_IP) ||
        arp_pkt_in->hw_len != NET_MAC_LEN ||
        arp_pkt_in->pro_len != NET_IP_LEN) return;
    uint16_t opcode =  arp_pkt_in->opcode16;
    if (opcode != swap16(ARP_REQUEST) && opcode != swap16(ARP_REPLY)) return;
    // 对于合法的数据包，更新ARP表项，增加该数据包来源IP与MAC的映射
    map_set(&arp_table, arp_pkt_in->sender_ip, src_mac);
    // 查看该接收报文的IP地址是否有对应的数据包缓存，若有则发送该数据包并从缓存中删除
    buf_t *buf_in_map = (buf_t *)map_get(&arp_buf, arp_pkt_in->sender_ip);
    if (buf_in_map != NULL) {
        ethernet_out(buf_in_map, arp_pkt_in->sender_mac, NET_PROTOCOL_IP);
        map_delete(&arp_buf, arp_pkt_in->sender_ip);
        return;
    }
    
    // 若没有缓存，判断该数据包是否为请求本机MAC的ARP请求，是则发送ARP响应
    if (opcode == swap16(ARP_REQUEST) && memcmp(arp_pkt_in->target_ip, net_if_ip, NET_IP_LEN) == 0) {
        arp_resp(arp_pkt_in->sender_ip, arp_pkt_in->sender_mac);
    }
    
}

/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip)
{
    // 根据已知IP查ARP表，若存在对应MAC则直接发送
    uint8_t *mac_in_map = (uint8_t *)map_get(&arp_table, ip);
    if (mac_in_map != NULL) {
        ethernet_out(buf, mac_in_map, NET_PROTOCOL_IP);
        return;
    }
    // ARP表中不存在时，判断当前缓存中是否有数据包，若有则说明正在等待该IP回应ARP请求，此时不能再发送ARP请求
    // 若没有缓存，则缓存该数据包，然后先发送ARP请求以获得目标IP对应的MAC地址
    if (map_get(&arp_buf, ip) == NULL) {
        map_set(&arp_buf, ip, buf);
        arp_req(ip);
    }
}

/**
 * @brief 初始化arp协议
 * 
 */
void arp_init()
{
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}