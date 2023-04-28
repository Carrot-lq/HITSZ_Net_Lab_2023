#include "udp.h"
#include "ip.h"
#include "icmp.h"

/**
 * @brief udp处理程序表
 * 
 */
map_t udp_table;

/**
 * @brief udp伪校验和计算
 * 
 * @param buf 要计算的包
 * @param src_ip 源ip地址
 * @param dst_ip 目的ip地址
 * @return uint16_t 伪校验和
 */
static uint16_t udp_checksum(buf_t *buf, uint8_t *src_ip, uint8_t *dst_ip)
{
    // buf数据包括UDP头部与数据，计算校验和的范围还需覆盖一个伪头部
    // 增加UDP伪头部，并备份其中数据
    int len = buf->len;
    buf_add_header(buf, sizeof(udp_peso_hdr_t));
    udp_peso_hdr_t backup_data;
    memcpy(&backup_data, buf->data, sizeof(udp_peso_hdr_t));
    // 准备伪头部
    // 伪头部的位置为该包ip头位置，src_ip与dst_ip指针仍指向这块区域
    // 不可使用这种方式获取伪头部udp_peso_hdr_t *udp_peso_hdr = (udp_peso_hdr_t *)buf->data;
    // 这会导致若先memcpy了dst_ip，则指针src_ip的数据会被覆盖
    udp_peso_hdr_t udp_peso_hdr;
    memcpy(udp_peso_hdr.src_ip, src_ip, NET_IP_LEN);
    memcpy(udp_peso_hdr.dst_ip, dst_ip, NET_IP_LEN);
    udp_peso_hdr.placeholder = 0;
    udp_peso_hdr.protocol = NET_PROTOCOL_UDP;
    udp_peso_hdr.total_len16 = swap16(buf->len - sizeof(udp_peso_hdr_t));
    uint16_t checksum = 0;
    // 数据非偶数字长时填充一个字节的0
    if (len % 2) {
        buf_add_padding(buf, 1); 
    }
    // 将伪头部拷贝至数据之前
    memcpy(buf->data, &udp_peso_hdr, sizeof(udp_peso_hdr_t));
    // 计算校验和
    checksum = checksum16((uint16_t *)buf->data, buf->len);
    // 数据非偶数字长时去除填充的0
    if (len % 2) {
        buf_remove_padding(buf, 1);
    } 
    // 恢复伪头部位置原数据，去除伪头部
    memcpy(buf->data, &backup_data, sizeof(udp_peso_hdr_t));
    buf_remove_header(buf, sizeof(udp_peso_hdr_t));
    return checksum;
}

/**
 * @brief 处理一个收到的udp数据包
 * 
 * @param buf 要处理的包
 * @param src_ip 源ip地址
 */
void udp_in(buf_t *buf, uint8_t *src_ip)
{
    // 判断数据包是否合法
    if (buf->len < sizeof(udp_hdr_t)) return;
    udp_hdr_t *udp_hdr_in = (udp_hdr_t *)buf->data;
    if (buf->len < swap16(udp_hdr_in->total_len16)) return;
    // 检验校验和，不一致则丢弃，一致则恢复校验和字段
    uint16_t checksum_received = udp_hdr_in->checksum16;
    udp_hdr_in->checksum16 = 0;
    if (checksum_received != udp_checksum(buf, src_ip, net_if_ip)) return;
    udp_hdr_in->checksum16 = checksum_received;
    // 查找目的端口号对应的处理函数
    uint16_t dst_port16 = swap16(udp_hdr_in->dst_port16);
    udp_handler_t *handler = map_get(&udp_table, &dst_port16);
    if (handler == NULL) {
        // 若没找到，增加IPv4数据报头部，然后发送一个端口不可达的ICMP差错报文
        buf_add_header(buf, sizeof(ip_hdr_t));
        icmp_unreachable(buf, src_ip, ICMP_CODE_PORT_UNREACH);
    } else {
        // 去掉UDP报头，调用对应处理函数
        buf_remove_header(buf, sizeof(udp_hdr_t));
        (*handler)(buf->data, buf->len, src_ip, swap16(udp_hdr_in->src_port16));
    }
}

/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的包
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_out(buf_t *buf, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port)
{
    // 为数据包添加UDP首部并填充字段
    buf_add_header(buf, sizeof(udp_hdr_t));
    udp_hdr_t *udp_hdr_out = (udp_hdr_t *)buf->data;
    udp_hdr_out->src_port16 = swap16(src_port);
    udp_hdr_out->dst_port16 = swap16(dst_port);
    udp_hdr_out->total_len16 = swap16(buf->len);
    // 计算校验和
    udp_hdr_out->checksum16 = 0;
    udp_hdr_out->checksum16 = udp_checksum(buf, net_if_ip, dst_ip);
    // 发送UDP数据包
    ip_out(buf, dst_ip, NET_PROTOCOL_UDP);
}

/**
 * @brief 初始化udp协议
 * 
 */
void udp_init()
{
    map_init(&udp_table, sizeof(uint16_t), sizeof(udp_handler_t), 0, 0, NULL);
    net_add_protocol(NET_PROTOCOL_UDP, udp_in);
}

/**
 * @brief 打开一个udp端口并注册处理程序
 * 
 * @param port 端口号
 * @param handler 处理程序
 * @return int 成功为0，失败为-1
 */
int udp_open(uint16_t port, udp_handler_t handler)
{
    return map_set(&udp_table, &port, &handler);
}

/**
 * @brief 关闭一个udp端口
 * 
 * @param port 端口号
 */
void udp_close(uint16_t port)
{
    map_delete(&udp_table, &port);
}

/**
 * @brief 发送一个udp包
 * 
 * @param data 要发送的数据
 * @param len 数据长度
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port)
{
    buf_init(&txbuf, len);
    memcpy(txbuf.data, data, len);
    udp_out(&txbuf, src_port, dst_ip, dst_port);
}