#include "net.h"
#include "icmp.h"
#include "ip.h"

/**
 * @brief 发送icmp响应
 * 
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip)
{
    // 直接复制整个请求报文至txbuf，包括报头+数据
    // 然后修改报头为响应报头，此时txbuf中即为数据部分与请求报文相同的响应报文
    buf_init(&txbuf, req_buf->len);
    memcpy(txbuf.data, req_buf->data, req_buf->len);
    // 修改响应报头，其中id和seq与请求报文相同，不用修改
    icmp_hdr_t *icmp_hdr_resp = (icmp_hdr_t *)txbuf.data;
    icmp_hdr_resp->type = ICMP_TYPE_ECHO_REPLY;
    icmp_hdr_resp->code = 0;
    // 计算校验和，范围为整个报文
    icmp_hdr_resp->checksum16 = 0;
    icmp_hdr_resp->checksum16 = checksum16((uint16_t *)txbuf.data, txbuf.len);
    // 发送数据包
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip)
{
    // 数据包长小于ICMP头部长度，则丢弃不处理
    if (buf->len < sizeof(icmp_hdr_t)) return;
    icmp_hdr_t *icmp_in = (icmp_hdr_t *)buf->data;
    // 报文若为回显请求，发送回显应答
    if (icmp_in->type == ICMP_TYPE_ECHO_REQUEST) {
        icmp_resp(buf, src_ip);
    }
}

/**
 * @brief 发送icmp不可达
 * 
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code)
{
    // 差错报文数据只需包括IP报头与报文前8字节
    buf_init(&txbuf, sizeof(ip_hdr_t) + 8);
    memcpy(txbuf.data, recv_buf->data, sizeof(ip_hdr_t) + 8);
    // 添加ICMP报头
    buf_add_header(&txbuf, sizeof(icmp_hdr_t));
    icmp_hdr_t *icmp_hdr_unreachable = (icmp_hdr_t *)txbuf.data;
    icmp_hdr_unreachable->type = ICMP_TYPE_UNREACH;
    icmp_hdr_unreachable->code = code;
    // id与seq字段在差错报文中未用，必须为0
    icmp_hdr_unreachable->id16 = 0;
    icmp_hdr_unreachable->seq16 = 0;
    // 计算校验和，范围为整个ICMP报文
    icmp_hdr_unreachable->checksum16 = 0;
    icmp_hdr_unreachable->checksum16 = checksum16((uint16_t *)txbuf.data, txbuf.len);
    // 发送数据包
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 * 
 */
void icmp_init(){
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}