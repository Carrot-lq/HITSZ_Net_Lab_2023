#include "net.h"
#include "icmp.h"
#include "ip.h"
#include "windows.h"
#include "sys/time.h"

/**
 * @brief 收到的ping包，<pid, buf_t>的容器
 * 
 */
map_t icmp_buf;


void icmp_ping_test(uint8_t* target_ip, int times)
{
    static int pkt_send_num = 0;
    static int pkt_rec_num = 0;
    static struct timeval lasttime, nowtime;
    static long min_use_time_ms = 9999;
    static long max_use_time_ms = 0;
    static long total_use_time_ms = 0;
    static int first_flag = 1;
    static int last_received_flag = 0;
    uint16_t pid = GetCurrentProcessId();   // windows
    gettimeofday(&nowtime, NULL);
    
    if (pkt_send_num > times) return;
    if (pkt_send_num == times && last_received_flag == 1){
        printf("%d packets transmitted, %d received, %2.2f%% packet loss\n", pkt_send_num, pkt_rec_num, (float)(pkt_send_num - pkt_rec_num)/(pkt_send_num)*100);
        if(pkt_rec_num > 0) printf("min = %ldms, max = %ldms, avg = %ldms\n", min_use_time_ms, max_use_time_ms, total_use_time_ms/pkt_rec_num);
        pkt_send_num++;
    }
    
    if (first_flag) {
        printf("Ping %s %lld bytes of data.\n",iptos(target_ip), sizeof(icmp_hdr_t) + sizeof(struct timeval));
        icmp_req(target_ip);
        first_flag = 0;
        lasttime = nowtime;
        pkt_send_num++;
        return;
    }
    buf_t *icmp_in_buf = map_get(&icmp_buf, &pid);
    if (icmp_in_buf != NULL && last_received_flag == 0) {
        last_received_flag = 1;
        pkt_rec_num++;
        // 获得收到报文的用时，更新时间相关信息
        struct timeval *use_time = (struct timeval *)(icmp_in_buf->data + sizeof(icmp_hdr_t));
        long use_time_ms = use_time->tv_sec * 1000 + use_time->tv_usec / 1000;
        total_use_time_ms += use_time_ms;
        if (min_use_time_ms > use_time_ms) min_use_time_ms = use_time_ms;
        if (max_use_time_ms < use_time_ms) max_use_time_ms = use_time_ms;
    }
    // 收到回复，间隔1s发送ping
    if (nowtime.tv_sec >= lasttime.tv_sec + 1 && last_received_flag) {
        // 从map中删除已接收的报文
        map_delete(&icmp_buf, &pid);
        last_received_flag = 0;
        // 发送下一个ping
        printf("Ping %s %lld bytes of data.\n",iptos(target_ip), sizeof(icmp_hdr_t) + sizeof(struct timeval));
        icmp_req(target_ip);
        pkt_send_num++;
        lasttime = nowtime;
        return;
    }
    // 超时，发送下一个ping
    if (nowtime.tv_sec >= lasttime.tv_sec + 5){
        printf("No responde!\n");
        // ping
        printf("Ping %s %lld bytes of data.\n",iptos(target_ip), sizeof(icmp_hdr_t) + sizeof(struct timeval));
        icmp_req(target_ip);
        pkt_send_num++;
        lasttime = nowtime;
        return;
    }    
}

long get_time_ms_from_now(struct timeval *rec_time)
{
    struct timeval now_time;
    gettimeofday(&now_time, NULL);
    return (now_time.tv_sec - rec_time->tv_sec) * 1000 + (now_time.tv_usec - rec_time->tv_usec)/1000;
}

/**
 * @brief 发送icmp回显请求
 * 
 * @param dst_ip 目标ip地址
 * @return buf_t 发送的ICMP请求数据包
 */
void icmp_req(uint8_t *dst_ip)
{
    buf_t buf;
    // 数据包包括ICMP头部 + 时间戳数据
    buf_init(&buf, sizeof(icmp_hdr_t) + sizeof(struct timeval));
    // 准备ICMP头部
    uint16_t pid = GetCurrentProcessId();   // windows
    static int seq = 0;
    icmp_hdr_t *icmp_hdr_req = (icmp_hdr_t *)buf.data;
    icmp_hdr_req->type = ICMP_TYPE_ECHO_REQUEST;
    icmp_hdr_req->code = 0;
    icmp_hdr_req->id16 = swap16(pid);
    icmp_hdr_req->seq16 = swap16(seq);
    icmp_hdr_req->checksum16 = 0;
    // 数据为当前时间
    struct timeval now_time;
    gettimeofday(&now_time, NULL);
    memcpy(buf.data + sizeof(icmp_hdr_t), &now_time, sizeof(struct timeval));
    // 计算校验和
    icmp_hdr_req->checksum16 = checksum16((uint16_t *)buf.data, buf.len);
    // 发送数据包
    ip_out(&buf, dst_ip, NET_PROTOCOL_ICMP);
    seq++;
    return buf;
}

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
 * 
 * 新增对ICMP应答的处理
 */
void icmp_in(buf_t *buf, uint8_t *src_ip)
{
    // 数据包长小于ICMP头部长度，则丢弃不处理
    if (buf->len < sizeof(icmp_hdr_t)) return;
    icmp_hdr_t *icmp_in = (icmp_hdr_t *)buf->data;
    // 校验检验和
    uint16_t checksum_received = icmp_in->checksum16;
    icmp_in->checksum16 = 0;
    if (checksum_received != checksum16((uint16_t *)buf->data, buf->len)) return;
    icmp_in->checksum16 = checksum_received;
    // 响应不同类型的ICMP报文
    if (icmp_in->type == ICMP_TYPE_ECHO_REQUEST) {
        // 报文若为回显请求，发送回显应答
        icmp_resp(buf, src_ip);
    } else if (icmp_in->type == ICMP_TYPE_ECHO_REPLY) {
        // 报文若为回显应答，按照PING的格式进行打印
        // 获得发送与接收时间
        struct timeval *rec_time = (struct timeval *)(buf->data + sizeof(icmp_hdr_t));
        struct timeval now_time;
        gettimeofday(&now_time, NULL);
        // 计算用时
        long use_time_sec = now_time.tv_sec - rec_time->tv_sec;
        long use_time_usec = now_time.tv_usec - rec_time->tv_usec;
        long time_ms = use_time_sec * 1000 + use_time_usec / 1000;
        // 修改报文的数据段为到达的用时，添加至map中等待ping处理
        rec_time->tv_sec = use_time_sec;
        rec_time->tv_usec = use_time_usec;
        
        int id = swap16(icmp_in->id16);
        map_set(&icmp_buf, &id, buf);
        
        printf("%lld bytes from %s: ", buf->len, iptos(src_ip));
        printf("icmp_id=%d, icmp_seq=%d, time=%ld ms.\n",swap16(icmp_in->id16), swap16(icmp_in->seq16), time_ms);

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
    map_init(&icmp_buf, sizeof(uint16_t), sizeof(icmp_hdr_t) + sizeof(struct timeval), 0, 4, NULL);
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}