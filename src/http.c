#include "http.h"
#include "tcp.h"
#include "net.h"
#include "assert.h"

#define TCP_FIFO_SIZE 40

typedef struct http_fifo {
    tcp_connect_t* buffer[TCP_FIFO_SIZE];
    uint8_t front, tail, count;
} http_fifo_t;

static http_fifo_t http_fifo_v;

static void http_fifo_init(http_fifo_t* fifo) {
    fifo->count = 0;
    fifo->front = 0;
    fifo->tail = 0;
}

static int http_fifo_in(http_fifo_t* fifo, tcp_connect_t* tcp) {
    if (fifo->count >= TCP_FIFO_SIZE) {
        return -1;
    }
    fifo->buffer[fifo->front] = tcp;
    fifo->front++;
    if (fifo->front >= TCP_FIFO_SIZE) {
        fifo->front = 0;
    }
    fifo->count++;
    return 0;
}

static tcp_connect_t* http_fifo_out(http_fifo_t* fifo) {
    if (fifo->count == 0) {
        return NULL;
    }
    tcp_connect_t* tcp = fifo->buffer[fifo->tail];
    fifo->tail++;
    if (fifo->tail >= TCP_FIFO_SIZE) {
        fifo->tail = 0;
    }
    fifo->count--;
    return tcp;
}

static size_t get_line(tcp_connect_t* tcp, char* buf, size_t size) {
    size_t i = 0;
    while (i < size) {
        char c;
        if (tcp_connect_read(tcp, (uint8_t*)&c, 1) > 0) {
            if (c == '\n') {
                break;
            }
            if (c != '\n' && c != '\r') {
                buf[i] = c;
                i++;
            }
        }
        net_poll();
    }
    buf[i] = '\0';
    return i;
}

static size_t http_send(tcp_connect_t* tcp, const char* buf, size_t size) {
    size_t send = 0;
    while (send < size) {
        send += tcp_connect_write(tcp, (const uint8_t*)buf + send, size - send);
        net_poll();
    }
    return send;
}

static void close_http(tcp_connect_t* tcp) {
    tcp_connect_close(tcp);
    printf("http closed.\n");
}



static void send_file(tcp_connect_t* tcp, const char* url) {
    FILE* file;
    uint32_t size;
    const char* content_type = "text/html";
    char file_path[255];
    char tx_buffer[1024];

    /*
    解析url路径，查看是否是查看XHTTP_DOC_DIR目录下的文件
    如果不是，则发送404 NOT FOUND
    如果是，则用HTTP/1.0协议发送

    注意，本实验的WEB服务器网页存放在XHTTP_DOC_DIR目录中
    */
    // 根据url获取指定的文件
    // XHTTP_DOC_DIR : "./htmldocs"
    memcpy(file_path, XHTTP_DOC_DIR, sizeof(XHTTP_DOC_DIR));
    strcat(file_path, url);
    if(strcmp(url, "/") == 0){
        strcat(file_path, "index.html");
    }
    file = fopen(file_path, "rb");
    printf("file==NULL:%d\n",file==NULL);
    // 若文件不存在，发送HTTP ERROR 404
    if(file == NULL){
        memset(tx_buffer, 0, sizeof(tx_buffer));
        strcpy(tx_buffer, "HTTP/1.0 404 NOT FOUND\r\n");
        strcat(tx_buffer, "Sever: \r\n");
        strcat(tx_buffer, "Content-Type: text/html\r\n");
        strcat(tx_buffer, "\r\n");
        http_send(tcp, tx_buffer, strlen(tx_buffer));
        return;
    }
    // 准备HTTP报头
    memset(tx_buffer, 0, sizeof(tx_buffer));
    strcpy(tx_buffer, "HTTP/1.0 200 OK\r\n");
    strcat(tx_buffer, "Sever: \r\n");
    strcat(tx_buffer, "Content-Type: \r\n");
    strcat(tx_buffer, "\r\n");
    http_send(tcp, tx_buffer, strlen(tx_buffer));
    // 读取文件并发送
    memset(tx_buffer, 0, sizeof(tx_buffer));
    while(fread(tx_buffer, sizeof(char), sizeof(tx_buffer), file) > 0){
        http_send(tcp, tx_buffer, sizeof(tx_buffer));
        memset(tx_buffer, 0, sizeof(tx_buffer));
    }
    // 发送完毕后关闭文件
    fclose(file);
}

static void http_handler(tcp_connect_t* tcp, connect_state_t state) {
    if (state == TCP_CONN_CONNECTED) {
        http_fifo_in(&http_fifo_v, tcp);
        printf("http conntected.\n");
    } else if (state == TCP_CONN_DATA_RECV) {
    } else if (state == TCP_CONN_CLOSED) {
        printf("http closed.\n");
    } else {
        assert(0);
    }
}


// 在端口上创建服务器。

int http_server_open(uint16_t port) {
    if (!tcp_open(port, http_handler)) {
        return -1;
    }
    http_fifo_init(&http_fifo_v);
    return 0;
}

// 从FIFO取出请求并处理。新的HTTP请求时会发送到FIFO中等待处理。

void http_server_run(void) {
    tcp_connect_t* tcp;
    char url_path[255];
    char rx_buffer[1024];

    while ((tcp = http_fifo_out(&http_fifo_v)) != NULL) {
        int i = 0, j = 0;
        char* c = rx_buffer;


        /*
        1、调用get_line从rx_buffer中获取一行数据，如果没有数据，则调用close_http关闭tcp，并继续循环
        */
        if (get_line(tcp, c, 100) == 0) {
            
            close_http(tcp);
            continue;
        }
        printf("getline: len:%d, c:%s\n",strlen(c),c);
        /*
        2、检查是否有GET请求，如果没有，则调用close_http关闭tcp，并继续循环
        */
        char method_type[4];
        memcpy(method_type, c, 3);
        if (strcmp(method_type, "GET") != 0) {
            close_http(tcp);
            continue;
        }

        /*
        3、解析GET请求的路径，注意跳过空格，找到GET请求的文件，调用send_file发送文件
        */
        printf("while: len:%d, c:%s\n",strlen(c),c);
        while(c[i+4] != ' '){
            url_path[i] = c[i+4];
            printf("%c",c[i+4]);
            i++;
        }
        url_path[i] = '\0';

        send_file(tcp, url_path);

        /*
        4、调用close_http关掉连接
        */
        close_http(tcp);

        printf("!! final close\n");
    }
}
