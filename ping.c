#include "ping.h"

int setupSocket(){
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW); // supply raw ip packets ip_hdrincl enabled on linux
    
    if (sockfd < 1){
        perror("socket");
        return -1;
    }

    return sockfd;
}


void printBytes(const int8* arr, int16 size){

    for(int i = 0; i < size; i ++){
        printf("%02x ", arr[i]);
    }

    printf("\n");
    
}
void copy(int8* destptr, const int8* srcptr, int16 size){
    for(int i = 0; i < (int) size; i ++ ){
        *(destptr + i) = *(srcptr + i);
    }
}

void sendIP(const int sock, const char* dest, const int8* pktbytes, int16 length){

    int8* buffer = (int8*)calloc(length, 1);
    
    copy(buffer, pktbytes, length);

    struct sockaddr_in addr = {0};

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(dest);
    //no need to handle ports for ping

    ssize_t res = sendto(sock, buffer, length, 0, (struct sockaddr*) &addr, sizeof(addr));

    if(res < 0){
        perror("sendto");
    }
    else{
        printf("total bytes: \t %d\nbytes send: \t%zd\n", length, res);
    }
}

void recvIP(const int sock, const char* src){
    if ( sock < 0 || !src){
        printf("Invalid socket or source");
        return;
    }

    int8 buffer[RECV_BUFF_SIZE];

    struct sockaddr_in srcaddr = {0};

    srcaddr.sin_family = AF_INET;
    srcaddr.sin_addr.s_addr = inet_addr(src);
    socklen_t addrlen = sizeof(srcaddr);

    ssize_t res = recvfrom(sock, buffer, RECV_BUFF_SIZE, 0, (struct sockaddr*) &srcaddr, &addrlen);

    if (res < 0){
        perror("recvfrom");
        return;
    }

    ipraw* ippkt = (ipraw*)calloc(sizeof(ipraw), 1);
    copy((int8*)ippkt, buffer, sizeof(ipraw));

    int16 icmpsize = res - sizeof(ipraw);

    icmpraw* icmppkt = (icmpraw*)calloc(icmpsize, 1);
    
    copy((int8*)icmppkt, buffer + (int16)sizeof(ipraw), icmpsize);

    printf("Bytes Received: %zd\n", res);
    printBytes(buffer, (int16)res);
    printBytes((int8*)icmppkt, (int16)icmpsize);
    free(ippkt);
}

int16 endian16(int16 val){//convert to network byte order
    int x = 1;

    if (*(char*)&x == 1){//little endian machine
        return (val << 8) | (val >> 8);
    }
    return val;
}

int16 checksum(const int8* p, int16 size){
    
    int32 checkS = 0;//accumulator

    for(int i = 0; i < (int) size; i+=2){//adding data values
        int16 word;

        if (i < size - 1)
            word = (p[i] << 8)|p[i + 1];
        
        else
            word = p[i]<<8;
        
        checkS = checkS + word;
        checkS = (checkS & 0xFFFF) + (checkS >> 16); //handle carry

    }
    checkS = ~checkS;

    return (int16)checkS;
}

ip* make_ip(int16* id, char* src, char* dst, type kind, int8* payload, int16 paylen){

    if (!id || !src || !dst || !kind)
        return (ip*)0;

    ip* pkt = (ip*)malloc(sizeof(ip));
    memset(pkt, 0, sizeof(ip));
    assert(pkt);

    pkt -> id = *id;
    pkt -> src = inet_addr(src);
    pkt -> dst = inet_addr(dst);
    pkt -> kind = kind;
    pkt -> payload = payload;
    pkt -> paylen = paylen;
    (*id)++;
    return pkt;
}

int8* eval_ip(ip* pkt){

    if(!pkt)
        return (int8*)0;
    
    ipraw* rawpkt = (ipraw*)calloc(sizeof(ipraw), 1);
    int8* ret = (int8*)calloc(sizeof(ipraw) + pkt -> paylen, 1);

    switch(pkt->kind){
        case ICMP: rawpkt -> protocol = 1;
                   break;
        
        default: return (int8*)0;
    }

    rawpkt -> version_ihl = (4<<4) | sizeof(ipraw)/4;
    rawpkt -> tos = 0;
    rawpkt -> length = endian16((int16)(sizeof(ipraw) + pkt -> paylen));
    rawpkt -> id = endian16(pkt -> id);
    rawpkt -> flags_offset = endian16(0);
    rawpkt -> ttl = 64;
    rawpkt -> checksum = 0;//initial
    rawpkt -> src = pkt -> src;
    rawpkt -> dst = pkt -> dst;
    //options excluded

    rawpkt -> checksum = checksum((int8*)rawpkt, sizeof(ipraw));

    copy(ret, (int8*)rawpkt, (int16)sizeof(ipraw));
    ret += (int16)sizeof(ipraw);
    copy(ret, pkt->payload, pkt->paylen);
    ret -= (int16)sizeof(ipraw);
    free(rawpkt);

    return (int8*)ret;

}


void show_ip(ip* pkt){
    if(!pkt)
        return;

    printf("[IP :]\n");
    printf("Id : %02x\n", pkt -> id);
    printf("Kind : %02x\n", pkt -> kind);
    printf("src : %02x\n", pkt -> src);
    printf("dst : %02x\n", pkt -> dst);
    
}


icmp* make_icmp(type kind, int8* data, int16 size, int16 id, int16 seq){

    if (!data || !size)
        return (icmp*)0;

    icmp* pkt;
    int16 n;

    n = sizeof(icmp) + size;
    pkt = (icmp*)malloc((int) n);
    memset(pkt, 0, sizeof(icmp));
    assert(pkt);

    pkt -> kind = kind;
    pkt -> size = size;
    pkt -> id = endian16(id);
    pkt -> seq = endian16(seq);
    pkt -> data = data;
    
    return pkt;
}

int8* eval_icmp(icmp* pkt){
    int8* p; //raw packet bytes;
    icmpraw *rawpkt = (icmpraw*)malloc(sizeof(icmpraw));
    memset(rawpkt, 0, sizeof(icmpraw));

    if(!pkt || !pkt -> data)
        return (int8*)0;
    
    switch(pkt -> kind){

        case ECHO:  rawpkt -> type = 8;
                    rawpkt -> code = 0;
                    break;
        
        case ECHOREPLY: rawpkt -> type = 0;
                        rawpkt -> code = 0;
                        break;
        
        default:   return (int8*)0;
                        
    }

    rawpkt -> checksum = 0;
    rawpkt -> id = pkt -> id;
    rawpkt -> seq = pkt -> seq;

    int16 size = sizeof(icmpraw) + pkt -> size;

    p = (int8*)malloc((int) size);
    memset(p, 0, (size_t)size);
    copy(p, (int8*)rawpkt, sizeof(icmpraw));
    p += sizeof(icmpraw);
    copy(p, pkt -> data, pkt -> size);
    p -= sizeof(icmpraw);

    rawpkt -> checksum = endian16(checksum(p, size));
    copy(rawpkt -> data, pkt -> data, pkt -> size);
    free(p);

    return (int8*)rawpkt;
}

void show_icmp(icmp* pkt){
    if(!pkt)
        return;

    printf("Type :\t%s\nSize :\t%d\n", (pkt->kind == ECHO)?"echo" : "echo reply", (int)pkt->size);

    char printData[(int)pkt -> size];

    for(int i = 0; i < (int) pkt -> size; i ++){
        printData[i] = *(pkt -> data + i);
    }

    printf("Data :\t %s\n", printData);
}

int main(int argc, char* argv[]){

    char* dest = argv[1];

    int16 icmp_id = rand()%50000;
    int16 seq_no = 1;

    icmp* icmppkt = make_icmp(ECHO, (int8*)"hello_friend", (int8)sizeof("hello_friend"), icmp_id++, seq_no++);
    int8* r_icmp = eval_icmp(icmppkt);
    
    int16 ip_id = rand()%50000;
    int16 icmp_size = sizeof(icmpraw) + icmppkt -> size;
    
    ip* ippkt = make_ip(&ip_id, "172.31.2.161", dest, ICMP, r_icmp, icmp_size);
    int8* r_ip = eval_ip(ippkt);
    int16 ip_size = sizeof(ipraw) + icmp_size;

    printBytes(r_icmp, icmp_size);
    printBytes(r_ip, ip_size);

    int socksend = setupSocket();
    int sockrecv = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if(socksend < 0){
        return 1;
    }

    sendIP(socksend, dest, r_ip, ip_size);
    recvIP(sockrecv, dest);
    free(icmppkt);
    free(r_icmp);
    free(ippkt);
    free(r_ip);

    return 0;
}

/*checksum calculation

    (sum of all 16 bit words)'
*/

/*
           
*/