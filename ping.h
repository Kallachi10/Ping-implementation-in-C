#include<stdio.h>
#include<assert.h>
#include<stdlib.h>
#include<string.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>

#define packed __attribute__((packed))
#define RECV_BUFF_SIZE 1500

typedef unsigned char int8;
typedef unsigned short int int16;
typedef unsigned int int32;
typedef unsigned long long int int64;

enum e_type{
    UNASSIGNED,
    ECHO,
    ECHOREPLY,
    ICMP,
    TCP,
    UDP
}packed;

typedef enum e_type type;

struct s_icmpraw{
    int8 type;
    int8 code;
    int16 checksum;
    int16 id;
    int16 seq;
    int8 data[];
}packed;

struct s_icmp{
    type kind : 3;
    int16 size;
    int16 id;
    int16 seq;
    int8* data;
}packed;

struct s_ip{
    int32 src;
    int32 dst;
    int16 id;
    type kind;
    int8* payload;
    int16 paylen;
}packed;

struct s_ipraw{
    int8 version_ihl;
    int8 tos;
    int16 length;
    int16 id;
    int16 flags_offset;
    int8 ttl;
    int8 protocol;
    int16 checksum;
    int32 src;
    int32 dst;
    int8 options[];
    
}packed;

typedef struct s_ip ip;
typedef struct s_ipraw ipraw;
typedef struct s_icmpraw icmpraw;
typedef struct s_icmp icmp;

icmp* make_icmp(type, int8*, int16, int16, int16);
int8* eval_icmp(icmp*);
int16 check_sum(const int8*, int16);
int16 endian(int16);
ip* make_ip(int16*, char*, char*, type, int8*, int16);
int8* eval_ip(ip*);
void printBytes(const int8*, int16);
void copy(int8*, const int8*, int16);
void show_icmp(icmp*);


