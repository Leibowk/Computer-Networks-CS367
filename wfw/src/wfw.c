//Kyle Leibowitz (leibowk@wwu.edu)

#include "conf.h"
#include "hash.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet6/in6.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>
#include <err.h>
#include <errno.h>

/* Constants */
#define STR1(x)   #x
#define STR(x)    STR1(x)
#define DEVICE    "device"
#define PORT      "port"
#define BROADCAST "broadcast"
#define ANYIF     "0.0.0.0"
#define ANYPORT   "0"
#define FRNDPORT  "42020"
//#define vlad6     "fd10:2020:c5c1:367:e3ef:a747:2c60:5f2b"
//#define leibowk   "fd10:2020:c5c1:367:7a89:5745:5ea9:07e4"
//#define vlad4     "10.3.68.109"
//#define david6    "fd10:2020:c5c1:367:2603:cd12:2cc5:eaf3"

#define PID       "pidfile"

#define BUFSZ 1514

/* Globals  */
static char* conffile   = STR(SYSCONFDIR) "/wfw.cfg";
static bool  printusage = false;
static bool foreground = false; 
static uint32_t leibowk[4] = {0xfd102020, 0xc5c10367, 0x7a895745, 0x5ea907e4};
// static uint32_t vlad[4] = {0xfd102020, 0xc5c10367, 0xe3efa747, 0x2c605f2b};
// static uint32_t david[4] = {0xfd102020, 0xc5c10367, 0x2603cd12, 0x2cc5eaf3};

/*Types */

   struct ports{
    uint16_t localPort;
    uint16_t remotePort;
    char remoteIP[16];
  };

  struct frame {
    char dst[6];
    char src[6];
    short type;
    char data[1500];
  };

  struct IPv6struct{
    uint32_t flow;
    uint32_t paylen:16;
    uint32_t nxtHdr:8;
    uint32_t hoplim:8;
    char srcaddr[16];
    char dstaddr[16];
    char data[1460];
  };
  
  struct IPv4struct{
    uint8_t version : 4;
    uint8_t ihl : 4;
    uint8_t tos;
    uint16_t len;
    uint16_t id;
    uint16_t flags : 3;
    uint16_t frag_offset : 13;
    uint8_t ttl;
    uint8_t proto;
    uint16_t csum;
    uint32_t saddr;
    uint32_t daddr;
    char data[1340];
};

  struct udp{
    char src[16];
    char dst[16];
    char len[16];
    char checkSum[16];
    char data[1276];
  };

  struct segment{
    uint16_t srcport;
    uint16_t dstport;
    uint32_t seqnum;
    uint32_t acknum;
    uint16_t       : 4;
    uint16_t hdrsz : 4;
    uint16_t FIN   : 1;
    uint16_t SYN   : 1;
    uint16_t RST   : 1;
    uint16_t PSH   : 1;
    uint16_t ACK   : 1;                       
    uint16_t URG   : 1;
    uint16_t       : 2;
    uint16_t window;    
    uint16_t checksum;  
    uint16_t urgent;    
    uint32_t options[];                    
  };

/* Prototypes */

/* Parse Options
 * argc, argv   The command line
 * returns      true iff the command line is successfully parsed
 *
 * This function sets the otherwise immutable global variables (above).  
 */
static
bool parseoptions(int argc, char* argv[]);

/* Usage
 * cmd   The name by which this program was invoked
 * file  The steam to which the usage statement is printed
 *
 * This function prints the simple usage statement.  This is typically invoked
 * if the user provides -h on the command line or the options don't parse.  
 */
static
void usage(char* cmd, FILE* file);

/* Ensure Tap
 * path     The full path to the tap device.
 * returns  If this function returns, it is the file descriptor for the tap
 *          device. 
 * 
 * This function tires to open the specified device for reading and writing.  If
 * that open fails, this function will report the error to stderr and exit the
 * program.   
 */
static
int  ensuretap(char* path);

/*  frndSocket
*   Makes a socket for friends to communicate over to relay malicious attack information
*/
static int frndSocket();

/* Ensure Socket
 * localaddress   The IPv4 address to bind this socket to.
 * port           The port number to bind this socket to.
 *
 * This function creates a bound socket.  Notice that both the local address and
 * the port number are strings.  
 */
static
int ensuresocket(char* localaddr, char* port);

/* Make Socket Address
 * address, port  The string representation of an IPv4 socket address.
 *
 * This is a convince routine to convert an address-port pair to an IPv4 socket
 * address.  
 */
static
struct sockaddr_in makesockaddr(char* address, char* port);

/* mkfdset
 * set    The fd_set to populate
 * ...    A list of file descriptors terminated with a zero.
 *
 * This function will clear the fd_set then populate it with the specified file
 * descriptors.  
 */
static
int mkfdset(fd_set* set, ...);

/* Bridge 
 * tap     The local tap device
 * in      The network socket that receives broadcast packets.
 * out     The network socket on with to send broadcast packets.
 * bcaddr  The broadcast address for the virtual ethernet link.
 *
 * This is the main loop for wfw.  Data from the tap is broadcast on the
 * socket.  Data broadcast on the socket is written to the tap.  
 */
static
void bridge(int tap, int in, int out, int frnds, struct sockaddr_in bcaddr);


/* Connect To the specified host and service
 * host     The host name or address to connect to.
 * svc      The service name or service to connect to.
 * returns  -1 or a connected socket.
 * 
 * Note a non-negative return is a newly created socket that shall be closed.  
 */
static
int connectto(const char* name, const char* svc);


void kvfree(void* key, void* value);

static
void deamonize(hashtable conf);

/* Main
 * 
 * Mostly, main parses the command line, the conf file, creates the necessary
 * structures and then calls bridge.  Bridge is where the real work is done. 
 */

int main(int argc, char* argv[]) {
  int result = EXIT_SUCCESS;

  if(!parseoptions(argc, argv)) {
    usage(argv[0], stderr);
    result = EXIT_FAILURE;
  }
  else if(printusage) {
    usage(argv[0], stdout);
  }
  else {
    hashtable conf = readconf (conffile);
    int       tap  = ensuretap (htstrfind (conf, DEVICE));
    int       frnds = frndSocket();
    int       out  = ensuresocket(ANYIF, ANYPORT);
    int       in   = ensuresocket(htstrfind (conf, BROADCAST),
                                  htstrfind (conf, PORT));
    struct sockaddr_in
      bcaddr       = makesockaddr (htstrfind (conf,BROADCAST),
                                   htstrfind (conf, PORT));

    if(!foreground){
     deamonize(conf);
    }

    bridge(tap, in, out, frnds, bcaddr);
    //bridge(tap, in, out, bcaddr);

    close(in);
    close(out);
    close(tap);
    close(frnds);
    htfree(conf);
  }

  return result;
}


//making current process a deamon process
static
void deamonize(hashtable conf){
  daemon(0,0);
  FILE* pidfile = fopen(htstrfind(conf, PID), "w");
  if(hthasstrkey(conf, PID)){
    if(pidfile!=NULL){
      fprintf(pidfile, "%d\n", getpid());
      fclose(pidfile);
    }
  }
}

/* Parse Options
 *
 * see man 3 getopt
 */
static
bool parseoptions(int argc, char* argv[]) {
  static const char* OPTS = "hc:f";

  bool parsed = true;

  char c = getopt(argc, argv, OPTS);
  while(c != -1) {
    switch (c) {
    case 'c':
      conffile = optarg;
      break;
        
    case 'h':
      printusage = true;
      break;

    case 'f':
      foreground = true;
      break;

    case '?':
      parsed = false;
      break;
    }

    c = parsed ? getopt(argc, argv, OPTS) : -1;
  }

  if(parsed) {
    argc -= optind;
    argv += optind;
  }

  return parsed;
}

/* Print Usage Statement
 *
 */

static
void usage(char* cmd, FILE* file) {
  fprintf(file, "Usage: %s -c file.cfg [-h]\n", cmd);
}

/* Ensure Tap device is open.
 *
 */
static
int ensuretap(char* path) {
  int fd = open(path, O_RDWR | O_NOSIGPIPE);
  if(-1 == fd) {
    perror("open");
    fprintf(stderr, "Failed to open device %s\n", path);
    exit(EXIT_FAILURE);
  }
  return fd;
}

/* Ensure socket
 *
 * Note the use of atoi, htons, and inet_pton. 
 */
static
int ensuresocket(char* localaddr, char* port) {
  int sock = socket(PF_INET, SOCK_DGRAM, 0);
  if(-1 == sock) {
    perror("socket");
    exit (EXIT_FAILURE);
  }

  int bcast = 1;
  if (-1 == setsockopt(sock, SOL_SOCKET, SO_BROADCAST,
                       &bcast, sizeof(bcast))) {
    perror("setsockopt(broadcast)");
    exit(EXIT_FAILURE);
  }

  struct sockaddr_in addr = makesockaddr(localaddr, port);
  if(0 != bind(sock, (struct sockaddr*)&addr, sizeof(addr))) {
    perror("bind");
    char buf[80];
    fprintf(stderr,
            "failed to bind to %s\n",
            inet_ntop(AF_INET, &(addr.sin_addr), buf, 80));
    exit(EXIT_FAILURE);
  }

  return sock;  
}

/* Make Sock Addr
 * 
 * Note the use of inet_pton and htons.
 */
static
struct sockaddr_in makesockaddr(char* address, char* port) {
  struct sockaddr_in addr;
  bzero(&addr, sizeof(addr));
  addr.sin_len    = sizeof(addr);
  addr.sin_family = AF_INET;
  addr.sin_port   = htons(atoi(port));
  inet_pton(AF_INET, address, &(addr.sin_addr));

  return addr;
}

/* mkfdset
 *
 * Note the use of va_list, va_arg, and va_end. 
 */
static
int mkfdset(fd_set* set, ...) {
  int max = 0;
  
  FD_ZERO(set);
  
  va_list ap;
  va_start(ap, set);
  int s = va_arg(ap, int);
  while(s != 0) {
    if(s > max)
      max = s;
    FD_SET(s, set);
    s = va_arg(ap, int);
  }
  va_end(ap);
  
  return max;
}
     

 void kvfree(void* key, void* value) {
  free(key);
  free(value);
}

/* Connect To the specified host and service
 * 
 */

/* Connect To the specified host and service
 * 
 */

/* Timed Connect
 * 
 * This function tries to connect to the specified sockaddr if a connection can
 * be made within tval time.  
 *
 * The socket is temporarily put in non-blocking mode, a connection is tarted,
 * and select is used to do the actual timeout logic.  
 */
static
int timedconnect(int              sock,
                 struct sockaddr* addr,
                 socklen_t        leng,
                 struct timeval   tval) {

  int status = -1;
  
  int ostate = fcntl(sock, F_GETFL, NULL);
  int nstate = ostate | O_NONBLOCK;
  
  if( ostate < 0 || fcntl(sock, F_SETFL, nstate) < 0) {
    perror("fcntl");
  }
  else {
    status = connect(sock, addr, leng);
    if(status < 0 && errno == EINPROGRESS) {
      fd_set wrset;
      int maxfd = mkfdset(&wrset, sock, 0);
      status = (0 < select(maxfd+1, NULL, &wrset, NULL, &tval) ?
                0 : -1);
    }

    ostate = fcntl(sock, F_GETFL, NULL);
    nstate = ostate & ~O_NONBLOCK;
    if(ostate < 0 || fcntl(sock, F_SETFL, &nstate) < 0) {
      perror("fcntl");
    }
  }

  return status;

}

/* Try to connect
 * ai       An addrinfo structure.
 * returns  -1 or a socket connected to the sockaddr within ai.  
 *
 * This function will create a new socket and try to connect to the socketaddr
 * contained within the provided addrinfo structure.  
 */
static
int tryconnect(struct addrinfo* ai) {
  assert(ai);
  struct timeval tv = {1,0};
  int s = socket(ai->ai_family, ai->ai_socktype, 0);
  if(s != -1 && 0 != timedconnect(s, ai->ai_addr, ai->ai_addrlen, tv)) {
    close(s);
    s = -1;
  }
  return s;
}

 static
 int connectto(const char* name, const char* svc) {
  assert(name != NULL);
  assert(svc  != NULL);

  int s = -1;
  
  struct addrinfo hint;
  bzero(&hint, sizeof(struct addrinfo));
  hint.ai_socktype = SOCK_STREAM;
  
  struct addrinfo* info = NULL;
    
  if (0    == getaddrinfo(name, svc, &hint, &info) &&
      NULL != info ) {
    
    struct addrinfo* p = info;

    s = tryconnect(p);
    while (s == -1 && p->ai_next != NULL) {
      printf("testing where stuck in CONNECTTO whileLOOPPPPP\n");
      p = p->ai_next;
      s = tryconnect(p);
    }
    // printf("testing where stuck end of connectTO LOOP\n");
  }

  freeaddrinfo(info);
  return s;
}

//Function to print an ipv6 structure
void printIPv6(void* buffer, ssize_t rdct){
  printf("FRAME: \n");
  printf("Destination address: ");
  for (size_t i = 0; i < 6; ++i)
    printf("%02X ", ((uint8_t *)buffer)[i]);

  printf("\n");

  printf("Source address: ");
  for (size_t i = 6; i < 12; ++i)
    printf("%02X ", ((uint8_t *)buffer)[i]);

  printf("\n");

  printf("Type: ");
  for (size_t i = 12; i < 14; ++i)
    printf("%02X ", ((uint8_t *)buffer)[i]);

  printf("\n \n");

  printf("IPV6: \n");
  printf("Flow: ");
  for (size_t i = 14; i < 18; ++i)
    printf("%02X ", ((uint8_t *)buffer)[i]);

  printf("\n");
  printf("PayLen: ");
  for (size_t i = 18; i < 20; ++i)
    printf("%02X ", ((uint8_t *)buffer)[i]);

  printf("\n");

  printf("nextHeader: ");
  printf("%02X ", ((uint8_t *)buffer)[20]);  
  printf("\n");

  printf("HopLimit: ");
  printf("%02X ", ((uint8_t *)buffer)[21]);
  printf("\n");

  printf("Srcadd: ");
  for (size_t i = 22; i < 38; ++i)
    printf("%02X ", ((uint8_t *)buffer)[i]);

  printf("\n");

  printf("DstAddr: ");
  for (size_t i = 38; i < 54; ++i)
    printf("%02X ", ((uint8_t *)buffer)[i]);

  printf("\n \n");

  printf("ALL OTHER DATA: ");
  for (size_t i = 54; i < rdct; ++i)
    printf("%02X ", ((uint8_t *)buffer)[i]);

  printf("\n \n \n");

}

//Function to print IPv6 source addresses
void printSource(void* source){
  printf("Srcadd: ");
  for (size_t i = 0; i < 16; ++i)
    printf("%02X ", ((uint8_t *)source)[i]);
  
  printf("\n");
}

//Function to log buffer structures
void logStruct(ssize_t rdct, void* buffer){
  FILE *fptr;
  // opening file in writing mode
  fptr = fopen("aLog.txt", "a");

  // exiting program 
  if (fptr == NULL) {
      printf("Error!");
      exit(1);
  }

  for (size_t i = 0; i < rdct; ++i)
    fprintf(fptr, "%02X ", ((uint8_t *)buffer)[i]);
  fputs("\n", fptr);
  
  fputs(" \n \n \n", fptr);
  fclose(fptr);
  
}

//memcmp helper function
static int macComp(void* mem1, void* mem2){
  return memcmp(mem1, mem2, 6);
}

//Function to tell if something is a broadcast
bool isBroadCast(void* key){
  unsigned char test1[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  unsigned char test2[2] = {0x33, 0x33};
  return ((memcmp(test1, key, 6)==0)||(memcmp(test2, key, 2)==0));
}

//Function to see if a buffer has an IPv6
bool hasIPv6(void * key){
  const uint8_t testIPv6[2]= {0x86, 0xDD};
  return (memcmp(key, testIPv6, sizeof testIPv6)==0);
}

//Function to duplicate memory
void* memdup(void* p, size_t s){
  char* n = malloc(s);
  if(n != NULL)
    memcpy(n,p,s);
  return n;
}

//Function to get ports structure
struct ports getTapPorts(struct IPv6struct* myIP, struct segment* mySeg){
  struct ports newPort;
  newPort.localPort= ntohs((mySeg)->srcport);
  newPort.remotePort= ntohs((mySeg)->dstport);
  strncpy(newPort.remoteIP, (myIP)->dstaddr, 16);
  return newPort;
}

//Function to get ports structure with dstport and srcport inversed
struct ports getPorts(struct IPv6struct* myIP, struct segment* mySeg){
  struct ports aPort;
  aPort.localPort= ntohs((mySeg)->dstport);
  aPort.remotePort= ntohs((mySeg)->srcport);
  strncpy(aPort.remoteIP, (myIP)->srcaddr, 16);
  return aPort;
}

//Function to insert buffersrc into the ht.
void insertSrcHt(hashtable ht, struct frame buffer, struct sockaddr_in from){
  if (!hthaskey(ht, (&buffer)->src, 6) ){
    bool broadCast = isBroadCast((&buffer)->src);
    if (!broadCast){
      htinsert(ht, memdup(buffer.src, 6), 6, memdup(&from, sizeof(from)));
    }
  }
  else{
    memcpy(htfind(ht, (&buffer)->src, 6), &from, sizeof(struct sockaddr_in));
  }
}

//Forwards the frame.
void forwardFrame(struct frame buffer, int tap, ssize_t rdct){
  if(-1 == write(tap, &buffer, rdct)) {
    perror("write");
  }
}

//Function to insert a key into the synHt if a syn bit is found. Inserts a ports structure.
void insertSeg(struct frame buffer, hashtable synHt){
  if(hasIPv6(&(&buffer)->type)){
    struct IPv6struct* myIP = (struct IPv6struct*)(buffer.data);
    if(((myIP)->nxtHdr)==6){
      struct segment* mySeg = (struct segment*)(myIP)->data;
      if(((mySeg)->SYN)==1){            
        struct ports newPort= getTapPorts(myIP, mySeg);          
        if(!hthaskey(synHt, &newPort, sizeof(newPort))){
          htinsert(synHt, memdup(&newPort, sizeof(newPort)), sizeof(newPort), 0);
        }
      }
    }
  }
}

//Function that verifies buffer isn't ipv6 and doesn't have segment
bool notIPNorSeg(struct frame buffer){
  struct IPv6struct* myIP = (struct IPv6struct*)(buffer.data);
  return (!(hasIPv6(&(&buffer)->type) && ((myIP)->nxtHdr)==6));
}

//Function to see if the synHt contains the ports key possibly contained in the buffer
bool hasPortKey(struct frame buffer, hashtable synHt ){
  if(hasIPv6(&(&buffer)->type)){
    struct IPv6struct* myIP = (struct IPv6struct*)(buffer.data);
    if(((myIP)->nxtHdr)==6){
      struct segment* mySeg = (struct segment*)(myIP)->data;
      struct ports aPort = getPorts(myIP, mySeg);
      return (hthaskey(synHt, &aPort, sizeof(aPort)));
    }
  }
  return false;
}

//Function to verify that I am not adding myself to the blacklist
bool nonAuthroizedConnection(uint32_t* srcaddr){
  if (0 == memcmp(srcaddr, &leibowk, 16)){
  // if ((0 == memcmp(srcaddr, &leibowk, 16))||(0 == memcmp(srcaddr, &david, 16))||(0 == memcmp(srcaddr, &vlad, 16))){
    // printf("You/A friend tried to connect, allowing :) \n");
    // printSource(srcaddr);
    return false;
  }
  return true;
}

//Function to update partners blacklists.
void updateFriendsBlacklist(void* key){
  char* name = "vlad4";
  char* name2 = "david4";
  char* regalwildlings = "rw";

  int vladSock = connectto(name, FRNDPORT);
  int davidSock = connectto(name2, FRNDPORT);

  // printf("stuck at write! \n");
  write(vladSock, regalwildlings, strlen(regalwildlings));
  write(vladSock, (char*)key, strlen(key));
  // printf("after write! \n");
  write(davidSock, regalwildlings, strlen(regalwildlings));
  write(davidSock, (char*)key, strlen(key));
  shutdown(vladSock, SHUT_RDWR);
  close(vladSock);
  shutdown(davidSock, SHUT_RDWR);
  close(davidSock);
}

//Function to update the bad actors list. Once find a bad actor update my own blacklist and send the info to my partners
void updateBadActors(struct frame buffer, hashtable badActors, ssize_t rdct){
  if(hasIPv6(&(&buffer)->type)){
    struct IPv6struct* myIP = (struct IPv6struct*)(buffer.data);
    if(((myIP)->nxtHdr)==6){
      if( nonAuthroizedConnection((uint32_t*)myIP->srcaddr)){ 
        if(!hthaskey(badActors, &(myIP)->srcaddr, sizeof(myIP->srcaddr))){
          // printf("Adding to the blacklist!\n");
          //printIPv6(&buffer, rdct);
          // printSource(&(myIP->srcaddr));
          htinsert(badActors, memdup((myIP)->srcaddr, sizeof(myIP->srcaddr)), sizeof(myIP->srcaddr), 0);
        }
        //TO AVOID RACE TO CONNECT DO FRIEND UPDATE IN SEPERATE THREAD
        updateFriendsBlacklist(&(myIP->srcaddr));
      }
    }
  }
}

//Function to update blacklist using partners info. They should be sending "rw" to signify it was they who sent it.
void friendsBlacklistUpdate(char* buffer, hashtable badActors){
  char* comparable = "rw";
  if(memcmp(comparable, buffer, 2)==0){
    if(!hthaskey(badActors, &buffer[2], sizeof(&buffer[2]))){
      // printf("found a partners blacklisted IP and adding! - \n");
      // printSource(&buffer[2]);
      htinsert(badActors, memdup(&buffer[2], sizeof(&buffer[2])), sizeof(&buffer[2]), 0);
    }
  }
}
//Function to test if an address is a bad actor and should be blocked
bool notBadActor(struct frame buffer, hashtable badActors){
   struct IPv6struct* myIP = (struct IPv6struct*)(buffer.data);
   return (!(hthaskey(badActors, &(myIP->srcaddr), sizeof(myIP->srcaddr))));
}

//Function that makes a server to connect to group's sockets
int frndSocket(){
  int s = -1;
  s = socket(PF_INET, SOCK_STREAM, 0);
  int status = fcntl(s, F_SETFL, fcntl(s, F_GETFL, 0) | O_NONBLOCK);
  if(status==-1){
    printf("Couldn't properly set up nonblocking socket \n");
  }

  struct sockaddr_in addr;

  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(42020);
  addr.sin_addr.s_addr = 0;

  if(-1 == bind (s, (struct sockaddr*)&addr, sizeof(addr))){
    perror("bind");
    close(s);
    exit(EXIT_FAILURE);
  }

  if (-1 == listen(s, 1)){
      perror("listen");
      close(s);
      exit(EXIT_FAILURE);
  }
  return s;
}


/* Bridge
 * 
 * Note the use of select, sendto, and recvfrom.  
 */
static
void bridge(int tap, int in, int out, int frnds, struct sockaddr_in bcaddr) {

  fd_set rdset;
  int maxfd = mkfdset(&rdset, tap, in, out, frnds, 0);
  hashtable ht = htnew(32, macComp, kvfree);
  hashtable synHt = htnew(32, macComp, kvfree);
  hashtable badActors = htnew(32, macComp, kvfree);

  while(0 <= select(1+maxfd, &rdset, NULL, NULL, NULL)) {
    if(FD_ISSET(tap, &rdset)) {
      struct frame buffer;
      ssize_t rdct = read(tap, &buffer, BUFSZ);
      
      if(rdct < 0) {
        perror("buffer read");
      }

      else{
        insertSeg(buffer, synHt);
        struct sockaddr_in* socket;
        if (hthaskey(ht, (&buffer)->dst, 6) ){
          socket = htfind(ht, (&buffer)->dst, 6);
        }
        else{
          socket = &bcaddr;
        }
        if (-1 == sendto(out, &buffer, rdct, 0, (struct sockaddr*)socket, sizeof(struct sockaddr))){
          perror("sendto");
        }
      }
    }


    else if(FD_ISSET(in, &rdset) || FD_ISSET(out, &rdset)) {

      int sock = FD_ISSET(in, &rdset) ? in : out;
      
      struct frame buffer;
      struct sockaddr_in from;
      socklen_t          flen = sizeof(from);
      ssize_t rdct = recvfrom(sock, &buffer, BUFSZ, 0, 
                              (struct sockaddr*)&from, &flen);
      if(rdct < 0) {
        perror("recvfrom"); 
      }

      else{
        updateBadActors(buffer, badActors, rdct);
        insertSrcHt(ht,buffer,from);
        if((notBadActor(buffer, badActors))&&(hasPortKey(buffer, synHt) || notIPNorSeg(buffer))){
          forwardFrame(buffer, tap, rdct);
        }
      }
    }

    else if(FD_ISSET(frnds, &rdset)) {
      struct sockaddr_in addr;
      socklen_t len = sizeof(addr);
      int c = accept(frnds, (struct sockaddr*)&addr, &len);
      char buffer[80];
      while(0 < read(c, buffer, 80)){
      }

      friendsBlacklistUpdate(buffer, badActors);

      shutdown(c, SHUT_RDWR);
      close(c);
    }

    maxfd = mkfdset(&rdset, tap, in, out, frnds, 0);
  }
}