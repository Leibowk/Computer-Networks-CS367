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
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* Constants */
#define STR1(x)   #x
#define STR(x)    STR1(x)
#define DEVICE    "device"
#define PORT      "port"
#define BROADCAST "broadcast"
#define ANYIF     "0.0.0.0"
#define ANYPORT   "0"
#define PID       "pidfile"

#define BUFSZ 1514

/* Globals  */
static char* conffile   = STR(SYSCONFDIR) "/wfw.cfg";
static bool  printusage = false;
static bool foreground = false;


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
void bridge(int tap, int in, int out, struct sockaddr_in bcaddr);

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
    int       out  = ensuresocket(ANYIF, ANYPORT);
    int       in   = ensuresocket(htstrfind (conf, BROADCAST),
                                  htstrfind (conf, PORT));
    struct sockaddr_in
      bcaddr       = makesockaddr (htstrfind (conf,BROADCAST),
                                   htstrfind (conf, PORT));

    if(!foreground){
     deamonize(conf);
    }

    bridge(tap, in, out, bcaddr);
    
    close(in);
    close(out);
    close(tap);
    htfree(conf);
  }

  return result;
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
     

/* Bridge
 * 
 * Note the use of select, sendto, and recvfrom.  
 */
 void kvfree(void* key, void* value) {
  free(key);
  free(value);
}

static int memcompare(void* mem1, void* mem2){
  return memcmp(mem1, mem2, 6);
}

char* mallocString(char* bufString){
  char* string = malloc(6);
  memcpy(string, bufString, 6);
  return string;
}

struct sockaddr_in* mallocSockAddIn(struct sockaddr_in from){
  struct sockaddr_in* pointer = malloc(sizeof(struct sockaddr_in));
  memcpy(pointer, &from, sizeof(struct sockaddr_in));
  return pointer;
}

bool isBroadCast(void* key){
  unsigned char test1[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  unsigned char test2[2] = {0x33, 0x33};
  return ((memcmp(test1, key, 6)==0)||(memcmp(test2, key, 2)==0));
}

static
void bridge(int tap, int in, int out, struct sockaddr_in bcaddr) {

  fd_set rdset;

  int maxfd = mkfdset(&rdset, tap, in, out, 0);

  hashtable ht = htnew(32, memcompare, kvfree);

  struct frame {
    char dst[6];
    char src[6];
    short type;
    char data[1500];
  };

  while(0 <= select(1+maxfd, &rdset, NULL, NULL, NULL)) {

    if(FD_ISSET(tap, &rdset)) {
      struct frame buffer;
      ssize_t rdct = read(tap, &buffer, BUFSZ);
      if(rdct < 0) {
        perror("read");
      }
      struct sockaddr_in* socket;
      if (hthaskey(ht, (&buffer)->dst, 6) ){
        socket = htfind(ht, (&buffer)->dst, 6);
      }
      else{
        socket = &bcaddr;
      }

      if (-1 == sendto(out, &buffer, rdct, 0,
                            (struct sockaddr*)socket,
                            sizeof(struct sockaddr))){
        perror("sendto");
      }
    }


    else if(FD_ISSET(in, &rdset)) {

      struct frame buffer;
      struct sockaddr_in from;
      socklen_t          flen = sizeof(from);
      ssize_t rdct = recvfrom(in, &buffer, BUFSZ, 0, 
                              (struct sockaddr*)&from, &flen);
      if(rdct < 0) {
        perror("recvfrom");
      }
      if (!hthaskey(ht, (&buffer)->src, 6) ){
        bool broadCast = isBroadCast((&buffer)->src);
        if (!broadCast){
          htinsert(ht, mallocString(buffer.src), 6, mallocSockAddIn(from));
          }
        }
      else{
        memcpy(htfind(ht, (&buffer)->src, 6), &from, sizeof(struct sockaddr_in));
      }
   
      if(-1 == write(tap, &buffer, rdct)) {
        perror("write");
      }
    }

    else if(FD_ISSET(out, &rdset)) {
      struct frame buffer;
      struct sockaddr_in from;
      socklen_t          flen = sizeof(from);
      ssize_t rdct = recvfrom(out, &buffer, BUFSZ, 0, 
                              (struct sockaddr*)&from, &flen);
      if(rdct < 0) {
        perror("recvfrom");
      }

      if(-1 == write(tap, &buffer, rdct)) {
        perror("write");
      }
    }
    

    maxfd = mkfdset(&rdset, tap, in, out, 0);
  }

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

 
