/* Copyright (c) 2016 by the author(s)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * ============================================================================
 *
 * Author(s):
 *   Stefan Wallentowitz <stefan@wallentowitz.de>
 *   Nicolai Gutmann <nicolai.gutmann@tum.de>
 */
//GDB server for Open SoC Debug
#include "opensocdebug.h"



#include <stdio.h>
#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>

#include "or1k_spr_defs.h"
#include "opensocdebug.h"

//TODO Adapt for multiple cores/memories


//TODO Number of registers?
//TODO correct number?
#define GDB_BUF_MAX 512
/* Indices of GDB registers that are not GPRs. Must match GDB settings! */
#define PPC_REGNUM  (MAX_GPRS + 0)	/*!< Previous PC */
#define NPC_REGNUM  (MAX_GPRS + 1)	/*!< Next PC */
#define SR_REGNUM   (MAX_GPRS + 2)	/*!< Supervision Register */
#define NUM_REGS    (MAX_GPRS + 3)	/*!< Total GDB registers */




/*! Definition of GDB target signals. Data taken from the GDB 6.8
    source. Only those we use defined here. */
enum target_signal {
  TARGET_SIGNAL_NONE =  0,
  TARGET_SIGNAL_INT  =  2,
  TARGET_SIGNAL_ILL  =  4,
  TARGET_SIGNAL_TRAP =  5,
  TARGET_SIGNAL_FPE  =  8,
  TARGET_SIGNAL_BUS  = 10,
  TARGET_SIGNAL_SEGV = 11,
  TARGET_SIGNAL_ALRM = 14,
  TARGET_SIGNAL_USR2 = 31,
  TARGET_SIGNAL_PWR  = 32
};


/*! Data structure for RSP buffers. Can't be null terminated, since it may
  include zero bytes */
struct rsp_buf
{
  char  data[GDB_BUF_MAX];
  int   len;
};


/*! Central data for the RSP connection */
static struct
{
  int                client_waiting;    /*!< Is client waiting a response? */
  int                proto_num;     /*!< Number of the protocol used */
  int                client_fd;     /*!< FD for talking to GDB */
  int                sigval;        /*!< GDB signal for any exception */
  unsigned long int  start_addr;    /*!< Start of last run */
  //struct mp_entry   *mp_hash[MP_HASH_SIZE];   /*!< Matchpoint hash table */
} rsp;

//Information on system accessed through OSD.
//Expand with IDs to assign this gdbserver to a specific core within
//system.
static struct {
    struct osd_context *ctx;
    uint16_t *memories; //Module IDs of MAMs
    size_t num_mems; //Number of memories in system
} osd;


static const char hexchars[]="0123456789abcdef";

/*---------------------------------------------------------------------------*/
/*!Utility to give the value of a hex char
   @param[in] ch  A character representing a hexadecimal digit. Done as -1,
                  for consistency with other character routines, which can use
                  -1 as EOF.
   @return  The value of the hex character, or -1 if the character is
            invalid.                                                         */
/*---------------------------------------------------------------------------*/
static int
hex (int  c)
{
  return  ((c >= 'a') && (c <= 'f')) ? c - 'a' + 10 :
          ((c >= '0') && (c <= '9')) ? c - '0' :
          ((c >= 'A') && (c <= 'F')) ? c - 'A' + 10 : -1;

}   /* hex () */


//Forward declarations of functions
static void               reg2hex (unsigned long int  val, char *buf);
static unsigned long int  hex2reg (char *buf);
static void               rsp_get_client ();
static void               rsp_client_request ();
static void               rsp_client_close ();
static void               put_packet (struct rsp_buf *buf);
static void               put_str_packet (const char *str);
static struct rsp_buf     get_packet ();
static void               put_rsp_char (char  c);
static int                get_rsp_char ();
static int                rsp_unescape (char *data, int len);
static void               rsp_report_exception ();
static void               rsp_continue (struct rsp_buf *buf);
static void               rsp_continue_with_signal (struct rsp_buf *buf);
static void               rsp_continue_generic (unsigned long int  addr,
                        unsigned long int  except);
static void               rsp_read_all_regs ();
static void               rsp_write_all_regs (struct rsp_buf *buf);
static void               rsp_read_mem (struct rsp_buf *buf);
static void               rsp_write_mem (struct rsp_buf *buf);
static void               rsp_read_reg (struct rsp_buf *buf);
static void               rsp_write_reg (struct rsp_buf *buf);
static void               rsp_query (struct rsp_buf *buf);
static void               rsp_command (struct rsp_buf *buf);
static void               rsp_set (struct rsp_buf *buf);
static void               rsp_restart ();
static void               rsp_step (struct rsp_buf *buf);
static void               rsp_step_with_signal (struct rsp_buf *buf);
static void               rsp_step_generic (unsigned long int  addr,
                        unsigned long int  except);
static void               rsp_vpkt (struct rsp_buf *buf);
static void               rsp_write_mem_bin (struct rsp_buf *buf);
static void               rsp_remove_matchpoint (struct rsp_buf *buf);
static void               rsp_insert_matchpoint (struct rsp_buf *buf);



/*---------------------------------------------------------------------------*/
/*!Convert a register to a hex digit string
   The supplied 32-bit value is converted to an 8 digit hex string.
   It is null terminated for convenient printing.
   @param[in]  val  The value to convert
   @param[out] buf  The buffer for the text string                           */
/*---------------------------------------------------------------------------*/
static void
reg2hex (unsigned long int  val,
	 char              *buf)
{
  int  n;			/* Counter for digits */

  for (n = 0; n < 8; n++)
    {
      int  nyb_shift = n * 4;
      buf[n] = hexchars[(val >> nyb_shift) & 0xf];
    }

  buf[8] = 0;			/* Useful to terminate as string */

}	/* reg2hex () */


/*---------------------------------------------------------------------------*/
/*!Convert a hex digit string to a register value
   The supplied 8 digit hex string is converted to a 32-bit value.
   @param[in] buf  The buffer with the hex string
   @return  The value to convert                                             */
/*---------------------------------------------------------------------------*/
static unsigned long int
hex2reg (char *buf)
{
  int                n;		/* Counter for digits */
  unsigned long int  val = 0;	/* The result */

  for (n = 0; n < 8; n++)
    {
      int  nyb_shift = n * 4;
      val |= hex (buf[n]) << nyb_shift;
    }

  return val;

} /* hex2reg () */


/*---------------------------------------------------------------------------*/
/*!Close the connection to the client if it is open                          */
/*---------------------------------------------------------------------------*/
static void
rsp_client_close ()
{
  if (-1 != rsp.client_fd)
    {
      close (rsp.client_fd);
      rsp.client_fd = -1;
    }
}   /* rsp_client_close () */


//Read a single char from GDB
static int
get_rsp_char ()
{
  if (-1 == rsp.client_fd)
    {
      fprintf (stderr, "Warning: Attempt to read from unopened RSP "
           "client: Ignored\n");
      return  -1;
    }

  /* Non-blocking read until successful (we retry after interrupts) or
     catastrophic failure. */
  while (1)
    {
      unsigned char  c;

      switch (read (rsp.client_fd, &c, sizeof (c)))
    {
    case -1:
        fprintf (stderr, "Warning: Failed to read from RSP client: "
               "Closing client connection\n");
        rsp_client_close ();
        return  -1;
        break;

    case 0:
      // EOF
      return  -1;

    default:
      return  c & 0xff; /* Success, we can return (no sign extend!) */
    }
    }
} /* get_rsp_char () */

/*---------------------------------------------------------------------------*/
/*!"Unescape" RSP binary data

   '#', '$' and '}' are escaped by preceding them by '}' and oring with 0x20.

   This function reverses that, modifying the data in place.

   @param[in] data  The array of bytes to convert
   @para[in]  len   The number of bytes to be converted

   @return  The number of bytes AFTER conversion                             */
/*---------------------------------------------------------------------------*/
static int
rsp_unescape (char *data,
	      int   len)
{
  int  from_off = 0;		/* Offset to source char */
  int  to_off   = 0;		/* Offset to dest char */

  while (from_off < len)
    {
      /* Is it escaped */
      if ( '}' == data[from_off])
	{
	  from_off++;
	  data[to_off] = data[from_off] ^ 0x20;
	}
      else
	{
	  data[to_off] = data[from_off];
	}

      from_off++;
      to_off++;
    }

  return  to_off;

}	/* rsp_unescape () */


//Write a single char to GDB
static void
put_rsp_char (char  c)
{

  /* Write until successful (we retry after interrupts) or catastrophic
     failure. */
  while (1)
    {
    switch (write (rsp.client_fd, &c, sizeof (c)))
    {
    case -1:
      fprintf (stderr, "Warning: Failed to write to RSP client: "
               "Closing client connection\n");
      rsp_client_close ();
      return;
      
      break;

    case 0:
      break;        /* Nothing written! Try again */

    default:
      printf("%c\n", c);
      return;       /* Success, we can return */
    }
    }
} /* put_rsp_char () */

//Put together a packet with $<packet info>#<checksum> and write it to
//GDB
static void
put_packet (struct rsp_buf *buf)
{
  int  ch;              /* Ack char */

  /* Construct $<packet info>#<checksum>. Repeat until the GDB client
     acknowledges satisfactory receipt. */
  do
    {
      unsigned char checksum = 0;   /* Computed checksum */
      int           count    = 0;   /* Index into the buffer */

#if RSP_TRACE
      printf ("Putting %s\n", buf->data);
      fflush (stdout);
#endif

      put_rsp_char ('$');       /* Start char */

      /* Body of the packet */
      for (count = 0; count < buf->len; count++)
    {
      unsigned char  ch = buf->data[count];

      /* Check for escaped chars */
      if (('$' == ch) || ('#' == ch) || ('*' == ch) || ('}' == ch))
        {
          ch       ^= 0x20;
          checksum += (unsigned char)'}';
          put_rsp_char ('}');
        }

      checksum += ch;
      put_rsp_char (ch);
    }

      put_rsp_char ('#');       /* End char */

      /* Computed checksum */
      put_rsp_char (hexchars[checksum >> 4]);
      put_rsp_char (hexchars[checksum % 16]);

      /* Check for ack of connection failure */
      ch = get_rsp_char ();
      if (-1 == ch)
    {
      return;           /* Fail the put silently. */
    }
    }
  while ('+' != ch);

}   /* put_packet () */


//Reformat a string to a rsp_buf and write it to GDB
static void
put_str_packet (const char *str)
{
  struct rsp_buf  buf;
  int             len = strlen (str);

  /* Construct the packet to send, so long as string is not too big,
     otherwise truncate. Add EOS at the end for convenient debug printout */

  if (len >= GDB_BUF_MAX)
    {
      fprintf (stderr, "Warning: String %s too large for RSP packet: "
           "truncated\n", str);
      len = GDB_BUF_MAX - 1;
    }

  strncpy (buf.data, str, len);
  buf.data[len] = 0;
  buf.len       = len;

  put_packet (&buf);

}   /* put_str_packet () */

//Read a packet consisting of $<packet_info>#<checksum> from GDB,
//and check checksum
struct rsp_buf get_packet() {
    struct rsp_buf buf;
    
    while (1) {
        unsigned char   checksum;
        int             count;
        int             ch;
        
        ch = get_rsp_char();
        while (ch != '$') {
            if (ch == -1) {
                buf.len = -1;
                return buf;
            }
            ch = get_rsp_char();
        }
        
        checksum = 0;
        count    = 0;
        
        while (count < GDB_BUF_MAX - 1) {
            ch = get_rsp_char();
            
            if (ch == -1) {
                buf.len = -1;
                return buf;
            }
                
            if(ch == '$') {
                checksum = 0;
                count = 0;
                
                continue;
            }
            
            if(ch == '#')
                break;
                
            checksum        = checksum + (unsigned char)ch;
            buf.data[count] = (char)ch;
            count           = count + 1;
        }
        
        buf.data[count] = 0;
        buf.len = count;
        
        if (ch == '#') {
            unsigned char inc_csum;
            
            ch = get_rsp_char();
            if (ch == -1) {
                buf.len = -1;
                return buf;
            }
            inc_csum = hex(ch) << 4;
            
            ch = get_rsp_char();
            if (ch == -1) {
                buf.len = -1;
                return buf;
            }
            inc_csum += hex(ch);
            
            if (checksum != inc_csum) {
                fprintf(stderr, "Warning: Bad RSP checksum: Computed "
                        "0x%02x, received 0x%02x\n", checksum, inc_csum);
                put_rsp_char('-');
            }
            else {
                put_rsp_char('+');
                break;
            }
        }
        else {
            fprintf(stderr, "Warning: RSP packet overran buffer\n");
        }
    }
    return buf;
} //get_packet()


static void handle_request(struct rsp_buf buf) {
    switch (buf.data[0])
    {
    case '!':
      /* Request for extended remote mode */
      put_str_packet ("OK");
      return;

    case '?':
      /* Return last signal ID */
      rsp_report_exception();
      return;

    case 'A':
      /* Initialization of argv not supported */
      fprintf (stderr, "Warning: RSP 'A' packet not supported: ignored\n");
      put_str_packet ("E01");
      return;

    case 'b':
      /* Setting baud rate is deprecated */
      fprintf (stderr, "Warning: RSP 'b' packet is deprecated and not "
           "supported: ignored\n");
      return;

    case 'B':
      /* Breakpoints should be set using Z packets */
      fprintf (stderr, "Warning: RSP 'B' packet is deprecated (use 'Z'/'z' "
           "packets instead): ignored\n");
      return;

    case 'c':
      /* Continue */
      rsp_continue (&buf);
      return;

    case 'C':
      /* Continue with signal */
      //TODO?
      //rsp_continue_with_signal (buf);
      return;

    case 'd':
      /* Disable debug using a general query */
      fprintf (stderr, "Warning: RSP 'd' packet is deprecated (define a 'Q' "
           "packet instead: ignored\n");
      return;

    case 'D':
      /* Detach GDB. Do this by closing the client. The rules say that
     execution should continue. TODO. Is this really then intended
     meaning? Or does it just mean that only vAttach will be recognized
     after this? */
      put_str_packet ("OK");
      rsp_client_close();
      rsp.sigval = TARGET_SIGNAL_NONE;  /* No signal now */
      //TODO Unstall CPU?
      return;

    case 'F':
      /* File I/O is not currently supported */
      fprintf (stderr, "Warning: RSP file I/O not currently supported: 'F' "
           "packet ignored\n");
      return;

    case 'g':
      rsp_read_all_regs ();
      return;

    case 'G':
      rsp_write_all_regs (&buf);
      return;
      
    case 'H':
      /* Set the thread number of subsequent operations. For now ignore
     silently and just reply "OK" */
      put_str_packet ("OK");
      return;

    case 'i':
      /* Single instruction step */
      fprintf (stderr, "Warning: RSP cycle stepping not supported: target "
           "stopped immediately\n");
      rsp.client_waiting = 1;           /* Stop reply will be sent */
      return;

    case 'I':
      /* Single instruction step with signal */
      fprintf (stderr, "Warning: RSP cycle stepping not supported: target "
           "stopped immediately\n");
      rsp.client_waiting = 1;           /* Stop reply will be sent */
      return;

    case 'k':
      /* Kill request. Do nothing for now. */
      return;

    case 'm':
      /* Read memory (symbolic) */
      rsp_read_mem (&buf);
      return;

    case 'M':
      /* Write memory (symbolic) */
      rsp_write_mem (&buf);
      return;

    case 'p':
      /* Read a register */
      rsp_read_reg (&buf);
      return;

    case 'P':
      /* Write a register */
      rsp_write_reg (&buf);
      return;

    case 'q':
      /* Any one of a number of query packets */
      rsp_query (&buf);
      return;

    case 'Q':
      /* Any one of a number of set packets */
      rsp_set (&buf);
      return;

    case 'r':
      /* Reset the system. Deprecated (use 'R' instead) */
      fprintf (stderr, "Warning: RSP 'r' packet is deprecated (use 'R' "
           "packet instead): ignored\n");
      return;

    case 'R':
      /* Restart the program being debugged. */
      rsp_restart ();
      return;

    case 's':
      /* Single step (one high level instruction). This could be hard without
     DWARF2 info */
      rsp_step (&buf);
      return;

    case 'S':
      /* Single step (one high level instruction) with signal. This could be
     hard without DWARF2 info */
      rsp_step_with_signal (&buf);
      return;

    case 't':
      /* Search. This is not well defined in the manual and for now we don't
     support it. No response is defined. */
      fprintf (stderr, "Warning: RSP 't' packet not supported: ignored\n");
      return;

    case 'T':
      /* Is the thread alive. We are bare metal, so don't have a thread
     context. The answer is always "OK". */
      put_str_packet ("OK");
      return;

    case 'v':
      /* Any one of a number of packets to control execution */
      rsp_vpkt (&buf);
      return;

    case 'X':
      /* Write memory (binary) */
      rsp_write_mem_bin (&buf);
      return;

    case 'z':
      /* Remove a breakpoint/watchpoint. */
      rsp_remove_matchpoint (&buf);
      return;

    case 'Z':
      /* Insert a breakpoint/watchpoint. */
      rsp_insert_matchpoint (&buf);
      return;

    default:
      /* Unknown commands are ignored */
      fprintf (stderr, "Warning: Unknown RSP request %s\n", buf.data);
      return;
    }
}   /* rsp_client_request () */

int main(int argc, char *argv[]) {
    
    //Establish connection with OSD daemon
    
    
    osd_new(&(osd.ctx), OSD_MODE_DAEMON, 0, 0);

    if (osd_connect(osd.ctx) != OSD_SUCCESS) {
        fprintf(stderr, "Cannot connect to Open SoC Debug daemon\n");
        exit(1);
    }
    
    if (OSD_SUCCESS != osd_get_memories(osd.ctx, &(osd.memories),
                        &(osd.num_mems))) {
        fprintf(stderr, "Cannot get module IDs for memories\n");
    }
    
    fprintf(stderr, "Successfully connected to Open SoC Debug daemon\n");
    
    
    struct rsp_buf  buf;
    int sock_fd;
    int optval;
    struct sockaddr_in serv_addr, cli_addr;
    socklen_t cli_len;
    int portno = 2828;

    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        fprintf(stderr, "ERROR: Cannot open RSP socket\n");
        return -1;
    }
    
    optval = 1;
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval,
                sizeof(optval));

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);

    if (bind(sock_fd, (struct sockaddr *) &serv_addr,
                sizeof(serv_addr)) < 0) {
        fprintf(stderr, "ERROR on binding");
        return -1;
    }
    
    listen(sock_fd,1);
    fprintf(stderr, "Listening for RSP on port %d\n", portno);
    //fflush(stdout);
    
    
    cli_len = sizeof(cli_addr);
    rsp.client_fd = accept(sock_fd, 
                        (struct sockaddr *) &cli_addr, 
                        &cli_len);
    if (rsp.client_fd < 0) {
        fprintf(stderr, "ERROR on accept");
        return -1;
    }
    
    fprintf(stderr, "GDB connected\n");
    
    optval = 1;
    setsockopt (rsp.client_fd, SOL_SOCKET, SO_KEEPALIVE,
                (char *)&optval, sizeof(optval));
    
    close(sock_fd);
    signal(SIGPIPE, SIG_IGN);
    
    while(1) {
        bzero(buf.data,256);
        buf = get_packet();
        
        //connection loss
        if (buf.len == -1) {
            rsp_client_close();
            return 0;
        }
        printf("Here is the message: %s\n",buf.data);

        handle_request(buf);
    }
    rsp_client_close();
    return 0;
}


/*---------------------------------------------------------------------------*/
/*!Send a packet acknowledging an exception has occurred
   This is only called if there is a client FD to talk to                    */
/*---------------------------------------------------------------------------*/
static void
rsp_report_exception ()
{
  struct rsp_buf  buf;

  /* Construct a signal received packet */
  buf.data[0] = 'S';
  buf.data[1] = hexchars[rsp.sigval >> 4];
  buf.data[2] = hexchars[rsp.sigval % 16];
  buf.data[3] = 0;
  buf.len     = strlen (buf.data);

  put_packet (&buf);

}   /* rsp_report_exception () */

//Continue command received
static void
rsp_continue (struct rsp_buf *buf)
{
    //TODO
    return;
}


/*---------------------------------------------------------------------------*/
/*!Handle a RSP read all registers request
   The registers follow the GDB sequence for OR1K: GPR0 through GPR31, PPC
   (i.e. SPR PPC), NPC (i.e. SPR NPC) and SR (i.e. SPR SR). Each register is
   returned as a sequence of bytes in target endian order.
   Each byte is packed as a pair of hex digits.                              */
/*---------------------------------------------------------------------------*/
static void
rsp_read_all_regs ()
{
  struct rsp_buf  buf;          /* Buffer for the reply */
  int             r;            /* Register index */
  uint16_t        readval[2];
  unsigned long int val;
  /* The GPRs */
  for (r = 0; r < MAX_GPRS; r++)
  {
      //TODO: replace fixed module number
      printf("for-loop\n");
      osd_reg_read32(osd.ctx, 5, 0x8000 | r, readval);
      printf("finished reg read\n");
      val = readval[0] << 16 | readval[1];
      reg2hex(val, &buf.data[r*8]);
      printf("finished reg2hex\n");
      buf.data[(r+1)*8] = 0;
      printf("Read: %s\n", &buf.data[r*8]);
  }

  /* PPC, NPC and SR */
  osd_reg_read32(osd.ctx, 5, 0x8000 | SPR_PPC, readval);
  val = readval[0] << 16 | readval[1];
  reg2hex (val, &(buf.data[PPC_REGNUM * 8]));
  val = readval[0] << 16 | readval[1];
  osd_reg_read32(osd.ctx, 5, 0x8000 | SPR_NPC, readval);
  val = readval[0] << 16 | readval[1];
  reg2hex (val, &(buf.data[NPC_REGNUM * 8]));
  osd_reg_read32(osd.ctx, 5, 0x8000 | SPR_SR, readval);
  val = readval[0] << 16 | readval[1];
  reg2hex (val, &(buf.data[SR_REGNUM * 8]));

  /* Finalize the packet and send it */
  buf.data[NUM_REGS * 8] = 0;
  buf.len                = NUM_REGS * 8;

  put_packet(&buf);
  return;
}   /* rsp_read_all_regs () */


/*---------------------------------------------------------------------------*/
/*!Handle a RSP write all registers request
   The registers follow the GDB sequence for OR1K: GPR0 through GPR31, PPC
   (i.e. SPR PPC), NPC (i.e. SPR NPC) and SR (i.e. SPR SR). Each register is
   supplied as a sequence of bytes in target endian order.
   Each byte is packed as a pair of hex digits.
   @todo There is no error checking at present. Non-hex chars will generate a
         warning message, but there is no other check that the right amount
         of data is present. The result is always "OK".
   @param[in] buf  The original packet request.                              */
/*---------------------------------------------------------------------------*/
static void
rsp_write_all_regs (struct rsp_buf *buf)
{
    //TODO
  //~ int             r;            /* Register index */

  //~ /* The GPRs */
  //~ for (r = 0; r < MAX_GPRS; r++)
    //~ {
      //~ cpu_state.reg[r] = hex2reg (&(buf->data[r * 8]));
    //~ }

  //~ /* PPC, NPC and SR */
  //~ cpu_state.sprs[SPR_PPC] = hex2reg (&(buf->data[PPC_REGNUM * 8]));
  //~ cpu_state.sprs[SPR_SR]  = hex2reg (&(buf->data[SR_REGNUM  * 8]));
  //~ set_npc (hex2reg (&(buf->data[NPC_REGNUM * 8])));

  //~ /* Acknowledge. TODO: We always succeed at present, even if the data was
     //~ defective. */
    put_str_packet ("OK");
    return;

}   /* rsp_write_all_regs () */


static int verify_memoryarea(unsigned int addr, int len) {
    
    
    
    struct osd_memory_descriptor *desc;
    uint8_t mod = osd.memories[0];
    osd_get_memory_descriptor(osd.ctx, mod, &desc);
    
    unsigned int baseaddr = desc->regions[0].base_addr;
    unsigned int size = desc->regions[0].size;
    
    fprintf(stderr, "Address: %i\n", addr);
    fprintf(stderr, "Length: %i\n", len);
    fprintf(stderr, "Base Address: %i\n", baseaddr);
    fprintf(stderr, "Size: %i\n", size);

    return (addr >= baseaddr) && ((addr+len) <= (baseaddr+size));
}
    


/*---------------------------------------------------------------------------*/
/*!Handle a RSP read memory (symbolic) request
   Syntax is:
     m<addr>,<length>:
   The response is the bytes, lowest address first, encoded as pairs of hex
   digits.
   The length given is the number of bytes to be read.
   @note This function reuses buf, so trashes the original command.
   @param[in] buf  The command received                                      */
/*---------------------------------------------------------------------------*/
static void
rsp_read_mem (struct rsp_buf *buf)
{
  unsigned int    addr;         /* Where to read the memory */
  int             len;          /* Number of bytes to read */
  int             off;          /* Offset into the memory */

  if (2 != sscanf (buf->data, "m%x,%x:", &addr, &len))
    {
      fprintf (stderr, "Warning: Failed to recognize RSP read memory "
           "command: %s\n", buf->data);
      put_str_packet ("E01");
      return;
    }

  /* Make sure we won't overflow the buffer (2 chars per byte) */
  if ((len * 2) >= GDB_BUF_MAX)
    {
      fprintf (stderr, "Warning: Memory read %s too large for RSP packet: "
           "truncated\n", buf->data);
      len = (GDB_BUF_MAX - 1) / 2;
    }

    /* Check memory area is valid */
  if (!verify_memoryarea(addr, len)) {  
      /* The error number doesn't matter. The GDB client will substitute
         its own */
      put_str_packet ("E01");
      return;
  }
    
    uint8_t data[len];
    osd_memory_read(osd.ctx, osd.memories[0], addr, data, len);
  /* Refill the buffer with the reply */
  for (off = 0; off < len; off++)
    {
      unsigned char  ch;
      ch = data[off];

      buf->data[off * 2]     = hexchars[ch >>   4];
      buf->data[off * 2 + 1] = hexchars[ch &  0xf];
    }

  buf->data[off * 2] = 0;           /* End of string */
  buf->len           = strlen (buf->data);
  put_packet (buf);

}   /* rsp_read_mem () */


/*---------------------------------------------------------------------------*/
/*!Handle a RSP write memory (symbolic) request
   Syntax is:
     m<addr>,<length>:<data>
   The data is the bytes, lowest address first, encoded as pairs of hex
   digits.
   The length given is the number of bytes to be written.
   @note This function reuses buf, so trashes the original command.
   @param[in] buf  The command received                                      */
/*---------------------------------------------------------------------------*/
static void
rsp_write_mem (struct rsp_buf *buf)
{
  unsigned int    addr;         /* Where to write the memory */
  uint8_t             len;          /* Number of bytes to write */
  char           *symdat;       /* Pointer to the symboli data */
  int             datlen;       /* Number of digits in symbolic data */
  int             off;          /* Offset into the memory */
  if (2 != sscanf (buf->data, "M%x,%x:", &addr, &len))
    {
      fprintf (stderr, "Warning: Failed to recognize RSP write memory "
           "command: %s\n", buf->data);
      put_str_packet ("E01");
      return;
    }

  /* Find the start of the data and check there is the amount we expect. */
  symdat = memchr ((const void *)buf->data, ':', GDB_BUF_MAX) + 1;
  datlen = buf->len - (symdat - buf->data);

  /* Sanity check */
  if (len * 2 != datlen){
      fprintf (stderr, "Warning: Write of %d digits requested, but %d digits "
           "supplied: packet ignored\n", len * 2, datlen );
      put_str_packet ("E01");
      return;
    }
    
    
    uint8_t data[len];

    if (0 == verify_memoryarea (addr, len)) {
      /* The error number doesn't matter. The GDB client will substitute
         its own */
      put_str_packet ("E01");
      return;
    }
    else {
        
        /* Write the bytes to memory */
        for (off = 0; off < len; off++)
        {
            data[off * 2] = hex (symdat[off * 2]);
            data[off * 2 + 1] = hex (symdat[off * 2 + 1]);
        }
        fprintf(stderr, "%s", data);
        if(osd_memory_write(osd.ctx, osd.memories[0], addr, data, len)
                != OSD_SUCCESS) {
            fprintf(stderr, "Memory write failed\n");
            put_str_packet ("E01");
            return;
        }
    }

    put_str_packet ("OK");

}   /* rsp_write_mem () */


/*---------------------------------------------------------------------------*/
/*!Read a single register
   The registers follow the GDB sequence for OR1K: GPR0 through GPR31, PC
   (i.e. SPR NPC) and SR (i.e. SPR SR). The register is returned as a
   sequence of bytes in target endian order.
   Each byte is packed as a pair of hex digits.
   @param[in] buf  The original packet request. Reused for the reply.        */
/*---------------------------------------------------------------------------*/
static void
rsp_read_reg (struct rsp_buf *buf)
{
  unsigned int  regnum;

  /* Break out the fields from the data */
  if (1 != sscanf (buf->data, "p%x", &regnum))
    {
      fprintf (stderr, "Warning: Failed to recognize RSP read register "
           "command: %s\n", buf->data);
      put_str_packet ("E01");
      return;
    }
    
  int valid_regnum = (regnum < MAX_GPRS) || (regnum == PPC_REGNUM) ||
        (regnum == NPC_REGNUM) || (regnum == SR_REGNUM);
  if (valid_regnum) {
      uint16_t readval[2];
      unsigned long int val;
      //TODO: replace fixed module number
      osd_reg_read32(osd.ctx, 5, 0x8000 | regnum, readval);
      val = readval[0] << 16 | readval[1];
      reg2hex(val, &(buf->data[0]));
      buf->data[8] = 0; //EOS
  }
  else
  {
      /* Error response if we don't know the register */
      fprintf (stderr, "Warning: Attempt to read unknown register 0x%x: "
           "ignored\n", regnum);
      put_str_packet ("E01");
      return;
  }

  buf->len = strlen (buf->data);
  put_packet (buf);

}   /* rsp_write_reg () */

    
/*---------------------------------------------------------------------------*/
/*!Write a single register
   The registers follow the GDB sequence for OR1K: GPR0 through GPR31, PC
   (i.e. SPR NPC) and SR (i.e. SPR SR). The register is specified as a
   sequence of bytes in target endian order.
   Each byte is packed as a pair of hex digits.
   @param[in] buf  The original packet request.                              */
/*---------------------------------------------------------------------------*/
static void
rsp_write_reg (struct rsp_buf *buf)
{
    //TODO
    //put_str_packet ("OK");
    //return;
  unsigned int  regnum;
  char          valstr[9];      /* Allow for EOS on the string */

  /* Break out the fields from the data */
  if (2 != sscanf (buf->data, "P%x=%8s", &regnum, valstr))
  {
      fprintf (stderr, "Warning: Failed to recognize RSP write register "
           "command: %s\n", buf->data);
      put_str_packet ("E01");
      return;
    }
  
  int valid_regnum = (regnum < MAX_GPRS) || (regnum == PPC_REGNUM) ||
        (regnum == NPC_REGNUM) || (regnum == SR_REGNUM);
  if (valid_regnum) {
    unsigned long int val = hex2reg(valstr);
    uint16_t* writeval = &val;
    //TODO: Replace fixed module number
    osd_reg_write32(osd.ctx, 5, 0x8000 | regnum, writeval);
  }
  else
  {
      /* Error response if we don't know the register */
      fprintf (stderr, "Warning: Attempt to write unknown register 0x%x: "
           "ignored\n", regnum);
      put_str_packet ("E01");
      return;
  }
  put_str_packet ("OK");

}   /* rsp_write_reg () */


/*---------------------------------------------------------------------------*/
/*!Handle a RSP query request
   @param[in] buf  The request. Reused for any packets that need to be sent
                   back.                                                     */
/*---------------------------------------------------------------------------*/
static void
rsp_query (struct rsp_buf *buf)
{
  if (0 == strcmp ("qAttached", buf->data))
    {
        //TODO? Are we?
      /* We are always attaching to an existing process with the bare metal
     embedded system. */
      put_str_packet ("1");
    }
  else if (0 == strcmp ("qC", buf->data))
    {
      /* Return the current thread ID (unsigned hex). A null response
     indicates to use the previously selected thread. We use the constant
     OR1KSIM_TID to represent our single thread of control. */
      sprintf (buf->data, "QC1");
      buf->len = strlen (buf->data);
      put_packet (buf);
    }
  else if (0 == strncmp ("qCRC", buf->data, strlen ("qCRC")))
    {
      /* Return CRC of memory area */
      fprintf (stderr, "Warning: RSP CRC query not supported\n");
      put_str_packet ("E01");
    }
  else if (0 == strcmp ("qfThreadInfo", buf->data))
    {
      /* Return info about active threads. We return just the constant
     OR1KSIM_TID to represent our single thread of control. */
      sprintf (buf->data, "m1");
      buf->len = strlen (buf->data);
      put_packet (buf);
    }
  else if (0 == strcmp ("qsThreadInfo", buf->data))
    {
      /* Return info about more active threads. We have no more, so return the
     end of list marker, 'l' */
      put_str_packet ("l");
    }
  else if (0 == strncmp ("qGetTLSAddr:", buf->data, strlen ("qGetTLSAddr:")))
    {
      /* We don't support this feature */
      put_str_packet ("");
    }
  else if (0 == strncmp ("qL", buf->data, strlen ("qL")))
    {
      /* Deprecated and replaced by 'qfThreadInfo' */
      fprintf (stderr, "Warning: RSP qL deprecated: no info returned\n");
      put_str_packet ("qM001");
    }
  else if (0 == strcmp ("qOffsets", buf->data))
    {
      /* Report any relocation */
      put_str_packet ("Text=0;Data=0;Bss=0");
    }
  else if (0 == strncmp ("qP", buf->data, strlen ("qP")))
    {
      /* Deprecated and replaced by 'qThreadExtraInfo' */
      fprintf (stderr, "Warning: RSP qP deprecated: no info returned\n");
      put_str_packet ("");
    }
  else if (0 == strncmp ("qRcmd,", buf->data, strlen ("qRcmd,")))
    {
      /* This is used to interface to commands to do "stuff" */
      //TODO? Probably not supported?
      put_str_packet ("OK");
      //rsp_command (buf);
    }
  else if (0 == strncmp ("qSupported", buf->data, strlen ("qSupported")))
    {
      /* Report a list of the features we support. For now we just ignore any
     supplied specific feature queries, but in the future these may be
     supported as well. Note that the packet size allows for 'G' + all the
     registers sent to us, or a reply to 'g' with all the registers and an
     EOS so the buffer is a well formed string. */

      char  reply[GDB_BUF_MAX];

      sprintf (reply, "PacketSize=%x", GDB_BUF_MAX);
      put_str_packet (reply);
    }
  else if (0 == strncmp ("qSymbol:", buf->data, strlen ("qSymbol:")))
    {
      /* Offer to look up symbols. Nothing we want (for now). TODO. This just
     ignores any replies to symbols we looked up, but we didn't want to
     do that anyway! */
      put_str_packet ("OK");
    }
  else if (0 == strncmp ("qThreadExtraInfo,", buf->data,
             strlen ("qThreadExtraInfo,")))
    {
      /* Report that we are runnable, but the text must be hex ASCI
     digits. For now do this by steam, reusing the original packet */
      sprintf (buf->data, "%02x%02x%02x%02x%02x%02x%02x%02x%02x",
           'R', 'u', 'n', 'n', 'a', 'b', 'l', 'e', 0);
      buf->len = strlen (buf->data);
      put_packet (buf);
    }
  else if (0 == strncmp ("qTStatus", buf->data, strlen ("qTStatus")))  
    {
      /* We don't support tracing, so return empty packet. */
      put_str_packet ("");
    }
  else if (0 == strncmp ("qXfer:", buf->data, strlen ("qXfer:")))
    {
      /* For now we support no 'qXfer' requests, but these should not be
     expected, since they were not reported by 'qSupported' */
      fprintf (stderr, "Warning: RSP 'qXfer' not supported: ignored\n");
      put_str_packet ("");
    }
  else
    {
      fprintf (stderr, "Unrecognized RSP query: ignored\n");
    }
}   /* rsp_query () */


//~ /*---------------------------------------------------------------------------*/
//~ /*!Handle a RSP qRcmd request
  //~ The actual command follows the "qRcmd," in ASCII encoded to hex
   //~ @param[in] buf  The request in full                                       */
//~ /*---------------------------------------------------------------------------*/
//~ static void
//~ rsp_command (struct rsp_buf *buf)
//~ {
  //~ char  cmd[GDB_BUF_MAX];

  //~ hex2ascii (cmd, &(buf->data[strlen ("qRcmd,")]));

  //~ /* Work out which command it is */
  //~ if (0 == strncmp ("readspr ", cmd, strlen ("readspr")))
    //~ {
      //~ unsigned int       regno;

      //~ /* Parse and return error if we fail */
      //~ if( 1 != sscanf (cmd, "readspr %4x", &regno))
    //~ {
      //~ fprintf (stderr, "Warning: qRcmd %s not recognized: ignored\n",
           //~ cmd);
      //~ put_str_packet ("E01");
      //~ return;
    //~ }

      //~ /* SPR out of range */
      //~ if (regno > MAX_SPRS)
    //~ {
      //~ fprintf (stderr, "Warning: qRcmd readspr %x too large: ignored\n",
           //~ regno);
      //~ put_str_packet ("E01");
      //~ return;
    //~ }

      //~ /* Construct the reply */
      //~ sprintf (cmd, "%8lx", (unsigned long int)mfspr (regno));
      //~ ascii2hex (buf->data, cmd);
      //~ buf->len = strlen (buf->data);
      //~ put_packet (buf);
    //~ }
  //~ else if (0 == strncmp ("writespr ", cmd, strlen ("writespr")))
    //~ {
      //~ unsigned int       regno;
      //~ unsigned long int  val;

      //~ /* Parse and return error if we fail */
      //~ if( 2 != sscanf (cmd, "writespr %4x %8lx", &regno, &val))
    //~ {
      //~ fprintf (stderr, "Warning: qRcmd %s not recognized: ignored\n",
           //~ cmd);
      //~ put_str_packet ("E01");
      //~ return;
    //~ }

      //~ /* SPR out of range */
      //~ if (regno > MAX_SPRS)
    //~ {
      //~ fprintf (stderr, "Warning: qRcmd writespr %x too large: ignored\n",
           //~ regno);
      //~ put_str_packet ("E01");
      //~ return;
    //~ }

      //~ /* Update the SPR and reply "OK" */
      //~ mtspr (regno, val);
      //~ put_str_packet ("OK");
    //~ }
      
//~ }   /* rsp_command () */


/*---------------------------------------------------------------------------*/
/*!Handle a RSP set request
   @param[in] buf  The request                                               */
/*---------------------------------------------------------------------------*/
static void
rsp_set (struct rsp_buf *buf)
{
  if (0 == strncmp ("QPassSignals:", buf->data, strlen ("QPassSignals:")))
    {
      /* Passing signals not supported */
      put_str_packet ("");
    }
  else if ((0 == strncmp ("QTDP",    buf->data, strlen ("QTDP")))   ||
       (0 == strncmp ("QFrame",  buf->data, strlen ("QFrame"))) ||
       (0 == strcmp  ("QTStart", buf->data))                    ||
       (0 == strcmp  ("QTStop",  buf->data))                    ||
       (0 == strcmp  ("QTinit",  buf->data))                    ||
       (0 == strncmp ("QTro",    buf->data, strlen ("QTro"))))
    {
      /* All tracepoint features are not supported. This reply is really only
     needed to 'QTDP', since with that the others should not be
     generated. */
      put_str_packet ("");
    }
  else
    {
      fprintf (stderr, "Unrecognized RSP set request: ignored\n");
    }
}   /* rsp_set () */


/*---------------------------------------------------------------------------*/
/*!Handle a RSP restart request
   For now we just put the program counter back to the one used with the last
   vRun request. There is no point in unstalling the processor, since we'll
   never get control back.                                                   */
/*---------------------------------------------------------------------------*/
static void
rsp_restart ()
{
    //TODO?
  //~ set_npc (rsp.start_addr);

}   /* rsp_restart () */


/*---------------------------------------------------------------------------*/
/*!Handle a RSP step request
   Parse the command to see if there is an address. Uses the underlying
   generic step function, with EXCEPT_NONE.
   @param[in] buf  The full step packet                          */
/*---------------------------------------------------------------------------*/
static void
rsp_step (struct rsp_buf *buf)
{
    //TODO
    return;
  //~ unsigned long int  addr;      /* The address to step from, if any */

  //~ if (0 == strcmp ("s", buf->data))
    //~ {
      //~ addr = cpu_state.pc;  /* Default uses current NPC */
    //~ }
  //~ else if (1 != sscanf (buf->data, "s%lx", &addr))
    //~ {
      //~ fprintf (stderr,
           //~ "Warning: RSP step address %s not recognized: ignored\n",
           //~ buf->data);
      //~ addr = cpu_state.pc;  /* Default uses current NPC */
    //~ }

  //~ rsp_step_generic (addr, EXCEPT_NONE);

}   /* rsp_step () */


/*---------------------------------------------------------------------------*/
/*!Handle a RSP step with signal request
   Currently null. Will use the underlying generic step function.
   @param[in] buf  The full step with signal packet              */
/*---------------------------------------------------------------------------*/
static void
rsp_step_with_signal (struct rsp_buf *buf)
{
    //TODO?
    return;
  //~ printf ("RSP step with signal '%s' received\n", buf->data);

}   /* rsp_step_with_signal () */


/*---------------------------------------------------------------------------*/
/*!Generic processing of a step request
   The signal may be EXCEPT_NONE if there is no exception to be
   handled. Currently the exception is ignored.
   The single step flag is set in the debug registers and then the processor
   is unstalled.
   @param[in] addr    Address from which to step
   @param[in] except  The exception to use (if any)                          */
/*---------------------------------------------------------------------------*/
static void
rsp_step_generic (unsigned long int  addr,
          unsigned long int  except)
{
    //TODO
    return;
  //~ /* Set the address as the value of the next program counter */
  //~ set_npc (addr);

  //~ /* Clear Debug Reason Register and watchpoint break generation in Debug Mode
     //~ Register 2 */
  //~ cpu_state.sprs[SPR_DRR]   = 0;
  //~ cpu_state.sprs[SPR_DMR2] &= ~SPR_DMR2_WGB;

  //~ /* Set the single step trigger in Debug Mode Register 1 and set traps to be
     //~ handled by the debug unit in the Debug Stop Register */
  //~ cpu_state.sprs[SPR_DMR1] |= SPR_DMR1_ST;
  //~ cpu_state.sprs[SPR_DSR]  |= SPR_DSR_TE;

  //~ /* Unstall the processor */
  //~ set_stall_state (0);

  //~ /* Any signal is cleared. */
  //~ rsp.sigval = TARGET_SIGNAL_NONE;

  //~ /* Note the GDB client is now waiting for a reply. */
  //~ rsp.client_waiting = 1;

}   /* rsp_step_generic () */


/*---------------------------------------------------------------------------*/
/*!Handle a RSP 'v' packet
   These are commands associated with executing the code on the target
   @param[in] buf  The request                                               */
/*---------------------------------------------------------------------------*/
static void
rsp_vpkt (struct rsp_buf *buf)
{
  if (0 == strncmp ("vAttach;", buf->data, strlen ("vAttach;")))
    {
      /* Attaching is a null action, since we have no other process. We just
     return a stop packet (using TRAP) to indicate we are stopped. */
      put_str_packet ("S05");
      return;
    }
  else if (0 == strcmp ("vCont?", buf->data))
    {
      /* For now we don't support this. */
      put_str_packet ("");
      return;
    }
  else if (0 == strncmp ("vCont", buf->data, strlen ("vCont")))
    {
      /* This shouldn't happen, because we've reported non-support via vCont?
     above */
      fprintf (stderr, "Warning: RSP vCont not supported: ignored\n" );
      return;
    }
  else if (0 == strncmp ("vFile:", buf->data, strlen ("vFile:")))
    {
      /* For now we don't support this. */
      fprintf (stderr, "Warning: RSP vFile not supported: ignored\n" );
      put_str_packet ("");
      return;
    }
  else if (0 == strncmp ("vFlashErase:", buf->data, strlen ("vFlashErase:")))
    {
      /* For now we don't support this. */
      fprintf (stderr, "Warning: RSP vFlashErase not supported: ignored\n" );
      put_str_packet ("E01");
      return;
    }
  else if (0 == strncmp ("vFlashWrite:", buf->data, strlen ("vFlashWrite:")))
    {
      /* For now we don't support this. */
      fprintf (stderr, "Warning: RSP vFlashWrite not supported: ignored\n" );
      put_str_packet ("E01");
      return;
    }
  else if (0 == strcmp ("vFlashDone", buf->data))
    {
      /* For now we don't support this. */
      fprintf (stderr, "Warning: RSP vFlashDone not supported: ignored\n" );
      put_str_packet ("E01");
      return;
    }
  else if (0 == strncmp ("vRun;", buf->data, strlen ("vRun;")))
    {
      /* We shouldn't be given any args, but check for this */
      if (buf->len > strlen ("vRun;"))
    {
      fprintf (stderr, "Warning: Unexpected arguments to RSP vRun "
           "command: ignored\n");
    }

      /* Restart the current program. However unlike a "R" packet, "vRun"
     should behave as though it has just stopped. We use signal
     5 (TRAP). */
      rsp_restart ();
      put_str_packet ("S05");
    }
  else
    {
      fprintf (stderr, "Warning: Unknown RSP 'v' packet type %s: ignored\n",
           buf->data);
      put_str_packet ("");
      return;
    }
}   /* rsp_vpkt () */


/*---------------------------------------------------------------------------*/
/*!Handle a RSP write memory (binary) request
   Syntax is:
     X<addr>,<length>:
   Followed by the specified number of bytes as raw binary. Response should be
   "OK" if all copied OK, E<nn> if error <nn> has occurred.
   The length given is the number of bytes to be written. However the number
   of data bytes may be greater, since '#', '$' and '}' are escaped by
   preceding them by '}' and oring with 0x20.
   @param[in] buf  The command received                                      */
/*---------------------------------------------------------------------------*/
static void
rsp_write_mem_bin (struct rsp_buf *buf)
{
	unsigned int  addr;           /* Where to write the memory */
	int           len;            /* Number of bytes to write */
	char*         bindat;         /* Pointer to the binary data */
	int           off;            /* Offset to start of binary data */
	int           newlen;         /* Number of bytes in bin data */

	if (2 != sscanf (buf->data, "X%x,%x:", &addr, &len))
	{
		fprintf (stderr, "Warning: Failed to recognize RSP write memory "
		"command: %s\n", buf->data);
		put_str_packet ("E01");
		return;
	}

	/* Find the start of the data and "unescape" it */
	bindat = memchr ((const void *)buf->data, ':', GDB_BUF_MAX) + 1;
	off    = bindat - buf->data;
	newlen = rsp_unescape (bindat, buf->len - off);

	/* Sanity check */
	if (newlen != len)
    {
		int  minlen = len < newlen ? len : newlen;

		fprintf (stderr, "Warning: Write of %d bytes requested, but %d bytes "
			"supplied. %d will be written\n", len, newlen, minlen);
		len = minlen;
	}

    if (0 == verify_memoryarea (addr, len)) {
      /* The error number doesn't matter. The GDB client will substitute
         its own */
      put_str_packet ("E01");
      return;
    }
    else {
        
        /* Write the bytes to memory */
        if(osd_memory_write(osd.ctx, osd.memories[0], addr, bindat, len)
                != OSD_SUCCESS) {
            fprintf(stderr, "Memory write failed\n");
            put_str_packet ("E01");
            return;
        }
    }

    put_str_packet ("OK");
	return;

}   /* rsp_write_mem_bin () */

      
/*---------------------------------------------------------------------------*/
/*!Handle a RSP remove breakpoint or matchpoint request
   For now only memory breakpoints are implemented, which are implemented by
   substituting a breakpoint at the specified address. The implementation must
   cope with the possibility of duplicate packets.
   @todo This doesn't work with icache/immu yet
   @param[in] buf  The command received                                      */
/*---------------------------------------------------------------------------*/
static void
rsp_remove_matchpoint (struct rsp_buf *buf)
{
    //TODO
    return;
  //~ enum mp_type       type;      /* What sort of matchpoint */
  //~ int                type_for_scanf;    /* To avoid old GCC limitations */
  //~ unsigned long int  addr;      /* Address specified */
  //~ int                len;       /* Matchpoint length (not used) */
  //~ struct mp_entry   *mpe;       /* Info about the replaced instr */

  //~ /* Break out the instruction. We have to use an intermediary for the type,
     //~ since older GCCs do not like taking the address of an enum
     //~ (dereferencing type-punned pointer). */
  //~ if (3 != sscanf (buf->data, "z%1d,%lx,%1d", &type_for_scanf, &addr, &len))
    //~ {
      //~ fprintf (stderr, "Warning: RSP matchpoint deletion request not "
           //~ "recognized: ignored\n");
      //~ put_str_packet ("E01");
      //~ return;
    //~ }

  //~ type = type_for_scanf;

  //~ /* Sanity check that the length is 4 */
  //~ if (4 != len)
    //~ {
      //~ fprintf (stderr, "Warning: RSP matchpoint deletion length %d not "
           //~ "valid: 4 assumed\n", len);
      //~ len = 4;
    //~ }

  //~ /* Sort out the type of matchpoint */
  //~ switch (type)
    //~ {
    //~ case BP_MEMORY:
      //~ /* Memory breakpoint - replace the original instruction. */
      //~ mpe = mp_hash_delete (type, addr);

      //~ /* If the BP hasn't yet been deleted, put the original instruction
     //~ back. Don't forget to free the hash table entry afterwards.
     //~ We make sure both the instruction cache is invalidated first, so that
     //~ the write goes through the cache. */
      //~ if (NULL != mpe)
    //~ {
      //~ ic_inv (addr);
      //~ set_program32 (addr, mpe->instr);
      //~ free (mpe);
    //~ }

      //~ put_str_packet ("OK");

      //~ return;
     
    //~ case BP_HARDWARE:
      //~ put_str_packet ("");      /* Not supported */
      //~ return;

    //~ case WP_WRITE:
      //~ put_str_packet ("");      /* Not supported */
      //~ return;

    //~ case WP_READ:
      //~ put_str_packet ("");      /* Not supported */
      //~ return;

    //~ case WP_ACCESS:
      //~ put_str_packet ("");      /* Not supported */
      //~ return;

    //~ default:
      //~ fprintf (stderr, "Warning: RSP matchpoint type %d not "
           //~ "recognized: ignored\n", type);
      //~ put_str_packet ("E01");
      //~ return;

    //~ }
}   /* rsp_remove_matchpoint () */

      
/*---------------------------------------------------------------------------*/
/*!Handle a RSP insert breakpoint or matchpoint request
   For now only memory breakpoints are implemented, which are implemented by
   substituting a breakpoint at the specified address. The implementation must
   cope with the possibility of duplicate packets.
   @todo This doesn't work with icache/immu yet
   @param[in] buf  The command received                                      */
/*---------------------------------------------------------------------------*/
static void
rsp_insert_matchpoint (struct rsp_buf *buf)
{
    //TODO
    return;
  //~ enum mp_type       type;      /* What sort of matchpoint */
  //~ int                type_for_scanf;    /* To avoid old GCC limitations */
  //~ unsigned long int  addr;      /* Address specified */
  //~ int                len;       /* Matchpoint length (not used) */

  //~ /* Break out the instruction. We have to use an intermediary for the type,
     //~ since older GCCs do not like taking the address of an enum
     //~ (dereferencing type-punned pointer). */
  //~ if (3 != sscanf (buf->data, "Z%1d,%lx,%1d", &type_for_scanf, &addr, &len))
    //~ {
      //~ fprintf (stderr, "Warning: RSP matchpoint insertion request not "
           //~ "recognized: ignored\n");
      //~ put_str_packet ("E01");
      //~ return;
    //~ }

  //~ type = type_for_scanf;

  //~ /* Sanity check that the length is 4 */
  //~ if (4 != len)
    //~ {
      //~ fprintf (stderr, "Warning: RSP matchpoint insertion length %d not "
           //~ "valid: 4 assumed\n", len);
      //~ len = 4;
    //~ }

  //~ /* Sort out the type of matchpoint */
  //~ switch (type)
    //~ {
    //~ case BP_MEMORY:
      //~ /* Memory breakpoint - substitute a TRAP instruction
     //~ We make sure th instruction cache is invalidated first, so that the
     //~ read and write always work correctly. */
      //~ mp_hash_add (type, addr, eval_direct32 (addr, 0, 0));
      //~ ic_inv (addr);
      //~ set_program32 (addr, OR1K_TRAP_INSTR);
      //~ put_str_packet ("OK");

      //~ return;
     
    //~ case BP_HARDWARE:
      //~ put_str_packet ("");      /* Not supported */
      //~ return;

    //~ case WP_WRITE:
      //~ put_str_packet ("");      /* Not supported */
      //~ return;

    //~ case WP_READ:
      //~ put_str_packet ("");      /* Not supported */
      //~ return;

    //~ case WP_ACCESS:
      //~ put_str_packet ("");      /* Not supported */
      //~ return;

    //~ default:
      //~ fprintf (stderr, "Warning: RSP matchpoint type %d not "
           //~ "recognized: ignored\n", type);
      //~ put_str_packet ("E01");
      //~ return;

    //~ }

}   /* rsp_insert_matchpoint () */
