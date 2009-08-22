/*
 * Hyenae
 *   Advanced Network Packet Generator
 *
 * Copyright (C) 2009  Robin Richter
 *
 *   Contact  : richterr@users.sourceforge.net
 *   Homepage : http://sourceforge.net/projects/hyenae/
 *
 * This file is part of Hyenae.
 *
 * Hyenae is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Hyenae is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Hyenae.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "hyenae-base.h"

/* -------------------------------------------------------------------------- */

int
  hy_initialize() {

  /*
   * USAGE:
   *   Global initializations such as the
   *   random number generator.
   */

  #ifdef OS_UNIX
    if (getuid() != 0) {
      return HY_ER_NOT_ROOT;
    }
	#endif /* OS_UNIX */
  #ifndef HY_INITIALIZE
		#define HY_INITIALIZE
    srand(time(NULL));
  #endif /* HY_INITIALIZE */
  return HY_ER_OK;
} /* hy_initialize */

/* -------------------------------------------------------------------------- */

void
  hy_output
  (
    FILE* file,
    int type,
    int time_stamp,
    const char* fmt,
    ...
  ) {

  /*
   * USAGE:
   *   Global output function
   */

  char ts_buf[HY_OUT_TMP_TS_BUFLEN];
  char out_buf[HY_OUT_BUFLEN];
  time_t t = 0;
  struct tm* tm_tmp = NULL;
  va_list args;

  memset(ts_buf, 0, HY_OUT_TMP_TS_BUFLEN);
  memset(out_buf, 0, HY_OUT_BUFLEN);
  va_start(args, fmt);
  vsprintf(out_buf, fmt, args);
  va_end(args);
  if (time_stamp > 0) {
    t = time(NULL);
    tm_tmp = localtime(&t);
    strftime(
      ts_buf,
      HY_OUT_TMP_TS_BUFLEN,
      HY_OUT_TS_FMT,
      tm_tmp);
    strcat(ts_buf, " ");
  }
  hy_handle_output(file, type, ts_buf, out_buf);
} /* hy_output */

/* -------------------------------------------------------------------------- */

void
  hy_handle_output_default
    (
      FILE* file,
      int type,
      const char* timestamp,
      const char* output
    ) {

  /*
   * USAGE:
   *   Default output handler
   */

  char type_buf[HY_OUT_TMP_TYPE_BUFLEN];

  memset(type_buf, 0, HY_OUT_TMP_TYPE_BUFLEN);
  switch(type) {
    case HY_OUT_T_TASK:
      strncpy(
        type_buf,
        "* ",
        HY_OUT_TMP_TYPE_BUFLEN);
      break;
    case HY_OUT_T_NOTE:
      strncpy(
        type_buf,
        "  NOTE: ",
        HY_OUT_TMP_TYPE_BUFLEN);
      break;
    case HY_OUT_T_WARNING:
      strncpy(type_buf,
      "  WARNING: ",
      HY_OUT_TMP_TYPE_BUFLEN);
      break;
    case HY_OUT_T_ERROR:
      strncpy(
        type_buf,
        "  ERROR: ",
        HY_OUT_TMP_TYPE_BUFLEN);
      break;
    case HY_OUT_T_RESULT:
      strncpy(
        type_buf,
        "  > ",
        HY_OUT_TMP_TYPE_BUFLEN);
      break;
    case HY_OUT_T_FINISHED:
      strncpy(
        type_buf,
        "* Finished: ",
        HY_OUT_TMP_TYPE_BUFLEN);
      break;
  }
  fprintf(file, "%s%s%s\n", timestamp, type_buf, output);
  fflush(file);
} /* hy_handle_output_default */

/* -------------------------------------------------------------------------- */

int
  hy_was_key_pressed() {

  /*
   * USAGE:
   *   Platform independent function to
   *   determine if the user has pressed a key.
   */

  #ifdef OS_WINDOWS
    return _kbhit();
  #else

    /* The following source code is based on
       Morgan McGuires (morgan@cs.brown.edu)
       POSIX implementation of _kbhit. */

    int byt_wait = 0;
    static int init = 0;
    timeval_t tmo;
    fd_set fd;

    if (init == 0) {
      struct termios trm;
      tcgetattr(0, &trm);
      trm.c_lflag &= ~ICANON;
      tcsetattr(0, TCSANOW, &trm);
      setbuf(stdin, NULL);
      init = 1;
    }
    FD_ZERO(&fd);
    FD_SET(0, &fd);
    tmo.tv_sec  = 0;
    tmo.tv_usec = 0;
    return select(0 + 1, &fd, NULL, NULL, &tmo);
  #endif /* OS_WINDOWS */
}

/* -------------------------------------------------------------------------- */

char*
  hy_str_to_lower
    (
      char* string,
      int len
    ) {

  /*
   * USAGE:
   *   Converts a string to lower
   *   case characters.
   */

  int i = 0;

  while (i < len) {
    switch(*(string + i)) {
      case 'A':
        *(string + i) = 'a';
        break;
      case 'B':
        *(string + i) = 'b';
        break;
      case 'C':
        *(string + i) = 'c';
        break;
      case 'D':
        *(string + i) = 'd';
        break;
      case 'E':
        *(string + i) = 'e';
        break;
      case 'F':
        *(string + i) = 'f';
        break;
      case 'G':
        *(string + i) = 'g';
        break;
      case 'H':
        *(string + i) = 'h';
        break;
      case 'I':
        *(string + i) = 'i';
        break;
      case 'J':
        *(string + i) = 'j';
        break;
      case 'K':
        *(string + i) = 'k';
        break;
      case 'L':
        *(string + i) = 'l';
        break;
      case 'M':
        *(string + i) = 'm';
        break;
      case 'N':
        *(string + i) = 'n';
        break;
      case 'O':
        *(string + i) = 'o';
        break;
      case 'P':
        *(string + i) = 'p';
        break;
      case 'Q':
        *(string + i) = 'q';
        break;
      case 'R':
        *(string + i) = 'r';
        break;
      case 'S':
        *(string + i) = 's';
        break;
      case 'T':
        *(string + i) = 't';
        break;
      case 'U':
        *(string + i) = 'u';
        break;
      case 'V':
        *(string + i) = 'v';
        break;
      case 'W':
        *(string + i) = 'w';
        break;
      case 'X':
        *(string + i) = 'x';
        break;
      case 'Y':
        *(string + i) = 'y';
        break;
      case 'Z':
        *(string + i) = 'z';
        break;
      default:
        break;
    }
    i = i + 1;
  }
  return string;
} /* hy_str_to_lower */

/* -------------------------------------------------------------------------- */

char*
  hy_str_to_upper
    (
      char* string,
      int len
    ) {

  /*
   * USAGE:
   *   Converts a string to upper
   *   case characters.
   */

  int i = 0;

  while (i < len) {
    switch(*(string + i)) {
      case 'a':
        *(string + i) = 'A';
        break;
      case 'b':
        *(string + i) = 'B';
        break;
      case 'c':
        *(string + i) = 'C';
        break;
      case 'd':
        *(string + i) = 'D';
        break;
      case 'e':
        *(string + i) = 'E';
        break;
      case 'f':
        *(string + i) = 'F';
        break;
      case 'g':
        *(string + i) = 'G';
        break;
      case 'h':
        *(string + i) = 'H';
        break;
      case 'i':
        *(string + i) = 'I';
        break;
      case 'j':
        *(string + i) = 'J';
        break;
      case 'k':
        *(string + i) = 'K';
        break;
      case 'l':
        *(string + i) = 'L';
        break;
      case 'm':
        *(string + i) = 'M';
        break;
      case 'n':
        *(string + i) = 'N';
        break;
      case 'o':
        *(string + i) = 'O';
        break;
      case 'p':
        *(string + i) = 'P';
        break;
      case 'q':
        *(string + i) = 'Q';
        break;
      case 'r':
        *(string + i) = 'R';
        break;
      case 's':
        *(string + i) = 'S';
        break;
      case 't':
        *(string + i) = 'T';
        break;
      case 'u':
        *(string + i) = 'U';
        break;
      case 'v':
        *(string + i) = 'V';
        break;
      case 'w':
        *(string + i) = 'W';
        break;
      case 'x':
        *(string + i) = 'X';
        break;
      case 'y':
        *(string + i) = 'Y';
        break;
      case 'z':
        *(string + i) = 'Z';
        break;
      default:
        break;
    }
    i = i + 1;
  }
  return string;
} /* hy_str_to_upper */

/* -------------------------------------------------------------------------- */

int
  hy_random
    (
      int min,
      int max
    ) {

  /*
   * USAGE:
   *   Devision-By-Zero safe random
   *   number generator.
   */

  if (min >= max) {
    return min;
  }
  return (rand() % max - min) + min;
} /* hy_random */

/* -------------------------------------------------------------------------- */

void
  hy_randomize_buffer
    (
      unsigned char* buffer,
      unsigned int len
    ) {

  /*
   * USAGE:
   *   Randomizes all characters of the
   *   given buffer.
   */

  unsigned i = 0;

  while (i < len) {
    *(buffer + i) = hy_random(1, 255);
    i = i + 1;
  }
} /* hy_randomize_buffer */

/* -------------------------------------------------------------------------- */

int
  hy_load_file_to_buffer
    (
      const char* filename,
      unsigned char** buffer,
      unsigned int *len
    ) {

  /*
   * USAGE:
   *   Loads a file into the given buffer.
   */

  int c = 0;
  int ret = HY_ER_OK;
  unsigned int i = 0;
  FILE* f = NULL;

  if ((f = fopen(filename, "r")) == NULL) {
    return HY_ER_FOPEN;
  }
  fseek(f, 0, SEEK_END);
  *len = ftell(f);
  if (*len == 0) {
    return HY_ER_FILE_EMPTY;
  }
  fseek(f, 0, SEEK_SET);
  *buffer = malloc(*len);
  memset(*buffer, 0, *len);
  while ((c = fgetc(f)) != EOF && i < *len) {
    *(*buffer + i) = c;
    i = i + 1;
  }
  fclose(f);
  return ret;
} /* hy_load_file_to_buffer */

/* -------------------------------------------------------------------------- */

unsigned long
  hy_get_milliseconds_of_day() {

  /*
   * USAGE:
   *   Returns the number of milliseconds that have
   *   passed since the beginning of the epoch. The
   *   epoch varies between windows and unix systems. */

  unsigned long ret = 0;
  #ifdef OS_WINDOWS
    FILETIME ft;
    unsigned __int64 tmp = 0;
    static int lag;
  #else
    timeval_t tv;
  #endif /* OS_WINDOWS */
  #ifdef OS_WINDOWS
    /* The following source code is based on an
       article found on http://www.openasthra.com */
    memset(&ft, 0, sizeof(FILETIME));
    GetSystemTimeAsFileTime(&ft);
    tmp = tmp | ft.dwHighDateTime;
    tmp = tmp << 32;
    tmp = tmp | ft.dwLowDateTime;
    tmp = tmp / 10;
    ret =
      ((long)(tmp / 1000000UL) * 1000) +
      ((long)(tmp % 1000000UL) / 1000);
  #else
    memset(&tv, 0, sizeof(timeval_t));
    gettimeofday(&tv, NULL);
    ret =
      (tv.tv_sec * 1000) +
      (tv.tv_usec / 1000);
  #endif /* OS_WINDOWS */
  return ret;
} /* hy_get_milliseconds_of_day */

/* -------------------------------------------------------------------------- */

void
  hy_sleep
    (
      int msec
    )
     {

  /*
   * USAGE:
   *   Platform independent sleep function.
   */

  #ifdef OS_WINDOWS
    Sleep(msec);
  #else
    usleep(msec * 1000);
  #endif /* OS_WINDOWS */
} /* hy_sleep */

/* -------------------------------------------------------------------------- */

int
  hy_get_if_name_by_index
    (
      int index,
      char** if_name
    ) {

  /*
   * USAGE:
   *   Fills the given buffer with the name of
   *   the network interface, found on the
   *   given index.
   */

  int i = 0;
  int if_fnd = 0;
  char err_buf[PCAP_ERRBUF_SIZE];
  pcap_if_t* if_n = NULL;
  pcap_if_t* if_lst = NULL;

  if (pcap_findalldevs(&if_lst, err_buf) == -1) {
    return HY_ER_PCAP_FINDALLDEVS;
  }
  for(if_n = if_lst; if_n; if_n = if_n->next) {
    i = i + 1;
    if (i == index) {
      *if_name = malloc(strlen(if_n->name) + 1);
      memset(*if_name, 0, strlen(if_n->name) + 1);
      strncpy(*if_name, if_n->name, strlen(if_n->name));
      if_fnd = 1;
      break;
    }
  }
  pcap_freealldevs(if_lst);
  if (if_fnd == 0) {
    return HY_ER_NO_SUCH_IF;
  }
  return HY_ER_OK;
} /* hy_get_if_name_by_index */

/* -------------------------------------------------------------------------- */

void
  hy_shutdown_close_socket
    (
      int socket
    ) {

  /*
   * USAGE:
   *   Shuts down and closes the
   *   given socket.
   */

  #ifdef OS_WINDOWS
    shutdown(socket, SD_BOTH);
  #else
    shutdown(socket, SHUT_RDWR);
  #endif /* OS_WINDOWS */
  close(socket);
} /* hy_shutdown_close_socket */

/* -------------------------------------------------------------------------- */

const char*
  hy_get_error_msg
    (
      int error
    ) {

  /*
   * USAGE:
   *   Returns a description for the
   *   given error code.
   */

  if (error == HY_ER_OK) {
    return "No errors";
  } else if (error == HY_ER_NOT_ROOT) {
    return "Root privileges required";
  } else if (error == HY_ER_FOPEN) {
    return "Unable to open file";
  } else if (error == HY_ER_FILE_EMPTY) {
    return "File is empty";
  } else if (error == HY_ER_PCAP_FINDALLDEVS) {
    return "Pcap was unable to find any network interfaces";
  } else if (error == HY_ER_WSA_STARTUP) {
    return "Failed to initialize WinSock";
  } else if (error == HY_ER_SOCK_CREATE) {
    return "Failed to create socket";
  } else if(error == HY_ER_SOCK_SETOPT) {
    return "Failed to set required socket option";
  } else if (error == HY_ER_SOCK_BIND) {
    return "Failed to bind socket";
  } else if (error == HY_ER_SOCK_LISTEN) {
    return "Failed to bring socket to listen mode";
  } else if (error == HY_ER_SOCK_ACCEPT) {
    return "Failed to accept client connection";
  } else if (error == HY_ER_CREATE_THREAD) {
    return "Failed to create new thread";
  } else if (error == HY_ER_CF_KEY_BUFLEN_EXCEED) {
    return "Key buffer length exceeded (too long key)";
  } else if (error == HY_ER_CF_VAL_BUFLEN_EXCEED) {
    return "Value buffer length exceeded (too long value)";
  } else if (error == HY_ER_CF_EMPTY_KEY) {
    return "File contains an empty or invalid key";
  } else if (error == HY_ER_CF_NO_KEYS) {
    return "File contains no keys";
  } else if (error == HY_ER_AMBIG_EOA_HW) {
    return "Ambiguous End-Of-Address character (hardware address)";
  } else if (error == HY_ER_AMBIG_EOA_IP) {
    return "Ambiguous End-Of-Address character (IP address)";
  } else if (error == HY_ER_AD_T_UNKNOWN) {
    return "Pattern contains an unknown address type";
  } else if (error == HY_ER_IP_V_UNKNOWN) {
    return "Unknown IP version";
  } else if (error == HY_ER_AD_EMPTY) {
    return "Pattern contains an empty address strip";
  } else if (error == HY_ER_AD_BUFLEN_EXCEED) {
    return "Address buffer length exceeded (too long address)";
  } else if (error == HY_ER_PORT_EMPTY) {
    return "Pattern contains an empty port strip";
  } else if (error == HY_ER_PT_BUFLEN_EXCEED) {
    return "Pattern buffer length exceeded (too long pattern)";
  } else if (error == HY_ER_SRV_PT_WCC_PERMIT) {
    return "Server address patterns can not contain wildcards";
  } else if (error == HY_ER_NO_SUCH_IF) {
    return "No such network interface";
  } else if (error == HY_ER_PCAP_OPEN_LIVE) {
    return "Pcap failed to open the specified network interface";
  } else if (error == HY_ER_NO_SRC_PT_GIVEN) {
    return "No source pattern given";
  } else if (error == HY_ER_NO_DST_PT_GIVEN) {
    return "No destination pattern given";
  } else if (error == HY_ER_NO_SND_PT_GIVEN) {
    return "No sender pattern given";
  } else if (error == HY_ER_NO_TCP_SRC_PT_GIVEN) {
    return "No TCP source pattern given";
  } else if (error == HY_ER_NO_IP_REQ_GIVEN) {
    return "No \"Requested IP-Address\" pattern given";
  } else if (error == HY_ER_NO_TRG_PT_GIVEN) {
    return "No target pattern given";
  } else if (error == HY_ER_NO_TCP_DST_PT_GIVEN) {
    return "No TCP destination pattern given";
  } else if (error == HY_ER_NO_SRV_IP_GIVEN) {
    return "No server identifier pattern given";
  } else if (error == HY_ER_PKT_PAY_UNSUPPORTED) {
    return "Payload not supported for this attack";
  } else if (error == HY_ER_AT_T_UNKNOWN) {
    return "No or unknown attack type given";
  } else if (error == HY_MTU_LIMIT_EXCEED) {
    return "MTU limit exceeded (too large packet)";
  } else if (error == HY_ER_PCAP_WRITE) {
    return "Pcap failed to write data to the network";
  } else if (error == HY_ER_MULTIPLE_IP_V) {
    return "Patterns containing multiple IP versions";
  } else if (error == HY_ER_WRONG_IP_V) {
    return "Wrong IP address version";
  } else if (error == HY_ER_WRONG_PT_FMT_SRC) {
    return "Wrong address pattern format (source)";
  } else if (error == HY_ER_WRONG_PT_FMT_DST) {
    return "Wrong address pattern format (destination)";
  } else if (error == HY_ER_WRONG_PT_FMT_SND) {
    return "Wrong address pattern format (sender)";
  } else if (error == HY_ER_WRONG_PT_FMT_TCP_SRC) {
    return "Wrong address pattern format (TCP source)";
  } else if (error == HY_ER_WRONG_PT_FMT_IP_REQ) {
    return "Wrong address pattern format (requested IP-Address)";
  } else if (error == HY_ER_WRONG_PT_FMT_TRG) {
    return "Wrong address pattern format (target)";
  } else if (error == HY_ER_WRONG_PT_FMT_TCP_DST) {
    return "Wrong address pattern format (TCP destination)";
  } else if (error == HY_ER_WRONG_PT_FMT_SRV_IP) {
    return "Wrong address pattern format (server identifier)";
  } else if (error == HY_ER_NO_TCP_FLAGS) {
    return "No TCP flags given";
  } else if (error == HY_ER_DNS_NO_QUERIES) {
    return "No DNS query given";
  } else if (error == HY_ER_DNS_NO_ANSWERS) {
    return "No DNS answer given";
  } else if (error == HY_ER_DNS_QRY_BUFLEN_EXCEED) {
    return "Maximum DNS query length exceeded (too long pattern)";
  } else if (error == HY_ER_DNS_ANS_BUFLEN_EXCEED) {
    return "Maximum DNS answer length exceeded (too long pattern)";
  } else if (error == HY_ER_DNS_QRY_N_BUFLEN_EXCEED) {
    return "DNS query contains a hostname that is too long";
  } else if (error == HY_ER_DNS_ANS_N_BUFLEN_EXCEED) {
    return "DNS answer contains a hostname that is too long";
  } else if (error == HY_ER_DNS_ANS_PT_BUFLEN_EXCEED) {
    return "DNS answer contains a pattern that is too long";
  } else if (error == HY_ER_DNS_ANS_FMT_ERROR) {
    return "DNS answer contains an invalid pattern";
  } else if (error == HY_ER_MAX_RA_PKT_LEN_EXCEED) {
    return "Maximum remote attack packet length exceeded (too long payload)";
  } else if (error == HY_ER_PR_MALFORMED_RAR_H) {
    return "Malformed remote attack request";
  } else if (error == HY_ER_UNKNOWN_SL_KEY) {
    return "Server list file contains an invalid key";
  } else if (error == HY_ER_WRONG_PT_FMT_SRV) {
    return "Wrong address pattern format (server)";
  } else if (error == HY_ER_RA_INVALID_SRV_AD_T) {
    return "Invalid server address type";
  } else if (error == HY_ER_PWD_BUFLEN_EXCEED) {
    return "Password buffer length ecxeeded (too long password)";
  } else if (error == HY_ER_TO_SHORT_PWD) {
    return "The given password is too short";
  } else if (error == HY_ER_EMPTY_PWD_STRIP) {
    return "Pattern contains an empty password strip";
  } else if (error == HY_ER_UNKNOWN_IP_KEY) {
    return "IP list file contains an invalid key";
  } else if (error == HY_ER_INVALID_IP_LST_ADDR) {
    return "IP address list contains an invalid IP address";
  } else if (error == HY_ER_DMN_LOG_FILE_BUFLEN_EXCEED) {
    return "Logfile path buffer exceeded, to long log file path";
  } else if (error == HY_ER_PORT_ZERO) {
    return "Port number can not be zero";
  } else if (error == HY_ER_BACKLOG_ZERO) {
    return "Backlog can not be zero";
  } else if (error == HY_ER_MAX_CL_ZERO) {
    return "Number of maximum client connections can not be zero";
  } else if (error == HY_ER_MAX_CL_PKT_DUR_LMT_ZERO) {
    return "At least a packet or an attack duration limit is requiered";
  } else if (error == HY_ER_FOPEN_LOG_FILE) {
    return "Unable to open/create log file";
  } else if (error == HY_ER_CLI_PKT_LMT_EXCEED) {
    return "Requested packet count exceeds daemon limit";
  } else if (error == HY_ER_CLI_DUR_LMT_EXCEED) {
    return "Requested atack duration exceeds daemon limit";
  } else if (error == HY_ER_INP_BUFLEN_EXCEED) {
    return "Maximum input length exceeded";
  } else if (error == HY_ER_WRONG_PT_FMT) {
    return "Wrong pattern format";
  } else if (error == HY_ER_ICMP_UNR_CODE_UNKNOWN) {
    return "Unknown ICMP \"Destination Unreachable\" code";
  } else if (error == HY_ER_TCP_FLG_UNKNOWN) {
    return "TCP flag pattern contains an unknown flag";
  } else {
    return "An unknown error occurred";
  }
} /* hy_get_error_msg */

/* -------------------------------------------------------------------------- */
