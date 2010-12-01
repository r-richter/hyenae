#
# Hyenae
#   Advanced Network Packet Generator
#
# Copyright (C) 2009  Robin Richter
#
#   Contact  : richterr@users.sourceforge.net
#   Homepage : http://sourceforge.net/projects/hyenae/
#
# This file is part of Hyenae.
#
# Hyenae is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Hyenae is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Hyenae.  If not, see <http://www.gnu.org/licenses/>.
#

#
# Initialization
#

AC_INIT(
  [Hyenae],
  [0.36-1],
  [richterr@users.sourceforge.net])

AC_CONFIG_HEADERS([config.h])

AC_CONFIG_FILES([
    Makefile
    man/Makefile
    src/Makefile
  ])

AM_INIT_AUTOMAKE([-Wall -Werror foreign])

#
# Standard system check
#

AC_PROG_CC
AC_STDC_HEADERS

#
# Check for getopt
#

GETOPT=""
AC_CHECK_HEADER([getopt.h], , GETOPT="no")
if test "$GETOPT" = "no"; then
  AC_MSG_ERROR([Missing header file: getopt.h])
fi

#
# Determine operation system
#

OS=""
AC_CHECK_HEADER([windows.h], OS="Windows", OS="UNIX")
if test "$OS" = "UNIX"; then

  #
  # Check for required UNIX header files
  #

  TERMIOS=""
  AC_CHECK_HEADER([termios.h], , TERMIOS="no")
  if test "$TERMIOS" = "no"; then
    AC_MSG_ERROR([Missing header file: termios.h])
  fi

  SYS_TIME=""
  AC_CHECK_HEADER([sys/time.h], , SYS_TIME="no")
  if test "$SYS_TIME" = "no"; then
    AC_MSG_ERROR([Missing header file: sys/time.h])
  fi

  SYS_SELECT=""
  AC_CHECK_HEADER([sys/select.h], , SYS_SELECT="no")
  if test "$SYS_SELECT" = "no"; then
    AC_MSG_ERROR([Missing header file: sys/select.h])
  fi

  SYS_SOCKET=""
  AC_CHECK_HEADER([sys/socket.h], , SYS_SOCKET="no")
  if test "$SYS_SOCKET" = "no"; then
    AC_MSG_ERROR([Missing header file: sys/socket.h])
  fi

  SYS_UN=""
  AC_CHECK_HEADER([sys/un.h], , SYS_UN="no")
  if test "$SYS_UN" = "no"; then
    AC_MSG_ERROR([Missing header file: sys/un.h])
  fi

  NETINET_IN=""
  AC_CHECK_HEADER([netinet/in.h], , NETINET_IN="no")
  if test "$NETINET_IN" = "no"; then
    AC_MSG_ERROR([Missing header file: netinet/in.h])
  fi

  #
  # Check for POSIX thread support
  #

  PTHREAD=""
  AC_CHECK_LIB([pthread], [pthread_create], , PTHREAD="no")
  if test "$PTHREAD" = "no"; then
    AC_MSG_ERROR([Missing library: pthread])
  fi

  PTHREAD=""
  AC_CHECK_HEADER([pthread.h], , PTHREAD="no")
  if test "$PTHREAD" = "no"; then
    AC_MSG_ERROR([Missing header file: pthread.h])
  fi

  #
  # Check for dnet/dumbnet
  #

  DNET=""
  AC_CHECK_LIB([dnet], [eth_set], , DNET="no")
  if test "$DNET" = "no"; then
    DNET=""
    AC_CHECK_LIB([dumbnet], [eth_set], , DNET="no")
    if test "$DNET" = "no"; then
      AC_MSG_ERROR([Missing library: libdnet/libdumbnet])
    fi
    DNET_NAME="dumbnet"
  else
    DNET_NAME="dnet"
  fi

  if test "$DNET_NAME" = "dumbnet"; then
    DNET=""
    AC_CHECK_HEADER([dumbnet.h], , DNET="no")
    if test "$DNET" = "no"; then
      AC_MSG_ERROR([Missing header file: dumbnet.h])
    fi
  else
    DNET=""
    AC_CHECK_HEADER([dnet.h], , DNET="no")
    if test "$DNET" = "no"; then
      AC_MSG_ERROR([Missing header file: dnet.h])
    fi
  fi

  #
  # Check for pcap
  #

  PCAP=""
  AC_CHECK_LIB([pcap], [pcap_findalldevs], , PCAP="no")
  if test "$PCAP" = "no"; then
    AC_MSG_ERROR([Missing library: libpcap])
  fi

  PCAP=""
  AC_CHECK_HEADER([pcap.h], , WPCAP="no")
  if test "$PCAP" = "no"; then
    AC_MSG_ERROR([Missing header file: pcap.h])
  fi

  #
  # Assign required libraries to link
  #

  LIBS="$LIBS -lpthread -lpcap -l$DNET_NAME"

  #
  # Define OS_UNIX
  #

  AC_DEFINE([OS_UNIX], [], [Defined when the system UNIX based])

else

  #
  # Check for required Windows header files
  #

  CONIO=""
  AC_CHECK_HEADER([conio.h], , CONIO="no")
  if test "$CONIO" = "no"; then
    AC_MSG_ERROR([Missing header file: conio.h])
  fi

  #
  # Check for WinSock support
  #

  WINSOCK2=""
  AC_CHECK_LIB([ws2_32], [main], , WINSOCK2="no")
  if test "$WINSOCK2" = "no"; then
    AC_MSG_ERROR([Missing library: ws2_32])
  fi
  WINSOCK2=""
  AC_CHECK_HEADER([winsock2.h], , WINSOCK2="no")
  if test "$WINSOCK2" = "no"; then
    AC_MSG_ERROR([Missing header file: winsock2.h])
  fi
  WS2TCPIP=""
  AC_CHECK_HEADER([ws2tcpip.h], , WS2TCPIP="no")
  if test "$WS2TCPIP" = "no"; then
    AC_MSG_ERROR([Missing header file: ws2tcpip.h])
  fi

  #
  # Check for dnet
  #

  DNET=""
  AC_CHECK_LIB([dnet], [main], , DNET="no")
  if test "$DNET" = "no"; then
    AC_MSG_ERROR([Missing library: libdnet])
  fi

  DNET=""
  AC_CHECK_HEADER([dnet.h], , DNET="no")
  if test "$DNET" = "no"; then
    AC_MSG_ERROR([Missing header file: dnet.h])
  fi

  #
  # Check for WinPcap
  #

  WPCAP=""
  AC_CHECK_LIB([wpcap], [main], , WPCAP="no")
  if test "$WPCAP" = "no"; then
    AC_MSG_ERROR([Missing library: libwpcap])
  fi

  WPCAP=""
  AC_CHECK_HEADER([pcap.h], , WPCAP="no")
  if test "$WPCAP" = "no"; then
    AC_MSG_ERROR([Missing header file: pcap.h])
  fi

  #
  # Assign required libraries to link
  #

  LIBS="$LIBS -lwpcap -ldnet -lws2_32 --static"

  #
  # Define OS_WINDOWS
  #

  AC_DEFINE([OS_WINDOWS], [], [Defined when the system is Windows based])
fi

#
# Create autoconf files
#

AC_OUTPUT
