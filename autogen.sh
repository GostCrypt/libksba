#!/bin/sh
# Run this to generate all the initial makefiles, etc.
#
# Copyright (C) 2003 g10 Code GmbH
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

PGM=libksba

# Required version of autoconf.  Keep it in sync with the AC_PREREQ
# macro at the top of configure.ac.
autoconf_vers=2.57

# Required version of automake. 
automake_vers=1.7.6


aclocal_vers="$automake_vers"
ACLOCAL=${ACLOCAL:-aclocal}
AUTOCONF=${AUTOCONF:-autoconf}
AUTOMAKE=${AUTOMAKE:-automake}
AUTOHEADER=${AUTOHEADER:-autoheader}
DIE=no

cvtver () {
    awk 'NR==1 {split($NF,A,".");X=1000000*A[1]+1000*A[2]+A[3];print X;exit 0}'
}

chkver () {
    expr `("$1" --version || echo "0") | cvtver` '>=' `echo "$2" | cvtver` \
           >/dev/null
}

check_version () {
    if ! chkver $1 $2 ; then
       echo "**Error**: "\`$1\'" not installed or too old."
       echo '           (version '$2' or newer is required)'
       DIE="yes"
       return 1
    else
       return 0
    fi
}


check_version $AUTOCONF $autoconf_vers
if check_version $AUTOMAKE $automake_vers ; then
  check_version $ACLOCAL $aclocal_vers
fi

if test "$DIE" = "yes"; then
    exit 1
fi

echo "Running aclocal -I m4 ..."
$ACLOCAL -I m4
echo "Running autoheader..."
$AUTOHEADER
echo "Running automake --gnu ..."
$AUTOMAKE --gnu;
echo "Running autoconf..."
$AUTOCONF

echo "You may now run \"./configure --enable-maintainer-mode && make\"."
