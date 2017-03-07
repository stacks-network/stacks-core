#!/bin/sh

BLOCKSTACK_VERSION="0.14.1"
VENV_DIR="$(pwd)/blockstack-$BLOCKSTACK_VERSION"
LOGPATH="/tmp/blockstack_${BLOCKSTACK_VERSION}_get_started.log"

echo "Welcome to Blockstack!"
echo "----------------------"
echo "This script will install Blockstack to a virtual environment at $VENV_DIR."
echo "A log of this script will be stored to $LOGPATH."
echo -n "Proceed? (Y/n) "
read YN

if [ -z "$YN" ] || [ "$YN" = "n" ] || [ "$YN" = "N" ]; then 
   echo "Exiting..."
   exit 0
fi

logecho() {
   echo "$(date) $1" >> "$LOGPATH"
   echo "$(date) $1"
}

exit_with_error() {
   logecho "$1" >&2

   # exit the virtualenv as well 
   type deactivate | grep "shell function" && deactivate
   exit 1
}

find_header() {
   HEADER_FILE="$1"
   logecho "Find header $HEADER_FILE"
   for HEADER_DIR in "/usr/include" "/usr/local/include" $2; do
        test -f "$HEADER_DIR"/"$HEADER_FILE"
        if [ $? -eq 0 ]; then 
           logecho "Found $HEADER_FILE at $HEADER_DIR/$HEADER_FILE"
           return 0
        fi
   done
   return 1
}

find_library() {
   LIBRARY_PREFIX="$1"
   logecho "Find library $LIBRARY_PREFIX"
   for LIBRARY_DIR in "/lib" "/usr/lib" "/usr/local/lib" $2; do
       ls "$LIBRARY_DIR"/"$LIBRARY_PREFIX".* >/dev/null 2>&1
       if [ $? -eq 0 ]; then 
            logecho "Found $LIBRARY_PREFIX at $LIBRARY_DIR/$LIBRARY_PREFIX"
            return 0
       fi
   done
   return 1
}

exit_missing_sysdep() {
   exit_with_error "$1 is required.  You can install it with your system package manager."
}

exit_missing_executable() {
   INSTALL_WITH="$2"
   if [ -z "$INSTALL_WITH" ]; then 
      INSTALL_WITH="your system package manager"
   fi

   exit_with_error "Could not find '$1' executable.  You can install it with $INSTALL_WITH"
}

logecho "Begin Blockstack installation to $VENV_DIR"

# sanity check 
test -d "$VENV_DIR" && exit_with_error "Directory $VENV_DIR already exists.  Please remove it and try again."

# do some heuristics 
# should have Python 2.7.x
test -x "$(which python2)" || exit_missing_executable "Python"

python2 --version 2>&1 | grep "2.7" >/dev/null  || exit_missing_executable "Python2.7"

# should have pip >= 9.0.1
test -x "$(which pip)" || exit_missing_executable "pip"

# need pip >= 9.0.1
pip --version 2>&1 | grep "9.0" >/dev/null || exit_missing_executable "pip" "'pip install --upgrade pip'"

# should have virtualenv
test -x "$(which virtualenv)" || exit_missing_executable "virtualenv" "'pip install virtualenv'"

# need libpython-dev
find_header "python2.7/Python.h" || exit_missing_sysdep "python-dev"

# need libgmp 
find_library "libgmp.so" || exit_missing_sysdep "libgmp"

# need libgmp-dev
find_header "gmp.h" || exit_missing_sysdep "libgmp-dev"

# need libssl 
find_library "libssl.so" || exit_missing_sysdep "libssl"

# need libcrypto 
find_library "libcrypto.so" || exit_missing_sysdep "libcrypto"

# need libssl-dev
find_header "openssl/crypto.h" || exit_missing_sysdep "libssl-dev"

# need libffi
find_library "libffi.so" || exit_missing_sysdep "libffi"

# need libffi-dev.
# can be in /usr/lib/libffi-VERSION/include on some systems
find_header "ffi.h" "/usr/lib/libffi-*/include" || exit_missing_sysdep "libffi-dev"

mkdir "$VENV_DIR" || exit_with_error "Failed to make directory $VENV_DIR"
virtualenv "$VENV_DIR" 2>&1 | tee -a "$LOGPATH"
if [ $? -ne 0 ]; then 
   exit_with_error "Failed to set up virtualenv.  Logfile in $LOGPATH"
fi

source "$VENV_DIR"/bin/activate || exit_with_error "Failed to activate virtualenv.  Logfile in $LOGPATH"

pip install blockstack 2>&1 | tee -a "$LOGPATH" || exit_with_error "Failed to install blockstack.  Logfile in $LOGPATH"

# test blockstack 
test -x "$(which blockstack)" || exit_with_error "Failed to find installed blockstack program.  Logfile in $LOGPATH"

blockstack --version 2>/dev/null | grep "$BLOCKSTACK_VERSION" >/dev/null || exit_with_error "Could not find blockstack $BLOCKSTACK_VERSION.  Logfile in $LOGPATH."

logecho "Blockstack $BLOCKSTACK_VERSION installed to $VENV_DIR."
echo ""
echo "Success!  Activate virtualenv with 'source $VENV_DIR/bin/activate' to run 'blockstack'"
echo ""

exit 0

