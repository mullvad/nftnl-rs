#!/usr/bin/env bash

# give libnftnl C library dir as first argument and output binding as second.
# Example:
#  $ ./generate_bindings.sh ../../libnftnl-1.0.8 src/nftnl_1_0_8.rs

set -ue

LIBNFTNL_PATH=$1
BINDING_PATH=$2

echo "Writing the result to $BINDING_PATH"

bindgen \
    --no-doc-comments \
    --use-core \
    --no-prepend-enum-name \
    --allowlist-function '^nftnl_.+$' \
    --allowlist-type '^nftnl_.+$' \
    --allowlist-var '^nftnl_.+$' \
    --allowlist-var '^NFTNL_.+$' \
    --blocklist-type '(FILE|iovec)' \
    --blocklist-type '^_IO_.+$' \
    --blocklist-type '^__.+$' \
    --blocklist-type 'nlmsghdr' \
    --raw-line 'use libc::{c_char, c_int, c_void, iovec, nlmsghdr, FILE};' \
    --raw-line 'use core::option::Option;' \
    --ctypes-prefix 'libc' \
    -o $BINDING_PATH \
    libnftnl.h --\
    -I$LIBNFTNL_PATH/include

# Tidy up and correct things I could not manage to configure bindgen to do for me
sed -i 's/libc::\(c_[a-z]*\)/\1/g'  $BINDING_PATH
sed -i 's/::core::option::Option/Option/g' $BINDING_PATH
sed -i 's/_bindgen_ty_[0-9]\+/u32/g' $BINDING_PATH
sed -i 's/pub type u32 = u32;//g' $BINDING_PATH
sed -i '/#\[derive(Debug, Copy, Clone)\]/d' $BINDING_PATH

# Change struct bodies to (c_void);
#   Search regex: {\n +_unused: \[u8; 0],\n}
#   Replace string: (c_void);\n
sed -i -e '/^pub struct .* {$/ {
    N;N
    s/ {\n *_unused: \[u8; 0\],\n}/(c_void);\n/
}' "$BINDING_PATH"


# Remove all }\nextern "C" { to condense code a bit
#   Search regex: }\nextern "C" {
#   Replace string:
sed -i -e '/^extern "C" {$/ {
    :loop
    n
    /^}$/! b loop
    /^}$/ {
        N
        t reset_condition_flags
        :reset_condition_flags
        s/}\nextern "C" {//
        t loop
    }
}' "$BINDING_PATH"

# Add bindgen version to comment at start of file
sed -i "1s/bindgen/$(bindgen --version)/" $BINDING_PATH

rustfmt $BINDING_PATH
