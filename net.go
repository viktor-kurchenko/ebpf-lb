package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

func mac2String(m [6]uint8) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

func ipFromInt(x uint32) netip.Addr {
	b := []byte{0, 0, 0, 0}
	binary.NativeEndian.PutUint32(b, x)
	ip, ok := netip.AddrFromSlice(b)
	if !ok {
		panic(fmt.Sprintf("invalid IP address: %d", x))
	}
	return ip
}
