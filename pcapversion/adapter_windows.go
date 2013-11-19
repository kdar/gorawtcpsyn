// Taken and modified from golang/src/pkg/net

package main

import (
  "bytes"
  "errors"
  "net"
  "os"
  "syscall"
  "unsafe"
)

func localMac(dev string) (net.HardwareAddr, error) {
  adapterList, err := getAdapterList()
  if err != nil {
    return nil, err
  }

  for adapter := adapterList; adapter != nil; adapter = adapter.Next {
    if bytes.Contains([]byte(dev), adapter.AdapterName[:bytes.IndexRune(adapter.AdapterName[:], 0)]) {
      return adapter.Address[:adapter.AddressLength], nil
    }
  }

  return nil, errors.New("Could not find adapter")
}

func getAdapterList() (*syscall.IpAdapterInfo, error) {
  b := make([]byte, 1000)
  l := uint32(len(b))
  a := (*syscall.IpAdapterInfo)(unsafe.Pointer(&b[0]))
  // TODO(mikio): GetAdaptersInfo returns IP_ADAPTER_INFO that
  // contains IPv4 address list only. We should use another API
  // for fetching IPv6 stuff from the kernel.
  err := syscall.GetAdaptersInfo(a, &l)
  if err == syscall.ERROR_BUFFER_OVERFLOW {
    b = make([]byte, l)
    a = (*syscall.IpAdapterInfo)(unsafe.Pointer(&b[0]))
    err = syscall.GetAdaptersInfo(a, &l)
  }
  if err != nil {
    return nil, os.NewSyscallError("GetAdaptersInfo", err)
  }
  return a, nil
}
