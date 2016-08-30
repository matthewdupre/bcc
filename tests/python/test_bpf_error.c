// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")

#include <bcc/proto.h>

#define NUM_PORTS 311

struct port {
  int ifindex;
};

BPF_TABLE("hash", u32, u32, num_ports, 1);

BPF_TABLE("hash", int, struct port, ports, NUM_PORTS);

struct mac_key {
  u64 mac;
};

struct ifindex_info {
  u32 ifindex;
};

BPF_TABLE("hash", struct mac_key, struct ifindex_info, bridge, 1);

int ingress_response(struct __sk_buff *skb) {
  int dst_index = 0;
  struct port *pport = 0;
  u8 *cursor = 0;
  struct ifindex_info src_ifindex;
  struct ifindex_info *dst_ifindex = 0;
  struct mac_key src_mac;
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  //bpf_trace_printk("\n");
  //bpf_trace_printk("RECEIVER: GOT packet on port = %d\n", skb->ifindex);
  src_mac.mac = ethernet->src;
  src_ifindex.ifindex = skb->ifindex;

  dst_ifindex = bridge.lookup_or_init(&src_mac, &src_ifindex);
  pport = ports.lookup(&dst_index);
  if (pport) {
      //bpf_trace_printk("RECEIVER: SEND packet to dst_port = %d\n", pport->ifindex);
      bpf_clone_redirect(skb, pport->ifindex, 0);
      return 2;
  }
  return 2;
}


int bridge_port(struct __sk_buff *skb) {
  u8 *cursor = 0;
  int dst_index = 1;
  u32 *total_ports = 0;
  u32 index = 0;
  struct port *pport = 0;
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  struct mac_key dst_mac;
  struct ifindex_info *dst_ifindex = 0;
  u64 ts = 0;
  u64 te = 0;
  u64 delta = 0;
 
  dst_mac.mac = ethernet->dst;
  dst_ifindex = bridge.lookup(&dst_mac);

  total_ports = num_ports.lookup(&index);
  //if (total_ports)  
   //   bpf_trace_printk("Number of ports %d\n",*total_ports);
 
  if (dst_ifindex) {
      bpf_clone_redirect(skb, dst_ifindex->ifindex, 0);
      return 2;
  } else {
      ts = bpf_ktime_get_ns();

      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit; 
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;

      pport = ports.lookup(&dst_index);
      if (!pport) 
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;

      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;

      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;

      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;

      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;

      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;

      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;

      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
     
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;

      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
     
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;

      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
     
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;

      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      
      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;

      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;

      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;

      pport = ports.lookup(&dst_index);
      if (!pport)
          goto exit;
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;

exit:
      te = bpf_ktime_get_ns();
      delta = te - ts;
      //if (total_ports)
          bpf_trace_printk("Packet replicated on %d Ports in %d micro_sec\n", *total_ports, delta/1000);
      return 2;
  }
}
