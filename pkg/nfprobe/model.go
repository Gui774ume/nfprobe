/*
Copyright © 2022 GUILLAUME FOURNIER

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package nfprobe

import (
	"bytes"
	"fmt"
	"time"

	"golang.org/x/sys/unix"

	manager "github.com/DataDog/ebpf-manager"
)

const (
	// maxFilterCount is the maximum count of values per filter
	maxFilterCount = 100
	// maxTableNameLength is the maximum length of a netfilter table name
	maxTableNameLength = 32
	// maxDeviceNameLength is the maximum length of a device name
	maxDeviceNameLength = 16
)

func genericCountError(field string, len int) error {
	return fmt.Errorf("too many values were provided for the %s filter: got %d, expected %d", field, len, maxFilterCount)
}

func genericValueError(field string, value interface{}) error {
	return fmt.Errorf("invalid value for the %s filter: %v", field, value)
}

func init() {
	initStrToNFHook()
	initStrToNFProto()
	initStrToPacketType()
	initStrToVerdict()
}

// Options contains the parameters of NFProbe
type Options struct {
	// Stdout prints the collected events to stdout
	Stdout bool
	// KernelDebug prints the collected events in the trace_pipe
	KernelDebug bool
	// Hook filters events with the netfilter hook type
	Hook []NFHook
	// NFProto filters events with the netfilter proto
	NFProto []NFProto
	// PacketType filters events with the provided packet type
	PacketType []PacketType
	// Verdict filters events with the provided verdict
	Verdict []Verdict
	// NetworkNamespaceID filters events with the provided netns ID
	NetworkNamespaceID []int
	// TableName filters events with the provided table name
	TableName []string
	// InDeviceName filters events with the provided device name on input
	InDeviceName []string
	// InDeviceIfindex filters events with the provided device ifindex on input
	InDeviceIfindex []int
	// OutDeviceName filters events with the provided device name on output
	OutDeviceName []string
	// OutDeviceIfindex filters events with the provided device ifindex on output
	OutDeviceIfindex []int
	// EventHandler is called for each event
	EventHandler func(cpu int, data []byte, perfMap *manager.PerfMap, manager *manager.Manager)
}

func (o Options) IsValid() error {
	var count int
	if count = len(o.Hook); count > maxFilterCount {
		return genericCountError("Hook", count)
	} else {
		for _, hook := range o.Hook {
			if !hook.IsValid() {
				return genericValueError("Hook", hook)
			}
		}
	}
	if count = len(o.NFProto); count > maxFilterCount {
		return genericCountError("NFProto", count)
	} else {
		for _, proto := range o.NFProto {
			if !proto.IsValid() {
				return genericValueError("NFProto", proto)
			}
		}
	}
	if count = len(o.PacketType); count > maxFilterCount {
		return genericCountError("PacketType", count)
	} else {
		for _, t := range o.PacketType {
			if !t.IsValid() {
				return genericValueError("PacketType", t)
			}
		}
	}
	if count = len(o.Verdict); count > maxFilterCount {
		return genericCountError("Verdict", count)
	} else {
		for _, verdict := range o.Verdict {
			if !verdict.IsValid() {
				return genericValueError("Verdict", verdict)
			}
		}
	}
	if count = len(o.NetworkNamespaceID); count > maxFilterCount {
		return genericCountError("NetworkNamespaceID", count)
	}
	if count = len(o.TableName); count > maxFilterCount {
		return genericCountError("TableName", count)
	} else {
		for _, table := range o.TableName {
			if len(table) > maxTableNameLength {
				return genericValueError("TableName", fmt.Sprintf("'%s' too long, got %d, expected %d at most", table, len(table), maxTableNameLength))
			}
		}
	}
	if count = len(o.InDeviceName); count > maxFilterCount {
		return genericCountError("InDeviceName", count)
	} else {
		for _, name := range o.InDeviceName {
			if len(name) > maxDeviceNameLength {
				return genericValueError("InDeviceName", fmt.Sprintf("'%s' too long, got %d, expected %d at most", name, len(name), maxDeviceNameLength))
			}
		}
	}
	if count = len(o.InDeviceIfindex); count > maxFilterCount {
		return genericCountError("InDeviceIfindex", count)
	}
	if count = len(o.OutDeviceName); count > maxFilterCount {
		return genericCountError("OutDeviceName", count)
	} else {
		for _, name := range o.OutDeviceName {
			if len(name) > maxDeviceNameLength {
				return genericValueError("OutDeviceName", fmt.Sprintf("'%s' too long, got %d, expected %d at most", name, len(name), maxDeviceNameLength))
			}
		}
	}
	if count = len(o.OutDeviceIfindex); count > maxFilterCount {
		return genericCountError("OutDeviceIfindex", count)
	}
	return nil
}

// NFHook is used to define a netfilter hook
type NFHook uint8

var nfHookToStr = map[NFHook]string{
	unix.NF_INET_PRE_ROUTING:  "NF_INET_PRE_ROUTING",
	unix.NF_INET_LOCAL_IN:     "NF_INET_LOCAL_IN",
	unix.NF_INET_FORWARD:      "NF_INET_FORWARD",
	unix.NF_INET_LOCAL_OUT:    "NF_INET_LOCAL_OUT",
	unix.NF_INET_POST_ROUTING: "NF_INET_POST_ROUTING",
	unix.NF_INET_NUMHOOKS:     "NF_INET_NUMHOOKS",
}

var strToNFHook = map[string]NFHook{}

func initStrToNFHook() {
	for k, v := range nfHookToStr {
		strToNFHook[v] = k
	}
}

// NewNFHook returns a new NFHook instance if the provided value is known.
func NewNFHook(hook string) *NFHook {
	h, ok := strToNFHook[hook]
	if ok {
		return &h
	}
	return nil
}

// IsValid returns true if the NFHook value is known
func (h NFHook) IsValid() bool {
	_, ok := nfHookToStr[h]
	return ok
}

func (h NFHook) String() string {
	if s, ok := nfHookToStr[h]; ok {
		return s
	}
	return fmt.Sprintf("NFHook(%d)", h)
}

// NFProto is used to define a netfilter proto
type NFProto uint8

var nfProtoToStr = map[NFProto]string{
	unix.NFPROTO_UNSPEC:   "NFPROTO_UNSPEC",
	unix.NFPROTO_INET:     "NFPROTO_INET",
	unix.NFPROTO_IPV4:     "NFPROTO_IPV4",
	unix.NFPROTO_ARP:      "NFPROTO_ARP",
	unix.NFPROTO_NETDEV:   "NFPROTO_NETDEV",
	unix.NFPROTO_BRIDGE:   "NFPROTO_BRIDGE",
	unix.NFPROTO_IPV6:     "NFPROTO_IPV6",
	unix.NFPROTO_DECNET:   "NFPROTO_DECNET",
	unix.NFPROTO_NUMPROTO: "NFPROTO_NUMPROTO",
}

var strToNFProto = map[string]NFProto{}

func initStrToNFProto() {
	for k, v := range nfProtoToStr {
		strToNFProto[v] = k
	}
}

// NewNFProto returns a new NFProto instance if the provided value is known.
func NewNFProto(proto string) *NFProto {
	p, ok := strToNFProto[proto]
	if ok {
		return &p
	}
	return nil
}

// IsValid returns true if the NFProto value is known
func (p NFProto) IsValid() bool {
	_, ok := nfProtoToStr[p]
	return ok
}

func (p NFProto) String() string {
	if s, ok := nfProtoToStr[p]; ok {
		return s
	}
	return fmt.Sprintf("NFProto(%d)", p)
}

// PacketType represents the packet_type of a sk_buff
type PacketType uint8

var packetTypeToStr = map[PacketType]string{
	unix.PACKET_HOST:      "PACKET_HOST",
	unix.PACKET_BROADCAST: "PACKET_BROADCAST",
	unix.PACKET_MULTICAST: "PACKET_MULTICAST",
	unix.PACKET_OTHERHOST: "PACKET_OTHERHOST",
	unix.PACKET_OUTGOING:  "PACKET_OUTGOING",
	unix.PACKET_LOOPBACK:  "PACKET_LOOPBACK",
	unix.PACKET_USER:      "PACKET_USER",
	unix.PACKET_KERNEL:    "PACKET_KERNEL",
}

var strToPacketType = map[string]PacketType{}

func initStrToPacketType() {
	for k, v := range packetTypeToStr {
		strToPacketType[v] = k
	}
}

// NewPacketType returns a new PacketType instance if the provided value is known
func NewPacketType(packetType string) *PacketType {
	t, ok := strToPacketType[packetType]
	if ok {
		return &t
	}
	return nil
}

// IsValid returns true if the PacketType value is known
func (t PacketType) IsValid() bool {
	_, ok := packetTypeToStr[t]
	return ok
}

func (t PacketType) String() string {
	if s, ok := packetTypeToStr[t]; ok {
		return s
	}
	return fmt.Sprintf("PacketType(%d)", t)
}

// Verdict is the verdict decided by the table
type Verdict uint32

var verdictToStr = map[Verdict]string{
	0: "NF_DROP",
	1: "NF_ACCEPT",
	2: "NF_STOLEN",
	3: "NF_QUEUE",
	4: "NF_REPEAT",
	5: "NF_STOP",
}

var strToVerdict = map[string]Verdict{}

func initStrToVerdict() {
	for k, v := range verdictToStr {
		strToVerdict[v] = k
	}
}

// NewVerdict returns a new Verdict instance if the provided value is known
func NewVerdict(verdict string) *Verdict {
	v, ok := strToVerdict[verdict]
	if ok {
		return &v
	}
	return nil
}

// IsValid returns true if the Verdict value is known
func (v Verdict) IsValid() bool {
	_, ok := verdictToStr[v]
	return ok
}

// see includ/uapi/linux/netfilter.h
func (v Verdict) String() string {
	if s, ok := verdictToStr[v]; ok {
		return s
	}
	return fmt.Sprintf("Verdict(%d)", v)
}

// NFEvent represents the data retrieved from kernel space
type NFEvent struct {
	CPU int

	Hook      NFHook
	PF        NFProto
	TableName string

	PacketType         PacketType
	PacketCsum         uint32
	PacketAddr         uint64
	NetworkNamespaceID uint32
	Timestamp          time.Time
	Verdict            Verdict

	InDeviceIfindex  uint32
	InDeviceName     string
	OutDeviceIfindex uint32
	OutDeviceName    string
}

func (e *NFEvent) UnmarshalBinary(data []byte, resolver *TimeResolver) error {
	if len(data) < 100 {
		return fmt.Errorf("not enough data, expected %d, got %d", 100, len(data))
	}
	e.Hook = NFHook(data[0])
	e.PF = NFProto(data[1])
	e.PacketType = PacketType(data[2])
	// padding1, 1 byte
	e.NetworkNamespaceID = ByteOrder.Uint32(data[4:8])
	e.InDeviceIfindex = ByteOrder.Uint32(data[8:12])
	e.OutDeviceIfindex = ByteOrder.Uint32(data[12:16])
	e.PacketCsum = ByteOrder.Uint32(data[16:20])
	e.Verdict = Verdict(ByteOrder.Uint32(data[20:24]))
	// padding2, 4 bytes
	e.PacketAddr = ByteOrder.Uint64(data[24:32])
	e.Timestamp = resolver.ResolveMonotonicTimestamp(ByteOrder.Uint64(data[32:40]))
	e.InDeviceName = bytes.NewBuffer(bytes.Trim(data[40:56], "\x00")).String()
	e.OutDeviceName = bytes.NewBuffer(bytes.Trim(data[56:72], "\x00")).String()
	e.TableName = bytes.NewBuffer(bytes.Trim(data[72:104], "\x00")).String()
	return nil
}
