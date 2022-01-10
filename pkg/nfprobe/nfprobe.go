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
	"context"
	"fmt"
	"sync"
	"time"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var (
	stdoutFmt = "%-8s | %-3s | %-20s | %-15s | %-15s | %-10s | %-10s | %-10s | %-15s | %-15s | %-18s | %-4s\n"
	line      = "--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------"
)

// NFProbe is the main NFProbe structure
type NFProbe struct {
	handleEvent func(cpu int, data []byte, perfMap *manager.PerfMap, manager *manager.Manager)
	options     Options

	ctx        context.Context
	cancelFunc context.CancelFunc
	wg         *sync.WaitGroup

	manager           *manager.Manager
	managerOptions    manager.Options
	startTime         time.Time
	hookFilters       *ebpf.Map
	protoFilters      *ebpf.Map
	packetTypeFilters *ebpf.Map
	verdictFilters    *ebpf.Map
	netnsFilters      *ebpf.Map
	tableFilters      *ebpf.Map
	inNameFilters     *ebpf.Map
	inIfindexFilters  *ebpf.Map
	outNameFilters    *ebpf.Map
	outIfindexFilters *ebpf.Map

	timeResolver *TimeResolver
	event        *NFEvent
}

// NewNFProbe creates a new NFProbe instance
func NewNFProbe(options Options) (*NFProbe, error) {
	err := options.IsValid()
	if err != nil {
		return nil, err
	}

	e := &NFProbe{
		wg:          &sync.WaitGroup{},
		options:     options,
		handleEvent: options.EventHandler,
		event:       &NFEvent{},
	}
	if e.handleEvent == nil {
		e.handleEvent = e.defaultEventHandler
	}

	e.timeResolver, err = NewTimeResolver()
	if err != nil {
		return nil, err
	}
	e.ctx, e.cancelFunc = context.WithCancel(context.Background())
	return e, nil
}

// Start hooks on the requested symbols and begins tracing
func (e *NFProbe) Start() error {
	if e.options.Stdout {
		fmt.Printf(stdoutFmt, "Time", "CPU", "Hook", "Proto", "Type", "Table", "Verdict", "Netns", "Input", "Output", "Addr", "Csum")
		fmt.Println(line)
	}

	if err := e.startManager(); err != nil {
		return err
	}

	if err := e.pushFilters(); err != nil {
		return errors.Wrap(err, "couldn't push filters to the kernel")
	}
	return nil
}

// Stop shuts down NFProbe
func (e *NFProbe) Stop() error {
	if e.manager == nil {
		// nothing to stop, return
		return nil
	}

	e.cancelFunc()
	e.wg.Wait()

	if err := e.manager.Stop(manager.CleanAll); err != nil {
		return fmt.Errorf("couldn't stop manager: %w", err)
	}
	return nil
}

func (e *NFProbe) pushFilters() error {
	value := uint8(1)
	for _, key := range e.options.Hook {
		if err := e.hookFilters.Put(key, value); err != nil {
			return fmt.Errorf("couldn't push filter in %s kernel map: key %v: %v", "hook_filters", key, err)
		}
	}
	for _, key := range e.options.NFProto {
		if err := e.protoFilters.Put(key, value); err != nil {
			return fmt.Errorf("couldn't push filter in %s kernel map: key %v: %v", "proto_filters", key, err)
		}
	}
	for _, key := range e.options.PacketType {
		if err := e.packetTypeFilters.Put(key, value); err != nil {
			return fmt.Errorf("couldn't push filter in %s kernel map: key %v: %v", "packet_type_filters", key, err)
		}
	}
	for _, key := range e.options.Verdict {
		if err := e.verdictFilters.Put(key, value); err != nil {
			return fmt.Errorf("couldn't push filter in %s kernel map: key %v: %v", "verdict_filters", key, err)
		}
	}
	for _, key := range e.options.NetworkNamespaceID {
		if err := e.netnsFilters.Put(uint32(key), value); err != nil {
			return fmt.Errorf("couldn't push filter in %s kernel map: key %v: %v", "netns_filters", key, err)
		}
	}
	for _, key := range e.options.InDeviceIfindex {
		if err := e.inIfindexFilters.Put(uint32(key), value); err != nil {
			return fmt.Errorf("couldn't push filter in %s kernel map: key %v: %v", "in_ifindex_filters", key, err)
		}
	}
	for _, key := range e.options.OutDeviceIfindex {
		if err := e.outIfindexFilters.Put(uint32(key), value); err != nil {
			return fmt.Errorf("couldn't push filter in %s kernel map: key %v: %v", "out_ifindex_filters", key, err)
		}
	}

	for _, key := range e.options.InDeviceName {
		keyB := make([]byte, maxDeviceNameLength)
		copy(keyB, key)
		if err := e.inNameFilters.Put(keyB, value); err != nil {
			return fmt.Errorf("couldn't push filter in %s kernel map: key %v: %v", "in_name_filters", key, err)
		}
	}
	for _, key := range e.options.OutDeviceName {
		keyB := make([]byte, maxDeviceNameLength)
		copy(keyB, key)
		if err := e.outNameFilters.Put(keyB, value); err != nil {
			return fmt.Errorf("couldn't push filter in %s kernel map: key %v: %v", "out_name_filters", key, err)
		}
	}
	for _, key := range e.options.TableName {
		keyB := make([]byte, maxTableNameLength)
		copy(keyB, key)
		if err := e.tableFilters.Put(keyB, value); err != nil {
			return fmt.Errorf("couldn't push filter in %s kernel map: key %v: %v", "table_filters", key, err)
		}
	}

	return nil
}

var eventZero NFEvent

func (e *NFProbe) zeroEvent() *NFEvent {
	*e.event = eventZero
	return e.event
}

func (e *NFProbe) defaultEventHandler(cpu int, data []byte, perfMap *manager.PerfMap, manager *manager.Manager) {
	if !e.options.Stdout {
		return
	}

	var err error
	event := e.zeroEvent()
	event.CPU = cpu

	if err = event.UnmarshalBinary(data, e.timeResolver); err != nil {
		logrus.Errorf("couldn't decode event: %v", err)
		return
	}

	hour, min, sec := event.Timestamp.Clock()

	fmt.Printf(
		stdoutFmt,
		fmt.Sprintf("%2d:%2d:%2d", hour, min, sec),
		fmt.Sprintf("%2d", event.CPU),
		event.Hook,
		event.PF,
		event.PacketType,
		event.TableName,
		event.Verdict,
		fmt.Sprintf("%d", event.NetworkNamespaceID),
		event.InDeviceName,
		event.OutDeviceName,
		fmt.Sprintf("0x%x", event.PacketAddr),
		fmt.Sprintf("%x", event.PacketCsum),
	)
}
