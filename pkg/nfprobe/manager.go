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
	"math"
	"os"
	"time"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	"github.com/Gui774ume/nfprobe/pkg/assets"
)

// NFProbeUID is the UID used for the probes of nfprobe
var NFProbeUID = "nfprobe"

func (e *NFProbe) prepareManager() {
	e.manager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					UID:          NFProbeUID,
					EBPFSection:  "kprobe/ipt_do_table",
					EBPFFuncName: "kprobe_ipt_do_table",
				},
			},
			{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					UID:          NFProbeUID,
					EBPFSection:  "kretprobe/ipt_do_table",
					EBPFFuncName: "kretprobe_ipt_do_table",
				},
			},
			{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					UID:          NFProbeUID,
					EBPFSection:  "kprobe/ip6t_do_table",
					EBPFFuncName: "kprobe_ip6t_do_table",
				},
			},
			{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					UID:          NFProbeUID,
					EBPFSection:  "kretprobe/ip6t_do_table",
					EBPFFuncName: "kretprobe_ip6t_do_table",
				},
			},
		},
		PerfMaps: []*manager.PerfMap{
			{
				Map: manager.Map{
					Name: "events",
				},
				PerfMapOptions: manager.PerfMapOptions{
					PerfRingBufferSize: 8192 * os.Getpagesize(),
					DataHandler:        e.handleEvent,
				},
			},
		},
	}
	e.managerOptions = manager.Options{
		// DefaultKProbeMaxActive is the maximum number of active kretprobe at a given time
		DefaultKProbeMaxActive: 512,

		ActivatedProbes: []manager.ProbesSelector{
			&manager.AllOf{
				Selectors: []manager.ProbesSelector{
					&manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{UID: NFProbeUID, EBPFSection: "kprobe/ipt_do_table", EBPFFuncName: "kprobe_ipt_do_table"}},
					&manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{UID: NFProbeUID, EBPFSection: "kretprobe/ipt_do_table", EBPFFuncName: "kretprobe_ipt_do_table"}},
				},
			},
			&manager.BestEffort{
				Selectors: []manager.ProbesSelector{
					&manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{UID: NFProbeUID, EBPFSection: "kprobe/ip6t_do_table", EBPFFuncName: "kprobe_ip6t_do_table"}},
					&manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{UID: NFProbeUID, EBPFSection: "kretprobe/ip6t_do_table", EBPFFuncName: "kretprobe_ip6t_do_table"}},
				},
			},
		},

		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				// LogSize is the size of the log buffer given to the verifier. Give it a big enough (2 * 1024 * 1024)
				// value so that all our programs fit. If the verifier ever outputs a `no space left on device` error,
				// we'll need to increase this value.
				LogSize: 2097152,
			},
		},

		// Extend RLIMIT_MEMLOCK (8) size
		// On some systems, the default for RLIMIT_MEMLOCK may be as low as 64 bytes.
		// This will result in an EPERM (Operation not permitted) error, when trying to create an eBPF map
		// using bpf(2) with BPF_MAP_CREATE.
		//
		// We are setting the limit to infinity until we have a better handle on the true requirements.
		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
	}

	if e.options.KernelDebug {
		e.managerOptions.ConstantEditors = append(e.managerOptions.ConstantEditors, manager.ConstantEditor{
			Name:  "debug",
			Value: uint64(1),
		})
	}
	if len(e.options.Hook) > 0 {
		e.managerOptions.ConstantEditors = append(e.managerOptions.ConstantEditors, manager.ConstantEditor{
			Name:  "hook_filter",
			Value: uint64(1),
		})
	}
	if len(e.options.NFProto) > 0 {
		e.managerOptions.ConstantEditors = append(e.managerOptions.ConstantEditors, manager.ConstantEditor{
			Name:  "proto_filter",
			Value: uint64(1),
		})
	}
	if len(e.options.PacketType) > 0 {
		e.managerOptions.ConstantEditors = append(e.managerOptions.ConstantEditors, manager.ConstantEditor{
			Name:  "packet_type_filter",
			Value: uint64(1),
		})
	}
	if len(e.options.Verdict) > 0 {
		e.managerOptions.ConstantEditors = append(e.managerOptions.ConstantEditors, manager.ConstantEditor{
			Name:  "verdict_filter",
			Value: uint64(1),
		})
	}
	if len(e.options.NetworkNamespaceID) > 0 {
		e.managerOptions.ConstantEditors = append(e.managerOptions.ConstantEditors, manager.ConstantEditor{
			Name:  "netns_filter",
			Value: uint64(1),
		})
	}
	if len(e.options.TableName) > 0 {
		e.managerOptions.ConstantEditors = append(e.managerOptions.ConstantEditors, manager.ConstantEditor{
			Name:  "table_filter",
			Value: uint64(1),
		})
	}
	if len(e.options.InDeviceName) > 0 {
		e.managerOptions.ConstantEditors = append(e.managerOptions.ConstantEditors, manager.ConstantEditor{
			Name:  "in_name_filter",
			Value: uint64(1),
		})
	}
	if len(e.options.InDeviceIfindex) > 0 {
		e.managerOptions.ConstantEditors = append(e.managerOptions.ConstantEditors, manager.ConstantEditor{
			Name:  "in_ifindex_filter",
			Value: uint64(1),
		})
	}
	if len(e.options.OutDeviceName) > 0 {
		e.managerOptions.ConstantEditors = append(e.managerOptions.ConstantEditors, manager.ConstantEditor{
			Name:  "out_name_filter",
			Value: uint64(1),
		})
	}
	if len(e.options.OutDeviceIfindex) > 0 {
		e.managerOptions.ConstantEditors = append(e.managerOptions.ConstantEditors, manager.ConstantEditor{
			Name:  "out_ifindex_filter",
			Value: uint64(1),
		})
	}
}

func (e *NFProbe) selectMaps() error {
	var err error
	e.hookFilters, _, err = e.manager.GetMap("hook_filters")
	if err != nil {
		return errors.Errorf("couldn't find \"hook_filters\" map")
	}
	e.protoFilters, _, err = e.manager.GetMap("proto_filters")
	if err != nil {
		return errors.Errorf("couldn't find \"proto_filters\" map")
	}
	e.packetTypeFilters, _, err = e.manager.GetMap("packet_type_filters")
	if err != nil {
		return errors.Errorf("couldn't find \"packet_type_filters\" map")
	}
	e.verdictFilters, _, err = e.manager.GetMap("verdict_filters")
	if err != nil {
		return errors.Errorf("couldn't find \"verdict_filters\" map")
	}
	e.netnsFilters, _, err = e.manager.GetMap("netns_filters")
	if err != nil {
		return errors.Errorf("couldn't find \"netns_filters\" map")
	}
	e.tableFilters, _, err = e.manager.GetMap("table_filters")
	if err != nil {
		return errors.Errorf("couldn't find \"table_filters\" map")
	}
	e.inNameFilters, _, err = e.manager.GetMap("in_name_filters")
	if err != nil {
		return errors.Errorf("couldn't find \"in_name_filters\" map")
	}
	e.inIfindexFilters, _, err = e.manager.GetMap("in_ifindex_filters")
	if err != nil {
		return errors.Errorf("couldn't find \"in_ifindex_filters\" map")
	}
	e.outNameFilters, _, err = e.manager.GetMap("out_name_filters")
	if err != nil {
		return errors.Errorf("couldn't find \"out_name_filters\" map")
	}
	e.outIfindexFilters, _, err = e.manager.GetMap("out_ifindex_filters")
	if err != nil {
		return errors.Errorf("couldn't find \"out_ifindex_filters\" map")
	}
	return nil
}

func (e *NFProbe) startManager() error {
	// fetch ebpf assets
	buf, err := assets.Asset("/probe.o")
	if err != nil {
		return errors.Wrap(err, "couldn't find asset")
	}

	// setup a default manager
	e.prepareManager()

	// initialize the manager
	if err := e.manager.InitWithOptions(bytes.NewReader(buf), e.managerOptions); err != nil {
		return errors.Wrap(err, "couldn't init manager")
	}

	// select kernel space maps
	if err := e.selectMaps(); err != nil {
		return err
	}

	// start the manager
	if err := e.manager.Start(); err != nil {
		return errors.Wrap(err, "couldn't start manager")
	}

	e.startTime = time.Now()
	return nil
}
