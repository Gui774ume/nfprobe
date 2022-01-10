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

package run

import (
	"github.com/spf13/cobra"
)

// NFProbe represents the base command of nfprobe
var NFProbe = &cobra.Command{
	Use:  "nfprobe",
	RunE: nfprobeCmd,
	Long: "NFProbe is a NetFilter event tracing utility, powered by eBPF",
}

var options CLIOptions

func init() {
	NFProbe.Flags().VarP(
		NewLogLevelSanitizer(&options.LogLevel),
		"log-level",
		"l",
		"log level, options: panic, fatal, error, warn, info, debug or trace")
	NFProbe.Flags().BoolVar(
		&options.NFProbeOptions.Stdout,
		"stdout",
		true,
		"prints the collected events to stdout")
	NFProbe.Flags().BoolVar(
		&options.NFProbeOptions.KernelDebug,
		"debug",
		false,
		"prints a kernel level debug line for each event")
	NFProbe.Flags().Var(
		NewNFProbeOptionsSanitizer(&options.NFProbeOptions, "hook"),
		"hook",
		"list of hook filters, leave empty to disable this filter. options: NF_INET_PRE_ROUTING, NF_INET_LOCAL_IN, NF_INET_FORWARD, NF_INET_LOCAL_OUT, NF_INET_POST_ROUTING")
	NFProbe.Flags().Var(
		NewNFProbeOptionsSanitizer(&options.NFProbeOptions, "proto"),
		"proto",
		"list of proto filters, leave empty to disable this filter. options: NFPROTO_INET, NFPROTO_IPV4, NFPROTO_ARP, NFPROTO_NETDEV, NFPROTO_BRIDGE, NFPROTO_IPV6, NFPROTO_DECNET")
	NFProbe.Flags().Var(
		NewNFProbeOptionsSanitizer(&options.NFProbeOptions, "packet-type"),
		"packet-type",
		"list of packet-type filters, leave empty to disable this filter. options: PACKET_HOST, PACKET_BROADCAST, PACKET_MULTICAST, PACKET_OTHERHOST, PACKET_OUTGOING, PACKET_LOOPBACK, PACKET_USER, PACKET_KERNEL")
	NFProbe.Flags().Var(
		NewNFProbeOptionsSanitizer(&options.NFProbeOptions, "verdict"),
		"verdict",
		"list of verdict filters, leave empty to disable this filter. options: NF_DROP, NF_ACCEPT, NF_STOLEN, NF_QUEUE, NF_REPEAT")
	NFProbe.Flags().Var(
		NewNFProbeOptionsSanitizer(&options.NFProbeOptions, "netns"),
		"netns",
		"list of network namespace filters, leave empty to disable this filter. Example: 4026531992")
	NFProbe.Flags().StringArrayVar(
		&options.NFProbeOptions.TableName,
		"table",
		[]string{},
		"list of table name filters, leave empty to disable this filter. Example: nat")
	NFProbe.Flags().Var(
		NewNFProbeOptionsSanitizer(&options.NFProbeOptions, "in-ifindex"),
		"in-ifindex",
		"list of input device ifindex filters, leave empty to disable this filter. Example: 2")
	NFProbe.Flags().StringArrayVar(
		&options.NFProbeOptions.InDeviceName,
		"in-name",
		[]string{},
		"list of input device name filters, leave empty to disable this filter. Example: eth0")
	NFProbe.Flags().Var(
		NewNFProbeOptionsSanitizer(&options.NFProbeOptions, "out-ifindex"),
		"out-ifindex",
		"list of output device ifindex filters, leave empty to disable this filter. Example: 2")
	NFProbe.Flags().StringArrayVar(
		&options.NFProbeOptions.OutDeviceName,
		"out-name",
		[]string{},
		"list of output device name filters, leave empty to disable this filter. Example: eth0")
}
