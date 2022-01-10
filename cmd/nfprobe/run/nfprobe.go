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
	"os"
	"os/signal"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/Gui774ume/nfprobe/pkg/nfprobe"
)

func nfprobeCmd(cmd *cobra.Command, args []string) error {
	// Set log level
	logrus.SetLevel(options.LogLevel)

	// create a new NFProbe instance
	trace, err := nfprobe.NewNFProbe(options.NFProbeOptions)
	if err != nil {
		return errors.Wrap(err, "couldn't create a new NFProber")
	}

	// start NFProbe
	if err := trace.Start(); err != nil {
		return errors.Wrap(err, "couldn't start")
	}

	wait()

	if err = trace.Stop(); err != nil {
		logrus.Errorf("couldn't stop NFProbe properly: %v", err)
	}
	return nil
}

// wait stops the main goroutine until an interrupt or kill signal is sent
func wait() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig
}
