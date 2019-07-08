// Copyright (c) 2018-2019 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package iptables

import (
	"io"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"github.com/hashicorp/go-version"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/versionparse"
)

var (
	vXDotYDotZRegexp    = regexp.MustCompile(`v(\d+\.\d+\.\d+)`)
	kernelVersionRegexp = regexp.MustCompile(`Linux version (\d+\.\d+\.\d+)`)

	// iptables versions:
	// v1Dot4Dot7 is the oldest version we've ever supported.
	v1Dot4Dot7 = versionparse.MustParseVersion("1.4.7")
	// v1Dot6Dot0 added --random-fully to SNAT.
	v1Dot6Dot0 = versionparse.MustParseVersion("1.6.0")
	// v1Dot6Dot2 added --random-fully to MASQUERADE and the xtables lock to iptables-restore.
	v1Dot6Dot2 = versionparse.MustParseVersion("1.6.2")
	// v1Dot8Dot2 and earlier has a bug with -R in nftables mode.
	v1Dot8Dot2 = versionparse.MustParseVersion("1.8.2")

	// Linux kernel versions:
	// v3Dot10Dot0 is the oldest version we support at time of writing.
	v3Dot10Dot0 = versionparse.MustParseVersion("3.10.0")
	// v3Dot14Dot0 added the random-fully feature on the iptables interface.
	v3Dot14Dot0 = versionparse.MustParseVersion("3.14.0")
)

type Features struct {
	// SNATFullyRandom is true if --random-fully is supported by the SNAT action.
	SNATFullyRandom bool
	// MASQFullyRandom is true if --random-fully is supported by the MASQUERADE action.
	MASQFullyRandom bool
	// RestoreSupportsLock is true if the iptables-restore command supports taking the xtables lock and the
	// associated -w and -W arguments.
	RestoreSupportsLock bool
	// IptablesRestoreHasReplaceBug is true if iptables-restore mishandles the replace ("-R") command.
	// When in nftables mode, v1.8.2 and before end up replacing the wrong rule.
	IptablesRestoreHasReplaceBug bool
}

type FeatureDetector struct {
	lock         sync.Mutex
	featureCache *Features

	// Path to file with kernel version
	GetKernelVersionReader func() (io.Reader, error)
	// Factory for making commands, used by UTs to shim exec.Command().
	NewCmd      cmdFactory
	LookPath    func(file string) (string, error)
	backendMode string
}

func NewFeatureDetector(iptablesBackend string) *FeatureDetector {
	return &FeatureDetector{
		GetKernelVersionReader: versionparse.GetKernelVersionReader,
		NewCmd:                 newRealCmd,
		LookPath:               exec.LookPath,
		backendMode:            iptablesBackend,
	}
}

func (d *FeatureDetector) GetFeatures() *Features {
	d.lock.Lock()
	defer d.lock.Unlock()

	if d.featureCache == nil {
		d.refreshFeaturesLockHeld()
	}

	return d.featureCache
}

func (d *FeatureDetector) RefreshFeatures() {
	d.lock.Lock()
	defer d.lock.Unlock()

	d.refreshFeaturesLockHeld()
}

func (d *FeatureDetector) refreshFeaturesLockHeld() {
	// Get the versions.  If we fail to detect a version for some reason, we use a safe default.
	log.Debug("Refreshing detected iptables features")
	iptV, iptMode := d.getIptablesVersion()
	kerV := d.getKernelVersion()

	// Calculate the features.
	features := Features{
		SNATFullyRandom:              iptV.Compare(v1Dot6Dot0) >= 0 && kerV.Compare(v3Dot14Dot0) >= 0,
		MASQFullyRandom:              iptV.Compare(v1Dot6Dot2) >= 0 && kerV.Compare(v3Dot14Dot0) >= 0,
		RestoreSupportsLock:          iptV.Compare(v1Dot6Dot2) >= 0,
		IptablesRestoreHasReplaceBug: iptMode == "nft" && iptV.Compare(v1Dot8Dot2) <= 0,
	}

	if d.featureCache == nil || *d.featureCache != features {
		log.WithFields(log.Fields{
			"features":        features,
			"kernelVersion":   kerV,
			"iptablesVersion": iptV,
		}).Info("Updating detected iptables features")
		d.featureCache = &features
	}
}

func (d *FeatureDetector) getIptablesVersion() (*version.Version, string) {
	cmd := d.NewCmd(d.FindBestBinary(4, ""), "--version")
	out, err := cmd.Output()
	if err != nil {
		log.WithError(err).Warn("Failed to get iptables version, assuming old version with no optional features")
		return v1Dot4Dot7, "legacy"
	}
	s := string(out)
	log.WithField("rawVersion", s).Debug("Ran iptables --version")
	matches := vXDotYDotZRegexp.FindStringSubmatch(s)
	if len(matches) == 0 {
		log.WithField("rawVersion", s).Warn(
			"Failed to parse iptables version, assuming old version with no optional features")
		return v1Dot4Dot7, "legacy"
	}
	parsedVersion, err := version.NewVersion(matches[1])
	if err != nil {
		log.WithField("rawVersion", s).WithError(err).Warn(
			"Failed to parse iptables version, assuming old version with no optional features")
		return v1Dot4Dot7, "legacy"
	}

	mode := "legacy"
	if strings.Contains(s, "nf_tables") {
		mode = "nft"
	}

	log.WithFields(log.Fields{
		"version": parsedVersion,
		"mode":    mode,
	}).Debug("Parsed iptables version")

	return parsedVersion, mode
}

func (d *FeatureDetector) getKernelVersion() *version.Version {
	reader, err := d.GetKernelVersionReader()
	if err != nil {
		log.WithError(err).Warn("Failed to get the kernel version reader, assuming old version with no optional features")
		return v3Dot10Dot0
	}
	kernVersion, err := versionparse.GetKernelVersion(reader)
	if err != nil {
		log.WithError(err).Warn("Failed to get kernel version, assuming old version with no optional features")
		return v3Dot10Dot0
	}
	return kernVersion
}

// FindBestBinary tries to find an iptables binary for the configured variant (legacy/nftables mode) and returns the
// name of the binary.  Falls back on iptables/iptables-restore/iptables-save if the specific variant isn't available.
// Panics if no binary can be found.
func (d *FeatureDetector) FindBestBinary(ipVersion uint8, saveOrRestore string) string {
	verInfix := ""

	if ipVersion == 6 {
		verInfix = "6"
	}

	candidates := []string{
		"ip" + verInfix + "tables-" + d.backendMode,
		"ip" + verInfix + "tables",
	}

	if saveOrRestore != "" {
		for i := range candidates {
			candidates[i] += "-" + saveOrRestore
		}
	}

	logCxt := log.WithFields(log.Fields{
		"ipVersion":     ipVersion,
		"backendMode":   d.backendMode,
		"saveOrRestore": saveOrRestore,
		"candidates":    candidates,
	})

	for _, candidate := range candidates {
		_, err := d.LookPath(candidate)
		if err == nil {
			logCxt.WithField("command", candidate).Info("Looked up iptables command")
			return candidate
		}
	}

	logCxt.Panic("Failed to find iptables command")
	return ""
}
