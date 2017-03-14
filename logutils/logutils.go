// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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

package logutils

import (
	"fmt"
	"io"
	"log/syslog"
	"os"
	"path"
	"runtime"
	"sort"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/gavv/monotime"
	"github.com/mipearson/rfw"

	"bytes"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/projectcalico/felix/config"
)

var (
	counterDroppedLogs = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_logs_dropped",
		Help: "Number of logs dropped because the output stream was blocked.",
	})
)

func init() {
	prometheus.MustRegister(counterDroppedLogs)
}

// ConfigureEarlyLogging installs our logging adapters, and enables early logging to stderr
// if it is enabled by either the FELIX_EARLYLOGSEVERITYSCREEN or FELIX_LOGSEVERITYSCREEN
// environment variable.
func ConfigureEarlyLogging() {
	// Replace logrus' formatter with a custom one using our time format,
	// shared with the Python code.
	log.SetFormatter(&Formatter{})

	// Install a hook that adds file/line no information.
	log.AddHook(&ContextHook{})

	// First try the early-only environment variable.  Since the normal
	// config processing doesn't know about that variable, normal config
	// will override it once it's loaded.
	rawLogLevel := os.Getenv("FELIX_EARLYLOGSEVERITYSCREEN")
	if rawLogLevel == "" {
		// Early-only flag not set, look for the normal config-owned
		// variable.
		rawLogLevel = os.Getenv("FELIX_LOGSEVERITYSCREEN")
	}

	// Default to logging errors.
	logLevelScreen := log.ErrorLevel
	if rawLogLevel != "" {
		parsedLevel, err := log.ParseLevel(rawLogLevel)
		if err == nil {
			logLevelScreen = parsedLevel
		} else {
			log.WithError(err).Error("Failed to parse early log level, defaulting to error.")
		}
	}
	log.SetLevel(logLevelScreen)
	log.Infof("Early screen log level set to %v", logLevelScreen)
}

// ConfigureLogging uses the resolved configuration to complete the logging
// configuration.  It creates hooks for the relevant logging targets and
// attaches them to logrus.
func ConfigureLogging(configParams *config.Config) {
	// Parse the log levels, defaulting to panic if in doubt.
	logLevelScreen := safeParseLogLevel(configParams.LogSeverityScreen)
	logLevelFile := safeParseLogLevel(configParams.LogSeverityFile)
	logLevelSyslog := safeParseLogLevel(configParams.LogSeveritySys)

	// Work out the most verbose level that is being logged.
	mostVerboseLevel := logLevelScreen
	if logLevelFile > mostVerboseLevel {
		mostVerboseLevel = logLevelFile
	}
	if logLevelSyslog > mostVerboseLevel {
		mostVerboseLevel = logLevelScreen
	}
	// Disable all more-verbose levels using the global setting, this ensures that debug logs
	// are filtered out as early as possible.
	log.SetLevel(mostVerboseLevel)

	// Screen target.
	var dests []Destination
	if configParams.LogSeverityScreen != "" {
		screenDest := NewStreamDestination(logLevelScreen, os.Stdout)
		dests = append(dests, screenDest)
	}

	// File target.  We record any errors so we can log them out below after finishing set-up
	// of the logger.
	var fileDirErr, fileOpenErr error
	if configParams.LogSeverityFile != "" {
		fileDirErr = os.MkdirAll(path.Dir(configParams.LogFilePath), 0755)
		var rotAwareFile io.Writer
		rotAwareFile, fileOpenErr = rfw.Open(configParams.LogFilePath, 0644)
		if fileDirErr == nil && fileOpenErr == nil {
			fileDest := NewStreamDestination(logLevelFile, rotAwareFile)
			dests = append(dests, fileDest)
		}
	}

	// Syslog target.  Again, we record the error if we fail to connect to syslog.
	var sysErr error
	if configParams.LogSeveritySys != "" {
		// Set net/addr to "" so we connect to the system syslog server rather
		// than a remote one.
		net := ""
		addr := ""
		// The priority parameter is a combination of facility and default
		// severity.  We want to log with the standard LOG_USER facility; the
		// severity is actually irrelevant because the hook always overrides
		// it.
		priority := syslog.LOG_USER | syslog.LOG_INFO
		tag := "calico-felix"
		w, sysErr := syslog.Dial(net, addr, priority, tag)
		if sysErr == nil {
			syslogDest := NewSyslogDestination(logLevelSyslog, w)
			dests = append(dests, syslogDest)
		}
	}

	hook := NewBackgroundHook(filterLevels(mostVerboseLevel), logLevelSyslog, dests)
	hook.Start()
	log.AddHook(hook)

	// Disable logrus' default output, which only supports a single destination.  We use the
	// hook above to fan out logs to multiple destinations.
	log.SetOutput(&NullWriter{})

	// Since we push our logs onto a second thread via a channel, we can disable the
	// Logger's built-in mutex completely.
	log.StandardLogger().SetNoLock()

	// Do any deferred error logging.
	if fileDirErr != nil {
		log.WithError(fileDirErr).Fatal("Failed to create log file directory.")
	}
	if fileOpenErr != nil {
		log.WithError(fileOpenErr).Fatal("Failed to open log file.")
	}
	if sysErr != nil {
		log.WithError(sysErr).Error("Failed to connect to syslog.")
	}
}

// filterLevels returns all the logrus.Level values <= maxLevel.
func filterLevels(maxLevel log.Level) []log.Level {
	levels := []log.Level{}
	for _, l := range log.AllLevels {
		if l <= maxLevel {
			levels = append(levels, l)
		}
	}
	return levels
}

// Formatter is our custom log formatter, which mimics the style used by the Python version of
// Felix.  In particular, it uses a sortable timestamp and it includes the level, PID, file and line
// number.
//
//    2017-01-05 09:17:48.238 [INFO][85386] endpoint_mgr.go 434: Skipping configuration of
//    interface because it is oper down. ifaceName="cali1234"
type Formatter struct{}

func (f *Formatter) Format(entry *log.Entry) ([]byte, error) {
	// Sort the keys for consistent output.
	var keys []string = make([]string, 0, len(entry.Data))
	for k := range entry.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	b := entry.Buffer
	if b == nil {
		b = &bytes.Buffer{}
	}
	stamp := entry.Time.Format("2006-01-02 15:04:05.000")
	levelStr := strings.ToUpper(entry.Level.String())
	pid := os.Getpid()
	fileName := entry.Data["__file__"]
	lineNo := entry.Data["__line__"]
	fmt.Fprintf(b, "%s [%s][%d] %v %v: %v", stamp, levelStr, pid, fileName, lineNo, entry.Message)

	for _, key := range keys {
		if key == "__file__" || key == "__line__" {
			continue
		}
		var value interface{} = entry.Data[key]
		var stringifiedValue string
		if err, ok := value.(error); ok {
			stringifiedValue = err.Error()
		} else if stringer, ok := value.(fmt.Stringer); ok {
			// Trust the value's String() method.
			stringifiedValue = stringer.String()
		} else {
			// No string method, use %#v to get a more thorough dump.
			stringifiedValue = fmt.Sprintf("%#v", value)
		}
		fmt.Fprintf(b, " %v=%v", key, stringifiedValue)
	}

	b.WriteByte('\n')
	return b.Bytes(), nil
}

// FormatForSyslog formats logs in a way tailored for syslog.  It avoids logging information that is
// already included in the syslog metadata such as timestamp and PID.  The log level _is_ included
// because syslog doesn't seem to output it by default and it's very useful.
//
//    INFO endpoint_mgr.go 434: Skipping configuration of interface because it is oper down.
//    ifaceName="cali1234"
func FormatForSyslog(entry *log.Entry) string {
	// Sort the keys for consistent output.
	var keys []string = make([]string, 0, len(entry.Data))
	for k := range entry.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	levelStr := strings.ToUpper(entry.Level.String())
	fileName := entry.Data["__file__"]
	lineNo := entry.Data["__line__"]
	b := entry.Buffer
	if b == nil {
		b = &bytes.Buffer{}
	}
	fmt.Fprintf(b, "%s %v %v: %v", levelStr, fileName, lineNo, entry.Message)
	for _, key := range keys {
		if key == "__file__" || key == "__line__" {
			continue
		}
		var value interface{} = entry.Data[key]
		var stringifiedValue string
		if err, ok := value.(error); ok {
			stringifiedValue = err.Error()
		} else if stringer, ok := value.(fmt.Stringer); ok {
			// Trust the value's String() method.
			stringifiedValue = stringer.String()
		} else {
			// No string method, use %#v to get a more thorough dump.
			stringifiedValue = fmt.Sprintf("%#v", value)
		}
		fmt.Fprintf(b, " %v=%v", key, stringifiedValue)
	}
	b.WriteByte('\n')
	return b.String()
}

// NullWriter is a dummy writer that always succeeds and does nothing.
type NullWriter struct{}

func (w *NullWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

type ContextHook struct {
}

func (hook ContextHook) Levels() []log.Level {
	return log.AllLevels
}

func (hook ContextHook) Fire(entry *log.Entry) error {
	pcs := make([]uintptr, 4)
	if numEntries := runtime.Callers(6, pcs); numEntries > 0 {
		frames := runtime.CallersFrames(pcs)
		for {
			frame, more := frames.Next()
			if !shouldSkipFrame(frame) {
				entry.Data["__file__"] = path.Base(frame.File)
				entry.Data["__line__"] = frame.Line
				break
			}
			if !more {
				break
			}
		}
	}
	return nil
}

func shouldSkipFrame(frame runtime.Frame) bool {
	return strings.LastIndex(frame.File, "exported.go") > 0 ||
		strings.LastIndex(frame.File, "logger.go") > 0 ||
		strings.LastIndex(frame.File, "entry.go") > 0
}

type queuedLog struct {
	level     log.Level
	msgLine   []byte
	syslogMsg string
}

func NewStreamDestination(level log.Level, writer io.Writer) *StreamDestination {
	return &StreamDestination{
		level:   level,
		writer:  writer,
		channel: make(chan queuedLog, 10000),
	}
}

type StreamDestination struct {
	level   log.Level
	writer  io.Writer
	channel chan queuedLog

	// Our own copy of the dropped logs counter, used for logging out when we drop logs.
	// Must be read/updated using atomic.XXX.
	numDroppedLogs  uint64
	lastDropLogTime time.Duration
}

func (d *StreamDestination) Level() log.Level {
	return d.level
}

func (d *StreamDestination) Channel() chan<- queuedLog {
	return d.channel
}

func (d *StreamDestination) OnLogDropped() {
	atomic.AddUint64(&d.numDroppedLogs, 1)
}

func (d *StreamDestination) LoopWritingLogs() {
	var numSeenDroppedLogs uint64
	for {
		// Wait for something to log.
		ql := <-d.channel

		// If it's been a while since our last check, see if we're dropping logs.
		timeSinceLastCheck := monotime.Since(d.lastDropLogTime)
		if timeSinceLastCheck > time.Second {
			currentNumDroppedLogs := atomic.LoadUint64(&d.numDroppedLogs)
			if currentNumDroppedLogs > numSeenDroppedLogs {
				fmt.Fprintf(d.writer, "... dropped %d logs in %v ...\n",
					currentNumDroppedLogs-numSeenDroppedLogs,
					timeSinceLastCheck)
				numSeenDroppedLogs = currentNumDroppedLogs
			}
			d.lastDropLogTime = monotime.Now()
		}

		_, err := d.writer.Write(ql.msgLine)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write to log: %v", err)
		}
	}
}

func NewSyslogDestination(level log.Level, writer *syslog.Writer) *SyslogDestination {
	return &SyslogDestination{
		level:   level,
		writer:  writer,
		channel: make(chan queuedLog, 10000),
	}
}

type SyslogDestination struct {
	level   log.Level
	writer  *syslog.Writer
	channel chan queuedLog

	// Our own copy of the dropped logs counter, used for logging out when we drop logs.
	// Must be read/updated using atomic.XXX.
	numDroppedLogs  uint64
	lastDropLogTime time.Duration
}

func (d *SyslogDestination) Level() log.Level {
	return d.level
}

func (d *SyslogDestination) Channel() chan<- queuedLog {
	return d.channel
}

func (d *SyslogDestination) OnLogDropped() {
	atomic.AddUint64(&d.numDroppedLogs, 1)
}

func (d *SyslogDestination) LoopWritingLogs() {
	var numSeenDroppedLogs uint64
	for {
		// Wait for something to log.
		ql := <-d.channel

		// If it's been a while since our last check, see if we're dropping logs.
		timeSinceLastCheck := monotime.Since(d.lastDropLogTime)
		if timeSinceLastCheck > time.Second {
			currentNumDroppedLogs := atomic.LoadUint64(&d.numDroppedLogs)
			if currentNumDroppedLogs > numSeenDroppedLogs {
				d.writer.Warning(fmt.Sprintf("... dropped %d logs in %v ...\n",
					currentNumDroppedLogs-numSeenDroppedLogs,
					timeSinceLastCheck))
				numSeenDroppedLogs = currentNumDroppedLogs
			}
			d.lastDropLogTime = monotime.Now()
		}

		err := d.write(ql)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write to syslog: %v", err)
		}
	}
}

func (d *SyslogDestination) write(ql queuedLog) error {
	switch ql.level {
	case log.PanicLevel:
		return d.writer.Crit(ql.syslogMsg)
	case log.FatalLevel:
		return d.writer.Crit(ql.syslogMsg)
	case log.ErrorLevel:
		return d.writer.Err(ql.syslogMsg)
	case log.WarnLevel:
		return d.writer.Warning(ql.syslogMsg)
	case log.InfoLevel:
		return d.writer.Info(ql.syslogMsg)
	case log.DebugLevel:
		return d.writer.Debug(ql.syslogMsg)
	default:
		return nil
	}
}

type Destination interface {
	Level() log.Level
	LoopWritingLogs()
	Channel() chan<- queuedLog
	OnLogDropped()
}

type BackgroundHook struct {
	levels      []log.Level
	syslogLevel log.Level

	destinations []Destination

	// Our own copy of the dropped logs counter, used for logging out when we drop logs.
	// Must be read/updated using atomic.XXX.
	numDroppedLogs  uint64
	lastDropLogTime time.Duration
}

func NewBackgroundHook(levels []log.Level, syslogLevel log.Level, destinations []Destination) *BackgroundHook {
	return &BackgroundHook{
		destinations: destinations,
		levels:       levels,
		syslogLevel:  syslogLevel,
	}
}

func (h *BackgroundHook) Levels() []log.Level {
	return h.levels
}

func (h *BackgroundHook) Fire(entry *log.Entry) (err error) {
	var serialized []byte
	if serialized, err = entry.Logger.Formatter.Format(entry); err != nil {
		return
	}

	// entry's buffer will be reused after we return but we're about to send the message over
	// a channel; take a copy.
	bufCopy := make([]byte, len(serialized))
	copy(bufCopy, serialized)
	if entry.Buffer != nil {
		entry.Buffer.Truncate(0)
	}

	ql := queuedLog{
		level:   entry.Level,
		msgLine: bufCopy,
	}

	if entry.Level <= h.syslogLevel {
		// Special-case: syslog gets its own log string since out default log string
		// duplicates a lot of syslog metadata.  Only calculate that string if it's needed.
		ql.syslogMsg = FormatForSyslog(entry)
	}

	for _, dest := range h.destinations {
		if ql.level > dest.Level() {
			continue
		}
		select {
		case dest.Channel() <- ql:
		default:
			// Background thread isn't keeping up.  Drop the log and count how many
			// we've dropped.
			counterDroppedLogs.Inc()
			dest.OnLogDropped()
		}
	}
	return
}

func (h *BackgroundHook) Start() {
	for _, d := range h.destinations {
		go d.LoopWritingLogs()
	}
}

type LeveledHook struct {
	hook   log.Hook
	levels []log.Level
}

func (h *LeveledHook) Levels() []log.Level {
	return h.levels
}

func (h *LeveledHook) Fire(entry *log.Entry) error {
	return h.hook.Fire(entry)
}

// safeParseLogLevel parses a string version of a logrus log level, defaulting
// to logrus.PanicLevel on failure.
func safeParseLogLevel(logLevel string) log.Level {
	defaultedLevel := log.PanicLevel
	if logLevel != "" {
		parsedLevel, err := log.ParseLevel(logLevel)
		if err == nil {
			defaultedLevel = parsedLevel
		} else {
			log.WithField("raw level", logLevel).Warn(
				"Invalid log level, defaulting to panic")
		}
	}
	return defaultedLevel
}
