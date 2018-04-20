/*
MIT License

Copyright (c) 2018 Vegar Linge Haaland <vegar at vegarlh.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package main

import (
	"bufio"
	"flag"
	"regexp"
	"strings"

	"os"

	"github.com/CaliDog/certstream-go"
	"github.com/gregdel/pushover"
	"github.com/op/go-logging"
)

// MonitorKeywords Regex keywords to monitor
var MonitorKeywords []string

// HighlightKeywords Array of keywords to highlight
var HighlightKeywords []string

// AlertKeywords Array of keywords that will trigger alerts
var AlertKeywords []string

// LogFilePath is path to logfile..
var LogFilePath = "certstream.log"

// MonitorFilePath is the path to keyword file for domains to monitor
var MonitorFilePath = "monitor.txt"

// HighlightFilePath is path to keyword file for alerts
var HighlightFilePath = "highlight.txt"

// AlertFilePath is path to keyword file for alerts
var AlertFilePath = "alerts.txt"

// Set up logging
var log = logging.MustGetLogger("example")
var consoleOutputFormat = logging.MustStringFormatter(
	`%{color}%{time:2006-01-02 15:04.05} %{color:reset} %{message}`,
)

var logFileFormat = logging.MustStringFormatter(
	`%{time:2006-01-02 15:04.05} %{message}`,
)

// checkDomain returns true of a domain matches any regex keyword specified in check
func checkDomain(domain string, check []string) bool {
	for _, key := range check {
		if ret, _ := regexp.MatchString(key, "^#"); !ret {
			if ret, _ := regexp.MatchString(key, domain); ret {
				return true
			}
		}
	}
	return false
}

// keywords reads keywords from a file and returns them as a string array
func keywords(filePath string) []string {
	file, err := os.Open(filePath)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var keywords []string
	for scanner.Scan() {
		keywords = append(keywords, scanner.Text())
	}
	return keywords
}

func main() {

	// Set up command line arguments
	LogFile := *flag.String("f", LogFilePath, "Path of logfile to use. Defaults to "+LogFilePath)
	MonitorFile := *flag.String("m", MonitorFilePath, "Path of logfile to use. Defaults to "+MonitorFilePath)
	AlertFile := *flag.String("a", AlertFilePath, "Path of logfile to use. Defaults to "+MonitorFilePath)
	HighlightFile := *flag.String("h", HighlightFilePath, "Path of logfile to use. Defaults to "+HighlightFilePath)

	flag.Parse()

	// Set up logfile handle
	f, err := os.OpenFile(LogFile, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0660)
	if err != nil {
		panic(err)
	}
	w := bufio.NewWriter(f)
	defer f.Close()

	// Set up loggers
	loggingConsoleBackend := logging.NewLogBackend(os.Stderr, "", 0)
	loggingFileBackend := logging.NewLogBackend(w, "", 0)
	loggingConsoleFormatter := logging.NewBackendFormatter(loggingConsoleBackend, consoleOutputFormat)
	loggingFileFormatter := logging.NewBackendFormatter(loggingFileBackend, logFileFormat)
	logging.SetBackend(loggingConsoleFormatter, loggingFileFormatter)

	// Read in keywords for highlighting
	MonitorKeywords = keywords(MonitorFile)
	HighlightKeywords = keywords(HighlightFile)
	AlertKeywords = keywords(AlertFile)

	// Create a new pushover instance with a token
	push := pushover.New("YourAppTokenHere")

	// Create a new recipient
	recipient := pushover.NewRecipient("RecipientHere")

	// The true flag specifies that we don't want heartbeat messages.
	stream, errStream := certstream.CertStreamEventStream(true)
	for {
		select {
		case jq := <-stream:
			//messageType, _ := jq.String("message_type")
			mainDomain, _ := jq.String("data", "leaf_cert", "subject", "CN")
			domains, err := jq.ArrayOfStrings("data", "leaf_cert", "all_domains")
			if err != nil {
				log.Error("Error decoding jq string. Skipping")
				//log.Error(err)
				continue
			}

			for _, key := range MonitorKeywords {
				match, _ := regexp.MatchString(key, mainDomain)
				if match {
					highlight := false

					for _, domain := range domains {
						if checkDomain(domain, HighlightKeywords) {
							highlight = true
						}
						if checkDomain(domain, AlertKeywords) {
							// Create the message to send
							message := pushover.NewMessageWithTitle(strings.Join(domains, " "), "New TLS certificate for "+domain)

							// Send the message to the recipient
							_, err := push.SendMessage(message, recipient)
							if err != nil {
								log.Error(err)
							}
						}
					}

					if highlight {
						log.Critical(domains)
					} else {
						log.Notice(domains)
					}

					w.Flush()
					f.Sync()
					break
				}
			}

		case err := <-errStream:
			log.Error(err)
		}
	}
}
