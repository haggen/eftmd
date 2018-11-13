// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// This binary provides sample code for using the gopacket TCP assembler and TCP
// stream reader.  It reads packets off the wire and reconstructs HTTP requests
// it sees, logging them.
package main

import (
	"bufio"
	"compress/zlib"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// var iface = flag.String("i", "eth0", "Interface to get packets from")
// var fname = flag.String("r", "", "Filename to read from, overrides -i")
// var snaplen = flag.Int("s", 1600, "SnapLen for pcap packet capture")
// var filter = flag.String("f", "tcp and dst port 80", "BPF filter for pcap")
// var logAllPackets = flag.Bool("v", false, "Logs every packet in great detail")

// Build a simple HTTP request parser using tcpassembly.StreamFactory and tcpassembly.Stream interfaces

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct{}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net       gopacket.Flow
	transport gopacket.Flow
	r         tcpreader.ReaderStream
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	stream := &httpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go stream.run() // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &stream.r
}

func (h *httpStream) run() {
	buf := bufio.NewReader(&h.r)
	for {
		resp, err := http.ReadResponse(buf, nil)
		if err == io.EOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			//log.Println("Error reading stream", h.net, h.transport, ":", err)
		} else {
			if resp.StatusCode != http.StatusOK {
				continue
			}
			//body := tcpreader.DiscardBytesToEOF(resp.Body)
			//resp.Body.Close()
			reader, err := zlib.NewReader(resp.Body)
			if err != nil {
				log.Println("zlib.NewReader:", err)
			}
			b, err := ioutil.ReadAll(reader)
			if err != nil {
				log.Println("ioutil.ReadAll:", err)
			}
			resp.Body.Close()
			reader.Close()
			log.Println("---")
			log.Println(string(b))
		}
	}
}

func main() {
	handle, err := pcap.OpenOffline("tarkov.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("tcp and dst port 49855"); err != nil {
		log.Fatal(err)
	}

	// Set up assembly
	pool := tcpassembly.NewStreamPool(&httpStreamFactory{})
	assembler := tcpassembly.NewAssembler(pool)

	// Read in packets, pass to assembler.
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := src.Packets()
	ticker := time.Tick(time.Minute)
	for {
		select {
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				return
			}
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				// Unusable packet.
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}
}
