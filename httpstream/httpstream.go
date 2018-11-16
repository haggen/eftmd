package httpstream

import (
	"bufio"
	"io"
	"net/http"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// httpStreamProcessor handles the responses once assembled and read.
type httpStreamProcessor func(*http.Response)

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net       gopacket.Flow
	transport gopacket.Flow
	reader    tcpreader.ReaderStream
}

func (s *httpStream) read(processor httpStreamProcessor) {
	buf := bufio.NewReader(&s.reader)
	for {
		resp, err := http.ReadResponse(buf, nil)
		if err == io.EOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			continue
		} else {
			processor(resp)
		}
	}
}

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct {
	processor httpStreamProcessor
}

func (s *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	stream := &httpStream{
		net:       net,
		transport: transport,
		reader:    tcpreader.NewReaderStream(),
	}
	// Important... we must guarantee that data from the reader stream is read.
	go stream.read(s.processor)
	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &stream.reader
}

// New prepares a new HTTP assembly stream that reads and assembles packets from given handle into http.Responses to be processed.
func New(handle *pcap.Handle, processor httpStreamProcessor) {
	// Set up assembly.
	factory := &httpStreamFactory{
		processor: processor,
	}
	pool := tcpassembly.NewStreamPool(factory)
	assembler := tcpassembly.NewAssembler(pool)

	// Read in packets, pass to assembler.
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := src.Packets()
	refresh := time.Tick(time.Minute)
	for {
		select {
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				return
			}
			// Unusable packet.
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
		case <-refresh:
			// Every minute, flush connections that haven't seen activity recently.
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -5))
		}
	}
}
