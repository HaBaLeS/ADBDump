package main

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"flag"
)



type Options struct {
	captureInterface string
	capturePort int
	verbose bool
	captureFile string
}

var options Options


func main() {

	flag.Parse()

	//FIXME introduce logger instead of writing directly anf commandline option to be silent


	//TODO dump files

	//TODO Colorize Traffic --> Show short overview on packages

	//TODO Verbose mode

	//FIXME Pinning of 3rd party dependencies

	var (
		handle *pcap.Handle
		err error
	)

	if options.captureFile != "" {
		handle, err = pcap.OpenOffline(options.captureFile)
		if err != nil {
			color.Red("[e]\tCould not capture file %s", options.captureFile)
			color.Red("\t%s",err)
		}
	} else {
		handle, err = pcap.OpenLive(options.captureInterface, 64000, true, pcap.BlockForever)
		if err != nil {
			color.Red("[e]\tCould not open device %s", options.captureInterface)
			color.Red("\t%s",err)
		} else {
			color.HiGreen("[i]\tADBDump will start capturing on device: %s and port %d", options.captureInterface, options.capturePort)
		}
	}



	if handle != nil {
		defer handle.Close()

		filter := fmt.Sprintf("port %d", options.capturePort)
		logD(fmt.Sprintf("Using \"%s\" as BPF Filter", filter))
		e := handle.SetBPFFilter(filter)
		if e != nil {
			//FIXME Better error handling needed
			panic(e)
		}

		// Loop through packets in file
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				payload := tcp.Payload
				handlePayload(payload, tcp)
			}
		}

	}

}


func handlePayload(payload []byte, tcp *layers.TCP) {
	if len(payload) > 0 {
		if tcp.DstPort == 5037 { //Snip first 4 bytes
			payload = payload[4:]

			fmt.Printf("[ADB]\t")
		} else {
			fmt.Printf("[ANDR]\t")
		}
		max := 80
		if len(payload) < max{
			max = len(payload)
		}
		fmt.Println(string(payload[0:max]))
	}
}


func logD(s string) {
	color.HiGreen("[i]\t%s", s )
}

func init() {

	options = Options{}
	flag.StringVar(&options.captureInterface, "d", "lo", "Device to capture on")
	flag.IntVar(&options.capturePort, "p", 5037, "Port to capture on")
	flag.BoolVar(&options.verbose, "v", false, "Log not only commands, also content of the communication")
	flag.StringVar(&options.captureFile, "r", "" , "Read from file instead of ")

}