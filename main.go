package main

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"flag"
	"strings"
	"encoding/binary"
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

var (
	syncInProgress bool = false
	dataLen uint32 = 0

)

func handlePayload(payload []byte, tcp *layers.TCP) {
	//	fmt.Println(len(payload))
	if len(payload) > 0 {
		line :=string(payload)
		line = strings.TrimSpace(line)
		if tcp.DstPort == 5037 { //Snip first 4 bytes
			payload = payload[4:]
			if strings.LastIndex(line, "SEND") == 0{
				dataLen =binary.LittleEndian.Uint32(payload[4:8])
				color.Red("[ADB]%d\t%s", dataLen,line)
			} else if strings.LastIndex(line, "DATA") == 0{
				dataLen =binary.LittleEndian.Uint32(payload[4:8])
				color.Red("[ADB]:%d\t", dataLen)
			} else if strings.LastIndex(line, "shell") == 4{
				color.Red("[ADB][%d]\t%s",tcp.SrcPort,line)
			} else if strings.LastIndex(line, "host") == 4{
				color.Red("[ADB]\t%s",line)
			} else if strings.LastIndex(line, "sync") == 4{
				color.Red("[ADB]\t%s",line)
				syncInProgress = true
			} else if len(payload) > 20 && !syncInProgress {
				color.Blue("[ADB]\t%s",line[0:20])
			} else if !syncInProgress {
				color.Blue("[ADB]\t%s",line[0:8])
			}


		} else {
			max := 20
			if len(payload) < max{
				max = len(payload)
			}
			if strings.HasPrefix(line, "INSTRUMENTATION"){
				color.Green("[ANDR][%d]\t%s", tcp.DstPort, string(line))
			} else  if strings.HasPrefix(line, "["){
				color.HiBlack("[ANDR][%d]\t%s", tcp.DstPort, string(line))
			} else {
				color.Yellow("[ANDR][%d]\t%s", tcp.DstPort, string(line))
				if syncInProgress {
					color.Yellow(string(payload))
					if len(payload) == 8 {
						color.Yellow("%d", binary.LittleEndian.Uint32(payload[4:8]))
						syncInProgress = false
					}


				}
			}


		}
		//max := 20
		//if len(payload) < max{
		//	max = len(payload)
		//}


		if strings.Contains(line, "Exception"){
			//fmt.Println(line)
		}

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