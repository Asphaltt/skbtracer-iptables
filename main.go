package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -cc clang skbtracer ./ebpf/skbtracer.c -- -D__TARGET_ARCH_x86 -I./ebpf/headers -Wall

var usage = `examples:
skbtracer-iptables                                      # trace all packets
skbtracer-iptables --proto=icmp -H 1.2.3.4 --icmpid 22  # trace icmp packet with addr=1.2.3.4 and icmpid=22
skbtracer-iptables --proto=tcp  -H 1.2.3.4 -P 22        # trace tcp  packet with addr=1.2.3.4:22
skbtracer-iptables --proto=udp  -H 1.2.3.4 -P 22        # trace udp  packet wich addr=1.2.3.4:22
skbtracer-iptables -t -T -p 1 -P 80 -H 127.0.0.1 --proto=tcp --icmpid=100 -N 10000
`

var rootCmd = cobra.Command{
	Use:   "skbtracer-iptables",
	Short: "Trace any packet through iptables",
	Long:  usage,
	Run: func(cmd *cobra.Command, args []string) {
		if err := cfg.parse(); err != nil {
			fmt.Println(err)
			return
		}

		runGops()
		runEbpf()
	},
}

func main() {
	cobra.CheckErr(rootCmd.Execute())
}

// runEbpf attaches the kprobes and prints the kprobes' info.
func runEbpf() {
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{
		Cur: 4096,
		Max: 4096,
	}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %s", err)
	}
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		log.Fatalf("Failed to set temporary rlimit: %s", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	bpfSpec, err := loadSkbtracer()
	if err != nil {
		log.Printf("Failed to load bpf spec: %v", err)
		return
	}

	if err := bpfSpec.RewriteConstants(map[string]interface{}{
		"CFG": getBpfConfig(),
	}); err != nil {
		log.Printf("Failed to rewrite const for config: %v", err)
		return
	}

	var bpfObj skbtracerObjects
	if err := bpfSpec.LoadAndAssign(&bpfObj, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSize: ebpf.DefaultVerifierLogSize * 10,
		},
	}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Printf("Failed to load bpf obj: %v\n%-50v", err, ve)
		} else {
			log.Printf("Failed to load bpf obj: %v", err)
		}
		return
	}

	isHighVersion, err := isKernelVersionGte_5_16()
	if err != nil {
		log.Printf("Failed to check kernel version: %v", err)
		return
	}

	kIptDoTable := bpfObj.K_iptDoTable
	if !isHighVersion {
		kIptDoTable = bpfObj.IptDoTableOld
	}

	if kp, err := link.Kprobe("ipt_do_table", kIptDoTable, nil); err != nil {
		log.Printf("Failed to kprobe(ipt_do_table): %v", err)
		return
	} else {
		defer kp.Close()
		log.Printf("Attached kprobe(ipt_do_table)")
	}

	if krp, err := link.Kretprobe("ipt_do_table", bpfObj.KrIptDoTable, nil); err != nil {
		log.Printf("Failed to kretprobe(ipt_do_table): %v", err)
		return
	} else {
		defer krp.Close()
		log.Printf("Attached kretprobe(ipt_do_table)")
	}

	if kp, err := link.Kprobe("nf_hook_slow", bpfObj.K_nfHookSlow, nil); err != nil {
		log.Printf("Failed to kprobe(nf_hook_slow): %v", err)
		return
	} else {
		defer kp.Close()
		log.Printf("Attached kprobe(nf_hook_slow)")
	}

	if krp, err := link.Kretprobe("nf_hook_slow", bpfObj.KrNfHookSlow, nil); err != nil {
		log.Printf("Failed to kretprobe(nf_hook_slow): %v", err)
		return
	} else {
		defer krp.Close()
		log.Printf("Attached kretprobe(nf_hook_slow)")
	}

	rd, err := perf.NewReader(bpfObj.SkbtracerEvent, cfg.PerCPUBuffer)
	if err != nil {
		log.Printf("Failed to create perf event reader: %v", err)
		return
	}

	go func() {
		<-ctx.Done()
		_ = rd.Close()
		log.Println("Received signal, exiting program...")
	}()

	fmt.Printf("%-10s %-20s %-12s %-8s %-6s %-18s %-18s %-6s %-54s %s\n",
		"TIME", "SKB", "NETWORK_NS", "PID", "CPU", "INTERFACE", "DEST_MAC", "IP_LEN",
		"PKT_INFO", "IPTABLES_INFO")

	var event perfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("Reading from perf event reader: %v", err)
		}

		if record.LostSamples != 0 {
			log.Printf("Perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("Failed to parse perf event: %v", err)
			continue
		}

		fmt.Println(event.output())

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}
