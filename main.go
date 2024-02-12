package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/cilium/ebpf/link"
	"github.com/gavv/monotime"
	"github.com/mdlayher/arp"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf bpf/app.c -- -I../headers

type config struct {
	LoadBalancer server   `yaml:"lb"`
	Backends     []server `yaml:"backends"`
}

type server struct {
	IP   netip.Addr `yaml:"ip"`
	Port uint16     `yaml:"port"`
	MAC  string     `yaml:"mac"`
}

const (
	configFileName  = "config.yaml"
	lbCfgKey        = uint16(0)
	lbPortConstName = "port"
)

var constantsMap = map[string]interface{}{
	"lb_cfg_key": lbCfgKey,
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("failed to lookup network iface %q: %s", ifaceName, err)
	}

	config, err := configFromFile(iface)
	if err != nil {
		log.Fatalf("failed to load config: %s", err)
	}

	verifyLBIP(iface, config.LoadBalancer.IP)
	constantsMap[lbPortConstName] = config.LoadBalancer.Port
	populateBeMACs(iface, &config)

	objs := bpfObjects{}
	defer objs.Close()
	spec, err := loadBpf()
	if err != nil {
		log.Fatalf("failed to load BPF: %s", err)
	}
	if err := spec.RewriteConstants(constantsMap); err != nil {
		log.Fatalf("failed to rewrite load balancer port: %s", err)
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("failed to load and assign: %s", err)
	}

	if err := loadConfigInKernel(config, &objs); err != nil {
		log.Fatalf("failed to load config: %s", err)
	}

	if err := fillPortsMap(&objs); err != nil {
		log.Fatalf("failed to fill ports map: %s", err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpLoadBalancer,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("faile to attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		printStat(&objs)
	}
}

func configFromFile(iface *net.Interface) (config, error) {
	cfg, err := os.ReadFile(configFileName)
	if err != nil {
		return config{}, fmt.Errorf("failed to load config from file: %s", err)
	}
	config := config{}
	if err := yaml.Unmarshal(cfg, &config); err != nil {
		return config, fmt.Errorf("failed to unmarshal config: %s", err)
	}
	return config, nil
}

func verifyLBIP(iface *net.Interface, ip netip.Addr) error {
	addresses, err := iface.Addrs()
	if err != nil {
		return err
	}
	for i := range addresses {
		ifIP := addresses[i].(*net.IPNet).IP.String()
		if ifIP == ip.String() {
			return nil
		}
	}
	return fmt.Errorf("LB IP [%s] doesn't match network interface", ip)
}

func populateBeMACs(iface *net.Interface, config *config) error {
	config.LoadBalancer.MAC = iface.HardwareAddr.String()

	c, err := arp.Dial(iface)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	for i := range config.Backends {
		mac, err := c.Resolve(config.Backends[i].IP)
		if err != nil {
			return err
		}
		config.Backends[i].MAC = mac.String()
	}
	return nil
}

func mustParseMAC(addr string) net.HardwareAddr {
	mac, err := net.ParseMAC(addr)
	if err != nil {
		panic(fmt.Sprintf("failed to parse MAC address: %s, %s", addr, err))
	}
	return mac
}

func loadConfigInKernel(cfg config, objs *bpfObjects) error {
	lb := bpfLbCfg{
		Ip:      binary.LittleEndian.Uint32(cfg.LoadBalancer.IP.AsSlice()), //TODO: is it platform specific?
		Port:    cfg.LoadBalancer.Port,
		Mac:     [6]uint8(mustParseMAC(cfg.LoadBalancer.MAC)),
		BeCount: uint16(len(cfg.Backends)),
	}
	if err := objs.LbCfgMap.Put(lbCfgKey, lb); err != nil {
		return fmt.Errorf("failed to put LB config in the map: %s", err)
	}

	for i, be := range cfg.Backends {
		beCfg := bpfServerCfg{
			Ip:   binary.LittleEndian.Uint32(be.IP.AsSlice()),
			Port: be.Port,
			Mac:  [6]uint8(mustParseMAC(be.MAC)),
		}
		if err := objs.BeCfgMap.Put(uint16(i), beCfg); err != nil {
			return fmt.Errorf("failed to put BE config in the map: %s", err)
		}
	}
	return nil
}

func fillPortsMap(objs *bpfObjects) error {
	for i := 1024; i <= 65535; i++ {
		p := uint16(i)
		if err := objs.Ports.Put(nil, &p); err != nil {
			return err
		}
	}
	return nil
}

func printStat(objs *bpfObjects) {
	iterator := objs.ClientTupplePortMap.Iterate()
	stats := strings.Builder{}
	var clientPort uint16
	var clientTupple bpfClientTupple
	for iterator.Next(&clientTupple, &clientPort) {
		var beCfg bpfServerCfg
		objs.PortBeCfgMap.Lookup(&clientPort, &beCfg)
		var connTrack bpfConnTrack
		objs.PortConnTrackMap.Lookup(&clientPort, &connTrack)

		connDuration := time.Duration(monotime.Now().Nanoseconds() - connTrack.Ts).Round(time.Second)
		stats.WriteString(fmt.Sprintf("[%s] %s:%d ---> %s:%d [%s] [last activity: %s]\n",
			mac2String(clientTupple.Mac), ipFromInt(clientTupple.Ip), clientPort,
			ipFromInt(beCfg.Ip), beCfg.Port, mac2String(beCfg.Mac), connDuration))
	}
	fmt.Printf("Stats:\n%s\n", stats.String())
}
