package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/cilium/ebpf/link"
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

	config, err := configFromFile()
	if err != nil {
		log.Fatalf("failed to load config: %s", err)
	}

	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("failed to lookup network iface %q: %s", ifaceName, err)
	}

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

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		fmt.Printf("Working...\n")
	}
}

func configFromFile() (config, error) {
	cfg, err := os.ReadFile(configFileName)
	if err != nil {
		return config{}, fmt.Errorf("failed to load config from file: %s", err)
	}
	config := config{}
	if err := yaml.Unmarshal(cfg, &config); err != nil {
		return config, fmt.Errorf("failed to unmarshal config: %s", err)
	}
	constantsMap[lbPortConstName] = config.LoadBalancer.Port
	return config, nil
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
		Ip:      binary.LittleEndian.Uint32(cfg.LoadBalancer.IP.AsSlice()),
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
