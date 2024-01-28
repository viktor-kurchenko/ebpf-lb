TARGET = bpf/app
BPF_APP = xdp_lb
# INTERFACE = wlp1s0
# INTERFACE = lo
# INTERFACE = docker0
INTERFACE = virbr0

BPF_C = ${TARGET:=.c}
BPF_OBJ = ${BPF_C:.c=.o}

build: clean
	clang -target bpf \
		  -Wall -O2 -g \
		  -c $(BPF_C) \
		  -I/usr/include \
		  -o $(BPF_OBJ)
	go generate

clean:
	rm -f $(BPF_OBJ)
	rm -f ${BPF_OBJ:.o=.ll}
	rm -f bpf_bpf*

attach: detach
	sudo bpftool prog load $(BPF_OBJ) /sys/fs/bpf/$(BPF_APP)
	sudo bpftool net attach xdpgeneric pinned /sys/fs/bpf/$(BPF_APP) dev $(INTERFACE)

detach:
	sudo bpftool net detach xdpgeneric dev $(INTERFACE)
	sudo rm -f /sys/fs/bpf/$(BPF_APP)

trace:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

tcp-echo:
	ncat -l 8080 --keep-open --exec "/bin/cat"

udp-echo:
	ncat -l 8080 --keep-open --udp --exec "/bin/cat"

run: build
	sudo go run . $(INTERFACE)

# server-1: docker run --rm -it -e TCP_PORT=8001 -e NODE_NAME="EchoNode" -p 8001:8001 cjimti/go-echo
# server-2: docker run --rm -it -e TCP_PORT=8002 -e NODE_NAME="EchoNode" -p 8002:8002 cjimti/go-echo
# client: docker run --rm -it nicolaka/netshoot /bin/bash