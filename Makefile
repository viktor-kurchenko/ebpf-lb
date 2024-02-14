TARGET = bpf/app
BPF_APP = xdp_lb
INTERFACE = docker0

LB_PORT = 8080
BE_PORT = 8000

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

run: build
	sudo go run . $(INTERFACE)

infra-run:
	./scripts/start_docker_infra.sh $(INTERFACE) $(LB_PORT) $(BE_PORT)

infra-stop:
	./scripts/stop_docker_infra.sh
