TARGET = bpf/app
BPF_APP = xdp_lb
INTERFACE = docker0

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
	echo "Starting BE-1 ..."
	docker run -e HTTP_PORT=$(BE_PORT) -h be-1 --name be-1 --rm -d -t mendhak/http-https-echo:31
	BE1_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' be-1)
	echo "Starting BE-2 ..."
	docker run -e HTTP_PORT=$(BE_PORT) -h be-2 --name be-2 --rm -d -t mendhak/http-https-echo:31
	BE2_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' be-2)
	echo "Starting clients ..."
	docker run --name cl-1 --rm -d -it nicolaka/netshoot /bin/bash
	docker run --name cl-2 --rm -d -it nicolaka/netshoot /bin/bash

infra-stop:
	docker stop be-1 be-2 cl-1 cl-2 || true
