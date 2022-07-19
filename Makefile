all: clean build build-linux

.PHONY: build
clean:
	rm -rf out/

build:
	go build -a -installsuffix cgo -o out/nginx-auth-kubapi ./main.go

.PHONY: build-linux
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -o out/nginx-auth-kubeapi-linux-amd64 ./main.go

.PHONY: build-docker
build-docker:
	docker build -t dixont/nginx-auth-kubeapi
