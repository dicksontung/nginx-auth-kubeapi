FROM golang:alpine

COPY /out/nginx-auth-kubeapi-linux-amd64 /usr/local/bin/nginx-auth-kubeapi

CMD ["nginx-auth-kubeapi", "start"]