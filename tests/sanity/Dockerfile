FROM golang:1.13.4 as build-env

RUN go get -u github.com/kubernetes-csi/csi-test/...

FROM frolvlad/alpine-glibc
WORKDIR /app/csi-sanity/
COPY --from=build-env /go/bin/csi-sanity .

ENTRYPOINT [ "./csi-sanity" ]
