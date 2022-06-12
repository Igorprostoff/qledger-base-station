FROM golang:latest

RUN mkdir project
COPY *.go ./project/
COPY go.mod ./project
COPY go.sum ./project

WORKDIR project

RUN go mod tidy
RUN go build .
RUN chmod 777 /go/project/qapi
ENTRYPOINT ["/go/project/qapi"]