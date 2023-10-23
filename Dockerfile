FROM golang:1.21-bullseye AS build-go
COPY . /app
WORKDIR /app
ENV CGO_ENABLED=0
RUN go get -v
RUN go build -o vulnivore .

FROM gcr.io/distroless/base:nonroot
COPY --from=build-go /app/vulnivore /vulnivore
WORKDIR /
ENV VULNIVORE_ADDR="0.0.0.0:8192"
EXPOSE 8192
ENTRYPOINT [ "/vulnivore" ]
