FROM golang:1.22

# Set destination for COPY
WORKDIR /app

# Download Go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY *.go ./

# Copy the start script
COPY files/start /start
RUN chmod +x /start

# Set the entrypoint
USER 1001
ENTRYPOINT ["/start"]
