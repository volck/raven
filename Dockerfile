# Start from the golang base image
FROM golang:1.22

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. 
# If the go.mod and the go.sum file are not changed, then the docker cache will not be invalidated
RUN go mod download 

# Copy the source code into the container
COPY *.go ./

# Copy the start script into the container
COPY files/start /start

# Make the start script executable
RUN chmod +x /start

# Switch to a non-root user
USER 1001

# Command to run the executable
ENTRYPOINT ["/start"]