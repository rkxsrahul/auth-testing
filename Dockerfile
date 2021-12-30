FROM golang:1.16


# Set go bin which doesn't appear to be set already.
ENV GOBIN /go/bin
ENV GO111MODULE=off

# build directories
ADD . /go/src/git.xenonstack.com/akirastack/continuous-security-auth
WORKDIR /go/src/git.xenonstack.com/akirastack/continuous-security-auth

#Go dep!
RUN go install git.xenonstack.com/akirastack/continuous-security-auth
ENTRYPOINT /go/bin/continuous-security-auth

EXPOSE 8000
