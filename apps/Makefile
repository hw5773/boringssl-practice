CC      = gcc
LD      = ld
AR      = ar
NM      = nm
OBJCOPY = objcopy
OBJDUMP = objdump
READELF = readelf

CERT_FILE=cert.der
KEY_FILE=priv.der

GCC=gcc

CLIENT=client
SERVER=server
CLIENT_SRC=client.c
CLIENT_OBJ=client.o
SERVER_SRC=server.c
SERVER_OBJ=server.o

BINS=${CLIENT} ${SERVER} ${VANILA} ${VANILA_CACHE}
OBJS=${CLIENT_OBJ} ${SERVER_OBJ} ${VANILA_OBJ} ${VANILA_CACHE_OBJ}

CFLAGS=-I${HOME}/boringssl-practice/boringssl/include
LDFLAGS=-L${HOME}/boringssl-practice/boringssl/build/ssl -L${HOME}/boringssl-practice/boringssl/build/crypto -lssl -lcrypto -ldl -lpthread

HOST=www.bob.com
PORT=5555
NUM_OF_THREADS=1
CONTENT=index.html

all: client server

client: ${CLIENT_OBJ}
	${GCC} -o ${CLIENT} ${CLIENT_OBJ} ${LDFLAGS}

server: ${SERVER_OBJ}
	${GCC} -o ${SERVER} ${SERVER_OBJ} ${LDFLAGS}

client.o: ${CLIENT_SRC}
	${GCC} ${FLAGS} ${CFLAGS} -c $<

server.o: ${SERVER_SRC}
	${GCC} ${FLAGS} ${CFLAGS} -c $<

cstart:
	./${CLIENT} ${HOST} ${PORT} ${CONTENT} ${NUM_OF_THREADS}

sstart:
	./${SERVER} ${PORT} ${LABEL}

clean:
	rm ${BINS} ${OBJS}
