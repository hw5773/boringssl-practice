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

CLIENT_1=client_1
SERVER_1=server_1

HOST=www.bob.com
PORT=5555
NUM_OF_THREADS=1
CONTENT=index.html

default:
	@echo "1) You should open two terminals -- one for the server and the other for the client"
	@echo "2) Then execute 'make start_i' for the server and 'make client_i' for the client, where i is the problem number"

cstart_1:
	./${CLIENT_1} ${HOST} ${PORT} ${CONTENT} ${NUM_OF_THREADS}

sstart_1:
	./${SERVER_1} ${PORT}

cstart_3:
	./${CLIENT_3} ${HOST} ${PORT} ${CONTENT} ${NUM_OF_THREADS}

sstart_3:
	./${SERVER_3} ${PORT}

cstart_4:
	./${CLIENT_4} ${HOST} ${PORT} ${CONTENT} ${NUM_OF_THREADS}

sstart_4:
	./${SERVER_4} ${PORT}

