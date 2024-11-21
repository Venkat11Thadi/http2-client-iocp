#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <assert.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <memory>
#include <openssl/applink.c>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <thread>
#include <vector>
#include <winsock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#define NGHTTP2_NO_SSIZE_T
#include <nghttp2/nghttp2.h>

#include "http_parser.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#pragma warning(disable : 4996)

#define BUFFER_SIZE 4096

using namespace std;

#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

typedef struct {  
    const char* uri;
    struct http_parser_url* u;
    char* authority;
    char* path;
    size_t authoritylen;
    size_t pathlen;
    int32_t stream_id;
} http2_stream_data;

typedef struct {
    nghttp2_session* session;
    struct evdns_base* dnsbase;
    struct bufferevent* bev;
    http2_stream_data* stream_data;
} http2_session_data;

typedef enum _IO_OPERATION
{
    CLIENT_ACCEPT,
    SEND,
    RECV,
    IO,
} IO_OPERATION, * PERIO_OPERATIONS;

typedef struct _PER_IO_DATA
{
    WSAOVERLAPPED overlapped;
    SOCKET sockfd;
    WSABUF wsaSendBuf, wsaRecvBuf;
    CHAR sendBuffer[BUFFER_SIZE], recvBuffer[BUFFER_SIZE];
    DWORD bytesSend, bytesRecv;
    IO_OPERATION ioOperation;
    SSL* ssl;
    SSL_CTX* sslCtx;
    CHAR* hostname;
    EVP_PKEY* pkey;
    BIO* rbio, * wbio;
    BOOL bioFlag = FALSE;
    BOOL recvFlag = FALSE;
} PER_IO_DATA, * LPPER_IO_DATA;


void init();
void initializeWinsock();
void initializeOpenSSL();
void openssl_cleanup();
SOCKET createSocket(const char *host, int port);
LPPER_IO_DATA UpdateIoCompletionPort(SOCKET socket, IO_OPERATION ioOperation);
static DWORD WINAPI WorkerThread(LPVOID lparameter);
static void initialize_nghttp2_session(http2_session_data* session_data);

HANDLE CompletionPort;

int main()
{
	init();
	return 0;
}

void init()
{
    initializeWinsock();
    initializeOpenSSL();
    CompletionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    if (!CompletionPort)
    {
        printf("Cannot create ProxyCompletionPort.\n");
        WSACleanup();
        return;
    }
    printf("ProxyCompletionPort created.\n");

    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    for (DWORD i = 0; i < systemInfo.dwNumberOfProcessors; i++)
    {
        HANDLE pThread = CreateThread(NULL, 0, WorkerThread, CompletionPort, 0, NULL);
        if (pThread == NULL)
        {
            printf("Failed to create worker thread.");
            WSACleanup();
            return;
        }
        CloseHandle(pThread);
    }

    const char* uri = "https://www.google.com";
    struct http_parser_url u;
    char* host;
    uint16_t port;
    int rv;

    /* Parse the |uri| and stores its components in |u| */
    rv = http_parser_parse_url(uri, strlen(uri), 0, &u);
    if (rv != 0) {
        printf("Could not parse URI %s", uri);
    }
    host = _strdup(&uri[u.field_data[UF_HOST].off]);
    if (!(u.field_set & (1 << UF_PORT))) {
        port = 443;
    }
    else {
        port = u.port;
    }

    SOCKET sockfd = createSocket(host, port);
    if (sockfd == INVALID_SOCKET)
    {
        printf("Inalid socket.\n");
        return;
    }

    LPPER_IO_DATA ioData = UpdateIoCompletionPort(sockfd, CLIENT_ACCEPT);
    if (ioData == NULL)
    {
        printf("UpdateIoCompeltionPort failed.\n");
        return;
    }
    printf("UpdateIoCompeltionPort done.\n");

    ioData->hostname = host;

    ioData->rbio = BIO_new(BIO_s_mem());
    ioData->wbio = BIO_new(BIO_s_mem());
    if (!ioData->rbio || !ioData->wbio)
    {
        printf("BIO_new failed.");
        return;
    }
    else
    {
        // set the memory BIOs to non-blocking mode
        BIO_set_nbio(ioData->rbio, 1);
        BIO_set_nbio(ioData->wbio, 1);
    }

    ioData->sslCtx = SSL_CTX_new(TLS_client_method());
    /*SSL_CTX_set_options(ioData->sslCtx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
        SSL_OP_NO_COMPRESSION |
        SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

    SSL_CTX_set_alpn_protos(ioData->sslCtx, (const unsigned char*)"\x02h2", 3);*/
    ioData->ssl = SSL_new(ioData->sslCtx);
    SSL_set_connect_state(ioData->ssl); // to act as client
    SSL_set_bio(ioData->ssl, ioData->rbio, ioData->wbio);

    /*char request[48];
    sprintf(request, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host);*/

    int ret = 0, status;
    DWORD flags = 0;
    char buffer[BUFFER_SIZE] = { '\0' };
    int bio_read, bio_write;

    if (!SSL_is_init_finished(ioData->ssl))
    {
        ret = SSL_do_handshake(ioData->ssl);
        if (ret == 1)
        {
            printf("ssl handshake done\n");
        }
        status = SSL_get_error(ioData->ssl, ret);
        if (status == SSL_ERROR_WANT_READ || status == SSL_ERROR_WANT_WRITE)
        {
            bio_read = BIO_read(ioData->wbio, buffer, BUFFER_SIZE);
            if (bio_read > 0)
            {
                printf("bio_read: %d\n", bio_read);
                memcpy(ioData->wsaSendBuf.buf, buffer, sizeof(buffer));
                ioData->wsaSendBuf.len = bio_read;
                if (WSASend(ioData->sockfd, &ioData->wsaSendBuf, 1, &ioData->bytesSend, 0, &ioData->overlapped, NULL) == SOCKET_ERROR)
                {
                    int error = WSAGetLastError();
                    printf("WSASend() failed.");
                    if (error != WSA_IO_PENDING)
                    {
                        printf("Failed to send response: %d\n", error);
                        closesocket(ioData->sockfd);
                        delete ioData;
                    }
                }
                else
                {
                    printf("WSASend: %d\n", ioData->bytesSend);
                }
                memset(buffer, '\0', BUFFER_SIZE);
            }
            else
            {
                memset(ioData->recvBuffer, '\0', BUFFER_SIZE);
                if (WSARecv(ioData->sockfd, &ioData->wsaRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
                {
                    int error = WSAGetLastError();
                    printf("WSARecv() failed.");
                    if (error != WSA_IO_PENDING)
                    {
                        printf("Failed to recv response: %d\n", error);
                        closesocket(ioData->sockfd);
                        delete ioData;
                    }
                }
                else
                {
                    printf("WSARecv: %d\n", ioData->bytesRecv);
                }
                //recvbytes = recv(ioData->sockfd, buffer, BUFFER_SIZE, 0);
                //printf("recv: %d\n", recvbytes);
            }
        }
        else if (status == SSL_ERROR_SSL)
        {
            printf("ssl_error_ssl\n");
            return;
        }
        else
        {
            printf("ssl_get_error: %d\n", status);
            return;
        }
    }

    while (TRUE)
        Sleep(1000);

    return;
}

static DWORD WINAPI WorkerThread(LPVOID lparameter)
{
    HANDLE completionPort = (HANDLE)lparameter;
    LPPER_IO_DATA socketData = NULL;
    LPWSAOVERLAPPED overlapped = NULL;
    DWORD flags = 0;
    DWORD bytesTransferred = 0;

    while (TRUE)
    {
        BOOL result = GetQueuedCompletionStatus(completionPort,
                                                &bytesTransferred,
                                                (PDWORD_PTR)&socketData,
                                                (LPOVERLAPPED*)&overlapped,
                                                INFINITE);

        LPPER_IO_DATA ioData = (LPPER_IO_DATA)overlapped;
        if (!result)
        {
            printf("GetQueuedCompletionStatus failed: %d\n", GetLastError());
        }

        if (ioData == NULL)
        {
            printf("IO_DATA NULL\n");
            return 0;
        }

        if (!result || bytesTransferred == 0)
        {
            printf("Connection closed.\n");
            if (ioData)
            {
                closesocket(ioData->sockfd);
                ioData->sockfd = INVALID_SOCKET;
                delete ioData;
            }
            return 0;
        }

        int ret = 0, status, error;
        DWORD flags = 0;
        char buffer[BUFFER_SIZE] = { '\0' };
        int bio_read, bio_write, ssl_read, ssl_write, sendbytes, recvbytes;

        switch (ioData->ioOperation)
        {
        case CLIENT_ACCEPT: 
        {
            int val = 1;

            printf("CLIENT_ACCEPT\n");
            if (strlen(ioData->recvBuffer) > 0)
            {
                int bio_write = BIO_write(ioData->rbio, ioData->recvBuffer, bytesTransferred);
                if (bio_write > 0)
                {
                    printf("[+]BIO_write() server - %d bytes.\n", bio_write);
                }
                memset(ioData->recvBuffer, '\0', BUFFER_SIZE);
            }

            if (!SSL_is_init_finished(ioData->ssl))
            {
                ret = SSL_do_handshake(ioData->ssl);
                if (ret == 1)
                {
                    printf("SSL handshake done.\n");

                    const unsigned char* alpn = NULL;
                    unsigned int alpnlen = 0;

                    /*if (alpn == NULL) {
                        SSL_get0_alpn_selected(ioData->ssl, &alpn, &alpnlen);
                    }

                    if (alpn == NULL || alpnlen != 2 || memcmp("h2", alpn, 2) != 0) {
                        fprintf(stderr, "h2 is not negotiated\n");
                        break;
                    }*/

                    setsockopt(ioData->sockfd, IPPROTO_TCP, TCP_NODELAY, (char*)&val, sizeof(val));

                    ioData->ioOperation = RECV;
                    
                    char request[48];
                    char buffer[BUFFER_SIZE];
                    sprintf(request, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", ioData->hostname);

                    ssl_write = SSL_write(ioData->ssl, request, strlen(request));
                    if (ssl_write > 0) {
                        bio_read = BIO_read(ioData->wbio, buffer, BUFFER_SIZE);
                        if (bio_read > 0)
                        {
                            memcpy(ioData->wsaSendBuf.buf, buffer, bio_read);
                            ioData->wsaSendBuf.len = bio_read;
                            if (WSASend(ioData->sockfd, &ioData->wsaSendBuf, 1, &ioData->bytesSend, 0, &ioData->overlapped, NULL) == SOCKET_ERROR)
                            {
                                int error = WSAGetLastError();
                                printf("WSASend() failed: %d\n", error);
                                if (error != WSA_IO_PENDING)
                                {
                                    printf("Failed to send response: %d\n", error);
                                    closesocket(ioData->sockfd);
                                    delete ioData;
                                    break;
                                }
                            }
                            else
                            {
                                printf("WSASend: %d\n", ioData->bytesSend);
                            }
                            break;
                        }
                        else
                        {
                            printf("bio_read failed\n");
                        }
                    }
                    else
                    {
                        printf("ssl_write failed\n");
                    }
                    
                    break;
                }
                status = SSL_get_error(ioData->ssl, ret);
                printf("ssl_get_error: %d\n", status);
                if (status == SSL_ERROR_WANT_READ || status == SSL_ERROR_WANT_WRITE)
                {
                    bio_read = BIO_read(ioData->wbio, buffer, BUFFER_SIZE);
                    if (bio_read > 0)
                    {
                        printf("bio_read: %d\n", bio_read);
                        memcpy(ioData->wsaSendBuf.buf, buffer, sizeof(buffer));
                        ioData->wsaSendBuf.len = bio_read;
                        if (WSASend(ioData->sockfd, &ioData->wsaSendBuf, 1, &ioData->bytesSend, 0, &ioData->overlapped, NULL) == SOCKET_ERROR)
                        {
                            int error = WSAGetLastError();
                            printf("WSASend() failed: %d\n", error);
                            if (error != WSA_IO_PENDING)
                            {
                                printf("Failed to send response: %d\n", error);
                                closesocket(ioData->sockfd);
                                delete ioData;
                                break;
                            }
                        }
                        else
                        {
                            printf("WSASend: %d\n", ioData->bytesSend);
                        }
                        memset(buffer, '\0', BUFFER_SIZE);
                        break;
                    }
                    else
                    {
                        memset(ioData->recvBuffer, '\0', BUFFER_SIZE);
                        ioData->bytesRecv = 0;
                        ioData->wsaRecvBuf.len = BUFFER_SIZE;

                        if (WSARecv(ioData->sockfd, &ioData->wsaRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
                        {
                            int error = WSAGetLastError();
                            printf("WSARecv failed: %d\n", error);
                            if (error != WSA_IO_PENDING)
                            {
                                printf("WSARecv failed: %d\n", error);
                                closesocket(ioData->sockfd);
                                delete ioData;
                                break;
                            }
                        }
                        else
                        {
                            printf("WSARecv: %d\n", ioData->bytesRecv);
                        }
                        break;
                    }
                }
                else if (status == SSL_ERROR_SSL)
                {
                    printf("ssl_error_ssl\n");
                }
                else
                {
                    printf("ssl_get_error: %d\n", status);
                }
                break;
            }

            break;
        }

        case RECV:
        {
            if (strlen(ioData->recvBuffer) > 0)
            {
                printf("RECV\n");
                int bio_write = BIO_write(ioData->rbio, ioData->recvBuffer, bytesTransferred);
                if (bio_write > 0)
                {
                    printf("bio_write: %d\n", bio_write);
                    ioData->recvFlag = FALSE;
                    memset(ioData->recvBuffer, '\0', BUFFER_SIZE);
                    ssl_read = SSL_read(ioData->ssl, ioData->recvBuffer, BUFFER_SIZE);
                    if (ssl_read <= 0)
                    {
                        error = SSL_get_error(ioData->ssl, ssl_read);
                        if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
                        {
                            ioData->bytesRecv = 0;
                            ioData->recvFlag = TRUE;
                            memset(ioData->recvBuffer, '\0', BUFFER_SIZE);

                            if (WSARecv(ioData->sockfd, &ioData->wsaRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
                            {
                                int error = WSAGetLastError();
                                printf("WSARecv 2 pending\n");
                                if (error != WSA_IO_PENDING)
                                {
                                    printf("WSARecv() client IO - % d\n", error);
                                    closesocket(ioData->sockfd);
                                    SSL_free(ioData->ssl);
                                    SSL_CTX_free(ioData->sslCtx);
                                    delete ioData;
                                    break;
                                }
                            }
                            else
                            {
                                printf("WSARecv 2: %d\n", ioData->bytesRecv);
                            }
                            break;
                        }
                        else if (error == SSL_ERROR_SSL)
                        {
                            printf("SSL_get_error() CLIENT_IO - %s.", ERR_error_string(ERR_get_error(), NULL));
                            break;
                        }
                        else
                        {
                            printf("[+]SSL_get_error() - %d", error);
                            break;
                        }
                    }
                    else
                    {
                        printf("ssl_read: %d\n", ssl_read);
                        printf("%s\n", ioData->recvBuffer);
                        while ((ssl_read = SSL_read(ioData->ssl, ioData->recvBuffer, BUFFER_SIZE) > 0))
                        {
                            printf("ssl_read: %d\n", ssl_read);
                            printf("%s\n", ioData->recvBuffer);
                        }
                    }
                }
                else 
                {
                    printf("bio_write failed\n");
                }
                
            }
            if (!ioData->recvFlag)
            {
                ioData->recvFlag = TRUE;
                memset(ioData->recvBuffer, '\0', BUFFER_SIZE);

                if (WSARecv(ioData->sockfd, &ioData->wsaRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
                {
                    int error = WSAGetLastError();
                    printf("WSARecv 1 pending\n");
                    if (error != WSA_IO_PENDING)
                    {
                        printf("WSARecv()- %d\n", error);
                        closesocket(ioData->sockfd);
                        SSL_free(ioData->ssl);
                        SSL_CTX_free(ioData->sslCtx);
                        delete ioData;
                        break;
                    }
                }
                else
                {
                    printf("WSARecv 1: %d\n", ioData->bytesRecv);
                }
                break;
            }
            else
            {
                cout << "ELSE" << endl;
            }
            break;
        }

        default:
            break;
        }
    }
    
    return 0;
}

//static void initialize_nghttp2_session(http2_session_data* session_data) {
//    nghttp2_session_callbacks* callbacks;
//
//    nghttp2_session_callbacks_new(&callbacks);
//
//    nghttp2_session_callbacks_set_send_callback2(callbacks, send_callback);
//
//    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
//        on_frame_recv_callback);
//
//    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
//        callbacks, on_data_chunk_recv_callback);
//
//    nghttp2_session_callbacks_set_on_stream_close_callback(
//        callbacks, on_stream_close_callback);
//
//    nghttp2_session_callbacks_set_on_header_callback(callbacks,
//        on_header_callback);
//
//    nghttp2_session_callbacks_set_on_begin_headers_callback(
//        callbacks, on_begin_headers_callback);
//
//    nghttp2_session_client_new(&session_data->session, callbacks, session_data);
//
//    nghttp2_session_callbacks_del(callbacks);
//}

SOCKET createSocket(const char* hostname, int port)
{
    SOCKET sock;
    struct addrinfo hints, * res, * p;
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, port_str, &hints, &res) != 0)
    {
        cerr << "getaddrinfo" << endl;
        exit(EXIT_FAILURE);
    }

    for (p = res; p != NULL; p = p->ai_next)
    {
        sock = WSASocket(p->ai_family, p->ai_socktype, p->ai_protocol, NULL, 0, WSA_FLAG_OVERLAPPED);
        if (sock == INVALID_SOCKET)
        {
            cerr << "Invalid socket" << endl;
            continue;
        }

        if (WSAConnect(sock, p->ai_addr, p->ai_addrlen, NULL, NULL, NULL, NULL) == SOCKET_ERROR)
        {
            closesocket(sock);
            continue;
        }

        break;
    }

    if (p == NULL)
    {
        cerr << "Unable to connect to target server: " << hostname << endl;
        freeaddrinfo(res);
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(res);
    return sock;
}

LPPER_IO_DATA UpdateIoCompletionPort(SOCKET socket, IO_OPERATION ioOperation)
{
    LPPER_IO_DATA ioData = new PER_IO_DATA;

    memset(&ioData->overlapped, '\0', sizeof(WSAOVERLAPPED));
    ioData->sockfd = socket;
    ioData->bytesRecv = 0;
    ioData->bytesSend = 0;
    ioData->ioOperation = ioOperation;

    memset(ioData->recvBuffer, '\0', BUFFER_SIZE);
    memset(ioData->sendBuffer, '\0', BUFFER_SIZE);

    ioData->wsaRecvBuf.buf = ioData->recvBuffer;
    ioData->wsaRecvBuf.len = sizeof(ioData->recvBuffer);
    ioData->wsaSendBuf.buf = ioData->sendBuffer;
    ioData->wsaSendBuf.len = sizeof(ioData->sendBuffer);

    ioData->ssl = NULL;
    ioData->sslCtx = NULL;
    ioData->pkey = NULL;

    ioData->rbio = NULL;
    ioData->wbio = NULL;

    if (CreateIoCompletionPort((HANDLE)socket, CompletionPort, (ULONG_PTR)ioData, 0) == NULL)
    {
        delete ioData;
        return NULL;
    }

    return ioData;
}

void initializeWinsock()
{
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0)
    {
        printf("WSAStartup failed: %d\n", result);
        exit(EXIT_FAILURE);
    }
    else
    {
        printf("Winsock initialized.\n");
    }
}

void initializeOpenSSL()
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    printf("OpenSSL initialized.\n");
}

void openssl_cleanup()
{
    EVP_cleanup();
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();
    printf("OpenSSL cleaned up.\n");
}

