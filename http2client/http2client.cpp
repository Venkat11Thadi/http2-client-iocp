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
#include "Util.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#pragma warning(disable : 4996)

using namespace std;

void init();
LPPER_IO_DATA UpdateIoCompletionPort(SOCKET socket, IO_OPERATION ioOperation);
static DWORD WINAPI WorkerThread(LPVOID lparameter);
static void initialize_nghttp2_session(PER_IO_DATA* ioData);

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

    ioData->sslCtx = SSL_ctx_config();
    ioData->ssl = SSL_new(ioData->sslCtx);
    SSL_set_connect_state(ioData->ssl); // to act as client
    SSL_set_bio(ioData->ssl, ioData->rbio, ioData->wbio);

    ioData->uri = uri;
    ioData->session_data = create_http2_session_data();
    ioData->session_data->stream_data = create_http2_stream_data(uri, &u);

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
            }
        }
        else if (status == SSL_ERROR_SSL)
        {
            printf("SSL_ERROR_SSL\n");
            return;
        }
        else
        {
            printf("SSL_get_error: %d\n", status);
            return;
        }
    }

    while (TRUE)
        Sleep(1000);

    return;
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

    ioData->rbio = NULL;
    ioData->wbio = NULL;

    if (CreateIoCompletionPort((HANDLE)socket, CompletionPort, (ULONG_PTR)ioData, 0) == NULL)
    {
        delete ioData;
        return NULL;
    }

    return ioData;
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

            printf("case - client_accept\n");
            if (strlen(ioData->recvBuffer) > 0)
            {
                int bio_write = BIO_write(ioData->rbio, ioData->recvBuffer, bytesTransferred);
                if (bio_write > 0)
                {
                    printf("BIO_write: %d bytes.\n", bio_write);
                }
                memset(ioData->recvBuffer, '\0', BUFFER_SIZE);
            }

            if (!SSL_is_init_finished(ioData->ssl))
            {
                ret = SSL_do_handshake(ioData->ssl);
                if (ret == 1)
                {
                    printf("SSL handshake done.\n");

                    // check if alpn is negotiated after handshake
                    const unsigned char* alpn = NULL;
                    unsigned int alpnlen = 0;

                    if (alpn == NULL) {
                        SSL_get0_alpn_selected(ioData->ssl, &alpn, &alpnlen);
                    }

                    if (alpn == NULL || alpnlen != 2 || memcmp("h2", alpn, 2) != 0) {
                        fprintf(stderr, "h2 is not negotiated\n");
                        break;
                    }

                    setsockopt(ioData->sockfd, IPPROTO_TCP, TCP_NODELAY, (char*)&val, sizeof(val));

                    initialize_nghttp2_session(ioData);

                    // send client connection header
                    nghttp2_settings_entry iv[1] = { {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100} };
                    int rv;

                    // client 24 bytes magic string will be sent by nghttp2 library
                    rv = nghttp2_submit_settings(ioData->session_data->session, NGHTTP2_FLAG_NONE, iv, ARRLEN(iv));
                    if (rv != 0) {
                        printf("Could not submit SETTINGS: %s", nghttp2_strerror(rv));
                        break;
                    }
                    else
                    {
                        printf("Submitted settings\n");
                    }

                    // send request
                    submit_request(ioData->session_data); 

                    if (session_send(ioData->session_data) != 0) {
                        printf("session_send 1\n");
                        delete_http2_session_data(ioData->session_data);
                        break;
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
                            printf("WSASend IO pending\n");
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
                            printf("WSARecv IO pending\n");
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
                    printf("SSL_get_error() - %s\n", ERR_error_string(ERR_get_error(), NULL));
                    break;
                }
                else if (status == SSL_ERROR_SYSCALL)
                {
                    printf("SSL_get_error() - %s\n", ERR_error_string(ERR_get_error(), NULL));
                    break;
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
            printf("case - recv\n");
            int nghttp2_read;

            if (strlen(ioData->recvBuffer) > 0)
            {
                //printf("%s\n", ioData->recvBuffer);
                bio_write = BIO_write(ioData->rbio, ioData->recvBuffer, bytesTransferred);

                if (bio_write > 0)
                {
                    printf("bio_write: %d\n", bio_write);
                    memset(ioData->recvBuffer, '\0', BUFFER_SIZE);

                    ssl_read = SSL_read(ioData->ssl, ioData->recvBuffer, BUFFER_SIZE);

                    if (ssl_read <= 0)
                    {
                        error = SSL_get_error(ioData->ssl, ssl_read);
                        printf("SSL_read error - %d\n", error);

                        if ((error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) && !ioData->recvFlag)
                        {
                            ioData->bytesRecv = 0;
                            ioData->recvFlag = TRUE;
                            memset(ioData->recvBuffer, '\0', BUFFER_SIZE);

                            if (WSARecv(ioData->sockfd, &ioData->wsaRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
                            {
                                int error = WSAGetLastError();
                                printf("WSARecv IO pending\n");
                                if (error != WSA_IO_PENDING)
                                {
                                    printf("WSARecv client IO - %d\n", error);
                                    closesocket(ioData->sockfd);
                                    SSL_free(ioData->ssl);
                                    SSL_CTX_free(ioData->sslCtx);
                                    delete ioData; 
                                    break;
                                }
                            }
                            else
                            {
                                printf("WSARecv 2: %d bytes\n", ioData->bytesRecv);
                            }
                            break;
                        }
                        else if (error == SSL_ERROR_SSL)
                        {
                            printf("SSL_get_error() - %s\n", ERR_error_string(ERR_get_error(), NULL));
                            exit(0);
                        }
                        else if (error == SSL_ERROR_SYSCALL)
                        {
                            printf("SSL_get_error() - %s\n", ERR_error_string(ERR_get_error(), NULL));
                            SSL_shutdown(ioData->ssl);
                            exit(0);
                        }
                        else
                        {
                            printf("SSL_get_error() - %d\n", error);
                            break;
                        }
                    }
                    else
                    {
                        printf("ssl_read: %d\n", ssl_read);
                        nghttp2_read = nghttp2_session_mem_recv2(ioData->session_data->session, (uint8_t*)ioData->recvBuffer, ssl_read);
                        if (nghttp2_read < 0) {
                            printf("Fatal error: %s\n", nghttp2_strerror((int)nghttp2_read));
                            delete_http2_session_data(ioData->session_data);
                            break;
                        }
                        memset(ioData->recvBuffer, '\0', BUFFER_SIZE);
                        if (session_send(ioData->session_data) != 0) {
                            printf("session_send 2\n");
                            delete_http2_session_data(ioData->session_data);
                            break;
                        }
                        while ((ssl_read = SSL_read(ioData->ssl, ioData->recvBuffer, BUFFER_SIZE)) > 0)
                        {
                            printf("ssl_read: %d\n", ssl_read);
                            nghttp2_read = nghttp2_session_mem_recv2(ioData->session_data->session, (uint8_t*)ioData->recvBuffer, ssl_read);
                            if (nghttp2_read < 0) {
                                printf("Fatal error: %s\n", nghttp2_strerror((int)nghttp2_read));
                                delete_http2_session_data(ioData->session_data);
                                break;
                            }
                            memset(ioData->recvBuffer, '\0', BUFFER_SIZE);
                            if (session_send(ioData->session_data) != 0) {
                                printf("session_send 2\n");
                                delete_http2_session_data(ioData->session_data);
                                break;
                            }
                        }
                    }
                }

                ioData->recvFlag = FALSE;
            }

            if (!ioData->recvFlag)
            {
                ioData->recvFlag = TRUE;
                memset(ioData->recvBuffer, '\0', BUFFER_SIZE);

                if (WSARecv(ioData->sockfd, &ioData->wsaRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
                {
                    int error = WSAGetLastError();
                    printf("WSARecv IO pending\n");
                    if (error != WSA_IO_PENDING)
                    {
                        printf("WSARecv - %d\n", error);
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

            break;
        }

        default:
            break;
        }
    }

    return 0;
}

static void initialize_nghttp2_session(PER_IO_DATA* ioData) {
    nghttp2_session_callbacks* callbacks;

    nghttp2_session_callbacks_new(&callbacks);

    nghttp2_session_callbacks_set_send_callback2(callbacks, send_callback);

    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
        on_frame_recv_callback);

    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
        callbacks, on_data_chunk_recv_callback);

    nghttp2_session_callbacks_set_on_stream_close_callback(
        callbacks, on_stream_close_callback);

    nghttp2_session_callbacks_set_on_header_callback(callbacks,
        on_header_callback);

    nghttp2_session_callbacks_set_on_begin_headers_callback(
        callbacks, on_begin_headers_callback);

    nghttp2_session_client_new(&ioData->session_data->session, callbacks, ioData);

    nghttp2_session_callbacks_del(callbacks);
}