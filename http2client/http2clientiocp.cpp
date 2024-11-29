//#define _WINSOCK_DEPRECATED_NO_WARNINGS
//#define _CRT_SECURE_NO_WARNINGS
//
//#include <assert.h>
//#include <iostream>
//#include <iomanip>
//#include <sstream>
//#include <string>
//#include <memory>
//#include <openssl/applink.c>
//#include <openssl/err.h>
//#include <openssl/pem.h>
//#include <openssl/rand.h>
//#include <openssl/rsa.h>
//#include <openssl/ssl.h>
//#include <openssl/x509.h>
//#include <openssl/x509v3.h>
//#include <thread>
//#include <vector>
//#include <winsock2.h>
//#include <WS2tcpip.h>
//#include <Windows.h>
//
//#define NGHTTP2_NO_SSIZE_T
//#include <nghttp2/nghttp2.h>
//
//#include "http_parser.h"
//
//#pragma comment(lib, "ws2_32.lib")
//#pragma comment(lib, "libssl.lib")
//#pragma comment(lib, "libcrypto.lib")
//
//#pragma warning(disable : 4996)
//
//#define BUFFER_SIZE 4096
//
//using namespace std;
//
//#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))
//
//typedef struct {  
//    const char* uri;
//    struct http_parser_url* u;
//    char* authority;
//    char* path;
//    size_t authoritylen;
//    size_t pathlen;
//    int32_t stream_id;
//} http2_stream_data;
//
//typedef struct {
//    nghttp2_session* session;
//    struct evdns_base* dnsbase;
//    struct bufferevent* bev;
//    http2_stream_data* stream_data;
//} http2_session_data;
//
//typedef enum _IO_OPERATION
//{
//    CLIENT_ACCEPT,
//    SEND,
//    RECV,
//    IO,
//} IO_OPERATION, * PERIO_OPERATIONS;
//
//typedef struct _PER_IO_DATA
//{
//    WSAOVERLAPPED overlapped;
//    SOCKET sockfd;
//    WSABUF wsaSendBuf, wsaRecvBuf;
//    CHAR sendBuffer[BUFFER_SIZE], recvBuffer[BUFFER_SIZE];
//    DWORD bytesSend, bytesRecv;
//    IO_OPERATION ioOperation;
//    SSL* ssl;
//    SSL_CTX* sslCtx;
//    CHAR* hostname;
//    CHAR* uri;
//    EVP_PKEY* pkey;
//    BIO* rbio, * wbio;
//    http2_session_data* session_data;
//    BOOL bioFlag = FALSE;
//    BOOL recvFlag = FALSE;
//} PER_IO_DATA, * LPPER_IO_DATA;
//
//
//void init();
//void initializeWinsock();
//void initializeOpenSSL();
//void openssl_cleanup();
//SOCKET createSocket(const char *host, int port);
//LPPER_IO_DATA UpdateIoCompletionPort(SOCKET socket, IO_OPERATION ioOperation);
//static DWORD WINAPI WorkerThread(LPVOID lparameter);
//static http2_session_data* create_http2_session_data();
//static void delete_http2_session_data(http2_session_data* session_data);
//static http2_stream_data* create_http2_stream_data(const char* uri, struct http_parser_url* u);
//static void delete_http2_stream_data(http2_stream_data* stream_data);
//static void initialize_nghttp2_session(http2_session_data* session_data);
//static void submit_request(http2_session_data* session_data);
//
//HANDLE CompletionPort;
//const char* uri = "https://www.google.com";
//
//int main()
//{
//	init();
//	return 0;
//}
//
//void init()
//{
//    initializeWinsock();
//    initializeOpenSSL();
//    CompletionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
//    if (!CompletionPort)
//    {
//        printf("Cannot create ProxyCompletionPort.\n");
//        WSACleanup();
//        return;
//    }
//    printf("ProxyCompletionPort created.\n");
//
//    SYSTEM_INFO systemInfo;
//    GetSystemInfo(&systemInfo);
//    for (DWORD i = 0; i < systemInfo.dwNumberOfProcessors; i++)
//    {
//        HANDLE pThread = CreateThread(NULL, 0, WorkerThread, CompletionPort, 0, NULL);
//        if (pThread == NULL)
//        {
//            printf("Failed to create worker thread.");
//            WSACleanup();
//            return;
//        }
//        CloseHandle(pThread);
//    }
//
//    struct http_parser_url u;
//    char* host;
//    uint16_t port;
//    int rv;
//
//    /* Parse the |uri| and stores its components in |u| */
//    rv = http_parser_parse_url(uri, strlen(uri), 0, &u);
//    if (rv != 0) {
//        printf("Could not parse URI %s", uri);
//    }
//    host = _strdup(&uri[u.field_data[UF_HOST].off]);
//    if (!(u.field_set & (1 << UF_PORT))) {
//        port = 443;
//    }
//    else {
//        port = u.port;
//    }
//
//    SOCKET sockfd = createSocket(host, port);
//    if (sockfd == INVALID_SOCKET)
//    {
//        printf("Inalid socket.\n");
//        return;
//    }
//
//    LPPER_IO_DATA ioData = UpdateIoCompletionPort(sockfd, CLIENT_ACCEPT);
//    if (ioData == NULL)
//    {
//        printf("UpdateIoCompeltionPort failed.\n");
//        return;
//    }
//    printf("UpdateIoCompeltionPort done.\n");
//
//    ioData->hostname = host;
//
//    ioData->rbio = BIO_new(BIO_s_mem());
//    ioData->wbio = BIO_new(BIO_s_mem());
//    if (!ioData->rbio || !ioData->wbio)
//    {
//        printf("BIO_new failed.");
//        return;
//    }
//    else
//    {
//        // set the memory BIOs to non-blocking mode
//        BIO_set_nbio(ioData->rbio, 1);
//        BIO_set_nbio(ioData->wbio, 1);
//    }
//
//    ioData->sslCtx = SSL_CTX_new(TLS_client_method());
//    SSL_CTX_set_options(ioData->sslCtx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
//        SSL_OP_NO_COMPRESSION |
//        SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
//
//    SSL_CTX_set_alpn_protos(ioData->sslCtx, (const unsigned char*)"\x02h2", 3);
//    ioData->ssl = SSL_new(ioData->sslCtx);
//    SSL_set_connect_state(ioData->ssl); // to act as client
//    SSL_set_bio(ioData->ssl, ioData->rbio, ioData->wbio);
//
//    int ret = 0, status;
//    DWORD flags = 0;
//    char buffer[BUFFER_SIZE] = { '\0' };
//    int bio_read, bio_write;
//
//    if (!SSL_is_init_finished(ioData->ssl))
//    {
//        ret = SSL_do_handshake(ioData->ssl);
//        if (ret == 1)
//        {
//            printf("ssl handshake done\n");
//        }
//        status = SSL_get_error(ioData->ssl, ret);
//        if (status == SSL_ERROR_WANT_READ || status == SSL_ERROR_WANT_WRITE)
//        {
//            bio_read = BIO_read(ioData->wbio, buffer, BUFFER_SIZE);
//            if (bio_read > 0)
//            {
//                printf("bio_read: %d\n", bio_read);
//                memcpy(ioData->wsaSendBuf.buf, buffer, sizeof(buffer));
//                ioData->wsaSendBuf.len = bio_read;
//                if (WSASend(ioData->sockfd, &ioData->wsaSendBuf, 1, &ioData->bytesSend, 0, &ioData->overlapped, NULL) == SOCKET_ERROR)
//                {
//                    int error = WSAGetLastError();
//                    printf("WSASend() failed.");
//                    if (error != WSA_IO_PENDING)
//                    {
//                        printf("Failed to send response: %d\n", error);
//                        closesocket(ioData->sockfd);
//                        delete ioData;
//                    }
//                }
//                else
//                {
//                    printf("WSASend: %d\n", ioData->bytesSend);
//                }
//                memset(buffer, '\0', BUFFER_SIZE);
//            }
//            else
//            {
//                memset(ioData->recvBuffer, '\0', BUFFER_SIZE);
//                if (WSARecv(ioData->sockfd, &ioData->wsaRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
//                {
//                    int error = WSAGetLastError();
//                    printf("WSARecv() failed.");
//                    if (error != WSA_IO_PENDING)
//                    {
//                        printf("Failed to recv response: %d\n", error);
//                        closesocket(ioData->sockfd);
//                        delete ioData;
//                    }
//                }
//                else
//                {
//                    printf("WSARecv: %d\n", ioData->bytesRecv);
//                }
//            }
//        }
//        else if (status == SSL_ERROR_SSL)
//        {
//            printf("ssl_error_ssl\n");
//            return;
//        }
//        else
//        {
//            printf("ssl_get_error: %d\n", status);
//            return;
//        }
//    }
//
//    while (TRUE)
//        Sleep(1000);
//
//    return;
//}
//
//static DWORD WINAPI WorkerThread(LPVOID lparameter)
//{
//    HANDLE completionPort = (HANDLE)lparameter;
//    LPPER_IO_DATA socketData = NULL;
//    LPWSAOVERLAPPED overlapped = NULL;
//    DWORD flags = 0;
//    DWORD bytesTransferred = 0;
//
//    while (TRUE)
//    {
//        BOOL result = GetQueuedCompletionStatus(completionPort,
//                                                &bytesTransferred,
//                                                (PDWORD_PTR)&socketData,
//                                                (LPOVERLAPPED*)&overlapped,
//                                                INFINITE);
//
//        LPPER_IO_DATA ioData = (LPPER_IO_DATA)overlapped;
//        if (!result)
//        {
//            printf("GetQueuedCompletionStatus failed: %d\n", GetLastError());
//        }
//
//        if (ioData == NULL)
//        {
//            printf("IO_DATA NULL\n");
//            return 0;
//        }
//
//        if (!result || bytesTransferred == 0)
//        {
//            printf("Connection closed.\n");
//            if (ioData)
//            {
//                closesocket(ioData->sockfd);
//                ioData->sockfd = INVALID_SOCKET;
//                delete ioData;
//            }
//            return 0;
//        }
//
//        int ret = 0, status, error;
//        DWORD flags = 0;
//        char buffer[BUFFER_SIZE] = { '\0' };
//        int bio_read, bio_write, ssl_read, ssl_write, sendbytes, recvbytes;
//
//        switch (ioData->ioOperation)
//        {
//        case CLIENT_ACCEPT: 
//        {
//            int val = 1;
//
//            printf("CLIENT_ACCEPT\n");
//            if (strlen(ioData->recvBuffer) > 0)
//            {
//                int bio_write = BIO_write(ioData->rbio, ioData->recvBuffer, bytesTransferred);
//                if (bio_write > 0)
//                {
//                    printf("[+]BIO_write() server - %d bytes.\n", bio_write);
//                }
//                memset(ioData->recvBuffer, '\0', BUFFER_SIZE);
//            }
//
//            if (!SSL_is_init_finished(ioData->ssl))
//            {
//                ret = SSL_do_handshake(ioData->ssl);
//                if (ret == 1)
//                {
//                    printf("SSL handshake done.\n");
//
//                    /*const unsigned char* alpn = NULL;
//                    unsigned int alpnlen = 0;
//
//                    if (alpn == NULL) {
//                        SSL_get0_alpn_selected(ioData->ssl, &alpn, &alpnlen);
//                    }
//
//                    if (alpn == NULL || alpnlen != 2 || memcmp("h2", alpn, 2) != 0) {
//                        fprintf(stderr, "h2 is not negotiated\n");
//                        break;
//                    }
//
//                    setsockopt(ioData->sockfd, IPPROTO_TCP, TCP_NODELAY, (char*)&val, sizeof(val));*/
//
//                    ioData->ioOperation = RECV;
//
//                    struct http_parser_url u;
//
//                    http2_session_data *session_data = create_http2_session_data();
//                    session_data->stream_data = create_http2_stream_data(uri, &u);
//
//                    //initialize_nghttp2_session(session_data);
//
//                    //// send client connection header
//                    //nghttp2_settings_entry iv[1] = { {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100} };
//                    //int rv;
//
//                    //// client 24 bytes magic string will be sent by nghttp2 library
//                    //rv = nghttp2_submit_settings(session_data->session, NGHTTP2_FLAG_NONE, iv, ARRLEN(iv));
//                    //if (rv != 0) {
//                    //    printf("Could not submit SETTINGS: %s", nghttp2_strerror(rv));
//                    //    break;
//                    //}
//                    //else
//                    //{
//                    //    printf("Sunbmitted settings\n");
//                    //}
//
//                    //// send request
//                    //submit_request(session_data);
//                    
//                    char request[48];
//                    char buffer[BUFFER_SIZE];
//                    sprintf(request, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", ioData->hostname);
//
//                    ssl_write = SSL_write(ioData->ssl, request, strlen(request));
//                    if (ssl_write > 0) {
//                        bio_read = BIO_read(ioData->wbio, buffer, BUFFER_SIZE);
//                        if (bio_read > 0)
//                        {
//                            memcpy(ioData->wsaSendBuf.buf, buffer, bio_read);
//                            ioData->wsaSendBuf.len = bio_read;
//                            if (WSASend(ioData->sockfd, &ioData->wsaSendBuf, 1, &ioData->bytesSend, 0, &ioData->overlapped, NULL) == SOCKET_ERROR)
//                            {
//                                int error = WSAGetLastError();
//                                printf("WSASend() failed: %d\n", error);
//                                if (error != WSA_IO_PENDING)
//                                {
//                                    printf("Failed to send response: %d\n", error);
//                                    closesocket(ioData->sockfd);
//                                    delete ioData;
//                                    break;
//                                }
//                            }
//                            else
//                            {
//                                printf("WSASend: %d\n", ioData->bytesSend);
//                            }
//                            break;
//                        }
//                        else
//                        {
//                            printf("bio_read failed\n");
//                        }
//                    }
//                    else
//                    {
//                        printf("ssl_write failed\n");
//                    }
//                    
//                    break;
//                }
//
//                status = SSL_get_error(ioData->ssl, ret);
//                printf("ssl_get_error: %d\n", status);
//                if (status == SSL_ERROR_WANT_READ || status == SSL_ERROR_WANT_WRITE)
//                {
//                    bio_read = BIO_read(ioData->wbio, buffer, BUFFER_SIZE);
//                    if (bio_read > 0)
//                    {
//                        printf("bio_read: %d\n", bio_read);
//                        memcpy(ioData->wsaSendBuf.buf, buffer, sizeof(buffer));
//                        ioData->wsaSendBuf.len = bio_read;
//                        if (WSASend(ioData->sockfd, &ioData->wsaSendBuf, 1, &ioData->bytesSend, 0, &ioData->overlapped, NULL) == SOCKET_ERROR)
//                        {
//                            int error = WSAGetLastError();
//                            printf("WSASend() failed: %d\n", error);
//                            if (error != WSA_IO_PENDING)
//                            {
//                                printf("Failed to send response: %d\n", error);
//                                closesocket(ioData->sockfd);
//                                delete ioData;
//                                break;
//                            }
//                        }
//                        else
//                        {
//                            printf("WSASend: %d\n", ioData->bytesSend);
//                        }
//                        memset(buffer, '\0', BUFFER_SIZE);
//                        break;
//                    }
//                    else
//                    {
//                        memset(ioData->recvBuffer, '\0', BUFFER_SIZE);
//                        ioData->bytesRecv = 0;
//                        ioData->wsaRecvBuf.len = BUFFER_SIZE;
//
//                        if (WSARecv(ioData->sockfd, &ioData->wsaRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
//                        {
//                            int error = WSAGetLastError();
//                            printf("WSARecv failed: %d\n", error);
//                            if (error != WSA_IO_PENDING)
//                            {
//                                printf("WSARecv failed: %d\n", error);
//                                closesocket(ioData->sockfd);
//                                delete ioData;
//                                break;
//                            }
//                        }
//                        else
//                        {
//                            printf("WSARecv: %d\n", ioData->bytesRecv);
//                        }
//                        break;
//                    }
//                }
//                else if (status == SSL_ERROR_SSL)
//                {
//                    printf("ssl_error_ssl\n");
//                }
//                else
//                {
//                    printf("ssl_get_error: %d\n", status);
//                }
//                break;
//            }
//
//            break;
//        }
//
//        case RECV:
//        {
//            if (strlen(ioData->recvBuffer) > 0)
//            {
//                int bio_write = BIO_write(ioData->rbio, ioData->recvBuffer, bytesTransferred);
//                if (bio_write > 0)
//                {
//                    printf("bio_write: %d\n", bio_write);
//                    ioData->recvFlag = FALSE;
//                    memset(ioData->recvBuffer, '\0', BUFFER_SIZE);
//                    ssl_read = SSL_read(ioData->ssl, ioData->recvBuffer, BUFFER_SIZE);
//                    if (ssl_read <= 0)
//                    {
//                        error = SSL_get_error(ioData->ssl, ssl_read);
//                        if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
//                        {
//                            ioData->bytesRecv = 0;
//                            ioData->recvFlag = TRUE;
//                            memset(ioData->recvBuffer, '\0', BUFFER_SIZE);
//
//                            if (WSARecv(ioData->sockfd, &ioData->wsaRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
//                            {
//                                int error = WSAGetLastError();
//                                printf("WSARecv 2 pending\n");
//                                if (error != WSA_IO_PENDING)
//                                {
//                                    printf("WSARecv() client IO - % d\n", error);
//                                    closesocket(ioData->sockfd);
//                                    SSL_free(ioData->ssl);
//                                    SSL_CTX_free(ioData->sslCtx);
//                                    delete ioData;
//                                    break;
//                                }
//                            }
//                            else
//                            {
//                                printf("WSARecv 2: %d\n", ioData->bytesRecv);
//                            }
//                            break;
//                        }
//                        else if (error == SSL_ERROR_SSL)
//                        {
//                            printf("SSL_get_error() CLIENT_IO - %s.", ERR_error_string(ERR_get_error(), NULL));
//                            break;
//                        }
//                        else
//                        {
//                            printf("[+]SSL_get_error() - %d", error);
//                            break;
//                        }
//                    }
//                    else
//                    {
//                        printf("ssl_read: %d\n", ssl_read);
//                        printf("%s\n", ioData->recvBuffer);
//                        while ((ssl_read = SSL_read(ioData->ssl, ioData->recvBuffer, BUFFER_SIZE) > 0))
//                        {
//                            printf("ssl_read: %d\n", ssl_read);
//                            printf("%s\n", ioData->recvBuffer);
//                        }
//                    }
//                }
//                else 
//                {
//                    printf("bio_write failed\n");
//                }
//                
//            }
//            if (!ioData->recvFlag)
//            {
//                ioData->recvFlag = TRUE;
//                memset(ioData->recvBuffer, '\0', BUFFER_SIZE);
//
//                if (WSARecv(ioData->sockfd, &ioData->wsaRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
//                {
//                    int error = WSAGetLastError();
//                    printf("WSARecv 1 pending\n");
//                    if (error != WSA_IO_PENDING)
//                    {
//                        printf("WSARecv()- %d\n", error);
//                        closesocket(ioData->sockfd);
//                        SSL_free(ioData->ssl);
//                        SSL_CTX_free(ioData->sslCtx);
//                        delete ioData;
//                        break;
//                    }
//                }
//                else
//                {
//                    printf("WSARecv 1: %d\n", ioData->bytesRecv);
//                }
//                break;
//            }
//            else
//            {
//                cout << "ELSE" << endl;
//            }
//            break;
//        }
//
//        default:
//            break;
//        }
//    }
//    
//    return 0;
//}
//
//static http2_stream_data* create_http2_stream_data(const char* uri,
//    struct http_parser_url* u) {
//    /* MAX 5 digits (max 65535) + 1 ':' + 1 NULL (because of snprintf) */
//    size_t extra = 7;
//    http2_stream_data* stream_data = (http2_stream_data *) malloc(sizeof(http2_stream_data));
//    if (stream_data)
//    {
//        stream_data->uri = uri;
//        stream_data->u = u;
//        stream_data->stream_id = -1;
//
//        stream_data->authoritylen = u->field_data[UF_HOST].len;
//        stream_data->authority = (char*)malloc(stream_data->authoritylen + extra);
//        memcpy(stream_data->authority, &uri[u->field_data[UF_HOST].off],
//            u->field_data[UF_HOST].len);
//        if (u->field_set & (1 << UF_PORT)) {
//            stream_data->authoritylen +=
//                (size_t)snprintf(stream_data->authority + u->field_data[UF_HOST].len,
//                    extra, ":%u", u->port);
//        }
//
//        /* If we don't have path in URI, we use "/" as path. */
//        stream_data->pathlen = 1;
//        if (u->field_set & (1 << UF_PATH)) {
//            stream_data->pathlen = u->field_data[UF_PATH].len;
//        }
//        if (u->field_set & (1 << UF_QUERY)) {
//            /* +1 for '?' character */
//            stream_data->pathlen += (size_t)(u->field_data[UF_QUERY].len + 1);
//        }
//
//        stream_data->path = (char*)malloc(stream_data->pathlen);
//        if (u->field_set & (1 << UF_PATH)) {
//            memcpy(stream_data->path, &uri[u->field_data[UF_PATH].off],
//                u->field_data[UF_PATH].len);
//        }
//        else {
//            stream_data->path[0] = '/';
//        }
//        if (u->field_set & (1 << UF_QUERY)) {
//            stream_data->path[stream_data->pathlen - u->field_data[UF_QUERY].len - 1] =
//                '?';
//            memcpy(stream_data->path + stream_data->pathlen -
//                u->field_data[UF_QUERY].len,
//                &uri[u->field_data[UF_QUERY].off], u->field_data[UF_QUERY].len);
//        }
//    }
//    return stream_data;
//}
//
//static void delete_http2_stream_data(http2_stream_data* stream_data) {
//    free(stream_data->path);
//    free(stream_data->authority);
//    free(stream_data);
//}
//
///* Initializes |session_data| */
//static http2_session_data*
//create_http2_session_data() {
//    http2_session_data* session_data = (http2_session_data *) malloc(sizeof(http2_session_data));
//    if (session_data)
//    {
//        memset(session_data, 0, sizeof(http2_session_data));
//    }
//    return session_data;
//}
//
//static void delete_http2_session_data(http2_session_data* session_data) {
//
//    /*if (ssl) {
//        SSL_shutdown(ssl);
//    }*/
//    nghttp2_session_del(session_data->session);
//    session_data->session = NULL;
//    if (session_data->stream_data) {
//        delete_http2_stream_data(session_data->stream_data);
//        session_data->stream_data = NULL;
//    }
//    free(session_data);
//}
//
//static void print_header(FILE* f, const uint8_t* name, size_t namelen,
//    const uint8_t* value, size_t valuelen) {
//    fwrite(name, 1, namelen, f);
//    fprintf(f, ": ");
//    fwrite(value, 1, valuelen, f);
//    fprintf(f, "\n");
//}
//
///* Print HTTP headers to |f|. Please note that this function does not
//   take into account that header name and value are sequence of
//   octets, therefore they may contain non-printable characters. */
//static void print_headers(FILE* f, nghttp2_nv* nva, size_t nvlen) {
//    size_t i;
//    for (i = 0; i < nvlen; ++i) {
//        print_header(f, nva[i].name, nva[i].namelen, nva[i].value, nva[i].valuelen);
//    }
//    fprintf(f, "\n");
//}
//
///* nghttp2_send_callback2. Here we transmit the |data|, |length|
//   bytes, to the network. Because we are using libevent bufferevent,
//   we just write those bytes into bufferevent buffer. */
//static nghttp2_ssize send_callback(nghttp2_session* session,
//    const uint8_t* data, size_t length,
//    int flags, void* user_data) {
//    http2_session_data* session_data = (http2_session_data*)user_data;
//    struct bufferevent* bev = session_data->bev;
//    (void)session;
//    (void)flags;
//
//    //bufferevent_write(bev, data, length);
//    return (nghttp2_ssize)length;
//}
//
///* nghttp2_on_header_callback: Called when nghttp2 library emits
//   single header name/value pair. */
//static int on_header_callback(nghttp2_session* session,
//    const nghttp2_frame* frame, const uint8_t* name,
//    size_t namelen, const uint8_t* value,
//    size_t valuelen, uint8_t flags, void* user_data) {
//    http2_session_data* session_data = (http2_session_data*)user_data;
//    (void)session;
//    (void)flags;
//
//    switch (frame->hd.type) {
//    case NGHTTP2_HEADERS:
//        if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
//            session_data->stream_data->stream_id == frame->hd.stream_id) {
//            /* Print response headers for the initiated request. */
//            print_header(stderr, name, namelen, value, valuelen);
//            break;
//        }
//    }
//    return 0;
//}
//
///* nghttp2_on_begin_headers_callback: Called when nghttp2 library gets
//   started to receive header block. */
//static int on_begin_headers_callback(nghttp2_session* session,
//    const nghttp2_frame* frame,
//    void* user_data) {
//    http2_session_data* session_data = (http2_session_data*)user_data;
//    (void)session;
//
//    switch (frame->hd.type) {
//    case NGHTTP2_HEADERS:
//        if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
//            session_data->stream_data->stream_id == frame->hd.stream_id) {
//            fprintf(stderr, "Response headers for stream ID=%d:\n",
//                frame->hd.stream_id);
//        }
//        break;
//    }
//    return 0;
//}
//
///* nghttp2_on_frame_recv_callback: Called when nghttp2 library
//   received a complete frame from the remote peer. */
//static int on_frame_recv_callback(nghttp2_session* session,
//    const nghttp2_frame* frame, void* user_data) {
//    http2_session_data* session_data = (http2_session_data*)user_data;
//    (void)session;
//
//    switch (frame->hd.type) {
//    case NGHTTP2_HEADERS:
//        if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
//            session_data->stream_data->stream_id == frame->hd.stream_id) {
//            fprintf(stderr, "All headers received\n");
//        }
//        break;
//    }
//    return 0;
//}
//
///* nghttp2_on_data_chunk_recv_callback: Called when DATA frame is
//   received from the remote peer. In this implementation, if the frame
//   is meant to the stream we initiated, print the received data in
//   stdout, so that the user can redirect its output to the file
//   easily. */
//static int on_data_chunk_recv_callback(nghttp2_session* session, uint8_t flags,
//    int32_t stream_id, const uint8_t* data,
//    size_t len, void* user_data) {
//    http2_session_data* session_data = (http2_session_data*)user_data;
//    (void)session;
//    (void)flags;
//
//    if (session_data->stream_data->stream_id == stream_id) {
//        fwrite(data, 1, len, stdout);
//    }
//    return 0;
//}
//
///* nghttp2_on_stream_close_callback: Called when a stream is about to
//   closed. This example program only deals with 1 HTTP request (1
//   stream), if it is closed, we send GOAWAY and tear down the
//   session */
//static int on_stream_close_callback(nghttp2_session* session, int32_t stream_id,
//    uint32_t error_code, void* user_data) {
//    http2_session_data* session_data = (http2_session_data*)user_data;
//    int rv;
//
//    if (session_data->stream_data->stream_id == stream_id) {
//        fprintf(stderr, "Stream %d closed with error_code=%u\n", stream_id,
//            error_code);
//        rv = nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);
//        if (rv != 0) {
//            return NGHTTP2_ERR_CALLBACK_FAILURE;
//        }
//    }
//    return 0;
//}
//
//#define MAKE_NV(NAME, VALUE, VALUELEN)                                         \
//  {                                                                            \
//    (uint8_t *)NAME, (uint8_t *)VALUE,     sizeof(NAME) - 1,                   \
//    VALUELEN,        NGHTTP2_NV_FLAG_NONE,                                     \
//  }
//
//#define MAKE_NV2(NAME, VALUE)                                                  \
//  {                                                                            \
//    (uint8_t *)NAME,   (uint8_t *)VALUE,     sizeof(NAME) - 1,                 \
//    sizeof(VALUE) - 1, NGHTTP2_NV_FLAG_NONE,                                   \
//  }
//
//static void submit_request(http2_session_data* session_data)
//{
//    int32_t stream_id;
//    http2_stream_data* stream_data = session_data->stream_data;
//    const char* uri = stream_data->uri;
//    const struct http_parser_url* u = stream_data->u;
//    nghttp2_nv hdrs[] = {
//      MAKE_NV2(":method", "GET"),
//      MAKE_NV(":scheme", &uri[u->field_data[UF_SCHEMA].off],
//              u->field_data[UF_SCHEMA].len),
//      MAKE_NV(":authority", stream_data->authority, stream_data->authoritylen),
//      MAKE_NV(":path", stream_data->path, stream_data->pathlen) };
//    fprintf(stderr, "Request headers:\n");
//    print_headers(stderr, hdrs, ARRLEN(hdrs));
//    stream_id = nghttp2_submit_request2(session_data->session, NULL, hdrs,
//        ARRLEN(hdrs), NULL, stream_data);
//    if (stream_id < 0) {
//        printf("Could not submit HTTP request: %s", nghttp2_strerror(stream_id));
//    }
//    else
//    {
//        printf("HTTP request submitted\n");
//    }
//
//    stream_data->stream_id = stream_id;
//}
//
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
//
//SOCKET createSocket(const char* hostname, int port)
//{
//    SOCKET sock;
//    struct addrinfo hints, * res, * p;
//    char port_str[6];
//    snprintf(port_str, sizeof(port_str), "%d", port);
//
//    memset(&hints, 0, sizeof(hints));
//    hints.ai_family = AF_UNSPEC;
//    hints.ai_socktype = SOCK_STREAM;
//
//    if (getaddrinfo(hostname, port_str, &hints, &res) != 0)
//    {
//        cerr << "getaddrinfo" << endl;
//        exit(EXIT_FAILURE);
//    }
//
//    for (p = res; p != NULL; p = p->ai_next)
//    {
//        sock = WSASocket(p->ai_family, p->ai_socktype, p->ai_protocol, NULL, 0, WSA_FLAG_OVERLAPPED);
//        if (sock == INVALID_SOCKET)
//        {
//            cerr << "Invalid socket" << endl;
//            continue;
//        }
//
//        if (WSAConnect(sock, p->ai_addr, p->ai_addrlen, NULL, NULL, NULL, NULL) == SOCKET_ERROR)
//        {
//            closesocket(sock);
//            continue;
//        }
//
//        break;
//    }
//
//    if (p == NULL)
//    {
//        cerr << "Unable to connect to target server: " << hostname << endl;
//        freeaddrinfo(res);
//        exit(EXIT_FAILURE);
//    }
//
//    freeaddrinfo(res);
//    return sock;
//}
//
//LPPER_IO_DATA UpdateIoCompletionPort(SOCKET socket, IO_OPERATION ioOperation)
//{
//    LPPER_IO_DATA ioData = new PER_IO_DATA;
//
//    memset(&ioData->overlapped, '\0', sizeof(WSAOVERLAPPED));
//    ioData->sockfd = socket;
//    ioData->bytesRecv = 0;
//    ioData->bytesSend = 0;
//    ioData->ioOperation = ioOperation;
//
//    memset(ioData->recvBuffer, '\0', BUFFER_SIZE);
//    memset(ioData->sendBuffer, '\0', BUFFER_SIZE);
//
//    ioData->wsaRecvBuf.buf = ioData->recvBuffer;
//    ioData->wsaRecvBuf.len = sizeof(ioData->recvBuffer);
//    ioData->wsaSendBuf.buf = ioData->sendBuffer;
//    ioData->wsaSendBuf.len = sizeof(ioData->sendBuffer);
//
//    ioData->ssl = NULL;
//    ioData->sslCtx = NULL;
//    ioData->pkey = NULL;
//
//    ioData->rbio = NULL;
//    ioData->wbio = NULL;
//
//    if (CreateIoCompletionPort((HANDLE)socket, CompletionPort, (ULONG_PTR)ioData, 0) == NULL)
//    {
//        delete ioData;
//        return NULL;
//    }
//
//    return ioData;
//}
//
//void initializeWinsock()
//{
//    WSADATA wsaData;
//    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
//    if (result != 0)
//    {
//        printf("WSAStartup failed: %d\n", result);
//        exit(EXIT_FAILURE);
//    }
//    else
//    {
//        printf("Winsock initialized.\n");
//    }
//}
//
//void initializeOpenSSL()
//{
//    SSL_library_init();
//    SSL_load_error_strings();
//    OpenSSL_add_ssl_algorithms();
//    printf("OpenSSL initialized.\n");
//}
//
//void openssl_cleanup()
//{
//    EVP_cleanup();
//    ERR_free_strings();
//    CRYPTO_cleanup_all_ex_data();
//    printf("OpenSSL cleaned up.\n");
//}
//
