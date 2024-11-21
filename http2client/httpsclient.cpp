//#include <iostream>
//#include <winsock2.h>
//#include <ws2tcpip.h>
//#include <openssl/ssl.h>
//#include <openssl/err.h>
//
//using namespace std;
//
//#pragma comment(lib, "ws2_32.lib")
//#pragma comment(lib, "libssl.lib")
//#pragma comment(lib, "libcrypto.lib")
//
//#define HOSTNAME "www.google.com"
//#define PORT "443"
//#define BUFFER_SIZE 4096
//
//static void wsa_startup()
//{
//    WSADATA wsaData;
//    int wsaResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
//    if (wsaResult != 0) {
//        cerr << "WSAStartup failed: " << wsaResult << endl;
//        return;
//    }
//}
//
//static void initialize_openssl()
//{
//    SSL_load_error_strings(); // load error strings for corresponding error codes
//    OpenSSL_add_ssl_algorithms(); // load encryption and hash algorithms
//}
//
//static void cleanup_openssl()
//{
//    EVP_cleanup(); // free up memory taken by cryptographic algorithms.
//}
//
//static SSL_CTX* create_context()
//{
//    const SSL_METHOD* method;
//    SSL_CTX* ctx;
//
//    method = SSLv23_client_method(); // version flexible SSL_METHOD
//
//    ctx = SSL_CTX_new(method);
//    if (!ctx) {
//        perror("Unable to create SSL context");
//        ERR_print_errors_fp(stderr);
//        exit(EXIT_FAILURE);
//    }
//
//    return ctx;
//}
//
//int main() {
//    
//    wsa_startup();
//    initialize_openssl();
//    SSL_CTX* ctx = create_context();
//
//    struct addrinfo hints, * result, * ptr;
//    int res;
//    SOCKET server_sock;
//
//    // ZeroMemory(&hints, sizeof(hints));
//    memset(&hints, 0, sizeof(hints));
//    hints.ai_family = AF_UNSPEC;
//    hints.ai_socktype = SOCK_STREAM;
//    hints.ai_protocol = IPPROTO_TCP;
//
//    res = getaddrinfo(HOSTNAME, PORT, &hints, &result);
//    if (res != 0) {
//        cerr << "getaddrinfo failed: " << gai_strerror(res) << endl;
//        WSACleanup();
//        return EXIT_FAILURE;
//    }
//
//    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
//        server_sock = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
//        if (server_sock == INVALID_SOCKET) {
//            cerr << "Error at socket(): " << WSAGetLastError() << endl;
//            continue;
//        }
//
//        if (connect(server_sock, ptr->ai_addr, (int)ptr->ai_addrlen) == SOCKET_ERROR) {
//            closesocket(server_sock);
//            server_sock = INVALID_SOCKET;
//            continue;
//        }
//        break;
//    }
//
//    freeaddrinfo(result);
//
//    if (server_sock == INVALID_SOCKET) {
//        cerr << "Unable to connect to server!" << endl;
//        WSACleanup();
//        return EXIT_FAILURE;
//    }
//
//    BIO* rBio = BIO_new(BIO_s_mem());
//    BIO* wBio = BIO_new(BIO_s_mem());
//    char buffer[4096] = {'\0'};
//
//    SSL* ssl = SSL_new(ctx);
//    SSL_set_connect_state(ssl);
//    SSL_set_bio(ssl, rBio, wBio);
//    int ret = 0, status;
//    const char* request = "GET / HTTP/1.1\r\nHost: " HOSTNAME "\r\nConnection: close\r\n\r\n";
//
//    int bio_read, bio_write, ssl_read, ssl_write, sendbytes, recvbytes;
//
//    while (ret != 1)
//    {
//        ret = SSL_do_handshake(ssl);
//        if (ret == 1)
//        {
//            printf("ssl handshake done\n");
//            break;
//        }
//        status = SSL_get_error(ssl, ret);
//        if (status == SSL_ERROR_WANT_READ || status == SSL_ERROR_WANT_WRITE)
//        {
//            bio_read = BIO_read(wBio, buffer, BUFFER_SIZE);
//            if (bio_read > 0)
//            {
//                printf("bio_read: %d\n", bio_read);
//                sendbytes = send(server_sock, buffer, bio_read, 0);
//                memset(buffer, '\0', BUFFER_SIZE);
//                printf("send: %d\n", sendbytes);
//            }
//            else
//            {
//                recvbytes = recv(server_sock, buffer, BUFFER_SIZE, 0);
//                printf("recv: %d\n", recvbytes);
//                bio_write = BIO_write(rBio, buffer, recvbytes);
//                printf("bio_write: %d\n", bio_write);
//                memset(buffer, '\0', BUFFER_SIZE);
//            }
//        }
//        else if (status == SSL_ERROR_SSL)
//        {
//            printf("ssl_error_ssl\n");
//        }
//        else
//        {
//            printf("ssl_get_error: %d\n", status);
//        }
//    }
//
//    ssl_write = SSL_write(ssl, request, strlen(request));
//    if (ssl_write > 0)
//    {
//        printf("ssl_write: %d\n", ssl_write);
//        bio_read = BIO_read(wBio, buffer, BUFFER_SIZE);
//        if (bio_read > 0)
//        {
//            printf("bio_read: %d\n", bio_read);
//            sendbytes = send(server_sock, buffer, bio_read, 0);
//            memset(buffer, '\0', BUFFER_SIZE);
//            printf("send: %d\n", sendbytes);
//        }
//    }
//
//    while ((recvbytes = recv(server_sock, buffer, BUFFER_SIZE, 0)) > 0)
//    {
//        printf("recv: %d\n", recvbytes);
//        bio_write = BIO_write(rBio, buffer, recvbytes);
//        memset(buffer, '\0', BUFFER_SIZE);
//        if (bio_write > 0)
//        {
//            printf("bio_write: %d\n", bio_write);
//        }
//    }
//
//    while ((ssl_read = SSL_read(ssl, buffer, BUFFER_SIZE)) > 0)
//    {
//        printf("ssl_read: %d\n", ssl_read);
//        printf("%s\n", buffer);
//        memset(buffer, '\0', BUFFER_SIZE);
//    }
//
//    SSL_free(ssl);
//    closesocket(server_sock);
//    SSL_CTX_free(ctx);
//    cleanup_openssl();
//    WSACleanup();
//
//    return 0;
//}