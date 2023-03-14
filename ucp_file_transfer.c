#ifndef HAVE_CONFIG_H
#  define HAVE_CONFIG_H /* Force using config.h, so test would fail if header
                           actually tries to use it */
#endif

#include <ucp/api/ucp.h>

#include <sys/socket.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <assert.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  /* getopt */
#include <pthread.h> /* pthread_self */
#include <errno.h>   /* errno */
#include <time.h>
#include <signal.h>  /* raise */

#define FILE_LEN 100
#define BUF_SIZE 100 * 1024 * 1024

#define CHKERR_ACTION(_cond, _msg, _action) \
    do { \
        if (_cond) { \
            fprintf(stderr, "Failed to %s\n", _msg); \
            _action; \
        } \
    } while (0)


#define CHKERR_JUMP(_cond, _msg, _label) \
    CHKERR_ACTION(_cond, _msg, goto _label)


#define CHKERR_JUMP_RETVAL(_cond, _msg, _label, _retval) \
    do { \
        if (_cond) { \
            fprintf(stderr, "Failed to %s, return value %d\n", _msg, _retval); \
            goto _label; \
        } \
    } while (0)

struct msg {
    uint64_t        data_len;
};

struct ucx_context {
    int             completed;
};

static struct err_handling {
    ucp_err_handling_mode_t ucp_err_mode;
} err_handling_opt;

static ucs_status_t ep_status   = UCS_OK;
static uint16_t server_port     = 13337;
static sa_family_t ai_family    = AF_INET;
static long test_string_length  = 16;
static const ucp_tag_t tag      = 0x1337a880u;
static const ucp_tag_t tag_mask = UINT64_MAX;
static const char *addr_msg_str = "UCX address message";
static const char *data_msg_str = "UCX data message";
static int print_config         = 0;
static char trans_file[FILE_LEN];

static double get_us(struct timeval t) {
    return (t.tv_sec * 1000000 + t.tv_usec);
}

static ucs_status_t parse_cmd(int argc, char * const argv[], char **server_name);

static void request_init(void *request)
{
    struct ucx_context *contex = (struct ucx_context *)request;

    contex->completed = 0;
}

static void send_handler(void *request, ucs_status_t status, void *ctx)
{
    struct ucx_context *context = (struct ucx_context *)request;
    const char *str             = (const char *)ctx;

    context->completed = 1;

    printf("[0x%x] send handler called for \"%s\" with status %d (%s)\n",
           (unsigned int)pthread_self(), str, status,
           ucs_status_string(status));
}

static void failure_handler(void *arg, ucp_ep_h ep, ucs_status_t status)
{
    ucs_status_t *arg_status = (ucs_status_t *)arg;

    printf("[0x%x] failure handler called with status %d (%s)\n",
           (unsigned int)pthread_self(), status, ucs_status_string(status));

    *arg_status = status;
}

static void recv_handler(void *request, ucs_status_t status,
                         const ucp_tag_recv_info_t *info, void *user_data)
{
    struct ucx_context *context = (struct ucx_context *)request;

    context->completed = 1;

    printf("[0x%x] receive handler called with status %d (%s), length %lu\n",
           (unsigned int)pthread_self(), status, ucs_status_string(status),
           info->length);
}

static void ep_close(ucp_worker_h ucp_worker, ucp_ep_h ep, uint64_t flags)
{
    ucp_request_param_t param;
    ucs_status_t status;
    void *close_req;

    param.op_attr_mask = UCP_OP_ATTR_FIELD_FLAGS;
    param.flags        = flags;
    close_req          = ucp_ep_close_nbx(ep, &param);
    if (UCS_PTR_IS_PTR(close_req)) {
        do {
            ucp_worker_progress(ucp_worker);
            status = ucp_request_check_status(close_req);
        } while (status == UCS_INPROGRESS);
        ucp_request_free(close_req);
    } else {
        status = UCS_PTR_STATUS(close_req);
    }

    if (status != UCS_OK) {
        fprintf(stderr, "failed to close ep %p: %s\n", (void*)ep,
                ucs_status_string(status));
    }
}

int connect_common(const char *server, uint16_t server_port, sa_family_t af)
{
    int sockfd   = -1;
    int listenfd = -1;
    int optval   = 1;
    char service[8];
    struct addrinfo hints, *res, *t;
    int ret;

    snprintf(service, sizeof(service), "%u", server_port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags    = (server == NULL) ? AI_PASSIVE : 0;
    hints.ai_family   = af;
    hints.ai_socktype = SOCK_STREAM;

    ret = getaddrinfo(server, service, &hints, &res);
    CHKERR_JUMP(ret < 0, "getaddrinfo() failed", out);

    for (t = res; t != NULL; t = t->ai_next) {
        sockfd = socket(t->ai_family, t->ai_socktype, t->ai_protocol);
        if (sockfd < 0) {
            continue;
        }

        if (server != NULL) {
            if (connect(sockfd, t->ai_addr, t->ai_addrlen) == 0) {
                break;
            }
        } else {
            ret = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval,
                             sizeof(optval));
            CHKERR_JUMP(ret < 0, "server setsockopt()", err_close_sockfd);

            if (bind(sockfd, t->ai_addr, t->ai_addrlen) == 0) {
                ret = listen(sockfd, 0);
                CHKERR_JUMP(ret < 0, "listen server", err_close_sockfd);

                /* Accept next connection */
                fprintf(stdout, "Waiting for connection...\n");
                listenfd = sockfd;
                sockfd   = accept(listenfd, NULL, NULL);
                close(listenfd);
                break;
            }
        }

        close(sockfd);
        sockfd = -1;
    }

    CHKERR_ACTION(sockfd < 0,
                  (server) ? "open client socket" : "open server socket",
                  (void)sockfd /* no action */);

out_free_res:
    freeaddrinfo(res);
out:
    return sockfd;
err_close_sockfd:
    close(sockfd);
    sockfd = -1;
    goto out_free_res;
}

static ucs_status_t ucx_wait(ucp_worker_h ucp_worker, struct ucx_context *request,
                             const char *op_str, const char *data_str)
{
    ucs_status_t status;

    if (UCS_PTR_IS_ERR(request)) {
        status = UCS_PTR_STATUS(request);
    } else if (UCS_PTR_IS_PTR(request)) {
        while (!request->completed) {
            ucp_worker_progress(ucp_worker);
        }

        request->completed = 0;
        status             = ucp_request_check_status(request);
        ucp_request_free(request);
    } else {
        status = UCS_OK;
    }

    if (status != UCS_OK) {
        fprintf(stderr, "unable to %s %s (%s)\n", op_str, data_str,
                ucs_status_string(status));
    } else {
        printf("finish to %s %s\n", op_str, data_str);
    }

    return status;
}

static void ep_close_err_mode(ucp_worker_h ucp_worker, ucp_ep_h ucp_ep)
{
    uint64_t ep_close_flags;

    if (err_handling_opt.ucp_err_mode == UCP_ERR_HANDLING_MODE_PEER) {
        ep_close_flags = UCP_EP_CLOSE_FLAG_FORCE;
    } else {
        ep_close_flags = 0;
    }

    ep_close(ucp_worker, ucp_ep, ep_close_flags);
}

static void get_file_name(char *recv_buf, char *local_name) {
    char filename[100];
    int i = 0, k = 0;

    for (i = strlen(recv_buf); i > 0; i--) {
        if (recv_buf[i] != '/') {
            k++;
        }
        else {
            break;
        }
    }

    strncat(filename, recv_buf + (strlen(recv_buf) - k) + 1, k);
    strncat(local_name, filename, strlen(filename));
    return;
}

static int run_ucx_client(ucp_worker_h ucp_worker,
                          ucp_address_t *local_addr, size_t local_addr_len,
                          ucp_address_t *peer_addr, size_t peer_addr_len)
{
    struct msg *msg = NULL;
    size_t msg_len  = 0;
    int ret         = -1;
    ucp_request_param_t send_param;
    ucp_tag_recv_info_t info_tag;
    ucp_tag_message_h msg_tag;
    ucs_status_t status;
    ucp_ep_h server_ep;
    ucp_ep_params_t ep_params;
    struct ucx_context *request;
    FILE* fPtr = NULL;    
    size_t count = 0;
    size_t num = 0;

    /* Send client UCX address to server */
    ep_params.field_mask      = UCP_EP_PARAM_FIELD_REMOTE_ADDRESS |
                                UCP_EP_PARAM_FIELD_ERR_HANDLING_MODE |
                                UCP_EP_PARAM_FIELD_ERR_HANDLER |
                                UCP_EP_PARAM_FIELD_USER_DATA;
    ep_params.address         = peer_addr;
    ep_params.err_mode        = err_handling_opt.ucp_err_mode;
    ep_params.err_handler.cb  = failure_handler;
    ep_params.err_handler.arg = NULL;
    ep_params.user_data       = &ep_status;

    status = ucp_ep_create(ucp_worker, &ep_params, &server_ep);
    CHKERR_JUMP(status != UCS_OK, "ucp_ep_create\n", err);

    // send file path and name
    msg_len = sizeof(*msg) + FILE_LEN;
    msg     = malloc(msg_len);
    CHKERR_JUMP(msg == NULL, "allocate memory\n", err_ep);
    memset(msg, 0, msg_len);

    msg->data_len = FILE_LEN;
    memcpy(msg + 1, trans_file, FILE_LEN);

    send_param.op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
                              UCP_OP_ATTR_FIELD_USER_DATA;
    send_param.cb.send      = send_handler;
    send_param.user_data    = (void*)addr_msg_str;
    request                 = ucp_tag_send_nbx(server_ep, msg, msg_len, tag,
                                               &send_param);
    status                  = ucx_wait(ucp_worker, request, "send",
                                       addr_msg_str);
    if (status != UCS_OK) {
        free(msg);
        goto err_ep;
    }

    free(msg);

    // open the file stream
    fPtr = fopen(trans_file, "r");
    if (fPtr == NULL) {
        printf("open the file failed ! error message :%s\n", strerror(errno));
        return 0;
    }

    msg_len = sizeof(*msg) + BUF_SIZE;
    msg     = malloc(msg_len);
    CHKERR_JUMP(msg == NULL, "allocate memory\n", err_ep);
    memset(msg, 0, msg_len);

    // send file content
    while ((num = fread(msg, sizeof(char), BUF_SIZE, fPtr)) > 0) {
        count += num;
        request = ucp_tag_send_nbx(server_ep, msg, num, tag,
                                   &send_param);
        status = ucx_wait(ucp_worker, request, "send", data_msg_str);
        if (status != UCS_OK) {
            goto err_ep;
        }
    }

    ret = 0;

err_ep:
    ep_close_err_mode(ucp_worker, server_ep);
err:
    free(msg);
    return ret;
}

static ucs_status_t flush_ep(ucp_worker_h worker, ucp_ep_h ep)
{
    ucp_request_param_t param;
    void *request;

    param.op_attr_mask = 0;
    request            = ucp_ep_flush_nbx(ep, &param);
    if (request == NULL) {
        return UCS_OK;
    } else if (UCS_PTR_IS_ERR(request)) {
        return UCS_PTR_STATUS(request);
    } else {
        ucs_status_t status;
        do {
            ucp_worker_progress(worker);
            status = ucp_request_check_status(request);
        } while (status == UCS_INPROGRESS);
        ucp_request_free(request);
        return status;
    }
}

static long recv_file_content(ucp_worker_h ucp_worker, ucp_request_param_t* recv_param,
                              FILE* fPtr)
{
    struct msg* msg = NULL;
    struct ucx_context* request = NULL;
    size_t msg_len = 0;
    ucp_tag_message_h msg_tag;
    ucp_tag_recv_info_t info_tag;
    ucs_status_t status;
    long ret = 0;

    do {
        /* Progressing before probe to update the state */
        ucp_worker_progress(ucp_worker);

        /* Probing incoming events in non-block mode */
        msg_tag = ucp_tag_probe_nb(ucp_worker, tag, tag_mask, 1, &info_tag);
    } while (msg_tag == NULL);

    msg_len = info_tag.length;
    msg = malloc(msg_len);
    CHKERR_ACTION(msg == NULL, "allocate memory\n", ret = 0; goto err);

    request = ucp_tag_msg_recv_nbx(ucp_worker, msg, msg_len,
                                    msg_tag, recv_param);

    status  = ucx_wait(ucp_worker, request, "receive", data_msg_str);
    if (status != UCS_OK) {
        free(msg);
        ret = 0;
    }

    fwrite(msg, sizeof(char), msg_len, fPtr);
    ret = msg_len;
    
err:
    free(msg);
    return ret;
}

static int run_ucx_server(ucp_worker_h ucp_worker)
{
    struct msg *msg             = NULL;
    struct ucx_context *request = NULL;
    size_t msg_len              = 0;
    ucp_request_param_t recv_param;
    ucp_tag_recv_info_t info_tag;
    ucp_tag_message_h msg_tag;
    ucs_status_t status;
    ucp_ep_h client_ep;
    ucp_ep_params_t ep_params;
    char *file_name;
    size_t file_name_len;
    char local_name[100] = "/tmp/";
    long recv_cnt = 0;
    FILE* fPtr = NULL;
    int ret;
    struct timeval start_time, stop_time;

    /* Receive client file name */
    do {
        /* Progressing before probe to update the state */
        ucp_worker_progress(ucp_worker);

        /* Probing incoming events in non-block mode */
        msg_tag = ucp_tag_probe_nb(ucp_worker, tag, tag_mask, 1, &info_tag);
    } while (msg_tag == NULL);

    msg = malloc(info_tag.length);
    CHKERR_ACTION(msg == NULL, "allocate memory\n", ret = -1; goto err);

    recv_param.op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
                              UCP_OP_ATTR_FIELD_DATATYPE |
                              UCP_OP_ATTR_FLAG_NO_IMM_CMPL;
    recv_param.datatype     = ucp_dt_make_contig(1);
    recv_param.cb.recv      = recv_handler;

    request = ucp_tag_msg_recv_nbx(ucp_worker, msg, info_tag.length,
                                    msg_tag, &recv_param);

    status  = ucx_wait(ucp_worker, request, "receive", addr_msg_str);
    if (status != UCS_OK) {
        free(msg);
        ret = -1;
        goto err;
    }

    // process file name
    file_name_len = msg->data_len;
    file_name     = malloc(file_name_len);
    if (file_name == NULL) {
        fprintf(stderr, "unable to allocate memory for peer address\n");
        free(msg);
        ret = -1;
        goto err;
    }

    memcpy(file_name, msg + 1, file_name_len);

    free(msg);

    printf("recv file name: %s\n", file_name);
    get_file_name(file_name, local_name);
    printf("local file name: %s\n", local_name);

        
    // open the file in append mode
    fPtr = fopen(local_name, "w+");
    if (fPtr == NULL) {
        printf("open the file failed ! error message :%s\n", strerror(errno));
        goto err;
    }

    gettimeofday(&start_time, NULL);
    // receive file content
    while (1) {
        recv_cnt = recv_file_content(ucp_worker, &recv_param, fPtr);
        if (recv_cnt < BUF_SIZE) {
            printf("recv file finish!\n");
            break;
        }
    }
    
    gettimeofday(&stop_time, NULL);
    printf("Time use %f ms\n", (get_us(stop_time) - get_us(start_time)) / 1000);

    fclose(fPtr);
    ret = 0;

err:
    return ret;
}

static void progress_worker(void *arg)
{
    ucp_worker_progress((ucp_worker_h)arg);
}

static void print_usage()
{
    fprintf(stderr, "Usage: ucp_file_transfer [parameters]\n");
    fprintf(stderr, "UCP file transfer client/server utility\n");
    fprintf(stderr, "\nParameters are:\n");
    fprintf(stderr, "  -s      Server ip, needed for client side\n");
    fprintf(stderr, "  -f      file path and name, needed for client side\n");
    fprintf(stderr, "  -c      Print UCP configuration\n");
    fprintf(stderr, "\n");
}

ucs_status_t parse_cmd(int argc, char * const argv[], char **server_name)
{
    int c = 0, idx = 0;

    err_handling_opt.ucp_err_mode = UCP_ERR_HANDLING_MODE_NONE;

    while ((c = getopt(argc, argv, "s:f:ch")) != -1) {
        switch (c) {
        case 'f':
            strcpy(trans_file, optarg);
            printf("client will send file %s\n", trans_file);
            break;
        case 's':
            *server_name = optarg;
            break;
        case 'c':
            print_config = 1;
            break;
        case 'h':
        default:
            print_usage();
            return UCS_ERR_UNSUPPORTED;
        }
    }
    fprintf(stderr, "INFO: UCP_FILE_TRANSFER server = %s port = %d, pid = %d\n", 
            *server_name, server_port, getpid());

    for (idx = optind; idx < argc; idx++) {
        fprintf(stderr, "WARNING: Non-option argument %s\n", argv[idx]);
    }
    return UCS_OK;
}

int main(int argc, char **argv)
{
    /* UCP temporary vars */
    ucp_params_t ucp_params;
    ucp_worker_attr_t worker_attr;
    ucp_worker_params_t worker_params;
    ucp_config_t *config;
    ucs_status_t status;

    /* UCP handler objects */
    ucp_context_h ucp_context;
    ucp_worker_h ucp_worker;

    /* OOB connection vars */
    uint64_t local_addr_len   = 0;
    ucp_address_t *local_addr = NULL;
    uint64_t peer_addr_len    = 0;
    ucp_address_t *peer_addr  = NULL;
    char *client_target_name  = NULL;
    int oob_sock              = -1;
    int ret                   = -1;

    memset(&ucp_params, 0, sizeof(ucp_params));
    memset(&worker_attr, 0, sizeof(worker_attr));
    memset(&worker_params, 0, sizeof(worker_params));

    /* Parse the command line */
    status = parse_cmd(argc, argv, &client_target_name);
    CHKERR_JUMP(status != UCS_OK, "parse_cmd\n", err);

    /* UCP initialization */
    status = ucp_config_read(NULL, NULL, &config);
    CHKERR_JUMP(status != UCS_OK, "ucp_config_read\n", err);

    ucp_params.field_mask   = UCP_PARAM_FIELD_FEATURES |
                              UCP_PARAM_FIELD_REQUEST_SIZE |
                              UCP_PARAM_FIELD_REQUEST_INIT |
                              UCP_PARAM_FIELD_NAME;
    ucp_params.features     = UCP_FEATURE_TAG;

    ucp_params.request_size    = sizeof(struct ucx_context);
    ucp_params.request_init    = request_init;
    ucp_params.name            = "hello_world";

    status = ucp_init(&ucp_params, config, &ucp_context);

    if (print_config) {
        ucp_config_print(config, stdout, NULL, UCS_CONFIG_PRINT_CONFIG);
    }

    ucp_config_release(config);
    CHKERR_JUMP(status != UCS_OK, "ucp_init\n", err);

    worker_params.field_mask  = UCP_WORKER_PARAM_FIELD_THREAD_MODE;
    worker_params.thread_mode = UCS_THREAD_MODE_SINGLE;

    status = ucp_worker_create(ucp_context, &worker_params, &ucp_worker);
    CHKERR_JUMP(status != UCS_OK, "ucp_worker_create\n", err_cleanup);

    worker_attr.field_mask = UCP_WORKER_ATTR_FIELD_ADDRESS;

    status = ucp_worker_query(ucp_worker, &worker_attr);
    CHKERR_JUMP(status != UCS_OK, "ucp_worker_query\n", err_worker);
    local_addr_len = worker_attr.address_length;
    local_addr     = worker_attr.address;

    printf("[0x%x] local address length: %lu\n",
           (unsigned int)pthread_self(), local_addr_len);

    /* OOB connection establishment */
    if (client_target_name != NULL) {
        oob_sock = connect_common(client_target_name, server_port, ai_family);
        CHKERR_JUMP(oob_sock < 0, "client_connect\n", err_addr);

        ret = recv(oob_sock, &peer_addr_len, sizeof(peer_addr_len), MSG_WAITALL);
        CHKERR_JUMP_RETVAL(ret != (int)sizeof(peer_addr_len),
                           "receive address length\n", err_addr, ret);

        peer_addr = malloc(peer_addr_len);
        CHKERR_JUMP(!peer_addr, "allocate memory\n", err_addr);

        ret = recv(oob_sock, peer_addr, peer_addr_len, MSG_WAITALL);
        CHKERR_JUMP_RETVAL(ret != (int)peer_addr_len,
                           "receive address\n", err_peer_addr, ret);
    } else {
        oob_sock = connect_common(NULL, server_port, ai_family);
        CHKERR_JUMP(oob_sock < 0, "server_connect\n", err_peer_addr);

        ret = send(oob_sock, &local_addr_len, sizeof(local_addr_len), 0);
        CHKERR_JUMP_RETVAL(ret != (int)sizeof(local_addr_len),
                           "send address length\n", err_peer_addr, ret);

        ret = send(oob_sock, local_addr, local_addr_len, 0);
        CHKERR_JUMP_RETVAL(ret != (int)local_addr_len, "send address\n",
                           err_peer_addr, ret);
    }

    if (client_target_name != NULL) {
        ret = run_ucx_client(ucp_worker,
                             local_addr, local_addr_len,
                             peer_addr, peer_addr_len);
    } else {
        ret = run_ucx_server(ucp_worker);
    }

    close(oob_sock);

err_peer_addr:
    free(peer_addr);

err_addr:
    ucp_worker_release_address(ucp_worker, local_addr);

err_worker:
    ucp_worker_destroy(ucp_worker);

err_cleanup:
    ucp_cleanup(ucp_context);

err:
    return ret;
}


