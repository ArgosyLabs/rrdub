// SPDX-License-Identifier: MIT

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <inttypes.h>

#include <argp.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>

#include <assert.h>
#include <libgen.h>
#include <unistd.h>

#include <libubus.h>
#include <libubox/blobmsg.h>

#include <rrd.h>
#include <rrd_client.h>

#include <time.h>

bool global_debug = false;

#define DEBUG(format, ...) do { \
    if (global_debug) \
        fprintf(stderr, "%s:%d %s " format "\n", __FILE__, __LINE__, __FUNCTION__, ## __VA_ARGS__); \
} while(false)

typedef struct arguments_t {
    const char * rrdtool_socket;
    const char * ubus_socket;
    const char * ubus_object;
    struct group * group;
    struct passwd * user;
    char ** files;
    size_t n_files;
} arguments_t;

arguments_t arguments = { };

static struct argp_option options[] = {
    { "daemon", 'd', "<socket>", 0, "RRDtool daemon socket" },
    { "socket", 's', "<socket>", 0, "ubus socket" },
    { "object", 'o', "<name>", 0, "ubus object" },
    { "base",   'b', "<directory>", 0, "base directory" },
    { "user",   'U', "<user>", 0, "become user" },
    { "group",  'G', "<group>", 0, "become group" },
    { "verbose",'v', 0, OPTION_ARG_OPTIONAL, 0 },
    { 0 }
};

static
error_t
parse_option(int key, char *argument, struct argp_state *state) {
    struct arguments_t *arguments = (struct arguments_t *)state->input;

    switch (key) {
    default:
        return ARGP_ERR_UNKNOWN;

    case 'd':
        if (arguments->rrdtool_socket)
            argp_error(state, "multiple daemon arguments");

        arguments->rrdtool_socket = argument;
        break;

    case 's':
        if (arguments->ubus_socket)
            argp_error(state, "multiple socket arguments");

        arguments->ubus_socket = argument;
        break;

    case 'o':
        if (arguments->ubus_object)
            argp_error(state, "multiple object arguments");

        arguments->ubus_object = argument;
        break;

    case 'b':
        if (chdir(argument))
            argp_failure(state, EXIT_FAILURE, errno, "%s", argument);
        break;

    case 'U':
        if (arguments->user)
            argp_error(state, "multiple user arguments");

        arguments->user = getpwnam(argument);

        if (!arguments->user) {
            char *end;
            long int uid = strtol(argument, &end, 0);
            if ('\0' == *end)
                arguments->user = getpwuid(uid);
        }

        if (!arguments->user)
            argp_failure(state, EXIT_FAILURE, ENOENT, "%s", argument);

        break;

    case 'G':
        if (arguments->group)
            argp_error(state, "multiple group arguments");

        arguments->group = getgrnam(argument);

        if (!arguments->group) {
            char *end;
            long int gid = strtol(argument, &end, 0);
            if ('\0' == *end)
                arguments->group = getgrgid(gid);
        }

        if (!arguments->group)
            argp_failure(state, EXIT_FAILURE, ENOENT, "%s", argument);

        break;

    case 'v':
        global_debug = true;
        break;

    case ARGP_KEY_ARGS:
        arguments->files = state->argv + state->next;
        arguments->n_files = state->argc - state->next;
        break;

    case ARGP_KEY_END:
        if (!arguments->rrdtool_socket) arguments->rrdtool_socket = RRDCACHED_DEFAULT_ADDRESS;
        if (!arguments->ubus_object) arguments->ubus_object = "rrd";
        break;
    }

    return 0;
}

static struct argp argp = { options, parse_option, 0, 0 };

struct blob_buf blob;

typedef enum {
    UBM_RRD_FILE,
    UBM_RRD_CF,
    UBM_RRD_START,
    UBM_RRD_END,
    UBM_RRD_STEP,
    __UBM_RRD
} ubm_rrd_type;

static const struct blobmsg_policy ubm_rrd_info_policy[] = {
    [UBM_RRD_FILE]   = { .name = "file", .type = BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy ubm_rrd_fetch_policy[] = {
    [UBM_RRD_FILE]   = { .name = "file", .type = BLOBMSG_TYPE_STRING },
    [UBM_RRD_CF]     = { .name = "cf", .type = BLOBMSG_TYPE_STRING },
    [UBM_RRD_START]  = { .name = "start", .type = BLOBMSG_TYPE_INT32 },
    [UBM_RRD_END]    = { .name = "end", .type = BLOBMSG_TYPE_INT32 },
    [UBM_RRD_STEP]   = { .name = "step", .type = BLOBMSG_TYPE_INT32 },
};

static int
ubm_rrd_list
(
        struct ubus_context *ubus,
        struct ubus_object *object,
        struct ubus_request_data *request,
        const char *method,
        struct blob_attr *ba
) {
    DEBUG("object=%x peer=%x sequence=%u name=%s method=%s",
        request->object,
        request->peer,
        request->seq,
        object->name,
        method
        );

    blob_buf_init(&blob, 0);
    enum ubus_msg_status status = UBUS_STATUS_UNKNOWN_ERROR;

    char * list = rrdc_list(true, "/");
    if (!list) {
        blobmsg_add_string(&blob, "error", rrd_get_error());
    } else {
        char * saveptr = "";
        for (char * entry = strtok_r(list, "\n", &saveptr) ; entry ; entry = strtok_r(NULL, "\n", &saveptr)) {
            time_t last = rrdc_last(entry);
            DEBUG("%s @ %lu", entry, (unsigned long)last);
            if (last > 0)
                blobmsg_add_u64(&blob, entry, last);
        }
        free(list);
        status = UBUS_STATUS_OK;
    }

    blobmsg_add_u8(&blob, "success", status == UBUS_STATUS_OK);
    ubus_send_reply(ubus, request, blob.head);
    return status;
}

static int
ubm_rrd_stats(
        struct ubus_context *ubus,
        struct ubus_object *object,
        struct ubus_request_data *request,
        const char *method,
        struct blob_attr *ba
) {
    DEBUG("object=%x peer=%x sequence=%u name=%s method=%s",
        request->object,
        request->peer,
        request->seq,
        object->name,
        method
        );

    blob_buf_init(&blob, 0);
    enum ubus_msg_status status = UBUS_STATUS_UNKNOWN_ERROR;

    rrdc_stats_t * stats;
    if (rrdc_stats_get(&stats)) {
        blobmsg_add_string(&blob, "error", rrd_get_error());
    } else {
        for (rrdc_stats_t * cursor = stats ; cursor ; cursor = cursor->next)
            switch (cursor->type) {
            case RRDC_STATS_TYPE_GAUGE:
                blobmsg_add_double(&blob, cursor->name, cursor->value.gauge);
                break;
            case RRDC_STATS_TYPE_COUNTER:
                blobmsg_add_u64(&blob, cursor->name, cursor->value.counter);
                break;
            default:
                blobmsg_add_field(&blob, BLOB_ATTR_LAST, cursor->name, NULL, 0);
                break;
            }
        rrdc_stats_free(stats);
        status = UBUS_STATUS_OK;
    }

    blobmsg_add_u8(&blob, "success", status == UBUS_STATUS_OK);
    ubus_send_reply(ubus, request, blob.head);
    return status;
}

static int
ubm_rrd_flush(
        struct ubus_context *ubus,
        struct ubus_object *object,
        struct ubus_request_data *request,
        const char *method,
        struct blob_attr *ba
) {
    DEBUG("object=%x peer=%x sequence=%u name=%s method=%s",
        request->object,
        request->peer,
        request->seq,
        object->name,
        method
        );

    blob_buf_init(&blob, 0);
    enum ubus_msg_status status = UBUS_STATUS_UNKNOWN_ERROR;

    if (rrdc_flushall()) {
        blobmsg_add_string(&blob, "error", rrd_get_error());
    } else {
        status = UBUS_STATUS_OK;
    }

    blobmsg_add_u8(&blob, "success", status == UBUS_STATUS_OK);
    ubus_send_reply(ubus, request, blob.head);
    return status;
}

static int
ubm_rrd_ping(
        struct ubus_context *ubus,
        struct ubus_object *object,
        struct ubus_request_data *request,
        const char *method,
        struct blob_attr *ba
) {
    DEBUG("object=%x peer=%x sequence=%u name=%s method=%s",
        request->object,
        request->peer,
        request->seq,
        object->name,
        method
        );

    blob_buf_init(&blob, 0);
    enum ubus_msg_status status = UBUS_STATUS_UNKNOWN_ERROR;

    if (!rrdc_ping()) {
        blobmsg_add_string(&blob, "error", rrd_get_error());
    } else {
        status = UBUS_STATUS_OK;
    }

    blobmsg_add_u8(&blob, "success", status == UBUS_STATUS_OK);
    ubus_send_reply(ubus, request, blob.head);
    return status;
}

static int
ubm_rrd_info(
        struct ubus_context *ubus,
        struct ubus_object *object,
        struct ubus_request_data *request,
        const char *method,
        struct blob_attr *ba
) {
    DEBUG("object=%x peer=%x sequence=%u name=%s method=%s",
        request->object,
        request->peer,
        request->seq,
        object->name,
        method
        );

    struct blob_attr *table[__UBM_RRD];
    blobmsg_parse(
        ubm_rrd_info_policy,
        sizeof(ubm_rrd_info_policy)/sizeof(*ubm_rrd_info_policy),
        table,
        blob_data(ba),
        blob_len(ba)
        );

    if (!table[UBM_RRD_FILE])
        return UBUS_STATUS_INVALID_ARGUMENT;

    DEBUG("%s", blobmsg_get_string(table[UBM_RRD_FILE]));

    blob_buf_init(&blob, 0);
    enum ubus_msg_status status = UBUS_STATUS_UNKNOWN_ERROR;

    rrd_info_t * info = rrdc_info(blobmsg_get_string(table[UBM_RRD_FILE]));
    if (!info) {
        blobmsg_add_string(&blob, "error", rrd_get_error());
    } else {
        status = UBUS_STATUS_OK;
        for (rrd_info_t * cursor = info ; cursor ; cursor = cursor->next)
            switch (cursor->type) {
            default:
                DEBUG("key=%s type=%d", cursor->key, cursor->type);
                blob_buf_init(&blob, 0);
                status = UBUS_STATUS_UNKNOWN_ERROR;
                cursor = NULL;
                break;

            case RD_I_VAL:
                DEBUG("key=%s value=%lf", cursor->key, cursor->value.u_val);
                blobmsg_add_double(&blob, cursor->key, cursor->value.u_val);
                break;
            case RD_I_CNT:
                DEBUG("key=%s value=%lu", cursor->key, cursor->value.u_cnt);
                blobmsg_add_u64(&blob, cursor->key, cursor->value.u_cnt);
                break;
            case RD_I_STR:
                DEBUG("key=%s value=%s", cursor->key, cursor->value.u_str);
                blobmsg_add_string(&blob, cursor->key, cursor->value.u_str);
                break;
            case RD_I_INT:
                DEBUG("key=%s value=%u", cursor->key, cursor->value.u_int);
                blobmsg_add_u32(&blob, cursor->key, cursor->value.u_int);
                break;

            case RD_I_BLO: // value.u_blo.size, value.u_blo.ptr
                DEBUG("key=%s blob[%lu]", cursor->key, cursor->value.u_blo.size);
                blob_buf_init(&blob, 0);
                status = UBUS_STATUS_UNKNOWN_ERROR;
                cursor = NULL;
                break;
            }
        rrd_info_free(info);
    }

    blobmsg_add_u8(&blob, "success", status == UBUS_STATUS_OK);
    ubus_send_reply(ubus, request, blob.head);
    return status;
}

static int
ubm_rrd_fetch(
        struct ubus_context *ubus,
        struct ubus_object *object,
        struct ubus_request_data *request,
        const char *method,
        struct blob_attr *ba
) {
    DEBUG("object=%x peer=%x sequence=%u name=%s method=%s",
        request->object,
        request->peer,
        request->seq,
        object->name,
        method
        );

    struct blob_attr *table[__UBM_RRD];
    blobmsg_parse(
        ubm_rrd_fetch_policy,
        sizeof(ubm_rrd_fetch_policy)/sizeof(*ubm_rrd_fetch_policy),
        table,
        blob_data(ba),
        blob_len(ba)
        );

    if (!table[UBM_RRD_FILE])
        return UBUS_STATUS_INVALID_ARGUMENT;

    DEBUG("%s", blobmsg_get_string(table[UBM_RRD_FILE]));

    const char * cf = table[UBM_RRD_CF] ? blobmsg_get_string(table[UBM_RRD_CF]) : "LAST";
    time_t start = table[UBM_RRD_START] ? blobmsg_get_u32(table[UBM_RRD_START]) : 0;
    time_t end = table[UBM_RRD_END] ? blobmsg_get_u32(table[UBM_RRD_END]) : -1;
    unsigned long step = table[UBM_RRD_STEP] ? blobmsg_get_u32(table[UBM_RRD_STEP]) : 1;

    unsigned long columns = 0;
    char ** column_names = NULL;
    rrd_value_t * values = NULL;

    start = (start/step) * step;
    end = (end/step) * step;

    time_t last = rrdc_last(blobmsg_get_string(table[UBM_RRD_FILE]));

    DEBUG("rrdc_fetch cf=%s start=%lu end=%lu step=%lu",
        cf,
        (unsigned long)start,
        (unsigned long)end,
        (unsigned long)step
        );
    if (rrdc_fetch(
            blobmsg_get_string(table[UBM_RRD_FILE]),
            cf, &start, &end, &step, &columns, &column_names, &values
    )) {
        blob_buf_init(&blob, 0);
        blobmsg_add_string(&blob, "error", rrd_get_error());
        ubus_send_reply(ubus, request, blob.head);
        return UBUS_STATUS_UNKNOWN_ERROR;
    } else {
        if (last < end)
            end = last;

        blob_buf_init(&blob, 0);
        blobmsg_add_u64(&blob, "start", start);
        blobmsg_add_u64(&blob, "end", end);
        blobmsg_add_u64(&blob, "step", step);
        blobmsg_add_u64(&blob, "last", last);

        rrd_value_t * cursor = values;
        void *array = blobmsg_open_array(&blob, "values");
        for (time_t t = start ; t < end ; t += step, cursor += columns) {
            void *object = blobmsg_open_table(&blob, NULL);
            blobmsg_add_u64(&blob, "@", t);
            for (int i = 0 ; i < columns ; ++i)
                blobmsg_add_double(&blob, column_names[i], cursor[i]);
            blobmsg_close_table(&blob, object);
        }
        blobmsg_close_array(&blob, array);
        ubus_send_reply(ubus, request, blob.head);

        for (int i = 0 ; i < columns ; ++i)
            free(column_names[i]);

        free(column_names);
        free(values);
    }

    return UBUS_STATUS_OK;
}

const struct ubus_method ubm_rrd_methods[] = {
    UBUS_METHOD_NOARG("list", ubm_rrd_list),
    UBUS_METHOD_NOARG("stats", ubm_rrd_stats),
    UBUS_METHOD_NOARG("flush", ubm_rrd_flush),
    UBUS_METHOD_NOARG("ping", ubm_rrd_ping),
    UBUS_METHOD("info", ubm_rrd_info, ubm_rrd_info_policy),
    UBUS_METHOD("fetch", ubm_rrd_fetch, ubm_rrd_fetch_policy),
};

struct ubus_object_type ubm_rrd_object_type = UBUS_OBJECT_TYPE("rrd", ubm_rrd_methods);

struct ubus_object ubm_rrd_object = {
    .type = &ubm_rrd_object_type,
    .methods = ubm_rrd_methods,
    .n_methods = sizeof(ubm_rrd_methods)/sizeof(*ubm_rrd_methods),
};

static void
system_check(struct uloop_timeout *timer) {
    DEBUG("%p", timer);
    uloop_timeout_set(timer, 500);

    if (!rrdc_is_any_connected())
        uloop_end();
}

int main(int argc, char *argv[]) {
    if (uloop_init() || atexit(uloop_done))
        return EXIT_FAILURE;

    argp_parse(&argp, argc, argv, 0, 0,  &arguments);

    DEBUG("ubus_connect_ctx %s", arguments.ubus_socket);
    struct ubus_context ubus;
    if (ubus_connect_ctx(&ubus, arguments.ubus_socket))
        return EXIT_FAILURE;

    DEBUG("rrdc_connect %s", arguments.rrdtool_socket);
    if (rrdc_connect(arguments.rrdtool_socket))
        return EXIT_FAILURE;

    if (arguments.group) {
        DEBUG("group setgid %d", arguments.group->gr_gid);
        if (setgroups(1, &arguments.group->gr_gid) || setgid(arguments.group->gr_gid))
            return EXIT_FAILURE;
    } else if (arguments.user) {
        DEBUG("user setgid %d", arguments.user->pw_gid);
        if (setgroups(1, &arguments.user->pw_gid) || setgid(arguments.user->pw_gid))
            return EXIT_FAILURE;
    }

    if (arguments.user) {
        DEBUG("user setuid %d", arguments.user->pw_uid);
        if (setuid(arguments.user->pw_gid))
            return EXIT_FAILURE;
    }

    DEBUG("uid %d gid %d", getuid(), getgid());

    memset(&blob, 0, sizeof blob);

    DEBUG("ubus_add_uloop");
    ubus_add_uloop(&ubus);

    DEBUG("ubus_add_object");
    ubm_rrd_object.name = arguments.ubus_object;
    if (ubus_add_object(&ubus, &ubm_rrd_object))
        return EXIT_FAILURE;

    DEBUG("uloop_timeout_add");
    struct uloop_timeout timer = {
        .cb = system_check,
    };
    if (uloop_timeout_set(&timer, 500))
        return EXIT_FAILURE;

    DEBUG("uloop_run begin");
    uloop_run();
    DEBUG("uloop_run end");

    uloop_timeout_cancel(&timer);
    ubus_shutdown(&ubus);
    blob_buf_free(&blob);
    rrdc_disconnect();

    return EXIT_SUCCESS;
}

//
