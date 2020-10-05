#ifndef ELASTIC_CONNECTION_H
#define ELASTIC_CONNECTION_H

#include <seq-range-array.h>
#include <dovecot/http-client.h>
#include <dovecot/fts-api.h>
#include <json-c/json.h>

//struct fts_elastic_settings;
//struct elastic_connection;

struct fts_elastic_settings
{
    const char *url;        /* base URL to an ElasticSearch instance */
    const char *rawlog_dir; /* directory where raw http request and response will be saved */
    unsigned int bulk_size; /* maximum size of values indexed in _bulk requests default=5MB */
    bool refresh_on_update; /* if we want add ?refresh=true to elastic query*/
    bool refresh_by_fts;    /* if we want to allow refresh http request called by fts plugin */
    bool debug;             /* whether or not debug is set */
};

enum elastic_post_type {
    ELASTIC_POST_TYPE_BULK = 0,
    ELASTIC_POST_TYPE_SEARCH,
    ELASTIC_POST_TYPE_REFRESH,
    ELASTIC_POST_TYPE_DELETE,
    ELASTIC_POST_TYPE_DELETE_BY_QUERY,
};

struct elastic_result {
    const char *box_guid;

    ARRAY_TYPE(seq_range) uids;
    ARRAY_TYPE(fts_score_map) scores;
};

struct elastic_connection
{
    struct mail_namespace *ns;
    const char *username;
    char *es_username;
    char *es_password;
    /* ElasticSearch HTTP API information */
    char *http_host;
    in_port_t http_port;
    char *http_base_path;
    char *http_failure;
    int request_status;

    /* for streaming processing of results */
    struct istream *payload;
    struct io *io;
    struct json_tokener *tok;

    enum elastic_post_type post_type;

    /* context for the current search */
    struct elastic_search_context *ctx;

    /* if we should send ?refresh=true on update _bulk requests */
    unsigned int refresh_on_update : 1;
    unsigned int debug : 1;
    unsigned int http_ssl : 1;
};

struct elastic_search_context;

int elastic_connection_init_new(const struct fts_elastic_settings *set,
                            struct elastic_connection **conn_r);

int elastic_connection_init(const struct fts_elastic_settings *set,
                            struct mail_namespace *ns,
                            struct elastic_connection **conn_r,
                            const char **error_r);

void elastic_connection_deinit(struct elastic_connection *conn);

int elastic_connection_get_last_uid(struct elastic_connection *conn,
                                    string_t *query,
                                    uint32_t *last_uid_r);

int elastic_connection_post(struct elastic_connection *conn,
                            const char *path, string_t *cmd);

void elastic_connection_json(struct elastic_connection *conn, json_object *jobj);

void elastic_connection_search_hits(struct elastic_search_context *ctx,
                                    struct json_object *hits);

int elastic_connection_bulk(struct elastic_connection *conn, string_t *cmd);

int elastic_connection_refresh(struct elastic_connection *conn);

int elastic_connection_search(struct elastic_connection *conn,
                              pool_t pool, string_t *query,
                              struct fts_result *result_r);

int elastic_connection_search_scroll(struct elastic_connection *conn,
                                     pool_t pool, string_t *query,
                                     struct fts_result *result_r);

int elastic_connection_rescan(struct elastic_connection *conn,
                              pool_t pool, string_t *query,
                              struct fts_result **results_r);

int elastic_connection_delete_by_query(struct elastic_connection *conn,
                                       pool_t pool, string_t *query);

#endif

