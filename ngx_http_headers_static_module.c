/**	Include static headers when serving static files.
	(CERN-style)
*/

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static const char * const module_name_ = "headers_static_module";


typedef struct {
	ngx_flag_t enabled;
	ngx_flag_t strict;
	ngx_str_t path;
	ngx_str_t suffix;
} ngx_http_headers_static_loc_conf_t;

#define NGX_HTTP_HEADERS_STATIC_CONF_DEFAULT_ENABLED 0
#define NGX_HTTP_HEADERS_STATIC_CONF_DEFAULT_STRICT 1
#define NGX_HTTP_HEADERS_STATIC_CONF_DEFAULT_PATH ".web"
#define NGX_HTTP_HEADERS_STATIC_CONF_DEFAULT_SUFFIX ".meta"

static ngx_http_output_header_filter_pt ngx_http_next_header_filter_;


static ngx_int_t ngx_http_headers_static_init_(ngx_conf_t *);
static void *ngx_http_http_headers_static_create_loc_conf_(ngx_conf_t *);
static char *ngx_http_http_headers_static_merge_loc_conf_(ngx_conf_t *, void *, void *);
static ngx_int_t ngx_http_headers_static_header_filter_(ngx_http_request_t *);


static ngx_command_t ngx_http_headers_static_commands_[] = {
	{	ngx_string("static_headers"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
		                  |NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_headers_static_loc_conf_t, enabled),
		NULL
	},

	{	ngx_string("static_headers_strict"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
		                  |NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_headers_static_loc_conf_t, strict),
		NULL
	},

	{	ngx_string("static_headers_path"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
		                  |NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_headers_static_loc_conf_t, path),
		NULL
	},

	{	ngx_string("static_headers_suffix"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
		                  |NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_headers_static_loc_conf_t, suffix),
		NULL
	},

	ngx_null_command
};


static ngx_http_module_t  ngx_http_headers_static_module_ctx_ = {
	NULL,
	ngx_http_headers_static_init_,
	NULL,
	NULL,
	NULL,
	NULL,
	ngx_http_http_headers_static_create_loc_conf_,
	ngx_http_http_headers_static_merge_loc_conf_
};


static
ngx_int_t ngx_http_headers_static_init_(ngx_conf_t *cf) {
	(void)cf; /* unused */
	ngx_http_next_header_filter_ = ngx_http_top_header_filter;
	ngx_http_top_header_filter = ngx_http_headers_static_header_filter_;

	return NGX_OK;
}

static
void *ngx_http_http_headers_static_create_loc_conf_(ngx_conf_t *cf) {
	ngx_http_headers_static_loc_conf_t *conf;
	conf = ngx_pcalloc(cf->pool, sizeof *conf);
	if (conf == NULL)
		return NGX_CONF_ERROR;
	conf->enabled = NGX_CONF_UNSET;

	return conf;
}


static
char *ngx_http_http_headers_static_merge_loc_conf_(ngx_conf_t *cf, void *parent, void *child) {
	ngx_http_headers_static_loc_conf_t *prev = parent;
	ngx_http_headers_static_loc_conf_t *conf = child;

	ngx_conf_merge_value(conf->enabled, prev->enabled,
	                     NGX_HTTP_HEADERS_STATIC_CONF_DEFAULT_ENABLED);
	ngx_conf_merge_value(conf->strict, prev->strict,
	                     NGX_HTTP_HEADERS_STATIC_CONF_DEFAULT_STRICT);
	ngx_conf_merge_str_value(conf->path, prev->path,
	                         NGX_HTTP_HEADERS_STATIC_CONF_DEFAULT_PATH);
	ngx_conf_merge_str_value(conf->suffix, prev->suffix,
	                         NGX_HTTP_HEADERS_STATIC_CONF_DEFAULT_SUFFIX);

	if (conf->enabled != 0 && conf->enabled != 1) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%s\" ought to be \"on\" or \"off\", not \"%d\"", "static_headers", conf->enabled);
		return NGX_CONF_ERROR;
	}

	return NGX_CONF_OK;
}


ngx_module_t  ngx_http_headers_static_module = {
	NGX_MODULE_V1,
	&ngx_http_headers_static_module_ctx_,
	ngx_http_headers_static_commands_,
	NGX_HTTP_MODULE,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NGX_MODULE_V1_PADDING
};


/**	Populate a ngx_str_t with a newly-allocated path to a metafile, built from
	the contents of source_path and loc_conf.
*/
inline
static
ngx_int_t metafilename_build_(ngx_pool_t *pool, ngx_str_t *source_path, ngx_http_headers_static_loc_conf_t *loc_conf, ngx_str_t *metafilename) {
	ngx_str_t filename;
	u_char *x;

	/* split source_path into filename and basename */
	filename = *source_path;
	x = (u_char *)strrchr((char *)source_path->data, '/');
	if (x == NULL) {
		source_path->len = 0;
	} else {
		source_path->len = x - source_path->data;
		filename.len -= source_path->len + 2;
		filename.data = x + 1;
		*x = '\0';
	}

	metafilename->len = source_path->len + (source_path->len ? 1 : 0) +
	                    loc_conf->path.len + (loc_conf->path.len ? 1 : 0) +
	                    filename.len +
	                    loc_conf->suffix.len;
	metafilename->data = ngx_pnalloc(pool, metafilename->len + 1);
	if (metafilename->data == NULL) {
		ngx_memset(metafilename, 0, sizeof *metafilename);
		return NGX_ERROR;
	}

	x = metafilename->data;

	if (source_path->len) {
		ngx_memcpy(x, source_path->data, source_path->len);
		x += source_path->len;
		*(x++) = '/';
	}

	if (loc_conf->path.len) {
		ngx_memcpy(x, loc_conf->path.data, loc_conf->path.len);
		x += loc_conf->path.len;
		*(x++) = '/';
	}

	ngx_memcpy(x, filename.data, filename.len);
	x += filename.len;

	if (loc_conf->suffix.len) {
		ngx_memcpy(x, loc_conf->suffix.data, loc_conf->suffix.len);
		x += loc_conf->suffix.len;
	}

	*x = '\0';

	return NGX_OK;
}


/**	Add or alter a response header.
	Some response headers ought not be overridden statically, so this will
	refuse any attempts to set those.
	Some headers require extra processing or indexing to integrate with nginx,
	this will take care of those.

	This is destructive to the indexed strings: it updates the string struct
	the index points to, losing the old pointer and length.

	FIXME:
		cache-control header is not implemented
		last-modified header is not validated
*/
inline
static
ngx_int_t ngx_http_header_set_(ngx_http_request_t *r, ngx_str_t *key, ngx_str_t *value, ngx_flag_t strict, ngx_table_elt_t **ref) {
	ngx_table_elt_t *h = NULL;
	ngx_table_elt_t **h_ref = NULL;
	ngx_array_t *pa = NULL;

	*ref = NULL;

	/* Special-case the built-in headers, and fail on protocol-and-
		server-behavioral-headers.  There is certainly a case for 'no, really,
		just send this', but I felt that rejecting potentially protocol-meddling
		headers was the safer behavior, at least as a first go-around default.

		These headers are not allowed to be overridden, because they are
		generated based on content or connection state, and thus shouldn't be
		represented statically:
			accept_ranges
			content_length
			content_range
			date
			www_authenticate
		There may be more which ought to be included in this list.

		These headers have index pointers into the generic header list:
			content_encoding
			etag
			expires
			location
			refresh
			server

		These headers aren't handled generically:
			cache-control // list
			charset
			content_type
			last_modified
			link // list
			status
	*/
	switch (key->len) {
	case 16:
		if (strncasecmp("WWW-Authenticate", (char *)key->data, key->len) == 0) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			              "%s will not set \"%s\" header", module_name_, key->data);
			return strict ? NGX_EACCES : NGX_OK;
		}

		if (strncasecmp("Content-Encoding", (char *)key->data, key->len) == 0) {
			ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			               "%s overriding \"%s\"", module_name_, key->data);
			h_ref = &(r->headers_out.content_encoding);
			break;
		}

		break;

	case 14:
		if (strncasecmp("Content-Length", (char *)key->data, key->len) == 0) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			              "%s will not set \"%s\" header", module_name_, key->data);
			return strict ? NGX_EACCES : NGX_OK;
		}

		break;

	case 13:
		if (strncasecmp("Content-Range", (char *)key->data, key->len) == 0
		||  strncasecmp("Accept-Ranges", (char *)key->data, key->len) == 0) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			              "%s will not set \"%s\" header", module_name_, key->data);
			return strict ? NGX_EACCES : NGX_OK;
		}

		if (strncasecmp("Last-Modified", (char *)key->data, key->len) == 0) {
			ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			              "%s overriding '%s'", module_name_, key->data);
			h_ref = &(r->headers_out.last_modified);

			/* FIXME:
				RFC2616: An origin server MUST NOT send a Last-Modified date
				which is later than the server's time of message origination.
				In such cases, where the resource's last modification would
				indicate some time in the future, the server MUST replace that
				date with the message origination date.
			*/

			/* FIXME: should this get set, as well? */
			r->headers_out.last_modified_time = -1;
			break;
		}

		if (strncasecmp("Cache-Control", (char *)key->data, key->len) == 0) {
			pa = &(r->headers_out.cache_control);
			break;
		}

		break;

	case 12:
		if (strncasecmp("Content-Type", (char *)key->data, key->len) == 0) {
			size_t i;

			ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			              "%s overriding '%s'", module_name_, key->data);

			r->headers_out.content_type_lowcase = ngx_pnalloc(r->pool, value->len + 1);
			if (r->headers_out.content_type_lowcase == NULL)
				return NGX_ERROR;
			r->headers_out.content_type_len = value->len;
			r->headers_out.content_type_hash = 0;
			for (i = 0; i < value->len; i++) {
				u_char c = ngx_tolower(value->data[i]);
				r->headers_out.content_type_hash = ngx_hash(r->headers_out.content_type_hash, c);
				r->headers_out.content_type_lowcase[i] = c;
			}

			r->headers_out.content_type = *value;

			/* FIXME:
				should we set r->headers_out.charset if there's a ;charset= in
				content-type?
				Ignoring for now.
			*/

			return NGX_OK;
		}

		break;

	case 8:
		if (strncasecmp("Location", (char *)key->data, key->len) == 0) {
			ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			              "%s overriding '%s'", module_name_, key->data);
			h_ref = &(r->headers_out.location);
			break;
		}

		break;

	case 7:
		if (strncasecmp("Expires", (char *)key->data, key->len) == 0) {
			ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			              "%s overriding '%s'", module_name_, key->data);
			h_ref = &(r->headers_out.expires);
			break;
		}

		if (strncasecmp("Refresh", (char *)key->data, key->len) == 0) {
			ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			              "%s overriding '%s'", module_name_, key->data);
			h_ref = &(r->headers_out.refresh);
			break;
		}

		break;

	case 6:
		if (strncasecmp("Status", (char *)key->data, key->len) == 0) {
			ngx_http_status_t status;
			ngx_int_t rc;
			ngx_buf_t b;

			ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			              "%s overriding '%s'", module_name_, key->data);

			memset(&status, 0, sizeof status);
			memset(&b, 0, sizeof b);
			b.start = b.pos = value->data;
			b.end = b.last = value->data + value->len;

			/* allow just 'Status: 999' */
			if (value->data[0] != 'H')
				r->state = 9; /* HAX: sw_status from ngx_http_parse_status_line */
			else
				r->state = 0;

			rc = ngx_http_parse_status_line(r, &b, &status);
			if (rc == NGX_ERROR
			||  (rc == NGX_AGAIN && r->state <= 9)) {
				/* invalid status line */
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				              "%s will not set an unparsable \"%s\" header", module_name_, key->data);
				return strict ? NGX_EINVAL : NGX_OK;
			}

			r->headers_out.status = status.code;
			r->headers_out.status_line.data = status.start;
			r->headers_out.status_line.len = b.end - status.start;

			ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			              "%s status:%d", module_name_, status.code);
			ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			              "%s status.start:%s\n\tstatus_len:%d",
			              module_name_,
			              status.start, r->headers_out.status_line.len);

			return NGX_OK;
		}

		if (strncasecmp("Server", (char *)key->data, key->len) == 0) {
			ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			              "%s overriding '%s'", module_name_, key->data);
			h_ref = &(r->headers_out.server);
			break;
		}

		break;

	case 4:
		if (strncasecmp("Date", (char *)key->data, key->len) == 0) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			              "%s will not set \"%s\" header", module_name_, key->data);
			return strict ? NGX_EINVAL : NGX_OK;
		}

		if (strncasecmp("ETag", (char *)key->data, key->len) == 0) {
			ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			              "%s overriding '%s'", module_name_, key->data);
			h_ref = &(r->headers_out.etag);
			break;
		}

		if (strncasecmp("Link", (char *)key->data, key->len) == 0) {
			pa = &(r->headers_out.link);
			break;
		}

		break;

	case 0:
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
		              "%s will not add nameless header", module_name_);
		return strict ? NGX_EINVAL : NGX_OK;
	}

	if (h_ref)
		h = *h_ref;

	/*
		Anything else, just add it to the header pile.
		Nothing prevents multiple headers of the same name, here.
	*/

	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
	              "%s adding '%s'", module_name_, key->data);

	if (h == NULL) {
		h = ngx_list_push(&r->headers_out.headers);
		if (h == NULL)
			return NGX_ERROR;

		if (h_ref)
			*h_ref = h;
	}

	/*
		XXX: should h->lowcase_key get set here, as well?
	*/
	h->hash = 1;
	h->key = *key;
	h->value = *value;

	*ref = h;

	if (pa) {
		ngx_table_elt_t **ph;

		if (pa->elts == NULL) {
			if (ngx_array_init(pa, r->pool, 1, sizeof(ngx_table_elt_t *)) != NGX_OK) {
				return NGX_ERROR;
			}
		}

		ph = ngx_array_push(pa);
		if (ph == NULL) {
			return NGX_ERROR;
		}

		*ph = h;
	}

	return NGX_OK;
}


/**	Parse through the specified file, adding all headers encountered to the
	response.

	FIXME: this is pretty janky

*/
inline
static
ngx_int_t static_header_file_process_(ngx_file_t *f, ngx_http_request_t *r, ngx_flag_t strict) {
	ngx_keyval_t hkv;
	ssize_t n;
	u_char *buf;
	ngx_buf_t b;
	ngx_int_t rc;
	size_t metafile_sz;
	ngx_table_elt_t *ref;

	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
	              "%s processing metafile: %s", module_name_, f->name.data);

	if (f->valid_info) {
		metafile_sz = f->info.st_size;
	} else {
		ngx_file_info_t fi;

		if (ngx_fd_info(f->fd, &fi) == NGX_FILE_ERROR) {
			ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
			              ngx_fd_info_n " \"%V\" failed", f->name);
			return NGX_ERROR;
		}
		metafile_sz = fi.st_size;
	}

	if ((buf = ngx_pnalloc(r->pool, metafile_sz + 5)) == NULL)
		return NGX_ERROR;

	if ((n = ngx_read_file(f, buf, metafile_sz, 0)) == NGX_ERROR)
		return NGX_ERROR;

	if (n != (ssize_t)metafile_sz)
		return NGX_ERROR;

	/* XXX: dumb hack to ensure the header-parser will terminate */
	ngx_memcpy(buf + metafile_sz, "\r\n\r\n\0", 5);

	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
	              "%s read %d bytes of %d", module_name_, n, metafile_sz);

	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
	              "%s\n%*s", module_name_, metafile_sz, buf);

	ngx_memset(&b, 0, sizeof b);
	b.start = b.pos = buf;
	b.end = b.last = buf + metafile_sz + 4;

	memset(&hkv, 0, sizeof hkv);

	memset(r->lowcase_header, 0, NGX_HTTP_LC_HEADER_LEN);
	r->lowcase_index = 0;
	r->state = 0;
	r->header_hash = 0;
	r->invalid_header = 0;
	r->header_name_start = r->header_name_end = r->header_start = r->header_end = NULL;

	ref = NULL;

	for (;;) {
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		              "%s ref:%p", module_name_, ref);
		if (ref)
			ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			              "%s ref k[%d %*s] v[%d %*s]", module_name_,
			              ref->key.len, ref->key.len, ref->key.data,
			              ref->value.len, ref->value.len, ref->value.data);

		rc = ngx_http_parse_header_line(r, &b, 1);

		if (rc == NGX_OK) {
			ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			              "%s header parsed OK", module_name_);

			if (r->invalid_header) {
				if ((*(r->header_name_start) != ' ' && *(r->header_name_start) != '\t')
				||  ref == NULL) {
					ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
					              "%s invalid header in metafile \"%s\": \"%*s\"",
					              module_name_,
					              f->name.data,
					              r->header_end - r->header_name_start,
					              r->header_name_start);
					ref = NULL;

					continue;
				}

				ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				              "%s continuing header %p [%d, %*s].. (%p %p)", module_name_,
				              ref, ref->value.len, ref->value.len, ref->value.data,
				              r->header_end, r->header_start);
				/* this is a valid continuation of the previous header */
				ref->value.len = r->header_end - ref->value.data;

				continue;
			}

			hkv.key.len = r->header_name_end - r->header_name_start;
			hkv.key.data = r->header_name_start;

			hkv.value.len = r->header_end - r->header_start;
			hkv.value.data = r->header_start;

			ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			              "%s metafile header \"%V: %V\"",
			              module_name_,
			              &hkv.key,
			              &hkv.value);

			if (ngx_http_header_set_(r, &hkv.key, &hkv.value, strict, &ref) != NGX_OK) {
				return NGX_ERROR;
			}

			memset(&hkv, 0, sizeof hkv);

			continue;
		}

		/* we know we only have one buffer to read, so if it's incomplete, just
			give up */
		if (rc == NGX_AGAIN) {
			if (b.pos == b.last) {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				              "%s incomplete header", module_name_ );
				break;
			}
			continue;
		}

		if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
			ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			              "%s header done", module_name_);
			break;
		}

		/* rc == NGX_HTTP_PARSE_INVALID_HEADER */
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		              "%s header error", module_name_);
		return NGX_ERROR;
	}

	return NGX_OK;
}


static
ngx_int_t ngx_http_headers_static_header_filter_(ngx_http_request_t *r) {
	ngx_http_headers_static_loc_conf_t *loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_headers_static_module);

	if (loc_conf->enabled == 1) {
		ngx_str_t path;
		size_t root;
		ngx_str_t metafilename;
		ngx_http_core_loc_conf_t *clcf;
		ngx_open_file_info_t of;
		ngx_file_t f;

		if (ngx_http_map_uri_to_path(r, &path, &root, 0) == NULL)
			return NGX_HTTP_INTERNAL_SERVER_ERROR;

		if (metafilename_build_(r->pool, &path, loc_conf, &metafilename) == NGX_ERROR)
			return NGX_HTTP_INTERNAL_SERVER_ERROR;

		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		               "%s metafile '%s'", module_name_, metafilename.data);

		clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
		ngx_memset(&of, 0, sizeof of);
		of.read_ahead = clcf->read_ahead;
		of.directio = NGX_OPEN_FILE_DIRECTIO_OFF;
		of.valid = clcf->open_file_cache_valid;
		of.min_uses = clcf->open_file_cache_min_uses;
		of.errors = clcf->open_file_cache_errors;
		of.events = clcf->open_file_cache_events;

		if (ngx_http_set_disable_symlinks(r, clcf, &metafilename, &of) != NGX_OK)
			return NGX_HTTP_INTERNAL_SERVER_ERROR;

		if (ngx_open_cached_file(clcf->open_file_cache, &metafilename, &of, r->pool) != NGX_OK) {
			switch (of.err) {
			case NGX_ENOENT:
				/* no metafile is perfectly okay */
				break;

			case NGX_EACCES:
				/* could not open extant metafile, fail as if could not open file */
				ngx_log_error(NGX_LOG_ERR, r->connection->log, of.err,
				              "%s \"%s\" failed", of.failed, metafilename.data);
				return NGX_HTTP_FORBIDDEN;

			default:
				/* unexpected error */
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}
		} else {
			if ( ! of.is_file) {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				              "\"%s\" is not a file", metafilename.data);
				return NGX_DECLINED;
			}

			ngx_memset(&f, 0, sizeof f);
			f.fd = of.fd;
			f.name = metafilename;
			f.log = r->connection->log;
			f.directio = of.is_directio;

			ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			              "%s meta fd: %d", module_name_, f.fd);

			if (static_header_file_process_(&f, r, loc_conf->strict) != NGX_OK) {
				ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				              "%s processing failed", module_name_);

				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}

			ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			              "%s postprocessed", module_name_);
		}

		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		              "%s done", module_name_);
	}

	return ngx_http_next_header_filter_(r);
}
