# ngx_headers_static
## Inject headers from a file when serving content.

*This module is not distributed with the Nginx source.*

# Description
This module allows for the inclusion of arbitrary response headers from a static file for the corresponding content file being served, in a way reminiscent of CERN-style metafiles.

Limited validation is done on the included headers.

Header files should consist of headers in standard form:

	X-Extra-Header: some data
	X-Folded-Header: pre-folded header lines are
	    also supported

# Configuration
	location /foo {
		# enable static header injection for a location
		static_headers on;

		# where to find header file, relative to content file
		static_headers_path .web; # default is .web directory

		# how are header files named
		static_headers_suffix .meta; # default is .meta

		# with these values set, a request for content.txt would include any
		# headers from .web/content.txt.meta
	}
