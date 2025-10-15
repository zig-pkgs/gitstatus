const std = @import("std");

pub fn build(b: *std.Build) void {
    // Standard target and optimization options.
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const upstream = b.dependency("libgit2", .{});

    const upstream_gitstatus = b.dependency("gitstatus", .{});

    // Common C flags extracted from compile_commands.json
    const c_flags = [_][]const u8{
        "-std=gnu90",
        "-pipe",
        "-fno-plt",
        "-fexceptions",
        "-fstack-clash-protection",
        //"-fcf-protection",
        "-fno-omit-frame-pointer",
        "-mno-omit-leaf-frame-pointer",
        "-Wall",
        "-Wextra",
        "-Wformat",
        "-Wformat-security",
        "-Werror=format-security",
        "-Wstrict-aliasing",
        "-Wstrict-prototypes",
        "-Wdeclaration-after-statement",
        "-Wshift-count-overflow",
        "-Wunused-const-variable",
        "-Wunused-function",
        "-Wint-conversion",
        "-Wmissing-declarations",
        "-Wno-documentation-deprecated-sync",
        "-Wno-missing-field-initializers",
    };

    // --- Dependency: zlib ---
    const zlib_lib = b.addLibrary(.{
        .name = "z",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    zlib_lib.addIncludePath(upstream.path("deps/zlib/"));
    zlib_lib.root_module.addCMacro("STDC", "");
    zlib_lib.root_module.addCMacro("NO_GZIP", "");
    zlib_lib.root_module.addCMacro("NO_VIZ", "");
    zlib_lib.addCSourceFiles(.{
        .root = upstream.path("deps"),
        .files = &.{
            "zlib/adler32.c",
            "zlib/crc32.c",
            "zlib/deflate.c",
            "zlib/infback.c",
            "zlib/inffast.c",
            "zlib/inflate.c",
            "zlib/inftrees.c",
            "zlib/trees.c",
            "zlib/zutil.c",
        },
        .flags = &c_flags,
    });
    zlib_lib.installHeadersDirectory(upstream.path("deps/zlib"), "zlib", .{});

    // --- Dependency: http-parser ---
    const http_parser_lib = b.addLibrary(.{
        .name = "http-parser",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    http_parser_lib.addCSourceFile(.{
        .file = upstream.path("deps/http-parser/http_parser.c"),
        .flags = &c_flags,
    });
    http_parser_lib.installHeader(upstream.path("deps/http-parser/http_parser.h"), "http_parser.h");

    const pcre_config_h = b.addConfigHeader(
        .{ .style = .{ .cmake = upstream.path("deps/pcre/config.h.in") } },
        .{
            .HAVE_DIRENT_H = 1,
            .HAVE_SYS_STAT_H = 1,
            .HAVE_SYS_TYPES_H = 1,
            .HAVE_UNISTD_H = 1,
            .HAVE_WINDOWS_H = null,
            .HAVE_STDINT_H = 1,
            .HAVE_INTTYPES_H = 1,

            .HAVE_TYPE_TRAITS_H = null,
            .HAVE_BITS_TYPE_TRAITS_H = null,

            .HAVE_BCOPY = 1,
            .HAVE_MEMMOVE = 1,
            .HAVE_STRERROR = 1,
            .HAVE_STRTOLL = 1,
            .HAVE_STRTOQ = 1,
            .HAVE__STRTOI64 = null,
            .PCRE_STATIC = null,

            .SUPPORT_PCRE8 = 1,
            .SUPPORT_PCRE16 = null,
            .SUPPORT_PCRE32 = null,
            .SUPPORT_JIT = null,
            .SUPPORT_PCREGREP_JIT = null,
            .SUPPORT_UTF = null,
            .SUPPORT_UCP = null,
            .EBCDIC = null,
            .EBCDIC_NL25 = null,
            .BSR_ANYCRLF = null,
            .NO_RECURSE = 1,

            .HAVE_LONG_LONG = 1,
            .HAVE_UNSIGNED_LONG_LONG = 1,

            .SUPPORT_LIBBZ2 = null,
            .SUPPORT_LIBZ = null,
            .SUPPORT_LIBEDIT = null,
            .SUPPORT_LIBREADLINE = null,
            .SUPPORT_VALGRIND = null,
            .SUPPORT_GCOV = null,

            .NEWLINE = 10,
            .PCRE_POSIX_MALLOC_THRESHOLD = 10,
            .PCRE_LINK_SIZE = 2,
            .PCRE_PARENS_NEST_LIMIT = 250,
            .PCRE_MATCH_LIMIT = 10000000,
            .PCRE_MATCH_LIMIT_RECURSION = .MATCH_LIMIT,
            .PCREGREP_BUFSIZE = {},

            .MAX_NAME_SIZE = 32,
            .MAX_NAME_COUNT = 10000,
        },
    );

    // --- Dependency: pcre ---
    const pcre_lib = b.addLibrary(.{
        .name = "pcre",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    pcre_lib.addConfigHeader(pcre_config_h);
    pcre_lib.root_module.addCMacro("HAVE_CONFIG_H", "");
    pcre_lib.addIncludePath(upstream.path("deps/pcre"));
    pcre_lib.addCSourceFiles(.{
        .root = upstream.path("deps"),
        .files = &.{
            "pcre/pcre_byte_order.c",
            "pcre/pcre_chartables.c",
            "pcre/pcre_compile.c",
            "pcre/pcre_config.c",
            "pcre/pcre_dfa_exec.c",
            "pcre/pcre_exec.c",
            "pcre/pcre_fullinfo.c",
            "pcre/pcre_get.c",
            "pcre/pcre_globals.c",
            "pcre/pcre_jit_compile.c",
            "pcre/pcre_maketables.c",
            "pcre/pcre_newline.c",
            "pcre/pcre_ord2utf8.c",
            "pcre/pcre_refcount.c",
            "pcre/pcre_string_utils.c",
            "pcre/pcre_study.c",
            "pcre/pcre_tables.c",
            "pcre/pcre_ucd.c",
            "pcre/pcre_valid_utf8.c",
            "pcre/pcre_version.c",
            "pcre/pcre_xclass.c",
            "pcre/pcreposix.c",
        },
        .flags = &c_flags,
    });

    const features_h = b.addConfigHeader(
        .{
            .style = .{ .cmake = upstream.path("src/features.h.in") },
            .include_path = "git2/sys/features.h",
        },
        .{
            // Debugging and Tracing
            .GIT_DEBUG_POOL = null,
            .GIT_TRACE = 1,
            .GIT_THREADS = 1,
            .GIT_MSVC_CRTDBG = null,

            // Architecture
            .GIT_ARCH_64 = 1,
            .GIT_ARCH_32 = null,

            // System Features
            .GIT_USE_ICONV = null,
            .GIT_USE_NSEC = 1,
            .GIT_ZERO_NSEC = 1,
            .GIT_USE_STAT_MTIM = 1,
            .GIT_USE_STAT_MTIMESPEC = null,
            .GIT_USE_STAT_MTIME_NSEC = null,
            .GIT_USE_FUTIMENS = 1,

            // Regex Backend
            .GIT_REGEX_REGCOMP_L = null,
            .GIT_REGEX_REGCOMP = null,
            .GIT_REGEX_PCRE = null,
            .GIT_REGEX_PCRE2 = null,
            .GIT_REGEX_BUILTIN = 1,

            // SSH Backend
            .GIT_SSH = null,
            .GIT_SSH_MEMORY_CREDENTIALS = null,

            // Authentication Mechanisms
            .GIT_NTLM = null,
            .GIT_GSSAPI = null,
            .GIT_GSSFRAMEWORK = null,

            // HTTPS Backends
            .GIT_WINHTTP = null,
            .GIT_HTTPS = null,
            .GIT_OPENSSL = null,
            .GIT_SECURE_TRANSPORT = null,
            .GIT_MBEDTLS = null,

            // SHA1 Implementation
            .GIT_SHA1_COLLISIONDETECT = 1,
            .GIT_SHA1_WIN32 = null,
            .GIT_SHA1_COMMON_CRYPTO = null,
            .GIT_SHA1_OPENSSL = null,
            .GIT_SHA1_MBEDTLS = null,
        },
    );

    // --- Main Library: libgit2 ---
    const libgit2 = b.addLibrary(.{
        .name = "git2",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    libgit2.addConfigHeader(features_h);

    libgit2.want_lto = true;

    // Add include paths
    libgit2.addIncludePath(upstream.path("src"));
    libgit2.addIncludePath(upstream.path("include"));
    libgit2.addIncludePath(upstream.path("deps/pcre"));
    libgit2.addIncludePath(upstream.path("deps/http-parser"));
    libgit2.addIncludePath(upstream.path("deps/zlib"));

    // Add C preprocessor definitions
    libgit2.root_module.addCMacro("HAVE_QSORT_R_GNU", "");
    libgit2.root_module.addCMacro("SHA1DC_CUSTOM_INCLUDE_SHA1_C", "\"common.h\"");
    libgit2.root_module.addCMacro("SHA1DC_CUSTOM_INCLUDE_UBC_CHECK_C", "\"common.h\"");
    libgit2.root_module.addCMacro("SHA1DC_NO_STANDARD_INCLUDES", "1");
    libgit2.root_module.addCMacro("_FILE_OFFSET_BITS", "64");
    libgit2.root_module.addCMacro("_GNU_SOURCE", "");
    libgit2.root_module.addCMacro("_FORTIFY_SOURCE", "3");

    // Add all source files to the library
    libgit2.addCSourceFiles(.{
        .root = upstream.path("src"),
        .files = &.{
            "hash/sha1/collisiondetect.c",
            "hash/sha1/sha1dc/sha1.c",
            "hash/sha1/sha1dc/ubc_check.c",
            "unix/map.c",
            "unix/realpath.c",
            "alloc.c",
            "allocators/stdalloc.c",
            "allocators/win32_crtdbg.c",
            "annotated_commit.c",
            "apply.c",
            "attr.c",
            "attr_file.c",
            "attrcache.c",
            "blame.c",
            "blame_git.c",
            "blob.c",
            "branch.c",
            "buf_text.c",
            "buffer.c",
            "cache.c",
            "checkout.c",
            "cherrypick.c",
            "clone.c",
            "commit.c",
            "commit_list.c",
            "config.c",
            "config_cache.c",
            "config_entries.c",
            "config_file.c",
            "config_mem.c",
            "config_parse.c",
            "config_snapshot.c",
            "crlf.c",
            "date.c",
            "delta.c",
            "describe.c",
            "diff.c",
            "diff_driver.c",
            "diff_file.c",
            "diff_generate.c",
            "diff_parse.c",
            "diff_print.c",
            "diff_stats.c",
            "diff_tform.c",
            "diff_xdiff.c",
            "errors.c",
            "fetch.c",
            "fetchhead.c",
            "filebuf.c",
            "filter.c",
            "futils.c",
            "global.c",
            "graph.c",
            "hash.c",
            "hashsig.c",
            "ident.c",
            "idxmap.c",
            "ignore.c",
            "index.c",
            "indexer.c",
            "iterator.c",
            "mailmap.c",
            "merge.c",
            "merge_driver.c",
            "merge_file.c",
            "message.c",
            "midx.c",
            "mwindow.c",
            "net.c",
            "netops.c",
            "notes.c",
            "object.c",
            "object_api.c",
            "odb.c",
            "odb_loose.c",
            "odb_mempack.c",
            "odb_pack.c",
            "offmap.c",
            "oid.c",
            "oidarray.c",
            "oidmap.c",
            "pack-objects.c",
            "pack.c",
            "parse.c",
            "patch.c",
            "patch_generate.c",
            "patch_parse.c",
            "path.c",
            "pathspec.c",
            "pool.c",
            "posix.c",
            "pqueue.c",
            "proxy.c",
            "push.c",
            "reader.c",
            "rebase.c",
            "refdb.c",
            "refdb_fs.c",
            "reflog.c",
            "refs.c",
            "refspec.c",
            "regexp.c",
            "remote.c",
            "repository.c",
            "reset.c",
            "revert.c",
            "revparse.c",
            "revwalk.c",
            "settings.c",
            "signature.c",
            "sortedcache.c",
            "stash.c",
            "status.c",
            "strarray.c",
            "streams/mbedtls.c",
            "streams/openssl.c",
            "streams/registry.c",
            "streams/socket.c",
            "streams/stransport.c",
            "streams/tls.c",
            "strmap.c",
            "submodule.c",
            "sysdir.c",
            "tag.c",
            "thread-utils.c",
            "trace.c",
            "trailer.c",
            "transaction.c",
            "transport.c",
            "transports/auth.c",
            "transports/auth_negotiate.c",
            "transports/auth_ntlm.c",
            "transports/credential.c",
            "transports/credential_helpers.c",
            "transports/git.c",
            "transports/http.c",
            "transports/httpclient.c",
            "transports/local.c",
            "transports/smart.c",
            "transports/smart_pkt.c",
            "transports/smart_protocol.c",
            "transports/ssh.c",
            "transports/winhttp.c",
            "tree-cache.c",
            "tree.c",
            "tsort.c",
            "util.c",
            "varint.c",
            "vector.c",
            "wildmatch.c",
            "worktree.c",
            "xdiff/xdiffi.c",
            "xdiff/xemit.c",
            "xdiff/xhistogram.c",
            "xdiff/xmerge.c",
            "xdiff/xpatience.c",
            "xdiff/xprepare.c",
            "xdiff/xutils.c",
            "zstream.c",
        },
        .flags = &c_flags,
    });

    // Link libgit2 against its dependencies
    libgit2.linkLibrary(zlib_lib);
    libgit2.linkLibrary(http_parser_lib);
    libgit2.linkLibrary(pcre_lib);

    libgit2.installConfigHeader(features_h);
    libgit2.installHeadersDirectory(upstream.path("include"), "", .{});

    const gitstatus = b.addExecutable(.{
        .name = "gitstatusd",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libcpp = true,
        }),
    });
    gitstatus.root_module.addCMacro("GITSTATUS_VERSION", "v1.5.5");
    gitstatus.root_module.addCMacro("_FILE_OFFSET_BITS", "64");
    gitstatus.root_module.addCMacro("_LARGEFILE64_SOURCE", "");
    gitstatus.root_module.addCMacro("GITSTATUS_ZERO_NSEC", "");
    gitstatus.root_module.addCMacro("_GNU_SOURCE", "");
    gitstatus.addCSourceFiles(.{
        .root = upstream_gitstatus.path("src"),
        .files = &.{
            "arena.cc",
            "check_dir_mtime.cc",
            "dir.cc",
            "git.cc",
            "gitstatus.cc",
            "index.cc",
            "logging.cc",
            "options.cc",
            "repo.cc",
            "repo_cache.cc",
            "request.cc",
            "response.cc",
            "strings.cc",
            "tag_db.cc",
            "thread_pool.cc",
            "timer.cc",
        },
        .flags = &.{ "-std=c++14", "-funsigned-char" },
    });
    gitstatus.linkLibrary(libgit2);
    b.installArtifact(gitstatus);
}
