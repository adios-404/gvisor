load("//tools:defs.bzl", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_test(
    name = "bbr_test",
    size = "medium",
    srcs = [
        "appendix_a_test.go",
        "compare_test.go",
        "helpers_test.go",
        "probe_rtt_test.go",
    ],
    deps = [
        "//pkg/refs",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/tcp",
        "//pkg/tcpip/transport/tcp/test/pathmodel",
        "//pkg/tcpip/transport/tcp/test/simnet",
    ],
)
