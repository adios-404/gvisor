load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "simnet",
    testonly = 1,
    srcs = [
        "clock.go",
        "simnet.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/tcpip/transport/tcp/test/simnet",
    visibility = ["//pkg/tcpip/transport/tcp:__subpackages__"],
    deps = [
        "//pkg/buffer",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/seqnum",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/tcp",
        "//pkg/tcpip/transport/tcp/test/pathmodel",
        "//pkg/waiter",
    ],
)

go_test(
    name = "simnet_test",
    size = "small",
    srcs = ["simnet_test.go"],
    embed = [":simnet"],
    deps = [
        "//pkg/buffer",
        "//pkg/refs",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/seqnum",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/tcp",
        "//pkg/tcpip/transport/tcp/test/pathmodel",
    ],
)
