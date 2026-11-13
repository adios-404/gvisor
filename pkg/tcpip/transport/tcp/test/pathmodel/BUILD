load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "pathmodel",
    testonly = 1,
    srcs = ["pathmodel.go"],
    importpath = "gvisor.dev/gvisor/pkg/tcpip/transport/tcp/test/pathmodel",
    visibility = ["//pkg/tcpip/transport/tcp:__subpackages__"],
    deps = [
        "//pkg/buffer",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/stack",
    ],
)

go_test(
    name = "pathmodel_test",
    size = "small",
    srcs = ["pathmodel_test.go"],
    embed = [":pathmodel"],
    deps = [
        "//pkg/buffer",
        "//pkg/refs",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/faketime",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/stack",
    ],
)
