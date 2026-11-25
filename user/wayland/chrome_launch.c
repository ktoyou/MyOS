#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static const char chrome[] = "/opt/google/chrome/chrome";
static const char compositor[] = "/myos/wayland-compositor";
static const char wayland_socket[] = "/tmp/wayland-0";

static int read_url(char url[], size_t capacity) {
    FILE *config = fopen("/myos/chrome-url", "r");
    if (!config) {
        if (errno != ENOENT) return -1;
        memcpy(url, "about:blank", sizeof("about:blank"));
        return 0;
    }
    int valid = fgets(url, (int)capacity, config) != NULL;
    char *newline = valid ? strchr(url, '\n') : NULL;
    if (newline) *newline = 0;
    valid = newline && fgetc(config) == EOF && !ferror(config);
    fclose(config);
    if (valid && (!strcmp(url, "about:blank") || !strncmp(url, "http://", 7) ||
                  !strncmp(url, "https://", 8))) return 0;
    errno = EINVAL;
    return -1;
}

static int wait_for_wayland(void) {
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    memcpy(address.sun_path, wayland_socket, sizeof(wayland_socket));
    for (unsigned retry = 0; retry < 200; ++retry) {
        int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) return -1;
        int connected = connect(fd, (const struct sockaddr *)&address,
                                offsetof(struct sockaddr_un, sun_path) + sizeof(wayland_socket));
        int error = errno;
        close(fd);
        if (!connected) return 0;
        if (error != ENOENT && error != ECONNREFUSED) {
            errno = error;
            return -1;
        }
        if (poll(NULL, 0, 25) < 0) return -1;
    }
    errno = ETIMEDOUT;
    return -1;
}

int main(void) {
    char url[4096];
    if (read_url(url, sizeof(url))) {
        perror("Chrome URL");
        return 1;
    }

    pid_t child = fork();
    if (child < 0) {
        perror("fork compositor");
        return 1;
    }
    if (!child) {
        char *const args[] = {(char *)compositor, (char *)wayland_socket, NULL};
        char *const env[] = {NULL};
        execve(compositor, args, env);
        perror("exec compositor");
        _exit(1);
    }
    if (wait_for_wayland()) {
        perror("connect Wayland");
        return 1;
    }

    /* При недоступной сети окно всё равно должно появиться. */
    if (strcmp(url, "about:blank"))
        for (unsigned retry = 0; retry < 400 && access("/etc/resolv.conf", R_OK); ++retry)
            if (poll(NULL, 0, 25) < 0) break;

    /* V8 CodeRange требует отдельной поддержки W^X в MyOS. */
    char *const args[] = {
        (char *)chrome, "--ozone-platform=wayland", "--disable-gpu", "--js-flags=--jitless",
        "--window-size=800,600", "--no-first-run", "--no-default-browser-check",
        "--disable-background-networking", "--enable-logging=stderr",
        "--user-data-dir=/tmp/myos-chrome-profile", url, NULL,
    };
    char *const env[] = {
        "HOME=/tmp", "XDG_RUNTIME_DIR=/tmp", "WAYLAND_DISPLAY=wayland-0",
        access("/myos/chrome-debug", F_OK) == 0 ? "WAYLAND_DEBUG=client" : NULL, NULL,
    };
    execve(chrome, args, env);
    perror("exec Chrome");
    return 1;
}
