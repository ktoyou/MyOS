#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char path[] = "/etc/resolv.conf";
static const char generated[] = "nameserver 10.44.0.53\noptions single-request\n";
static const char renewed[] = "nameserver 10.44.0.54\noptions single-request\n";
static const char override[] = "nameserver 10.44.0.54\n";

static int fail(const char *message) {
    fprintf(stderr, "DNS guest FAIL: %s (errno=%d)\n", message, errno);
    return 1;
}

static int file_matches(int fd, const char *expected) {
    struct stat status;
    char data[128];
    size_t size = strlen(expected);
    return fstat(fd, &status) == 0 && S_ISREG(status.st_mode) && status.st_size == (off_t) size &&
        pread(fd, data, sizeof(data), 0) == (ssize_t) size && memcmp(data, expected, size) == 0 &&
        pread(fd, data, sizeof(data), size) == 0;
}

static int dir_matches(int expected) {
    DIR *directory = opendir("/etc");
    if (!directory) return 0;
    int found = 0;
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(directory))) {
        if (!strcmp(entry->d_name, "resolv.conf")) found++;
    }
    int error = errno;
    return closedir(directory) == 0 && !error && found == expected;
}

static int wait_for_file(int present) {
    for (int attempt = 0; attempt < 400; attempt++) {
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            if (present) return fd;
            close(fd);
        } else {
            if (errno != ENOENT) return -2;
            if (!present) return -1;
        }
        if (poll(NULL, 0, 25) != 0) return -2;
    }
    return -2;
}

static int override_test(int initial) {
    if (!file_matches(initial, override) || !dir_matches(1)) return fail("initial Live resolver file");
    if (close(initial) != 0) return fail("closing initial Live resolver file");
    static const char ready[] = "DNS override ready\n";
    if (write(STDOUT_FILENO, ready, sizeof(ready) - 1) != sizeof(ready) - 1)
        return fail("reporting override readiness");

    int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sock < 0) return fail("opening lease probe socket");
    const struct sockaddr_in local = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(0x0a2c0014u),
    };
    // Проверяем файл после назначения DHCP-адреса, когда возможна подмена.
    int bound = 0;
    for (int attempt = 0; attempt < 400; attempt++) {
        if (bind(sock, (const struct sockaddr *) &local, sizeof(local)) == 0) {
            bound = 1;
            break;
        }
        if (errno != EADDRNOTAVAIL || poll(NULL, 0, 25) != 0)
            return fail("waiting for lease in Live override boot");
    }
    if (!bound || close(sock) != 0) return fail("Live override lease");

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0 || !file_matches(fd, override) || !dir_matches(1) || close(fd) != 0)
        return fail("Live resolver file after DHCP");
    puts("DNS override PASS");
    return 0;
}

int main(void) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) return override_test(fd);
    if (errno != ENOENT || !dir_matches(0)) return fail("resolver file before DHCP");
    static const char ready[] = "DNS guest ready\n";
    if (write(STDOUT_FILENO, ready, sizeof(ready) - 1) != sizeof(ready) - 1)
        return fail("reporting DNS readiness");

    fd = wait_for_file(1);
    if (fd < 0 || !file_matches(fd, generated) || !dir_matches(1)) return fail("DHCP resolver file");
    struct stat snapshot, current;
    if (fstat(fd, &snapshot) != 0 || stat(path, &current) != 0 ||
        snapshot.st_ino != current.st_ino || snapshot.st_size != current.st_size ||
        lseek(fd, 0, SEEK_END) != snapshot.st_size || lseek(fd, 0, SEEK_SET) != 0)
        return fail("matching stat and fstat for current generation");

    const struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM};
    struct addrinfo *answers;
    int error = getaddrinfo("myos-dns.test.", NULL, &hints, &answers);
    if (error) {
        fprintf(stderr, "DNS guest getaddrinfo: %s (%d)\n", gai_strerror(error), error);
        return 1;
    }
    int found = 0;
    for (const struct addrinfo *record = answers; record; record = record->ai_next) {
        if (record->ai_family == AF_INET && record->ai_addrlen == sizeof(struct sockaddr_in)) {
            const struct sockaddr_in *address = (const struct sockaddr_in *) record->ai_addr;
            if (ntohl(address->sin_addr.s_addr) == 0x0a2c0064u) found = 1;
        }
    }
    freeaddrinfo(answers);
    if (!found) return fail("getaddrinfo A record");
    static const char resolved[] = "DNS guest resolved\n";
    if (write(STDOUT_FILENO, resolved, sizeof(resolved) - 1) != sizeof(resolved) - 1)
        return fail("reporting DNS resolution");

    if (wait_for_file(0) != -1 || !dir_matches(0)) return fail("resolver file after lease loss");
    if (!file_matches(fd, generated)) return fail("old resolver descriptor after lease loss");
    static const char absent[] = "DNS guest lease absent\n";
    if (write(STDOUT_FILENO, absent, sizeof(absent) - 1) != sizeof(absent) - 1)
        return fail("reporting missing lease");

    int replacement = wait_for_file(1);
    if (replacement < 0 || !file_matches(replacement, renewed) || !dir_matches(1) ||
        fstat(replacement, &current) != 0 ||
        snapshot.st_ino == current.st_ino || close(replacement) != 0)
        return fail("replacement resolver file and inode after new DHCP lease");
    if (!file_matches(fd, generated) || fstat(fd, &current) != 0 ||
        snapshot.st_ino != current.st_ino || close(fd) != 0)
        return fail("old resolver descriptor after DNS change");
    puts("DNS guest PASS");
    return 0;
}
