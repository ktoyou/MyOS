#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#define NSS_PATH "/tmp/.local/share/pki/nssdb"

static int copy_database(const char *name) {
    char path[128], buffer[4096];
    snprintf(path, sizeof(path), "/myos/chrome-test-nss/%s", name);
    int source = open(path, O_RDONLY | O_CLOEXEC);
    if (source < 0) { perror(path); return -1; }
    snprintf(path, sizeof(path), NSS_PATH "/%s", name);
    int dest = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (dest < 0) { perror(path); close(source); return -1; }

    int result = 0;
    for (;;) {
        ssize_t count = read(source, buffer, sizeof(buffer));
        if (!count) break;
        if (count < 0) { perror("NSS read"); result = -1; break; }
        for (ssize_t offset = 0; offset < count;) {
            ssize_t written = write(dest, buffer + offset, count - offset);
            if (written <= 0) { perror("NSS write"); result = -1; break; }
            offset += written;
        }
        if (result) break;
    }
    if (close(source)) result = -1;
    if (close(dest)) result = -1;
    return result;
}

int main(void) {
    if (!access("/myos/chrome-test-ml", F_OK)) {
        /* Chrome загружает эту библиотеку по абсолютному пути до включения seccomp. */
        void *library = dlopen("/opt/google/chrome/liboptimization_guide_internal.so", RTLD_NOW | RTLD_LOCAL);
        if (!library) { fprintf(stderr, "ChromeML: %s\n", dlerror()); return 1; }
        if (dlclose(library)) { fprintf(stderr, "ChromeML: %s\n", dlerror()); return 1; }
        fputs("ChromeML library loaded\n", stderr);
    }

    /* SQLite открывает NSS с записью. Копируем базу из Live в /tmp до старта штатного загрузчика. */
    static const char *directories[] = {"/tmp/.local", "/tmp/.local/share", "/tmp/.local/share/pki", NSS_PATH};
    for (unsigned i = 0; i < sizeof(directories) / sizeof(*directories); ++i)
        if (mkdir(directories[i], 0700)) { perror(directories[i]); return 1; }
    if (copy_database("cert9.db") || copy_database("key4.db") || copy_database("pkcs11.txt")) return 1;

    char *const arguments[] = {"/myos/chrome-launch-real", NULL};
    char *const environment[] = {NULL};
    execve(arguments[0], arguments, environment);
    perror("exec chrome-launch");
    return 1;
}
