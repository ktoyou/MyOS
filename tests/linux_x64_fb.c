typedef unsigned int u32;
typedef unsigned long word;

static long call(word number, word a, word b, word c, word d, word e, word f) {
    register word r10 __asm__("r10") = d;
    register word r8 __asm__("r8") = e;
    register word r9 __asm__("r9") = f;
    __asm__ volatile("syscall" : "+a"(number) : "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return (long)number;
}

static long request(long fd, word command, void *data) {
    return call(16, fd, command, (word)data, 0, 0, 0);
}

static long write_at(long fd, const void *data, word count, word offset) {
    return call(18, fd, (word)data, count, offset, 0, 0);
}

static long read_at(long fd, void *data, word count, word offset) {
    return call(17, fd, (word)data, count, offset, 0, 0);
}

static u32 row[5120];

static int check(void) {
    static const char node[] = "/dev/fb0";
    long fd = call(2, (word)node, 2, 0, 0, 0, 0);
    if (fd < 0) return 1;
    word stat[18];
    if (call(5, fd, (word)stat, 0, 0, 0, 0) || (stat[3] & 0170000) != 0020000 ||
        stat[5] != (29u << 8) ||
        call(21, (word)node, 6, 0, 0, 0, 0) || call(21, (word)node, 1, 0, 0, 0, 0) != -13)
        return 2;
    struct { u32 words[40]; u32 canary; } var = {.canary = 0x12345678};
    struct { u32 words[20]; u32 canary; } fix = {.canary = 0x87654321};
    if (request(fd, 0x4600, var.words) || request(fd, 0x4602, fix.words) ||
        request(fd, 0x4602, (void *)1) != -14 || request(fd, 0x4601, var.words) != -25 ||
        request(0, 0x4602, fix.words) != -25 || var.canary != 0x12345678 || fix.canary != 0x87654321)
        return 3;
    u32 width = var.words[0], height = var.words[1], pitch = fix.words[12];
    u32 red = var.words[8], green = var.words[11], blue = var.words[14];
    word size = (word)pitch * height;
    if (width < 640 || width > sizeof(row) / sizeof(row[0]) || height < 480 || pitch < width * 4 ||
        var.words[2] != width || var.words[3] != height || var.words[6] != 32 ||
        green != 8 || (red != 0 && red != 16) || red + blue != 16 ||
        var.words[9] != 8 || var.words[12] != 8 || var.words[15] != 8 ||
        fix.words[4] || fix.words[5] || fix.words[6] != size || fix.words[7] || fix.words[9] != 2)
        return 4;
    long ro = call(2, (word)node, 0, 0, 0, 0, 0), wo = call(2, (word)node, 1, 0, 0, 0, 0);
    unsigned char bytes[4] = {0x23, 0x45, 0x67, 0x89};
    if (ro < 0 || wo < 0 || write_at(ro, bytes, 1, 0) != -9 || read_at(wo, bytes, 1, 0) != -9 ||
        write_at(fd, bytes, 4, size - 2) != 2 || write_at(fd, bytes, 1, size) != -28 ||
        write_at(fd, bytes, 1, size + 1) != -27 || read_at(fd, bytes, 1, size) != 0 ||
        write_at(fd, (void *)0x7ffffffffffful, 2, size) != -14 ||
        call(9, 0, 4096, 3, 1, fd, 0) != -19) return 5;
    bytes[0] = bytes[1] = 0;
    if (read_at(fd, bytes, 4, size - 2) != 2 || bytes[0] != 0x23 || bytes[1] != 0x45 ||
        bytes[2] != 0x67 || bytes[3] != 0x89) return 5;
    if (call(8, fd, 12, 0, 0, 0, 0) != 12) return 6;
    long duplicate = call(32, fd, 0, 0, 0, 0, 0);
    if (duplicate < 0 || call(1, duplicate, (word)bytes, 4, 0, 0, 0) != 4 ||
        call(8, fd, 0, 1, 0, 0, 0) != 16 || read_at(fd, bytes, 4, 12) != 4 ||
        call(8, fd, 0, 1, 0, 0, 0) != 16 || call(8, ro, 0, 1, 0, 0, 0) != 0)
        return 6;
    long pages = call(9, 0, 8192, 3, 0x22, -1, 0);
    if (pages < 0 || call(10, pages + 4096, 4096, 0, 0, 0, 0)) return 7;
    volatile unsigned char *edge = (void *)(pages + 4094);
    edge[0] = 0x55;
    edge[1] = 0xaa;
    if (write_at(fd, (const void *)edge, 4, 0) != 2) return 7;
    edge[0] = edge[1] = 0;
    if (read_at(fd, (void *)edge, 4, 0) != 2 || edge[0] != 0x55 || edge[1] != 0xaa)
        return 7;
    const u32 rgb[] = {0xde292f, 0x23b471, 0x365ed6, 0xefd487};
    u32 color[4];
    for (unsigned i = 0; i < 4; ++i)
        color[i] = ((rgb[i] >> 16) << red) | (rgb[i] & 0xff00) | ((rgb[i] & 0xff) << blue);
    for (u32 y = 0; y < height; ++y) {
        unsigned band = y >= height / 2 ? 2 : 0;
        for (u32 x = 0; x < width; ++x) row[x] = color[band + (x >= width / 2)];
        if (write_at(fd, row, width * 4, (word)y * pitch) != width * 4) return 8;
    }
    return 0;
}

__attribute__((noreturn)) void _start(void) {
    call(231, check(), 0, 0, 0, 0, 0);
    __builtin_trap();
}
