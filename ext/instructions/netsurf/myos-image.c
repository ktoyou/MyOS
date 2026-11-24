#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <png.h>
#include <jpeglib.h>

#include "utils/utils.h"
#include "utils/errors.h"
#include "content/llcache.h"
#include "netsurf/bitmap.h"
#include "content/content_protected.h"
#include "content/content_factory.h"
#include "desktop/gui_internal.h"
#include "desktop/bitmap.h"
#include "image/image_cache.h"

static nserror raster_create(const content_handler *handler, lwc_string *mime,
        const struct http_parameter *params, llcache_handle *cache,
        const char *charset, bool quirks, struct content **result)
{
    struct content *content = calloc(1, sizeof(*content));
    if (!content)
        return NSERROR_NOMEM;
    nserror error = content__init(content, handler, mime, params, cache, charset, quirks);
    if (error != NSERROR_OK) {
        free(content);
        return error;
    }
    *result = content;
    return NSERROR_OK;
}

static struct bitmap *raster_decode(struct content *content)
{
    size_t length;
    const uint8_t *data = content__get_source_data(content, &length);
    unsigned *pixels = NULL;
    int width, height, alpha = 0;
    if (!data || length < 8 || length > INT_MAX)
        return NULL;
    int error;
    if (png_sig_cmp(data, 0, 8) == 0)
        error = png_decode_argb(data, length, &width, &height, &pixels, &alpha);
    else
        error = jpeg_decode_argb(data, length, &width, &height, &pixels, 1);
    if (error)
        return NULL;

    struct bitmap *bitmap = guit->bitmap->create(width, height, alpha ? BITMAP_NONE : BITMAP_OPAQUE);
    if (bitmap) {
        uint8_t *row = guit->bitmap->get_buffer(bitmap);
        size_t stride = guit->bitmap->get_rowstride(bitmap);
        for (int y = 0; y < height; y++, row += stride)
            memcpy(row, pixels + (size_t)y * width, width * sizeof(*pixels));
        /* На i386 число 0xAARRGGBB лежит в памяти как BGRA. */
        bitmap_format_to_client(bitmap, &(bitmap_fmt_t){ .layout = BITMAP_LAYOUT_B8G8R8A8 });
        guit->bitmap->modified(bitmap);
    }
    free(pixels);
    return bitmap;
}

static bool raster_complete(struct content *content)
{
    struct bitmap *bitmap = raster_decode(content);
    if (!bitmap)
        return false;
    content->width = guit->bitmap->get_width(bitmap);
    content->height = guit->bitmap->get_height(bitmap);
    content->size = (size_t)content->width * content->height * 4;
    if (image_cache_add(content, bitmap, raster_decode) != NSERROR_OK) {
        guit->bitmap->destroy(bitmap);
        return false;
    }
    content_set_ready(content);
    content_set_done(content);
    return true;
}

static nserror raster_clone(const struct content *old, struct content **result)
{
    struct content *copy = calloc(1, sizeof(*copy));
    if (!copy)
        return NSERROR_NOMEM;
    nserror error = content__clone(old, copy);
    if (error == NSERROR_OK &&
        (old->status == CONTENT_STATUS_READY || old->status == CONTENT_STATUS_DONE) &&
        !raster_complete(copy))
        error = NSERROR_CLONE_FAILED;
    if (error != NSERROR_OK) {
        content_destroy(copy);
        return error;
    }
    *result = copy;
    return NSERROR_OK;
}

static const content_handler raster_handler = {
    .create = raster_create, .data_complete = raster_complete,
    .destroy = image_cache_destroy, .redraw = image_cache_redraw,
    .clone = raster_clone, .get_internal = image_cache_get_internal,
    .type = image_cache_content_type, .is_opaque = image_cache_is_opaque,
};

static const char *raster_types[] = { "image/png", "image/jpeg", "image/pjpeg" };
nserror myos_raster_init(void);
CONTENT_FACTORY_REGISTER_TYPES(myos_raster, raster_types, raster_handler);
