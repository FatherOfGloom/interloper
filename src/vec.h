#ifndef VEC_H_
#define VEC_H_

#include <string.h>
#include <assert.h>
#include <stdlib.h>

#define VEC_INIT_CAPACITY 256
#define VEC_GROWTH_MULTIPLIER 2

typedef struct Vec {
    void* items;
    size_t len;
    size_t capacity;
} Vec;

#define vec_is_empty(v) ((v)->len == 0)
#define vec_push(v, item_size, val) vec_append(v, item_size, (val), 1);
#define vec_is_null(v) ((v)->items == NULL)

void vec_append(Vec* v, size_t item_size, const void* new_items, size_t count);
void vec_free(Vec* v);
int vec_realloc(Vec* v, size_t item_size, size_t new_v_cap);
Vec vec_with_cap(size_t item_size, size_t cap);

#endif // VEC_H_