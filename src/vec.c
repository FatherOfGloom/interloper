#include "vec.h"

void vec_append(Vec* v, size_t item_size, const void* new_items, size_t count) {
    if (v->len + count > v->capacity) {
        if (v->capacity == 0) {
            v->capacity = v->init_capacity > 0 ? v->init_capacity : VEC_INIT_CAPACITY;
        }

        while (v->len + count > v->capacity) {
            v->capacity *= VEC_GROWTH_MULTIPLIER;
        }

        v->items = realloc(v->items, v->capacity * item_size);
        assert(v->items != NULL && "unlucky peperony");
        (void)memset(v->items + (v->len * item_size), 0, (v->capacity - v->len) * item_size);
    }

    (void)memcpy(v->items + (v->len * item_size), new_items, count * item_size);
    v->len += count;
}

void vec_pop(Vec* v, size_t item_size) {
    assert((v->len - item_size >= 0 || v->capacity == 0) && "cannot pop from an empty vec");
    assert((!vec_is_null(v)) && "cannot pop from a null vec");
    (void)memset(v->items + v->len - item_size, 0, item_size);   
    v->len = v->len - item_size;
}

void vec_free(Vec* v) {
    if (v->items) {
        free(v->items);
    }

    v->items = NULL;
    v->len = 0;
    v->capacity = 0;
}

Vec vec_with_cap(size_t item_size, size_t cap) {
    Vec v = {0};
    (void)vec_realloc(&v, item_size, cap);
    return v;
}

int vec_realloc(Vec* v, size_t item_size, size_t new_v_cap) {
    if (v->capacity >= new_v_cap) {
        return 0;
    }

    v->capacity = new_v_cap;
    v->items = realloc(v->items, new_v_cap * item_size);
    assert(v->items && "unlucky peperony");
    (void)memset(v->items + v->len, 0, (v->capacity - v->len) * item_size);

    return 1;
}

void vec_reset(Vec* v) {
    v->len = 0;
}