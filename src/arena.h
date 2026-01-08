#ifndef ARENA_H_
#define ARENA_H_

#include <stddef.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

#ifndef ARENA_DEFAULT_ALIGNMENT
  #define ARENA_DEFAULT_ALIGNMENT (2 * sizeof(void*))
#endif

#ifndef ARENA_DEFAULT_CAP
  #define ARENA_DEFAULT_CAP (8 * 1024)
#endif

#define arena_panic(...)              \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        exit(0);                      \
    } while (0)

#define arena_nonnull(this)                                        \
    __extension__({                                                \
        void* _ptr = (this);                                       \
        if (!_ptr) {                                               \
            arena_panic("f:%s l:%d ERR: %s\n", __FILE__, __LINE__, \
                        "unwrap on a null value.");                \
        }                                                          \
        _ptr;                                                      \
    })

typedef struct ArenaChunk {
    struct ArenaChunk* next;
    size_t len;
    size_t cap;
    char memory[];
} ArenaChunk;

ArenaChunk* arena_chunk_alloc(size_t size_bytes);

typedef struct Arena {
    ArenaChunk* start;
    ArenaChunk* end;
} Arena;

void* arena_alloc(Arena* a, size_t size_bytes);
void* arena_alloc_aligned(Arena* a, size_t size_bytes, size_t alignment);
void arena_free(Arena* a);
void arena_reset(Arena* a);

#endif // ARENA_H_

#ifdef ARENA_IMPLEMENTATION

int is_power_of_two(uintptr_t ptr) {
    return (ptr & (ptr - 1)) == 0;
}

uintptr_t align_ptr(uintptr_t ptr, size_t alignment) {
    uintptr_t _ptr, _alignment, modulo;

    assert(is_power_of_two(alignment));
    _ptr = ptr;
    _alignment = (uintptr_t) alignment;
    modulo = _ptr & (_alignment - 1);

    if (modulo != 0) {
        _ptr += _alignment - modulo;
    }

    return _ptr;
}

ArenaChunk* arena_chunk_alloc(size_t size_bytes) {
    size_t cap = ARENA_DEFAULT_CAP < size_bytes ? size_bytes : ARENA_DEFAULT_CAP;

    size_t allocation_size = sizeof(ArenaChunk) + sizeof(uintptr_t) * cap;
    ArenaChunk* arena_chunk = (ArenaChunk*)arena_nonnull(malloc(allocation_size));
    arena_chunk->next = NULL;
    arena_chunk->len = 0;
    arena_chunk->cap = cap;

#if defined(ARENA_LOG)
    fprintf(stderr, "ARENA: Allocated a region with capacity: %zu bytes\n", arena_chunk->cap);
#endif

    return arena_chunk;
}

void arena_chunk_free(ArenaChunk* arena_chunk) {
    free(arena_chunk);
}

void* arena_alloc(Arena* a, size_t size_bytes) {
    return arena_alloc_aligned(a, size_bytes, ARENA_DEFAULT_ALIGNMENT);
}

void* arena_alloc_aligned(Arena* a, size_t size_bytes, size_t alignment) {
    if (a->end == NULL) {
        assert(a->start == NULL);
        a->end = arena_chunk_alloc(size_bytes);
        a->start = a->end;
    }

    uintptr_t current_ptr = (uintptr_t)a->end->memory + (uintptr_t)a->end->len;
    uintptr_t offset = align_ptr(current_ptr, alignment) - (uintptr_t)a->end->memory;

    while (offset + size_bytes > a->end->cap && a->end->next) {
        a->end = a->end->next;
        current_ptr = (uintptr_t)a->end->memory + (uintptr_t)a->end->len;
        offset = align_ptr(current_ptr, alignment) - (uintptr_t)a->end->memory;
    }

    if (offset + size_bytes > a->end->cap) {
        assert(a->end->next == NULL);
        a->end->next = arena_chunk_alloc(size_bytes);
        a->end = a->end->next;
    }

#if defined(ARENA_LOG)
    fprintf(
        stderr,
        "ARENA: alloc called. Prev len: %zu allocation size: %zu aligned offset: %zu\n",
        a->end->len, size_bytes, offset);
#endif

    void* new_ptr = &a->end->memory[offset];
    a->end->len = offset + size_bytes;
    memset(new_ptr, 0, size_bytes);

    return new_ptr;
}

void arena_free(Arena* a) {
    ArenaChunk* current = a->start;
    while (current) {
        ArenaChunk* tmp = current;
        current = current->next;
        arena_chunk_free(tmp);
    }

    a->start = NULL;
    a->end = NULL;
}

void arena_reset(Arena* a) {
    ArenaChunk* current = a->start;

    while (current) {
        current->len = 0;
        current = current->next;
    }

    a->end = a->start;
}

#endif // ARENA_IMPLEMENTATION