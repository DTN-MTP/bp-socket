#ifndef HASHMAP_H
#define HASHMAP_H

typedef struct hmap
{
	struct hnode **buckets;
	int num_buckets;
	int item_count;
} hmap_t;

hmap_t *hashmap_create(int num_buckets);
void hashmap_free(hmap_t *map);
void hashmap_deep_free(hmap_t *map, void (*free_func)(void *));
int hashmap_add(hmap_t *map, unsigned long key, void *value);
int hashmap_del(hmap_t *map, unsigned long key);
void *hashmap_get(hmap_t *map, unsigned long key);
void hashmap_print(hmap_t *map);

#endif
