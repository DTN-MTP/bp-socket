#ifndef HASHMAP_STR_H
#define HASHMAP_STR_H

typedef struct hsmap
{
	struct hsnode **buckets;
	int num_buckets;
	int item_count;
} hsmap_t;

hsmap_t *str_hashmap_create(int num_buckets);
void str_hashmap_free(hsmap_t *map);
void str_hashmap_deep_free(hsmap_t *map, void (*free_func)(void *));
int str_hashmap_add(hsmap_t *map, char *key, void *value);
int str_hashmap_del(hsmap_t *map, char *key);
void *str_hashmap_get(hsmap_t *map, char *key);
void str_hashmap_print(hsmap_t *map);

#endif
