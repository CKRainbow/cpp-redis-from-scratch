#include <assert.h>
#include <stdlib.h>

#include "hashtable.hpp"

/*
 * ptr -> ptr -> ptr
 *  |      |      |
 *  v      v      v
 *  N      N      N
 */

static void h_init(HTable *ht, size_t size)
{
    assert(size > 0 && ((size - 1) & size) == 0); // n must be a power of 2
    ht->table = (HNode **)calloc(size, sizeof(HNode *));
    ht->mask = size - 1;
    ht->size = 0;
}

static void h_insert(HTable &ht, HNode *node)
{
    // TODO: check if there is a node with the same key?
    size_t pos = node->hcode & ht.mask;
    HNode *next = ht.table[pos];
    node->next = next;
    ht.table[pos] = node;
    ht.size++;
}

static HNode **h_lookup(HTable &ht, HNode *key, bool (*eq)(HNode *a, HNode *b)) // a callback function
{
    if (!ht.table)
        return nullptr;

    size_t pos = key->hcode & ht.mask;
    HNode **from = &ht.table[pos]; // why use double pointer? `from equals to &HNode.next`
    for (HNode *cur = *from; (cur = *from) != nullptr; from = &cur->next)
    {
        if (cur->hcode == key->hcode && eq(cur, key))
        {
            return from;
        }
    }
    return nullptr;
}

static HNode *h_detach(HTable &ht, HNode **from)
{
    HNode *node = *from;
    *from = node->next; // change previous node's next
    ht.size--;
    return node; // we do not need to care about if the node is the head node or not
}

static void hm_trigger_rehashing(HMap *map)
{
    map->oldTable = map->newTable;
    h_init(&map->newTable, (map->newTable.mask + 1) << 2);
    map->migrate_pos = 0;
}

static void hm_help_rehashing(HMap *map)
{
    size_t nwork = 0;
    while (nwork < K_RESHAPING_WORK && map->oldTable.size > 0)
    {
        HNode **from = &map->oldTable.table[map->migrate_pos];
        if (!*from)
        {
            map->migrate_pos++;
            continue; // empty slot
        }
        HNode *node = h_detach(map->oldTable, from);
        h_insert(map->newTable, node);
        nwork++;
    }
    if (map->oldTable.size == 0 && map->newTable.table)
    {
        free(map->oldTable.table);
        map->oldTable = HTable{};
    }
}

HNode *hm_lookup(HMap *map, HNode *key, bool (*eq)(HNode *, HNode *))
{
    hm_help_rehashing(map);
    HNode **from = h_lookup(map->newTable, key, eq);
    if (!from)
    {
        from = h_lookup(map->oldTable, key, eq);
    }
    return from ? *from : nullptr;
}

HNode *hm_delete(HMap *map, HNode *key, bool (*eq)(HNode *, HNode *))
{
    hm_help_rehashing(map);
    if (HNode **from = h_lookup(map->newTable, key, eq))
    {
        return h_detach(map->newTable, from);
    }
    if (HNode **from = h_lookup(map->oldTable, key, eq))
    {
        return h_detach(map->oldTable, from);
    }
    return nullptr;
}

void hm_insert(HMap *map, HNode *node)
{
    if (!map->newTable.table)
    {
        h_init(&map->newTable, 4);
    }

    h_insert(map->newTable, node);

    if (!map->oldTable.table)
    {
        size_t shreshold = (map->newTable.mask + 1) * K_MAX_LOAD_FACTOR;
        if (map->newTable.size >= shreshold)
        {
            hm_trigger_rehashing(map);
        }
    }
    hm_help_rehashing(map);
}
