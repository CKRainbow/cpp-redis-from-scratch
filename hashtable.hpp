#include <inttypes.h>
#include <aio.h>
// intrusive data structure

const size_t K_MAX_LOAD_FACTOR = 8;
const size_t K_RESHAPING_WORK = 128;

struct HNode
{
    HNode *next;
    uint64_t hcode;
};

struct HTable
{
    HNode **table = nullptr;
    size_t mask = 0; // 2^n - 1 for module is slow we can use `hash(key) & (N - 1)`
    size_t size = 0; // key size
};

struct HMap
{
    HTable oldTable;
    HTable newTable;
    size_t migrate_pos = 0;
};

HNode *hm_lookup(HMap *map, HNode *key, bool (*eq)(HNode *, HNode *));
void hm_insert(HMap *map, HNode *node);
HNode *hm_delete(HMap *map, HNode *key, bool (*eq)(HNode *, HNode *));
size_t hm_size(HMap *map);
bool hm_foreach(HMap *map, bool (*cb)(HNode *, void *), void *arg);