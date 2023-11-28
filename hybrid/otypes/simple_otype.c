/***
    * For morello-hybrid mode 
    This example implements a simple cheri type allocator 
    to show how cheri otype values are made.
    This replicates libcheri's functions such as cheri_maketype 
    and libcheri_alloc_type_capability with some changes. 
    Consider comments above each function definition.
    
    *** NOTE *** 
    This example disabled cheriintrin.h just to show
    simple otype making and otype allocation.
    It is highly recommended to use cheriintrin.h instead of 
    disabling cherriintrinh and using cheri.h/cheric.h.
 ***/

#include "include/print.h"
#include "../include/utils.h"
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/stdatomic.h>
#include <assert.h>

#define SEALING_ROOT_SZ 1

/*
    Root sealing capability -//
*/
void *__capability sealing_root;

/*
    A variable to track a next otype  -//
*/
static _Atomic(uint64_t) type_next = SEALING_ROOT_SZ;

/*
    Creating a data capability to be sealed  
*/
static 
void *__capability 
datacap_create(void *LB, size_t sz_data) // LB: lower bound, base
{
    void *__capability datacap;

    datacap = cheri_ptrperm(LB, 
                            sz_data,
                            CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | 
                            CHERI_PERM_STORE | CHERI_PERM_LOAD_CAP |
                            CHERI_PERM_STORE_CAP | CHERI_PERM_STORE_LOCAL_CAP);
    return (datacap);
}

/* 
    __simple_maketype replicates cheri_maketype 
    with a minor change in its function type --
    while return type of cheri_maketype is otype_t, 
    simple_maketype's is capability itself without casting.
    Note: In cheriintrin.h, 
            typedef long cheri_otype_t (*not* otype_t).   
*/
static __inline 
void * __capability 
simple_maketype(void * __capability root_type, register_t type)
{
        void * __capability c;

        c = root_type;
        c = cheri_setoffset(c, type);   /* Set type as desired. */
        c = cheri_setbounds(c, 1);     /* ISA implies length of 1. */
        c = cheri_andperm(c, CHERI_PERM_GLOBAL | CHERI_PERM_SEAL); /* Perms. */
        return (c);
}
/* 
    simple_alloc_type_capability replicates cheri's 
    libcheri_alloc_type_capability with following change -- 
    (1) While cheri_alloc_type_capability takes two arguments 
        (&type_next, CHERI_OTYPE_USER_MAX for arguments), and
        adds 1 to type_next,
        simple_alloc_type_capability takes type_size instead of MAX,
        and increases type_next by the type_size.
    (2) While libcheri_alloc_type_capability initialises a root sealing cap
        on first use, this example initialises it in main function,
        not in simple_alloc_type_capability function.
*/

static inline 
void * __capability
simple_alloc_type_capability(_Atomic(uint64_t) *source, uint64_t type_size)
{
	void * __capability new_type_cap;
	uint64_t next;

	// This counter should be strictly monotonic.
	next = atomic_fetch_add_explicit(source, type_size, memory_order_relaxed);

    // Type must be within userspace otypes 
	if (next > CHERI_OTYPE_USER_MAX) {
		return (NULL);
	}
    
    // In this example, root object-type capability  
    new_type_cap = simple_maketype(sealing_root, next);
    return (new_type_cap);
}

int main() // Remove unused args
{
    // Init a global sealing_root capability -=//
    size_t sealing_root_sz = sizeof(sealing_root);
    
    if (sysctlbyname("security.cheri.sealcap", &sealing_root, &sealing_root_sz, NULL, 0) < 0)
    {
        printf("Fatal error. Cannot get `security.cheri.sealcap`.");
        exit(1);
    }
   
    /***
    *   otype 0x0 ~ 0x3      : reserved by morello,
    *         0x4 ~ USER_MAX : available for userspace
    ***/

    printf("> Sealing root: \n");
    print_cap(sealing_root);
    
    /***
    * Create 1st sealed data capability -=//
    ***/

    //- Creating a next sealing cap i.e. get a next type with size tysz_1 
    uint64_t tysz_1 = 3;   
    void *__capability sealcap_1 = simple_alloc_type_capability (&type_next, tysz_1);
    
    //- Allocate a memory and create a datacap 
    size_t dtsz_1 = 16;
    void * dtptr_1 = malloc (dtsz_1);
    void * __capability datacap_1 = datacap_create(dtptr_1, dtsz_1); 
    
    printf("** Creating 1st sealing cap and datacap\n");
    printf("> sealcap_1 (tysz= %04lx): \n", tysz_1);
    print_cap(sealcap_1);
    printf("> datacap_1 before sealing: \n");
    print_cap(datacap_1);

    // Sealing datacap with a sealing cap
    void * __capability sealed_dc_1 = cheri_seal(datacap_1, sealcap_1);
   
    // sealed_dc_1's otype is 5 (== sealing_root's value (0x4) + SEALING_ROOT_SZ)
    printf("> data_cap_1 after sealing: \n");
    print_cap(sealed_dc_1);

    /***
    * Create 2nd sealed data capability -=//
    ***/
    
    //- Create a next sealing cap with size tysz_2 
    uint64_t tysz_2 = 4;   
    void *__capability sealcap_2 = simple_alloc_type_capability (&type_next, tysz_2);

    size_t dtsz_2 = 32;
    void * dtptr_2 = malloc (dtsz_2);
    void * __capability datacap_2 = datacap_create(dtptr_2, dtsz_2); 
    
    printf("** Creating 2nd sealing cap and datacap\n");
    printf("> sealcap_2 (tysz= %04lx): \n", tysz_2);
    print_cap(sealcap_2);
    printf("> data_cap_2 before sealing \n");
    print_cap(datacap_2);
   
    // Sealing datacap with a sealing cap
    void * __capability sealed_dc_2 = cheri_seal(datacap_2, sealcap_2);

    // sealed_dc_2's otype is 8 (== sealcap_1's value + tysz_1) 
    printf("> data_cap_2 after sealing \n");
    print_cap(sealed_dc_2);
    
    // Check if both datacap are sealed
    assert(cheri_is_sealed(sealed_dc_1));
    assert(cheri_is_sealed(sealed_dc_2));

    // Check if both types are within valid range
    assert(CHERI_OTYPE_USER_MIN <= __builtin_cheri_type_get(sealed_dc_1) &&
           __builtin_cheri_type_get(sealed_dc_1) <= CHERI_OTYPE_USER_MAX);
    assert(CHERI_OTYPE_USER_MIN <= __builtin_cheri_type_get(sealed_dc_2) &&
           __builtin_cheri_type_get(sealed_dc_2) <= CHERI_OTYPE_USER_MAX);

    printf("> CHERI_OTYPE_USER_MIN: %04x\n", CHERI_OTYPE_USER_MIN);
    printf("> CHERI_OTYPE_USER_MAX: %04x\n", CHERI_OTYPE_USER_MAX);
    printf("** Success: all code/data capability types are within valid range ** \n");

    // Check if types differ
    assert(__builtin_cheri_type_get(sealed_dc_1) != __builtin_cheri_type_get(sealed_dc_2));
    printf("** Success: object 1 and 2's types differ ** \n");

    return 0;

}
