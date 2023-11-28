/***
    otype.c

    FIXME: this is for simple_otype.c
    This example implements a simple cheri type allocator 
    to show how cheri otype values are made.
    This replicates libcheri's functions such as cheri_maketype 
    and libcheri_alloc_type_capability with some changes. 
    Consider comments above each function definition.
    *** NOTE *** 
    This example does not use cheriintrin.h. 
    It is highly recommended to use cheriintrin.h instead of 
    disabling cherriintrinh and using cheri.h/cheric.h.
    This example disabled cheriintrin.h just to show
    simple otype making and otype allocation.
 ***/

#include "../../include/common.h"
#include "../include/utils.h"
#include <cheri/cheri.h>
#include <cheri/cheric.h>
#include <machine/sysarch.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/stdatomic.h>
#include <assert.h>
#include <stdlib.h>

#define SANDBOX_CODE_SZ 1024

// cheri_object test
struct cheri_object obj1;
static void *__capability codecap1;
static void *__capability datacap1;

/*
    Root sealing capability -//
*/
void *__capability sealing_root;

/*
    A variable to track a next otype  -//
*/

static _Atomic(uint64_t) type_next = 1;

/*
    Creating a data capability to be sealed  
*/

static void *__capability codecap_create(void (*sandbox_base)(void), void *sandbox_end)
{
    void *__capability codecap;

#ifdef __CHERI_PURE_CAPABILITY__
    (void) sandbox_end;
    codecap = cheri_andperm(sandbox_base, CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_EXECUTE);
#else
    codecap = cheri_codeptrperm(sandbox_base, (size_t) sandbox_end - (size_t) sandbox_base,
                                CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_EXECUTE);
#endif
    return (codecap);
}


/*
    Creating a data capability to be sealed  
*/
static 
void *__capability 
datacap_create(void *sandbox_base, void * sandbox_end) // LB: lower bound, base
{
    void *__capability datacap;

    datacap = cheri_ptrperm(sandbox_base, // TODO: define sandbox_base/end
                            (size_t) sandbox_end - (size_t) sandbox_base,
                            CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | 
                            CHERI_PERM_STORE | CHERI_PERM_LOAD_CAP |
                            CHERI_PERM_STORE_CAP | CHERI_PERM_STORE_LOCAL_CAP);
    return (datacap);
}

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
    new_type_cap = cheri_maketype(sealing_root, next);
    return (new_type_cap);
}

__attribute__((cheri_ccallee))
//__attribute__((cheri_method_suffix("_cap")))
__attribute__((cheri_method_class(obj1)))
void func1();

void func2();

int main() // Remove unused args
{
    printf("-->> otype_t\t\t:: %lu\n", sizeof(otype_t));
    printf("-->> cheri_otype_t\t:: %lu\n", sizeof(cheri_otype_t));
    // Init a global sealing_root capability -=//
    size_t sealing_root_sz = sizeof(sealing_root);
    
    if (sysctlbyname("security.cheri.sealcap", &sealing_root, &sealing_root_sz, NULL, 0) < 0)
    {
        printf("Fatal error. Cannot get `security.cheri.sealcap`.");
        exit(1);
    }
    
    /***
    * Create 1st sealed data capability -=//
    ***/

    //- Creating a next sealing cap i.e. get a next type with size tysz_1 
    void *__capability sealcap_1 = simple_alloc_type_capability (&type_next, 1);
    
//- Create cheri_object_1 *code* cap -//

    void *codeUB1 = (void *) (((size_t)func1) + SANDBOX_CODE_SZ);
    codecap1 = cheri_seal(codecap_create((void (*)(void))&func1, codeUB1), 
                          sealcap_1);

    //- Create cheri_object_1 *data* cap -//

    //- Two cheri_objects' data addr ranges are set overlapped. Ignore the numbers for this example.
    //-//
    void *apprx_data_UB = __builtin_frame_address(0);

    size_t database1 = (size_t) apprx_data_UB - 1024; // approx
    size_t dataend1 = (size_t) apprx_data_UB;
    datacap1 = cheri_seal(datacap_create((void *) database1, 
                         (void *) dataend1), sealcap_1);

    // Check if code/datacaps are sealed
    assert(cheri_is_sealed(codecap1));
    assert(cheri_is_sealed(datacap1));
    
    // Check if their types are the same
    assert(cheri_type_get(codecap1) == cheri_type_get(datacap1));
    
    printf("\n** codecap1 \n");
    pp_cap(codecap1);
    printf("\n** datacap1 \n");
    pp_cap(datacap1);

    // Code/datacaps perms should differ
    assert(cheri_perms_get(codecap1) != cheri_perms_get(datacap1));
    
    // fill obj
    obj1.co_codecap = codecap1;
    obj1.co_datacap = datacap1;
    
    // call func1 (ccallee)
    func1();
    
    // call func2 (NOT ccallee)
    func2();

    printf("*******  Success  ****************\n");

    return 0;

}

void func1()
{
    printf("--> end_of_func1\n");
}

void func2()
{
    printf("--> end_of_func2\n");
}

