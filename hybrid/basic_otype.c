/***
 * This example implements a simple cheri otype maker 
 * to show how cheri otype values are determined.
 * Function simple_maketype replicates cheri_maketype function.
 * Consider cheric.h for original cheri_maketype. 
 * Note: cheriintrin.h is not used in this example.
 ***/

#include "../include/print.h"
#include "include/utils.h"
#include <sys/sysctl.h>
#include <sys/types.h>

//- Create a global_sealcap to track the next cheri_otype -//
void *__capability global_sealcap;

uint64_t next; 

/*
 Replica of cheri_maketype with a different return type.
 Note that cheri_maketype's return type is otype, and 
 otype is typedefed long in cheriin.h
*/
void *__capability simple_maketype (void *__capability root_type, size_t tysz)
{
    void * __capability next_type;

    c = root_type;
    c = cheri_setoffset(next_type, tysz);   /* Set type as desired. */
    c = cheri_csetbounds(next_type, 1);     /* ISA implies length of 1. */
    c = cheri_andperm(next_type, CHERI_PERM_GLOBAL | CHERI_PERM_SEAL); /* Perms. */
    return (next_type);
}

int main() // Remove unused args
{
    printf("----------------------------------------\n");
    printf("CHERI_OTYPE_USER_MIN: %04x\n", CHERI_OTYPE_USER_MIN);
    printf("CHERI_OTYPE_USER_MAX: %04x\n", CHERI_OTYPE_USER_MAX);
    printf("----------------------------------------\n\n");

    //=- Init a global_sealing capability -=//
    
    //size_t global_sealcap_sz = sizeof(global_sealcap); // sizeof(global_sealcap);
    //printf("global_sealcap_sz: %lu\n", global_sealcap_sz);
    
    next = sizeof(global_sealcap); // sizeof(global_sealcap);

    //if (sysctlbyname("security.cheri.sealcap", &global_sealcap, &global_sealcap_sz, NULL, 0) < 0)
    if (sysctlbyname("security.cheri.sealcap", &global_sealcap, &next, NULL, 0) < 0)
    {
        printf("Fatal error. Cannot get `security.cheri.sealcap`.");
        exit(1);
    } 
    
    printf("** Global root sealcap\n");
    print_cap(global_sealcap);
    
    //=- Create arbitrary memory objects -=//
    size_t objsz_1 = sizeof(char);
    char * ptr_1 = malloc(objsz_1);
    void *__capability cap_1 = (__cheri_tocap int *__capability) ptr_1;
    write_ddc((void *__capability) cap_1);
    cap_1 = cheri_address_set((void *__capability) cap_1, (unsigned long) ptr_1);
    cap_1 = cheri_bounds_set((void *__capability) cap_1, objsz_1);
    cheri_perms_and(cap_1, CHERI_PERM_LOAD | CHERI_PERM_STORE | CHERI_PERM_LOAD_CAP);
    
    printf("** obj_cap_1 before sealing__________\n");
    print_cap(cap_1);
    
    void *__capability sealcap_1 = simple_maketype(global_sealcap, objsz_1);
    
    printf("** sealcap_1__________\n");
    print_cap(sealcap_1);
    
    void * __capability sealed_objcap = cheri_seal(cap_1, seal_cap_1);
    printf("** obj_cap_1 after sealing__________\n");
    print_cap(cap_1);
     
    
    size_t objsz_2 = sizeof(int) * 5;
    char * ptr_2 = malloc(objsz_2);
    
    //- Get a next type i.e. create a next sealing capability -//
    //size_t sealcap_size_1 = 7; // --> Random size is given to test how types are assigned
    //void *__capability sealcap_1 = alloc_type(sealcap_size_1);
    size_t sealcap_size_1 = global_sealcap_sz; // --> Random size is given to test how types are assigned
    void *__capability sealcap_1 = alloc_type(global_sealcap_sz);

    //- NOTE: Since this example is just to check otypes,
    //- we set arbitrary address ranges of code and data capability

    //- Create cheri_object_1 *code* cap -//

    void *sandbox_code_1_ubound = (void *) (((size_t) sandbox_1_func) + SANDBOX_CODE_SZ);
    cheriobj_1_codecap = cheri_seal(
        codecap_create((void (*)(void)) & sandbox_1_func, sandbox_code_1_ubound), sealcap_1);

    //- Create cheri_object_1 *data* cap -//

    //- Two cheri_objects' data addr ranges are set overlapped. Ignore the numbers for this example.
    //-//
    void *apprx_data_UB = __builtin_frame_address(0);

    size_t cheriobj_data_1_base = (size_t) apprx_data_UB - 1000; // approx
    size_t cheriobj_data_1_end = (size_t) apprx_data_UB;
    cheriobj_1_datacap = cheri_seal(
        datacap_create((void *) cheriobj_data_1_base, (void *) cheriobj_data_1_end), sealcap_1);

    //=- Setup cheri_object_2 -=//

    //- Create cheri_object_2 sealcap -//

    size_t sealcap_size_2 = 25; // arbitrary type size for sealcap2
    void *__capability sealcap_2 = alloc_type(sealcap_size_2);

    //- Create cheri_object_2 *code* cap -//

    void *cheriobj_2_code_base = (void *) (&sandbox_2_func);
    void *cheriobj_2_code_end = (void *) (((size_t) cheriobj_2_code_base) + SANDBOX_CODE_SZ);
    cheriobj_2_codecap = cheri_seal(
        codecap_create((void (*)(void))(&sandbox_2_func), cheriobj_2_code_end), sealcap_2);

    assert((size_t) &sandbox_1_func != (size_t) &sandbox_2_func);

    //- Create cheri_object_2 *data* cap -//
    void *cheriobj_2_data_base = (void *) ((size_t) apprx_data_UB - 1000); // approx
    cheriobj_2_datacap = cheri_seal(datacap_create(cheriobj_2_data_base, apprx_data_UB), sealcap_2);

    // Check
    assert(cheri_is_sealed(cheriobj_1_codecap));
    assert(cheri_is_sealed(cheriobj_1_datacap));
    assert(cheri_is_sealed(cheriobj_2_codecap));
    assert(cheri_is_sealed(cheriobj_2_datacap));


    printf(">>>> cheri_object_1__________________________\n");
    printf("Sealcap_1_user_defined_tysz : %04lx\n", sealcap_size_1);
    printf("___sealcap_1_info____\n");
    print_cap(sealcap_1);
    printf("___code_cap_1_sealed_info____\n");
    print_cap(cheriobj_1_codecap);
    printf("___data_cap_1_sealed_info____\n");
    print_cap(cheriobj_1_datacap);

    printf(">>>> cheri_object_2__________________________\n");

    printf("Sealcap_2_user_defined_tysz : %04lx\n", sealcap_size_2);
    printf("___sealcap_2_info____\n");
    print_cap(sealcap_2);
    printf("___code_cap_2_sealed_info____\n");
    print_cap(cheriobj_2_codecap);
    printf("___data_cap_2_sealed_info____\n");
    print_cap(cheriobj_2_datacap);

    printf(" ** code_1_type: %04x\n", cheri_type_get(cheriobj_1_codecap));
    printf(" ** data_1_type: %04x\n", cheri_type_get(cheriobj_1_datacap));
    printf(" ** code_2_type: %04x\n", cheri_type_get(cheriobj_2_codecap));
    printf(" ** data_2_type: %04x\n\n", cheri_type_get(cheriobj_2_datacap));

    // User-defined cheri_object's otype should be within valid range
    assert(CHERI_OTYPE_USER_MIN <= cheri_type_get(cheriobj_1_codecap) &&
           cheri_type_get(cheriobj_1_codecap) <= CHERI_OTYPE_USER_MAX);
    assert(CHERI_OTYPE_USER_MIN <= cheri_type_get(cheriobj_2_codecap) &&
           cheri_type_get(cheriobj_2_codecap) <= CHERI_OTYPE_USER_MAX);

    printf(" ** Success: all code/data capability types are within valid range ** \n");

    // Cheri_object_1 and 2's otypes should differ
    assert(cheri_type_get(cheriobj_1_codecap) != cheri_type_get(cheriobj_2_codecap));
    assert(cheri_type_get(cheriobj_1_datacap) != cheri_type_get(cheriobj_2_datacap));

    printf(" ** Success: object 1 and 2's types differ ** \n");

    // Each cheri_object's code and data address ranges are set the same,
    // but perms for code and data differ.
    // TODO: Test obj cap invoke
    assert(cheri_perms_get(cheriobj_1_codecap) != cheri_perms_get(cheriobj_1_datacap));
    assert(cheri_perms_get(cheriobj_2_codecap) != cheri_perms_get(cheriobj_2_datacap));
    printf(" ** Success: code and data capability perms differ ** \n");

    // TODO: cheri_invoke
    sandbox_1_func();
    sandbox_2_func();

    return 0;
}
