#include "Enclave_u.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C"{
#endif

void ocall_printf(const char* str) 
{

    printf("%s", str);

}

void ocall_nlog( uint32_t level, const char* msg )
{

}

void ocall_malloc( size_t size, uint8_t** ret )
{
    /**
     * Refer to: https://en.cppreference.com/w/c/memory/malloc
     * If size is zero, the behavior of malloc is implementation-defined.
     * For example, a null pointer may be returned.
     * Alternatively, a non-null pointer may be returned; but such a pointer should not be dereferenced, and should be passed to free to avoid memory leaks.
     */
     if( size == 0 ){
         *ret = NULL;
     }else{
         *ret = ( uint8_t* )malloc( size );
         if ( *ret ) {
             memset( *ret, 0, size );
         }
     }
}

#ifdef __cplusplus
}
#endif


