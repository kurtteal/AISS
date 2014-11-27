#include <stdio.h>
#include "protocol.h"
#include "com.h"

extern packet_t packet;

#define DEBUG OFF


void reset( )
{


}
char init( u32 keynum, u32 mode, u8 * Key , u8 * IV)
{
    //printf("Init...\n");
    return ' ';
}


char encrypt(u8 * data_in, u32 size_in, u8* data_out, u32 *size_out, u32 keynum,u8 * keyin,u8* IV)
{
	u32 mode = ROUNDS_10 | CBC_FLAG |FIRST_FLAG| ENCRYPT_FLAG;
  	init(  keynum,  mode, keyin ,  IV);
	return doFinal(data_in, size_in, data_out,size_out);


}
char decrypt(u8 * data_in, u32 size_in, u8* data_out, u32 * size_out,u32 keynum,u8* keyin,u8 *IV)
{
	u32 mode = ROUNDS_10 | CBC_FLAG |FIRST_FLAG| DECRYPT_FLAG;
	init(  keynum,  mode, keyin ,  IV);
	return doFinal(data_in, size_in, data_out,size_out);

}

char update_int(u8 * data_in, u32 size, u8 * data_out,u32 * rbytes, char fin_code)
{
    //printf("Before memcpy... Sizeof dataout: %d size: %d\n", sizeof(data_out), size);
    //printf("rbytes: %d\n", *rbytes);
	//memcpy( data_out, &(data_in[0]), (int)size );
    //printf("After memcpy...\n");

    int i = 0;
    while(i < size)
    {
        //XOR with 1
        data_out[i]=(char)(data_in[i] ^ (char)0xFF);
        i++;
    }
    //printf("After while...\n");
    *rbytes = size;
	return 1;
}


char  update(u8 * data_in, u32 size, u8 * data_out,u32 * size_out)
{
    //printf("Update...\n");
	return update_int(data_in, size,data_out, size_out,UPDATE_CODE);
}

char   doFinal_int(u8 * data_out,u32 *size_out)
{
	u32 n;
	char ret_code;

	/* Clear the update function internal buffer */
	ret_code  = update_int(NULL,0,data_out,&n,DOFINAL_CODE);
	/* Return number of received bytes*/
	*size_out = n;
	/* Return code*/
	return ret_code;
}

char   doFinal(u8 * data_in, u32 size,u8 * data_out,u32 *size_out)
{
    //printf("DoFinal...\n");
	*size_out = 0;
	/* Return code*/
	return 1;
}
