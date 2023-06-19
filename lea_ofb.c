#include <openssl/lea.h>
#include <openssl/modes.h>

void LEA_ofb128_encrypt(const unsigned char *in, unsigned char *out,
	size_t length, const LEA_KEY *key,
	unsigned char *ivec, int *num)
{
	CRYPTO_ofb128_encrypt(in,out,length,key,ivec,num,(block128_f)LEA_encrypt);
}
