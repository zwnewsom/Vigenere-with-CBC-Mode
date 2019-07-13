#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct blockInfo
{
    char **blocks;          // 2d char array to hold text in keyLength sized blocks
    char *key;              // string used to encipher each block
    char *IV;               // string used to initiate encipher algorithm
    int keyLength;          // must be between 2 and 10 characters inclusive
    int IVLength;           // must be equal to key length
    int charCount;          // number of characters in processed file
    int numBlocks;          // total characters divided by key length
    int remainder;          // dependent on whether keyLength divides evenly into charCount
} blockInfo;

void panic(char *s)
{
    // print to stderr, just in case normal output is being redirected to a file.
    fprintf(stderr, "%s", s);

    // exit with a non-normal return value.
    exit(1);
}

int count(FILE *inputFilePtr)
{
    int charCount = 0;
    char c;
    
    if (inputFilePtr == NULL)
    {
        panic("ERROR: inputFilePtr is NULL.\n");
        return 1;
    }
    
    c = fgetc(inputFilePtr);    
    while (c != EOF)
    {
        charCount++;
        c = fgetc(inputFilePtr);
    } 
    
    if (charCount <= 0)
        panic("ERROR: no text to process in input file!\n");
    
    rewind(inputFilePtr);
    
    return charCount;
}

blockInfo *createBlockInfo(char **array, int charCount)
{
    int i;
    
    // validate function parameters to avoid segfaults
    if (array == NULL)
    {
        panic("ERROR: **argv is NULL in createCipherBlock()!\n");
        return NULL;
    }
    
    if (charCount <= 0)
    {
        panic("ERROR: input file is empty!\n");
        return NULL;
    }
    
    blockInfo *info = malloc(sizeof(blockInfo));
    info->key = malloc(sizeof(char) * (strlen(array[2]) + 1));
    info->IV = malloc(sizeof(char) * (strlen(array[3]) + 1));
    
    // ensure calls to malloc() were successful; free any memory allocated up until that point
    if (info == NULL)
    {
        panic("ERROR: *block is NULL in createCipherBlock()!\n");
        free(info);
        return NULL;
    }
    
    if (info->key == NULL || info->IV == NULL)
    {
        panic("ERROR: malloc() failed in main.\n");
        free(info->key);
        free(info->IV);
        return NULL;
    }
    
    strcpy(info->key, array[2]);
    strcpy(info->IV, array[3]);
    
    info->keyLength = strlen(info->key);
    info->IVLength = strlen(info->IV);
    
    if (info->keyLength < 2 || info->keyLength > 10)
        panic("ERROR: key length must be between 2 and 10 characters inclusive!\n");
    
    if (info->keyLength != info->IVLength)
        panic("ERROR: key length must equal intialization vector length!\n");
        
    info->charCount = charCount;
    info->numBlocks = charCount / info->keyLength;// uses integer division to ensure strings map to correct indices
    info->remainder = charCount % info->keyLength;// uses mod to identify correct character indices
    
    if (info->remainder != 0)
        info->blocks = malloc(sizeof(char *) * info->numBlocks + 1);
    else
        info->blocks = malloc(sizeof(char *) * info->numBlocks);
    
    if (info->blocks == NULL)
    {
        panic("ERROR: malloc() failed to allocate space for **blocks in encipher().\n");
        free(info->blocks);
    }
    
    for (i = 0; i < ((info->remainder) == 0 ? info->numBlocks : info->numBlocks + 1); i++)
    {
        info->blocks[i] = malloc(sizeof(char) * info->keyLength + 1);
        if (info->blocks[i] == NULL)
        {
            panic("ERROR: malloc() failed to allocate space for blocks[i] in encipher().\n");
            free(info->blocks[i]);
        }
    }
    
    return info;
}

int decipher(blockInfo *info, FILE *decipheredTxtFilePtr, FILE *inputFilePtr)
{
    int i, j;
    
    // avoids segfaults
    if (info == NULL)
    {
        panic("ERROR: *info is NULL in encipher()!\n");
        return 1;
    }
    
    if (decipheredTxtFilePtr == NULL || inputFilePtr == NULL)
    {
        panic("ERROR: a NULL file pointer has been detected in encipher()!\n");
        return 1;
    }
        
    for (i = 0; !feof(inputFilePtr); i++)
    {
        fgets(info->blocks[i], info->keyLength + 1, inputFilePtr);
    }
    
    // decipher algorithm generalized form:
    // [(a - 97) - (b - 97) - (c - 97)] = x + (k26), where 'k' is some integer multiple of 26
    // --------------------------(k26 mod 26) + 97 = deciphered character's ASCII value
    for (i = info->numBlocks - 1; i >= 1; i--)
    {
        for (j = info->keyLength - 1; j >= 0 ; j--)
            info->blocks[i][j] = (((((info->blocks[i][j] - 97) - (info->key[j] - 97) - (info->blocks[i - 1][j] - 97)) + 104) % 26) + 97);
    }
        
    // convert only the 0th block to cipher text using key and IV
    for (i = 0; i < info->keyLength; i++)
        info->blocks[0][i] = (((((info->blocks[0][i] - 97) - (info->key[i] - 97) - (info->IV[i] - 97)) + 104) % 26) + 97);
        
    for (i = 0; i < info->numBlocks; i++)
        fprintf(decipheredTxtFilePtr, "%s", info->blocks[i]);
    
    rewind(decipheredTxtFilePtr);
    rewind(inputFilePtr);
    
    return 0;
}

void printOutput(blockInfo *info, char **array, FILE *plain, FILE *cipher)
{
    char c;
    
    printf("===================================\n");
    printf("*           ./decipher            *\n");
    printf("===================================\n");
    printf("Input file: %s\n", array[1]);
    printf("Key: %s\n", info->key);
    printf("IV: %s\n", info->IV);
    printf("Block size: %d\n", info->keyLength);
    printf("\nCipher Text (input):\n");
    
    c = fgetc(cipher);
    while (c != EOF) 
    {
        printf("%c", c);
        c = fgetc(cipher);
    }
    printf("\n");
    printf("\n# of plaintext characters (before padding): %d\n", info->charCount);
    printf("\nPlaintext:\n");
    
    c = fgetc(plain);
    while (c != EOF) 
    {
        printf("%c", c);
        c = fgetc(plain);
    }
    printf("\n");
    printf("\nPlaintext file: %s\n", "deciphered.txt");
    printf("# of padding characters: %d\n", info->keyLength - info->remainder);
    
    return;
}

blockInfo *destroyBlockInfo(blockInfo *info)
{
    int i;
    
    if (info == NULL)
        return NULL;
    
    for (i = 0; i < ((info->remainder) == 0 ? info->numBlocks : info->numBlocks + 1); i++)
        free(info->blocks[i]);
        
    free(info->blocks);
    free(info->key);
    free(info->IV);
    
    return NULL;
}
int main(int argc, char **argv)
{
    FILE *inputFilePtr = fopen(argv[1], "r+");
    FILE *decipheredTxtFilePtr = fopen("deciphered.txt", "w+");
    int i, charCount = count(inputFilePtr);
    
    blockInfo *info = createBlockInfo(argv, charCount);
    
    decipher(info, decipheredTxtFilePtr, inputFilePtr);
    
    printOutput(info, argv, decipheredTxtFilePtr, inputFilePtr);
    
    destroyBlockInfo(info);
    
    fclose(inputFilePtr);
    fclose(decipheredTxtFilePtr);
      
    return 0;
}


