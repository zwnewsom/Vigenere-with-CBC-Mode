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

// file preprocessing (remove special characters and spaces/ change upper to lower)
int processFile(FILE *inputFilePtr, FILE *plainTxtFilePtr)
{
    int charCount;
    char c;
    
    if (inputFilePtr == NULL)
        panic("ERROR: inputFilePtr is NULL.\n");
        
    if (plainTxtFilePtr == NULL)
        panic("ERROR: plainTxtFilePtr is NULL.\n");
        
    do 
    {
        c = getc(inputFilePtr);
        if (c >= 'A' && c <= 'Z')
        {
            c += 32;
            fprintf(plainTxtFilePtr, "%c", c);
            charCount++;
            continue;
        }
        else if (c >= 'a' && c <= 'z')
        {
            fprintf(plainTxtFilePtr, "%c", c);
            charCount++;
            continue; 
        }
    } while (c != EOF);
    
    if (charCount <= 0)
        panic("ERROR: no text to process in input file!\n");
    
    rewind(plainTxtFilePtr);
    
    return charCount;
}

blockInfo *createBlockInfo(char **array, int charCount)
{
    int i;
    
    if (array == NULL)
    {
        panic("ERROR: **argv is NULL in createCipherBlock()!\n");
        return NULL;
    }
    
    if (charCount <= 0)
    {
        panic("ERROR: plain.txt is empty!\n");
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
    
    // validate keyLength to avoid segfaults down the road
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

int encipher(blockInfo *info, FILE *plainTxtFilePtr, FILE *cipherTxtFilePtr)
{
    int i, j;
    
    // avoids segfaults
    if (info == NULL)
    {
        panic("ERROR: *info is NULL in encipher()!\n");
        return 1;
    }
    
    if (plainTxtFilePtr == NULL || cipherTxtFilePtr == NULL)
    {
        panic("ERROR: a NULL file pointer has been detected in encipher()!\n");
        return 1;
    }
        
    for (i = 0; !feof(plainTxtFilePtr); i++)
    {
        fgets(info->blocks[i], info->keyLength + 1, plainTxtFilePtr);
    }
    
    // pad remaining cells with 'x'
    if (info->remainder != 0)
        for (i = info->keyLength - 1; i > info->remainder - 1; i--)
            info->blocks[info->numBlocks][i] = 'x';
        
    // convert only the 0th block to cipher text using key and IV
    for (i = 0; i < info->keyLength; i++)
    {
        info->blocks[0][i] = ((((info->blocks[0][i] - 97) + (info->key[i] - 97) + (info->IV[i] - 97)) % 26) + 97);
    }
    
    fprintf(cipherTxtFilePtr, "%s", info->blocks[0]);
    
    /// encipher algorithm generalized form:
    // [(c1 - 97) + (c2 - 97) + (c3 - 97)] = x
    // ------------------------------------>(x mod 26) + 97 = enciphered character's ASCII value
    for (i = 1; i <= info->numBlocks; i++)
    {
        for (j = 0; j < info->keyLength; j++)
            info->blocks[i][j] = ((((info->blocks[i][j] - 97) + (info->key[j] - 97) + (info->blocks[i - 1][j] - 97)) % 26) + 97);
        fprintf(cipherTxtFilePtr, "%s", info->blocks[i]);
    }
    
    rewind(plainTxtFilePtr);
    rewind(cipherTxtFilePtr);
    
    return 0;
}

void printOutput(blockInfo *info, char **array, FILE *plain, FILE *cipher)
{
    char c;
    
    printf("===================================\n");
    printf("*           ./encipher            *\n");
    printf("===================================\n");
    printf("Input file: %s\n", array[1]);
    printf("Key: %s\n", info->key);
    printf("IV: %s\n", info->IV);
    printf("Block size: %d\n", info->keyLength);
    printf("\nPlaintext (after preprocessing):\n");
    
    c = fgetc(plain);
    while (c != EOF) 
    {
        printf("%c", c);
        c = fgetc(plain);
    }
    printf("\n");
    printf("\n# of plaintext characters (before padding): %d\n", info->charCount);
    printf("\nCiphertext:\n");
    
    c = fgetc(cipher);
    while (c != EOF) 
    {
        printf("%c", c);
        c = fgetc(cipher);
    }
    printf("\n");
    printf("\nCiphertext file: %s\n", "ciphered.txt");
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
    FILE *inputFilePtr = fopen(argv[1], "r");
    FILE *plainTxtFilePtr = fopen("plain.txt", "w+");
    FILE *cipherTxtFilePtr = fopen("cipher.txt", "w+");
    int i, charCount = processFile(inputFilePtr, plainTxtFilePtr);
    
    blockInfo *info = createBlockInfo(argv, charCount);
    
    encipher(info, plainTxtFilePtr, cipherTxtFilePtr);
    
    printOutput(info, argv, plainTxtFilePtr, cipherTxtFilePtr);
    
    destroyBlockInfo(info);
    
    fclose(inputFilePtr);
    fclose(plainTxtFilePtr);
    fclose(cipherTxtFilePtr);
      
    return 0;
}
