#include <iconv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void){
    iconv_t cd;
    char src_utf8[20]="utf8编码";
    char *inbuf=src_utf8;
    int inlen=strlen(inbuf);
    int outlen=255;
    char *outbuf=(char *)malloc(outlen);
    
    cd=iconv_open("gb2312","utf-8");
    iconv(cd,&inbuf,(size_t *)&inlen,&outbuf,&outlen);
    printf("%x\n",outbuf);

    printf("heiheihei\n");

    iconv_close(cd);
    free(outbuf);
    
    return 0;    
}
