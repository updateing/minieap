#ifndef CHECKV4_H
#define CHECKV4_H

unsigned char *computeV4(const unsigned char *src, int len);
char *computePwd(const unsigned char *md5, const char* username, const char* password);
#endif
