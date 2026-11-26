#include <stdio.h>
#include <stdlib.h>

void secure(void){ system("/bin/sh"); }
void vuln(void){ char buf[100]; gets(buf); }
int main(void){ vuln(); return 0; }
