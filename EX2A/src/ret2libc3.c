#include <stdio.h>

void secure(void){ puts("hello"); }
void vuln(void){ char buf[100]; gets(buf); }
int main(void){ vuln(); return 0; }
