#include <stdio.h>

char array[4]; // 0x407070

// Turns out DEADBEEF is already used in XP
int f(int a)
{
	if (a == 0xdead0000)
		return a + 0xbeee;
	else if (a == 0xbeee)
		return a + 0xdead0000;
	else
		return 0xcafebabe;
}

int main(void)
{
	int a = 0xdead0000;
	int b = 0xbeee;
	int c = 0;
	
	printf("f a: %x\n", f(a));
	printf("f b: %x\n", f(b));
	printf("f c: %x\n", f(c));
	
	int   d = f(a);
	char *p = (char *)&d;
	
	int i;
	for (i = 0; i < 4; i++) {
		array[i] = *p;
		p++;
	}
	
	for (i = 0; i < 4; i++) {
		printf("%x\n", array[i]);
	}
	return 0;
}