#include <stdio.h>
#include <string.h>

const char *reagent_code = "00419713568259015526";
const char *reagent_date = "20200116";

char code_buf[32];
char date_buf[32];

char *f(const char *str)
{
	if (strlen(str) == 20) {
		strcpy(code_buf, str);
		return code_buf;
	} else if (strlen(str) == 8) {
		strcpy(date_buf, str);
		return date_buf;
	}
	return NULL;
}

int main(void)
{	
	printf("%s\n", f(reagent_code));
	printf("%s\n", f(reagent_date));
	return 0;
}