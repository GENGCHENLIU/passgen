/*
To the extent possible under law, the author(s) have dedicated all copyright
and related and neighboring rights to this software to the public domain
worldwide. This software is distributed without any warranty.

You should have received a copy of the CC0 Public Domain Dedication along with
this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <math.h>
#include <limits.h>
#include <sys/random.h>

void printHelp() {
	// too lazy to write an actual man page
	fputs(
		"NAME\n"
		"	passgen - password generator\n"
		"\n"
		"SYNOPSIS\n"
		"	passgen [OPTION...] [LENGTH]\n"
		"\n"
		"DESCRIPTION\n"
		"	Generate cryptographically secure passwords of LENGTH characters,\n"
		"	default length is 22.\n"
		"\n"
		"OPTIONS\n"
		"	+l, --enable-lower\n"
		"		enables lowercase letters to be generated, default\n"
		"	-l, --disable-lower\n"
		"		disables lowercase letters\n"
		"	+u, --enable-upper\n"
		"		enables uppercase letters to be generated, default\n"
		"	-u, --disable-upper\n"
		"		disables uppercase letters\n"
		"	+n, --enable-number\n"
		"		enables numbers to be generated, default\n"
		"	-n, --disable-number\n"
		"		disables numbers\n"
		"	+s, --enable-symbol\n"
		"		enables symbols to be generated\n"
		"	-s, --disable-symbol\n"
		"		disables symbols, default\n"
		"	--help\n"
		"		prints this message\n",
		stderr
	);
}

// command line options
typedef enum {
	OPTION_LOWER_ENABLE,
	OPTION_LOWER_DISABLE,
	OPTION_UPPER_ENABLE,
	OPTION_UPPER_DISABLE,
	OPTION_NUMBER_ENABLE,
	OPTION_NUMBER_DISABLE,
	OPTION_SYMBOL_ENABLE,
	OPTION_SYMBOL_DISABLE,
	OPTION_HELP,
	OPTION_UNRECOGNIZED
} Option;

Option parseLongOption(char const *);

/* Parse command line options.
 * arg comes from argv of main()
 */
Option parseOption(char const *arg) {
	switch (arg[0]) {
		case '+':
			switch (arg[1]) {
				case 'l':
					if (!arg[2]) return OPTION_LOWER_ENABLE; break;
				case 'u':
					if (!arg[2]) return OPTION_UPPER_ENABLE; break;
				case 'n':
					if (!arg[2]) return OPTION_NUMBER_ENABLE; break;
				case 's':
					if (!arg[2]) return OPTION_SYMBOL_ENABLE; break;
			} break;

		case '-':
			switch (arg[1]) {
				// double dash long option
				case '-': return parseLongOption(arg);
				case 'l':
					if (!arg[2]) return OPTION_LOWER_DISABLE; break;
				case 'u':
					if (!arg[2]) return OPTION_UPPER_DISABLE; break;
				case 'n':
					if (!arg[2]) return OPTION_NUMBER_DISABLE; break;
				case 's':
					if (!arg[2]) return OPTION_SYMBOL_DISABLE; break;
			} break;
	}
	return OPTION_UNRECOGNIZED;
}

Option parseLongOption(char const *arg) {
	if (!strcmp(arg, "--help"))
		return OPTION_HELP;
	else if (!strcmp(arg, "--enable-lower"))
		return OPTION_LOWER_ENABLE;
	else if (!strcmp(arg, "--enable-upper"))
		return OPTION_UPPER_ENABLE;
	else if (!strcmp(arg, "--enable-number"))
		return OPTION_NUMBER_ENABLE;
	else if (!strcmp(arg, "--enable-symbol"))
		return OPTION_SYMBOL_ENABLE;
	else if (!strcmp(arg, "--disable-lower"))
		return OPTION_LOWER_DISABLE;
	else if (!strcmp(arg, "--disable-upper"))
		return OPTION_UPPER_DISABLE;
	else if (!strcmp(arg, "--disable-number"))
		return OPTION_NUMBER_DISABLE;
	else if (!strcmp(arg, "--disable-symbol"))
		return OPTION_SYMBOL_DISABLE;

	return OPTION_UNRECOGNIZED;
}

size_t randInt(size_t);


int main(int argc, char **argv) {
	char const LOWERS[] = "abcdefghijklmnopqrstuvwxyz";
	size_t const LOWERS_LEN = 26;
	char const UPPERS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	size_t const UPPERS_LEN = 26;
	char const NUMBERS[] = "0123456789";
	size_t const NUMBERS_LEN = 10;
	char const SYMBOLS[] = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
	size_t const SYMBOLS_LEN= 32;

	size_t const PASS_LEN_DEFAULT = 22;
	size_t passLen = PASS_LEN_DEFAULT;

	// HANDLE INPUT

	// flags
	bool enableLower,
		enableUpper,
		enableNumber,
		enableSymbol;
	// defaults
	enableLower = enableUpper = enableNumber = true;
	enableSymbol = false;

	// handle flags
	for (size_t i = 1; i < argc; ++i) {
		char const * const option = argv[i];
		switch (parseOption(option)) {
			case OPTION_LOWER_ENABLE:
				enableLower = true; break;
			case OPTION_LOWER_DISABLE:
				enableLower = false; break;
			case OPTION_UPPER_ENABLE:
				enableUpper = true; break;
			case OPTION_UPPER_DISABLE:
				enableUpper = false; break;
			case OPTION_NUMBER_ENABLE:
				enableNumber = true; break;
			case OPTION_NUMBER_DISABLE:
				enableNumber = false; break;
			case OPTION_SYMBOL_ENABLE:
				enableSymbol = true; break;
			case OPTION_SYMBOL_DISABLE:
				enableSymbol = false; break;
			case OPTION_HELP:
				printHelp(); goto exit;
			case OPTION_UNRECOGNIZED:
				if (i == argc-1) {	// last, check for LENGTH argument
					errno = 0;
					passLen = strtol(option, NULL, 10);
					if (errno) {	// conversion failed, treat as bad option
						passLen = PASS_LEN_DEFAULT;
						goto badOpt;
					}
					break;
				}
				badOpt:
				fputs("Unrecognized option: ", stderr);
				fputs(option, stderr);
				putc('\n', stderr);
		}
	}

	// BUILD PASSWORD

	// prep password chars
	size_t passCharsLen = 0;
	if (enableLower) passCharsLen += LOWERS_LEN;
	if (enableUpper) passCharsLen += UPPERS_LEN;
	if (enableNumber) passCharsLen += NUMBERS_LEN;
	if (enableSymbol) passCharsLen += SYMBOLS_LEN;

	// valid chars to build the password from
	char *passChars = calloc(passCharsLen, sizeof (*passChars));

	char *start = passChars;
	if (enableLower) { strcpy(start, LOWERS); start += LOWERS_LEN; }
	if (enableUpper) { strcpy(start, UPPERS); start += UPPERS_LEN; }
	if (enableNumber) { strcpy(start, NUMBERS); start += NUMBERS_LEN; }
	if (enableSymbol) { strcpy(start, SYMBOLS); start += SYMBOLS_LEN; }

	char *password = calloc(passLen+1, sizeof (*password));
	password[passLen] = '\0';

	// select random indices from passChars
	for (size_t i = 0; i < passLen; ++i) {
		errno = 0;
		size_t const r = randInt(passCharsLen);
		if (errno) {
			perror("Failed to get random");
			goto cleanup;
		}

		password[i] = passChars[r];
	}

	puts(password);

	cleanup:
	memset(password, 0, passLen);
	free(password);
	free(passChars);

	exit: return 0;
}

/**
 * Generate random integers in range [0, limit).
 * Returns 0 on success, sets errno and returns errno on failure.
 */
size_t randInt(size_t const limit) {
	// absolute max of size_t
	static size_t const MAX = ~0;

	restart:;
	size_t buf;
	// fill buf with random bytes; may fail so retry with for loop
	for (errno = 0;
			getrandom(&buf, sizeof (buf), 0) != sizeof (buf) && !errno; );
	if (errno) return 0;

	// discard remainders to achieve uniform distribution
	// MAX / limit is the integer number of times limit can fit in MAX
	// then * limit to get the largest integer multiple of limit
	// the distribution is uniform only when buf is within this bound
	// when buf is outside this bound, only some lower values of limit can be
	// produced, distorting the distribution
	if (buf > MAX / limit * limit)
		goto restart;

	return buf % limit;
}
