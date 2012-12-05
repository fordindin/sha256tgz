#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <unistd.h>
#include <ctype.h>

#include <openssl/sha.h>
#include <errno.h>
#include <math.h>

#include <fcntl.h>

#include <sys/param.h>
#include <regex.h>

#include <archive.h>
#include <archive_entry.h>
#include <wchar.h>

#define QUIET 1
#define NOQUIET 0

const char *
archive_entry_pathname(struct archive_entry *);
int64_t
archive_entry_size(struct archive_entry *);
char *
SHA256_End(SHA256_CTX *context, char *buf);

void
usage(char *selfpath)
{
		printf("Usage:\n\t%s [path_to_tar]\n", basename(selfpath));
		exit(0);
}
void
pt(unsigned char *md)
{
		int i;
		for (i=0; i<SHA256_DIGEST_LENGTH; i++)
		printf("%02x",md[i]);
		printf("\n");
}

char *
toUpper(char *str){
    char *newstr, *p;
    p = newstr = strdup(str);
    while((*p++=toupper(*p)));

    return newstr;
}


char *
int2charptr(int input){
		char *imode = malloc(( input == 0 ? 1 : (int)(log10(input)+1)));
		sprintf(imode, "%d", input);
		return imode;
}

int
int_into_SHA256_context(SHA256_CTX *c, int i){
		char *m;
		m = (char *)int2charptr(i);
		SHA256_Update(c, m, sizeof(m));
		free(m);
		return 0;
}

void
print_int_checksum(int in){
		unsigned char md[SHA256_DIGEST_LENGTH];
		SHA256_CTX c;
		SHA256_Init(&c);
		int_into_SHA256_context(&c, in);
		SHA256_Final(&(md[0]),&c);
		pt(md);
}

int
main(int argc, char **argv)
{
		char tarpath[PATH_MAX];
		char origtarpath[PATH_MAX];
		char selfpath[PATH_MAX];
		char *entrydata;
		struct archive *a;
		struct archive_entry *entry;
		int r;
		int64_t asize;
		//char *exclude_pattern = ".*/\\.svn/.*";
		//char buf[block];
		SHA256_CTX c, lc;
		unsigned char md[SHA256_DIGEST_LENGTH];
		regex_t preg;
		int ch;
		int quiet;
		char *modes[11];
		char *modeline;
		int modelinesize;


		(void)realpath(argv[0], selfpath);
		// "$." -- empty match for any not-multiline input string
		if (regcomp(&preg, "$.", REG_EXTENDED) != 0)
		{
			fprintf(stderr, "Bad pattern\n");
			exit(1);
		}

		while ((ch = getopt(argc, argv, "r:")) != -1) {
						switch (ch) {
						case 'r':
								if (regcomp(&preg, optarg, REG_EXTENDED) != 0)
								{
									fprintf(stderr, "Bad pattern\n");
									exit(1);
								}; break;
						case '?':
						default:
										 usage(selfpath);
						 }
		}
		argc -= optind;
		argv += optind;

	a = archive_read_new();
	archive_read_support_compression_all(a);
	archive_read_support_format_all(a);

	if (argc == 0)
	{
			strncpy(tarpath, "stdin", sizeof("stdin"));
			r = archive_read_open_filename(a, NULL, ARCHIVE_DEFAULT_BYTES_PER_BLOCK);
			quiet = QUIET;
	} else
	{
			(void)realpath(argv[0], tarpath);
			strcpy(origtarpath, argv[0]);
			r = archive_read_open_filename(a, tarpath, ARCHIVE_DEFAULT_BYTES_PER_BLOCK);
			quiet = NOQUIET;
	}
		SHA256_Init(&c);
		while ((r = archive_read_next_header(a, &entry)) == ARCHIVE_OK)
		{
				if (regexec(&preg, archive_entry_pathname(entry), 0, NULL, 0) !=0)
				{
						SHA256_Update(&c, archive_entry_pathname(entry), sizeof(archive_entry_pathname(entry)));
						//printf("%s\n",archive_entry_pathname(entry));
						modes[0] = int2charptr(archive_entry_dev(entry));
						modes[1] = int2charptr(archive_entry_mode(entry));
						modes[2] = int2charptr(archive_entry_devmajor(entry));
						modes[3] = int2charptr(archive_entry_devminor(entry));
						modes[4] = int2charptr(archive_entry_ino(entry));
						modes[5] = int2charptr(archive_entry_nlink(entry));
						modes[6] = int2charptr(archive_entry_rdevmajor(entry));
						modes[7] = int2charptr(archive_entry_rdevminor(entry));
						modes[8] = int2charptr(archive_entry_size(entry));
						modes[9] = int2charptr(archive_entry_uid(entry));
						modes[10] = int2charptr(archive_entry_gid(entry));
						modelinesize = 
										sizeof(modes[0]) +
										sizeof(modes[1]) +
										sizeof(modes[2]) +
										sizeof(modes[3]) +
										sizeof(modes[4]) +
										sizeof(modes[5]) +
										sizeof(modes[6]) +
										sizeof(modes[7]) +
										sizeof(modes[8]) +
										sizeof(modes[9]) +
										sizeof(modes[10]);
						modeline = malloc(modelinesize+1);
						snprintf(modeline,
										modelinesize,
										"%s%s%s%s%s%s%s%s%s%s%s",
										modes[0],
										modes[1],
										modes[2],
										modes[3],
										modes[4],
										modes[5],
										modes[6],
										modes[7],
										modes[8],
										modes[9],
										modes[10]
										);
						SHA256_Update(&c, modeline, modelinesize);
						free(modeline);
						if (archive_entry_filetype(entry) == AE_IFREG)
						{
								asize = archive_entry_size(entry);
								entrydata = malloc(asize);
								archive_read_data(a, entrydata, asize);
								SHA256_Update(&c, entrydata, asize);
								SHA256_Update(&lc, entrydata, asize);
								SHA256_Final(&(md[0]),&lc);
								pt(md);
								free(entrydata);
						}
						} else
						{
								archive_read_data_skip(a);
						}
		}
	if ( r == ARCHIVE_EOF )
	{
			if (quiet != QUIET)
					printf("%s (%s) = ", toUpper(basename(selfpath)), origtarpath);
			SHA256_Final(&(md[0]),&c);
			pt(md);
	} else {
			//fprintf(stderr, "%s: %s\n", tarpath, "Can't operate with archive");
			fprintf(stderr, "%s: %s\n", tarpath, archive_error_string(a));
			exit(1);
	}
	archive_read_close(a);
	archive_read_free(a);
	regfree(&preg);
}
