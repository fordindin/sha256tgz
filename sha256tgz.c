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

typedef enum {
		Quiet,
		Noquiet,
		Verbose } verbosity;

const char *
archive_entry_pathname(struct archive_entry *);
int64_t
archive_entry_size(struct archive_entry *);
char *
SHA256_End(SHA256_CTX *context, char *buf);

void
usage(char *selfpath)
{
		printf("Usage:\n\t%s[-r <exclude_expression> [path_to_tar]\n", basename(selfpath));
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


/*
char *
int2charptr(int64_t input){
		char *imode = malloc(( input == 0 ? 1 : (int)(log10(input)+1)));
		sprintf(imode, "%ld", input);
		return imode;
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
*/

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
		SHA256_CTX c;
		unsigned char md[SHA256_DIGEST_LENGTH];
		regex_t preg;
		int ch, i;
		verbosity verb; 
		char *modeline;
		int modelinesize;
		uint64_t (*modefunctions[11])( struct archive_entry *entry) = {
						archive_entry_mode,
						archive_entry_dev,
						archive_entry_devmajor,
						archive_entry_devminor,
						archive_entry_ino,
						archive_entry_nlink,
						archive_entry_rdevmajor,
						archive_entry_rdevminor,
						archive_entry_uid,
						archive_entry_gid,
						archive_entry_size
		};
		char modes[(int)(sizeof(modefunctions)/sizeof(modefunctions[0]))][16];


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
			verb = Quiet;
	} else
	{
			(void)realpath(argv[0], tarpath);
			strcpy(origtarpath, argv[0]);
			if ((r = archive_read_open_filename(a, tarpath, ARCHIVE_DEFAULT_BYTES_PER_BLOCK)) == ARCHIVE_OK){
					verb = Noquiet;
			} else {
					printf("%s\n", archive_error_string(a));
					exit(1);
			}
	} 

		int counter=0;
		SHA256_Init(&c);
		while ((r = archive_read_next_header(a, &entry)) == ARCHIVE_OK)
		{
				modelinesize = 0;
				if ((++counter % 100) == 0) {
						printf ("%09d ", counter);
						printf("%s\n",archive_entry_pathname(entry));
						}
				if (regexec(&preg, archive_entry_pathname(entry), 0, NULL, 0) !=0)
				{
						SHA256_Update(&c, archive_entry_pathname(entry), sizeof(archive_entry_pathname(entry)));
						//printf("%s\n",archive_entry_pathname(entry));
						for (i=0; i  < sizeof(modefunctions)/sizeof(modefunctions[0]); i++){
								sprintf(modes[i], "%ld", modefunctions[i](entry));
								modelinesize += sizeof(modes[i]);
						}
						modeline = malloc(modelinesize);
						for (i=0; i  < sizeof(modefunctions)/sizeof(modefunctions[0]); i++){
								if (i == 0){
										strlcpy(modeline, modes[i], sizeof(modes[i]));
								} else {
										strlcat(modeline, modes[i], sizeof(modes[i]));
								}
								//free(modes[i]);
						}
						SHA256_Update(&c, modeline, modelinesize);
						free(modeline);
						if (archive_entry_filetype(entry) == AE_IFLNK){
								SHA256_Update(&c, archive_entry_symlink(entry), sizeof(archive_entry_symlink(entry)));
						}
						if (archive_entry_filetype(entry) == AE_IFREG
								)
						{
								asize = archive_entry_size(entry);
								entrydata = malloc(asize);
								archive_read_data(a, entrydata, asize);
								SHA256_Update(&c, entrydata, asize);
								//SHA256_Update(&lc, entrydata, asize);
								//SHA256_Final(&(md[0]),&lc);
								//pt(md);
								free(entrydata);
						}
				} else
				{
						archive_read_data_skip(a);
				}
		}
	if ( r == ARCHIVE_EOF )
	{
			if (verb != Quiet)
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
