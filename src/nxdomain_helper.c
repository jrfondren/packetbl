#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <netdb.h>

/* must match build_options.ads */
#define MAX_REQUESTS 20

/* config must reject RBLs with names that would cause this to overflow with
 * the largest possible IP string */
#define MAX_NAME 256

struct gaicb bufreq[MAX_REQUESTS];
char stringbufs[MAX_REQUESTS][MAX_NAME];

int start_resolving_at (char *name, struct gaicb **req, int j) {
        *req = &bufreq[j - 1];
	memset(*req, 0, sizeof(**req));
	strcpy(stringbufs[j - 1], name);
	req[0]->ar_name = stringbufs[j - 1];
	return getaddrinfo_a(GAI_NOWAIT, req, 1, NULL);
}

const int c_eai_inprogress = EAI_INPROGRESS;
const int c_eai_again = EAI_AGAIN;
const int c_eai_alldone = EAI_ALLDONE;
