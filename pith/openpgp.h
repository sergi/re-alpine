/*
 * OpenPGP related defines and prototypes
 */

#ifdef OPENPGP
#ifndef PITH_OPENPGP_INCLUDED
#define PITH_OPENPGP_INCLUDED


#include "../pith/state.h"
#include "../pith/send.h"
#include "../pith/filttype.h"
//#include "../pith/smkeys.h"

//#include <openssl/rand.h>
//#include <openssl/err.h>


#define OUR_PGP_ENCLOSURE_SUBTYPE	"x-pgp-enclosure"


/* exported prototypes */
int            is_openpgp_body(BODY *b);
int            fiddle_openpgp_message(BODY *b, long msgno);
int            encrypt_outgoing_message(METAENV *header, BODY **bodyP, int do_sign);
int            sign_outgoing_message(METAENV *header, BODY **bodyP, int dont_detach);
void           free_openpgp_body_sparep(void **sparep);
void           gf_puts_uline(char *txt, gf_io_t pc);
void           openpgp_deinit(void);
OPENPGP_STUFF_S *new_openpgp_struct(void);


#endif /* PITH_OPENPGP_INCLUDED */
#endif /* OPENPGP */
