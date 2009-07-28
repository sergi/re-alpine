/*
 */

#ifdef OPENPGP
#ifndef PINE_OPENPGP_INCLUDED
#define PINE_OPENPGP_INCLUDED


#include "../pith/state.h"
#include "../pith/send.h"
#include "../pith/openpgp.h"


/* exported protoypes */
void   openpgp_info_screen(struct pine *ps);
void   openpgp_config_screen(struct pine *, int edit_exceptions);
int    openpgp_related_var(struct pine *, struct variable *);


#endif /* PINE_OPENPGP_INCLUDED */
#endif /* OPENPGP */
