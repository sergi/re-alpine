/*
 *  File:   	    openpgp.c
 *  Author: 	    vjensen@gmx.de
 *  Date:   	    08/2009
 */

#include "headers.h"

#ifdef OPENPGP

#include "../pith/charconv/utf8.h"
#include "../pith/status.h"
#include "../pith/store.h"
#include "../pith/conf.h"
#include "../pith/list.h"
#include "radio.h"
#include "keymenu.h"
#include "mailview.h"
#include "conftype.h"
#include "confscroll.h"
#include "setup.h"
#include "openpgp.h"




/* *******************************************************************
 * **** Private Routines *********************************************
 * **************************************************************** */



/* *******************************************************************
 * **** Public Entries ***********************************************
 * **************************************************************** */

void
openpgp_config_screen(struct pine *ps, int edit_exceptions)
{
}




int
openpgp_related_var(struct pine *ps, struct variable *var)
{
    return 0;
/*
    return var == &ps->vars[V_PUBLICCERT_DIR]
	||  var == &ps->vars[V_PUBLICCERT_CONTAINER]
	||  var == &ps->vars[V_CACERT_CONTAINER];
*/
}




void
format_openpgp_info(int pass, BODY *body, long msgno, gf_io_t pc)
{
    int    i;
    
    if (body->type == TYPEMULTIPART) {
    	PART *p;

        for (p=body->nested.part; p; p=p->next)
	    format_openpgp_info(pass, &p->body, msgno, pc);
    }

    /* TODO: fill... */

}




void
openpgp_info_screen(struct pine *ps)
{
    long      msgno;
    OtherMenu what;
    int       offset = 0;
    BODY     *body;
    ENVELOPE *env;
    HANDLE_S *handles = NULL;
    SCROLL_S  scrollargs;
    STORE_S  *store = NULL;
    
    ps->prev_screen = openpgp_info_screen;
    ps->next_screen = SCREEN_FUN_NULL;

    if(mn_total_cur(ps->msgmap) > 1L){
	q_status_message(SM_ORDER | SM_DING, 0, 3,
			 _("Can only view one message's information at a time."));
	return;
    }
    /* else check for existence of smime bits */

    msgno = mn_m2raw(ps->msgmap, mn_get_cur(ps->msgmap));
    
    env = mail_fetch_structure(ps->mail_stream, msgno, &body, 0);
    if(!env || !body){
	q_status_message(SM_ORDER, 0, 3,
			 _("Can't fetch body of message."));
	return;
    }
    
    what = FirstMenu;

    store = so_get(CharStar, NULL, EDIT_ACCESS);

    while(ps->next_screen == SCREEN_FUN_NULL){

    	ClearLine(1);

	so_truncate(store, 0);
	
	view_writec_init(store, &handles, HEADER_ROWS(ps),
			 HEADER_ROWS(ps) + 
			 ps->ttyo->screen_rows - (HEADER_ROWS(ps)
						  + HEADER_ROWS(ps)));

    	gf_puts_uline("Overview", view_writec);
    	gf_puts(NEWLINE, view_writec);

	format_openpgp_info(1, body, msgno, view_writec);
	gf_puts(NEWLINE, view_writec);
	format_openpgp_info(2, body, msgno, view_writec);

	view_writec_destroy();

	ps->next_screen = SCREEN_FUN_NULL;

	memset(&scrollargs, 0, sizeof(SCROLL_S));
	scrollargs.text.text	= so_text(store);
	scrollargs.text.src	= CharStar;
	scrollargs.text.desc	= "OpenPGP information";
	scrollargs.body_valid = 1;

	if(offset){		/* resize?  preserve paging! */
	    scrollargs.start.on		= Offset;
	    scrollargs.start.loc.offset = offset;
	    offset = 0L;
	}

	scrollargs.bar.title	= "OPENPGP INFORMATION";
/*	scrollargs.end_scroll	= view_end_scroll; */
	scrollargs.resize_exit	= 1;
	scrollargs.help.text	= NULL;
	scrollargs.help.title	= "HELP FOR OPENPGP INFORMATION VIEW";
	scrollargs.keys.menu	= &openpgp_info_keymenu;
	scrollargs.keys.what    = what;
	setbitmap(scrollargs.keys.bitmap);

	if(scrolltool(&scrollargs) == MC_RESIZE)
	  offset = scrollargs.start.loc.offset;
    }

    so_give(&store);
}


#endif /* OPENPGP */
