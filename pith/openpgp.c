#if !defined(lint) && !defined(DOS)
static char rcsid[] = "$Id$";
#endif

/*
 * OpenPGP (RFC3156) support.
 * Based on ideas from smime.c
 */

#include "../pith/headers.h"

#ifdef OPENPGP

#include "../pith/osdep/canaccess.h"
#include "../pith/helptext.h"
#include "../pith/store.h"
#include "../pith/status.h"
#include "../pith/detach.h"
#include "../pith/conf.h"
#include "../pith/openpgp.h"
#include "../pith/mailpart.h"
#include "../pith/mimedesc.h"
#include "../pith/reply.h"
#include "../pith/tempfile.h"
#include "../pith/readfile.h"
#include "../pith/remote.h"

#include <gpgme.h>

#define PUBLIC
#define PRIVATE	static


/* Already decoded/verified OpenPGP parts contain this
 * data in it's 'sparep'.
 */
typedef struct _PGPDATA {
    int		valid_sigs;
    int		bad_sigs;
    int		encrypted;			/* was encrypted */
    int		failed_decryption;		/* ...but decryption failed */

    char	raw[];				/* binary data of signature
						   (if signed) */
} PGPDATA;






#if 1
/* *******************************************************************
 * **** Debug Routines ***********************************************
 * **************************************************************** */

PRIVATE void
DumpBuffer(void const * arg1, size_t const len)
{
    size_t i;
    unsigned char const * p = arg1;
    char str[50];
    int  n = 0;

    for (i = 0; i < len; ++i, ++p) {
	n += sprintf(&str[n], "%02X", *p);
	if (((i + 1) % 16) == 0) {
	    dprint((2,"%s\n",str));
	    n = 0;			     /* flush str to output */
	}
	else if (((i + 1) % 8) == 0)
	    str[n++] = '-';
	else
	    str[n++] = ' ';
	str[n] = '\0';		   /* correct on flush, add and end */
    }
    dprint((2,"%s",str));
}



PRIVATE void
dump_gpgmedata(gpgme_data_t data)
{
    unsigned char buffer[256];
    size_t	st;
    off_t	pos;
    off_t const oldpos = gpgme_data_seek(data, 0, SEEK_CUR);
    off_t const size = gpgme_data_seek(data, 0, SEEK_END);
    pos = gpgme_data_seek(data, 0, SEEK_SET);
    if (0 != pos)
	dprint((1,"dump_gpgmedata: SEEK_SET != 0??? (%ld, %s)",pos,strerror(errno)));

    dprint((2,"Starting buffer dump (%p, %ld bytes)...",data,size));
    while ((st=gpgme_data_read(data, buffer, sizeof buffer)) > 0)
	DumpBuffer(buffer, st);

    pos = gpgme_data_seek(data, oldpos, SEEK_SET); /* restore position */
    if (oldpos != pos)
	dprint((1,"dump_gpgmedata: can't seek to %ld (%ld)",oldpos,pos));
    return;
}
#endif






/* *******************************************************************
 * **** Private Routines *********************************************
 * **************************************************************** */

/* Write information about all signatures, one line per sig, to 'pc'.
 */
PRIVATE void
openpgp_check_verify(gpgme_ctx_t ctx, PGPDATA * const pgpdata, gf_io_t pc)
{
    gpgme_verify_result_t const result = gpgme_op_verify_result(ctx);
    dprint((3, "openpgp_check_verify(, %p, %p): %p",pgpdata,pc,result));

    if (NULL != result) {
	gpgme_signature_t sig;
	for (sig = result->signatures; NULL != sig; sig = sig->next) {
	    dprint((2, "openpgp_check_verify, fingerprint '%s', summay %#x",sig->fpr,sig->summary));
	    if (NULL != pc) {
		snprintf(tmp_20k_buf, SIZEOF_20KBUF, _("fingerprint '%s', sigsum %#x"),sig->fpr,sig->summary);
		gf_puts(tmp_20k_buf, pc);
		gf_puts(NEWLINE, pc);
	    }
	    if ((sig->summary & GPGME_SIGSUM_VALID))
		++pgpdata->valid_sigs;
	    else
		++pgpdata->bad_sigs;
	}
    }

    return;
}




PRIVATE void
openpgp_check_decrypt(gpgme_ctx_t ctx, PGPDATA * const pgpdata, gf_io_t pc)
{
    gpgme_decrypt_result_t const result = gpgme_op_decrypt_result(ctx);
    gpgme_recipient_t rcv;
    dprint((3, "openpgp_check_decrypt(, %p, %p): %p",pgpdata,pc,result));

    if (NULL != result) {
	if (NULL != result->unsupported_algorithm) {
	    dprint((1, "openpgp_check_decrypt: unsupported algorithm %s",result->unsupported_algorithm));
	    if (NULL != pc) {
		snprintf(tmp_20k_buf, SIZEOF_20KBUF, _("Unsupported algoritm '%s' used"),result->unsupported_algorithm);
		gf_puts(tmp_20k_buf, pc);
		gf_puts(NEWLINE, pc);
	    }
	}

	for (rcv = result->recipients; NULL != rcv; rcv = rcv->next) {
	    ++pgpdata->encrypted;
	    dprint((2, "openpgp_check_decrypt, key '%s'",rcv->keyid));
	    if (NULL != pc) {
		snprintf(tmp_20k_buf, SIZEOF_20KBUF, _("encrypted for key '%s'"),rcv->keyid);
		gf_puts(tmp_20k_buf, pc);
		gf_puts(NEWLINE, pc);
	    }
	}
    }
    else {
	++pgpdata->failed_decryption;
	if (NULL != pc) {
	    gf_puts(_("This message couldn't be decrypted."), pc);
	    gf_puts(NEWLINE, pc);
	}
    }
    return;
}




PRIVATE void
check_sign_result(gpgme_sign_result_t result, gpgme_sig_mode_t type)
{
    if (result->invalid_signers) {
	dprint((1, "Invalid signer found: %s\n", result->invalid_signers->fpr));
	return;
    }
    if (!result->signatures || result->signatures->next) {
	dprint((1, "Unexpected number of signatures created\n"));
	return;
    }
    if (result->signatures->type != type) {
	dprint((1, "Wrong type of signature created\n"));
	return;
    }
}




PUBLIC OPENPGP_STUFF_S *
new_openpgp_struct(void)
{
    OPENPGP_STUFF_S *ret = NULL;

    ret = (OPENPGP_STUFF_S *)fs_get(sizeof *ret);
    memset((void *)ret, 0, sizeof *ret);


    return ret;
}




PRIVATE void
free_openpgp_struct(OPENPGP_STUFF_S **openpgp)
{
    if(openpgp && *openpgp){

	fs_give((void **)openpgp);
    }
}




PRIVATE gpgme_error_t
openpgp_new_context(gpgme_ctx_t * ctx)
{
    gpgme_error_t err = gpgme_new(ctx);
    if (GPG_ERR_NO_ERROR != err) {
	dprint((1, "gpgme_new() failed: %s", gpgme_strerror(err)));
	return err;
    }
    err = gpgme_set_protocol(*ctx, GPGME_PROTOCOL_OpenPGP);
    if (GPG_ERR_NO_ERROR != err) {
	dprint((1, "gpgme_set_protocol() failed: %s", gpgme_strerror(err)));
	gpgme_release(*ctx);
	return err;
    }
    return GPG_ERR_NO_ERROR;
}




PRIVATE gpgme_error_t
openpgp_lookup_key(ADDRESS * a, int const private, gpgme_key_t * key)
{
    gpgme_error_t err;
    gpgme_ctx_t listctx;
    gpgme_key_t key2;

    char	buf[MAXPATH];

    if (!a || !a->mailbox || !a->host)
	return gpgme_error_from_errno(EDESTADDRREQ);
    snprintf(buf, sizeof buf, "%s@%s", a->mailbox, a->host);
    
    err = openpgp_new_context(&listctx);
    if (GPG_ERR_NO_ERROR != err)
	return err;
    err = gpgme_op_keylist_start(listctx, buf, private);
    if (GPG_ERR_NO_ERROR == err)
	err = gpgme_op_keylist_next(listctx, key);
    if (GPG_ERR_NO_ERROR != err) {
	gpgme_release(listctx);
	dprint((1, "gpgme_op_keylist, %s not found: %s", buf, gpgme_strerror(err)));
	return gpgme_error_from_errno(ENOENT);
    }
    err = gpgme_op_keylist_next(listctx, &key2);
    if (GPG_ERR_NO_ERROR == err) {
	gpgme_key_release(*key);
	gpgme_key_release(key2);
	gpgme_release(listctx);
	dprint((2, "ambiguous specification of secret key `%s'\n", buf));
	return gpgme_error_from_errno(EALREADY);
    }
    gpgme_op_keylist_end(listctx);
    gpgme_release(listctx);
    return GPG_ERR_NO_ERROR;
}



PRIVATE gpgme_error_t
set_signer(gpgme_ctx_t ctx, METAENV *header)
{
    gpgme_error_t   err;
    gpgme_key_t	    key;

    err = openpgp_lookup_key(header->env->reply_to, 1, &key);
    if (GPG_ERR_NO_ERROR != err) {
	err = openpgp_lookup_key(header->env->from, 1, &key);
	if (err != GPG_ERR_NO_ERROR) {
	    return err;
	}
    }
    gpgme_signers_clear(ctx);
    err = gpgme_signers_add(ctx, key);
    gpgme_key_release(key);
    if (GPG_ERR_NO_ERROR != err) {
	dprint((1, "gpgme_signers_add() failed: %s", gpgme_strerror(err)));
    }
    return err;
}




/* Create a gpgme_key_t list from the addresses contained in
 * 'header'. */
PRIVATE gpgme_error_t
create_keyset(gpgme_ctx_t ctx, METAENV * header, int encrypt2self, gpgme_key_t ** result)
{
    gpgme_error_t err;

    gpgme_key_t *rset = NULL;
    unsigned int rset_n = 0;

    PINEFIELD	*pf;


    if (encrypt2self) {
	gpgme_key_t key = NULL;
	err = openpgp_lookup_key(header->env->reply_to, 0, &key);
	if (GPG_ERR_NO_ERROR != err) {
	    err = openpgp_lookup_key(header->env->from, 0, &key);
	    if (GPG_ERR_NO_ERROR != err) {
		goto error_exit;
	    }
	}
	fs_resize((void **)&rset, (sizeof *rset) * (rset_n+1));
	rset[rset_n++] = key;
    }

    for (pf = header->local; pf && pf->name; pf = pf->next) {
        if (pf->type == Address && pf->rcptto && pf->addr && *pf->addr) {
	    ADDRESS * a;
	    for (a=*pf->addr; a; a=a->next) {

		gpgme_key_t key = NULL;
		err = openpgp_lookup_key(a, 0, &key);
		if (GPG_ERR_NO_ERROR != err)
		    goto error_exit;	     /* abort whole process */

		fs_resize((void **)&rset, (sizeof *rset) * (rset_n+1));
		rset[rset_n++] = key;
	    }
	}
    }

    /* NULL terminate.  */

    fs_resize((void **)&rset, (sizeof *rset) * (rset_n+1));
    rset[rset_n++] = NULL;

    *result = rset;
    return GPG_ERR_NO_ERROR;

  error_exit:
    fs_give((void **)&rset);
    return err;
}




PRIVATE STORE_S *
store_from_gpgme(gpgme_data_t data)
{
    off_t pos = gpgme_data_seek(data, 0, SEEK_SET);
    if (0 != pos) {
	dprint((1,"store_from_gpgme: SEEK_SET != 0??? (%ld, %s)",pos,strerror(errno)));
	return NULL;
    }
    else {
	unsigned char buffer[256];
	size_t	st;
	STORE_S * s = so_get(TmpFileStar, NULL, EDIT_ACCESS);
	while ((st=gpgme_data_read(data, buffer, sizeof buffer)) > 0)
	    so_nputs(s, buffer, st);
	return s;
    }
}




/*
    Get the body of the given section of msg
 */
PRIVATE STORE_S *
get_part_contents(long msgno, const char *section)
{
    long len;
    gf_io_t     pc;
    STORE_S *store = NULL;
    char	*err;

    dprint((3, "get_part_contents(%ld, %s)",msgno,section));

    store = so_get(CharStar, NULL, EDIT_ACCESS);
    if (store) {
        gf_set_so_writec(&pc, store);

        err = detach(ps_global->mail_stream, msgno, (char *)section, 0L, &len, pc, NULL, 0L);

        gf_clear_so_writec(store);

        so_seek(store, 0, SEEK_SET);

        if (err) {
	    dprint((1, "get_part_contents: detach() failed, error %s",err));
	    so_give(&store);
	}
    }
    else {
	dprint((1, "get_part_contents: so_get() failed"));
    }
    dprint((3, "get_part_contents: read %ld bytes to %p",len,store));
    return store;
}




/* Create a copy of a section?  Interpret it and store binary? */
PRIVATE gpgme_data_t
get_data_from_part(long msgno, char const * section)
{
    STORE_S *	store;
    gpgme_data_t data = NULL;
    gpgme_error_t err;

    dprint((3, "get_data_from_part(%ld, %s)",msgno,section));

    store = get_part_contents(msgno, section);
    if (NULL == store) {
	dprint((1, "get_data_from_part: get_part_contents() failed"));
	return NULL;
    }

    do {
	unsigned char c;

	err = gpgme_data_new(&data);
	if (GPG_ERR_NO_ERROR != err) {
	    dprint((1, "gpgme_data_new() failed: %s", gpgme_strerror(err)));
	    break;
	}

	so_seek(store, 0, SEEK_SET);
	while (so_readc(&c, store)) {
	    err = gpgme_data_write(data, &c, 1);
	}
    } while (0);
    so_give(&store);

    dprint((3, "get_data_from_part: returning %p",data));
    return data;
}




PRIVATE void
setup_body(BODY *b, char *description, char *type, char *filename)
{
    b->type = TYPEAPPLICATION;
    b->subtype = cpystr(type);
    b->description = cpystr(description);

    if (NULL != filename) {
	b->disposition.type = cpystr("attachment");
	set_parameter(&b->disposition.parameter, "filename", filename);

	set_parameter(&b->parameter, "name", filename);
    }
}




/*
 * Flatten the given body into its MIME representation.
 * Return the result in a gpgme_data_t.
 */
PRIVATE long
rfc822_output_func(void *b, char *string)
{
    gpgme_data_t data = b;

    return (gpgme_data_write(data, string, strlen(string)) > 0 ? 1L : 0L);
}

PRIVATE gpgme_error_t
flatten_body(BODY *body, gpgme_data_t * data)
{
    gpgme_error_t err;
    off_t len;

    err = gpgme_data_new(data);
    if (GPG_ERR_NO_ERROR != err)
	return err;

    pine_encode_body(body); /* this attaches random boundary strings to multiparts */
    pine_write_body_header(body, rfc822_output_func, data);
    pine_rfc822_output_body(body, rfc822_output_func, data);

#if 0 /*needed?*/
    /* We need to truncate by two characters since the above
     * appends CRLF (if there is something in it at all). */

    len = gpgme_data_seek(data, 0, SEEK_CUR);
    if (len > 1) {
	/* TODO: better/faster way */

	size_t len;
	char * p = gpgme_data_release_and_get_mem(data, &len);
	len -= 2;				/* remove CRLF */
	gpgme_data_new_from_mem(data, buffer, len, 1); /* copy, size change */
	gpgme_free(p);
    }
#endif

    return err;
} 



/*
 * Recursively stash a pointer to the decrypted data in our
 * manufactured body.
 */
PRIVATE void
create_local_cache(char *base, BODY *b)
{
    if(b->type==TYPEMULTIPART){
        PART *p;

#if 0 
        cpytxt(&b->contents.text, base + b->contents.offset, b->size.bytes);
#else
    	/*
    	 * We don't really want to copy the real body contents. It shouldn't be
	 * used, and in the case of a message with attachments, we'll be 
	 * duplicating the files multiple times.
	 */
    	cpytxt(&b->contents.text, "BODY UNAVAILABLE", 16);
#endif

        for(p=b->nested.part; p; p=p->next)
          create_local_cache(base, (BODY*) p);
    }
    else{
        cpytxt(&b->contents.text, base + b->contents.offset, b->size.bytes);
    }
}






/* *******************************************************************
 * **** Public Entries ***********************************************
 * **************************************************************** */

/*
 *  Output a string in a distinctive style
 */
void
gf_puts_uline(char *txt, gf_io_t pc)
{
    pc(TAG_EMBED); pc(TAG_BOLDON);
    gf_puts(txt, pc);
    pc(TAG_EMBED); pc(TAG_BOLDOFF);
}




/* Installed as an atexit() handler to save no random data */
PUBLIC void
openpgp_deinit(void)
{
    dprint((3, "openpgp_deinit()"));
    free_openpgp_struct(&ps_global->openpgp);
}




/* Initialise OpenPGP stuff if needed */
PUBLIC gpgme_error_t
openpgp_init(void)
{
    gpgme_error_t err = GPG_ERR_NO_ERROR;

    if (F_OFF(F_DONT_DO_OPENPGP, ps_global)
	&&  !(ps_global->openpgp && ps_global->openpgp->inited)) {

	dprint((3, "openpgp_init()"));
	if(!ps_global->openpgp)
	    ps_global->openpgp = new_openpgp_struct();

	do {
	    char const * cp;

	    /* The function `gpgme_check_version' must be called before
	     * any other function in the library, because it initializes
	     * the thread support subsystem in GPGME. (from the info page) */
 
	    cp = gpgme_check_version(NULL);
	    printf("gpgme version=%s\n", cp);

	    /* Check for OpenPGP support */
	    err = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);
	    if (GPG_ERR_NO_ERROR != err) {
		dprint((1, "GPGME_PROTOCOL_OpenPGP not supported: %s", gpgme_strerror(err)));
		break;
	    }

	} while (0);

	if (GPG_ERR_NO_ERROR == err)
	    ps_global->openpgp->inited = 1;
    }
    return err;
}




PUBLIC void
free_openpgp_body_sparep(void **sparep)
{
    if (sparep  &&  *sparep) {
	fs_give(*sparep);
	*sparep = NULL;
    }
}




/* Return true if the body looks like something OpenPGP defines (that is
 * NOT the user-supplied data). */
PUBLIC int
is_openpgp_body(BODY *body)
{
    int result;

    result = body->type == TYPEAPPLICATION
	&&  body->subtype
	&&  (strucmp(body->subtype, "pgp-signature") == 0
	     || strucmp(body->subtype, "pgp-encrypted") == 0);

    return result;
}




/*
 *	b	BODY of whole message
 *	msgno
 * Given a multipart body of type multipart/signed, attempt to verify it.
 * Returns non-zero if the body was changed.
 *
 * Multipart/signed, application/pgp-signature
 *   part 1 (signed thing)
 *   part 2 (the OpenPGP signature)
 *
 * We're going to convert that to
 *
 * Multipart/OUR_OPENPGP_ENCLOSURE_SUBTYPE
 *   part 1 (signed thing)
 *   part 2 has been freed
 *
 * We also extract the signature from part 2 and save it
 * in the multipart body->sparep, and we add a description
 * in the multipart body->description (including the result
 * of the signature check).
 */
/*PRIVATE*/ int
do_detached_signature_verify(BODY *b, long msgno, char *section)
{
    char    newSec[100];
    gpgme_error_t err;
    gpgme_ctx_t	  ctx;
    gpgme_data_t  message, signature;

    PGPDATA *	pgpdata = NULL;
    void * descr = NULL;

    int	    modified_the_body = 0;


    dprint((3, "do_detached_signature_verify(msgno=%ld type=%d subtype=%s section=%s)", msgno, b->type, b->subtype ? b->subtype : "NULL", (section && *section) ? section : (section != NULL) ? "Top" : "NULL"));
    err = openpgp_init();
    if (GPG_ERR_NO_ERROR == err)
	err = openpgp_new_context(&ctx);
    if (GPG_ERR_NO_ERROR != err) {
	dprint((1, "do_detached_signature_verify: gpgme error %s", gpgme_strerror(err)));
	return modified_the_body;
    }


    do {
	off_t pos;
	/* Read first part of body, may be anything */

	snprintf(newSec, sizeof newSec, "%s%s1", section ? section : "", (section && *section) ? "." : "");
	if (NULL == (message = get_data_from_part(msgno, newSec)))
	    break;
	//dump_gpgmedata(message);
	pos = gpgme_data_seek(message, 0, SEEK_SET); /* rewind b4 work */
	if (0 != pos)
	    dprint((1,"do_detached_signature_verify: SEEK_SET != 0??? (%ld, %s)",pos,strerror(errno)));


	/* Second part contains detached signature
	 * in a application/pgp-signature part */

	snprintf(newSec, sizeof newSec, "%s%s2", section ? section : "", (section && *section) ? "." : "");
	if (NULL == (signature = get_data_from_part(msgno, newSec)))
	    break;
	//dump_gpgmedata(signature);
	pos = gpgme_data_seek(signature, 0, SEEK_SET);
	if (0 != pos)
	    dprint((1,"do_detached_signature_verify: SEEK_SET != 0??? (%ld, %s)",pos,strerror(errno)));

	/* Verify the signature and store the result in pgpdata. */

	err = gpgme_op_verify(ctx, signature, message, NULL);
	if (GPG_ERR_NO_ERROR != err) {
	    dprint((1, "gpgme_op_verify(): %s", gpgme_strerror(err)));
	    break;
	}
	pgpdata = fs_get(sizeof(PGPDATA));
	memset(pgpdata, 0, sizeof *pgpdata);
	openpgp_check_verify(ctx, pgpdata, NULL);

	if (0 == pgpdata->bad_sigs) {
	    descr = cpystr(0 != pgpdata->valid_sigs
			   ? _("This message was cryptographically signed." NEWLINE)
			   : _("This message couldn't be verified." NEWLINE));
	}
	else {
	    descr = cpystr(0 != pgpdata->valid_sigs
			   ? _("This message was cryptographically signed by some signatures." NEWLINE)
			   : _("This message contains bad signatures." NEWLINE));
	}
    } while (0);
    gpgme_data_release(signature);	signature = NULL;

    if (GPG_ERR_NO_ERROR == err) do {
	/* Everything OK.
	 * So build new body by freeing the 2nd subpart
	 * and changing the type of the multipart. */

	PART 	*p;

	/* Convert original body (application/pgp-signed or pgp-encrypted)
	 * to a multipart body with one sub-part (the decrypted body). */

	b->type = TYPEMULTIPART;
	if (b->subtype)
	    fs_give((void **)&b->subtype);

	/* This subtype is used in mailview.c to annotate the display of
	 * encrypted or signed messages.  This subtype also means that
	 * 'sparep' points to a valid PGPDATA structure. */

	b->subtype = cpystr(OUR_PGP_ENCLOSURE_SUBTYPE);
	b->encoding = ENC8BIT;

	if (b->description)
	    fs_give((void **)&b->description);
	b->description = descr;	descr = NULL;
	b->sparep = pgpdata;	pgpdata = NULL;

	if (b->disposition.type)
	    fs_give((void **)&b->disposition.type);
	if (b->contents.text.data)
	    fs_give((void **)&b->contents.text.data);
	if (b->parameter)
	    mail_free_body_parameter(&b->parameter);

	/* Remove the 2nd part and fix linking. */

    	p = b->nested.part;
	
	/* p is signed (plaintext) */
	if (p && p->next)
	    mail_free_body_part(&p->next);    /* hide the signature */


	modified_the_body = 1;
    } while (0);


    if (!modified_the_body) {
	/* We didn't modify the body so any allocated
	 * buffer is still only known to us (not stored in
	 * a new body).  Free storage before returning. */

	fs_give((void **)&pgpdata);
	fs_give(&descr);
    }
    gpgme_data_release(message);	message = NULL;
    gpgme_data_release(signature);	signature = NULL;
    gpgme_release(ctx);

    return modified_the_body;
}




/*
 *	b		describes message structure "encrypted"
 *	msgno		to get more data from MESSAGESTREAM
 *	section		addresses messagepart to decode
 *
 * Multipart/encrypted, application/pgp-encrypted (verified)
 *   part 1 (Content-Type: application/pgp-encrypted, not verified)
 *   part 2 (Content-Type: application/octet-stream, not verified)
 *
 * We're going to convert that to
 *
 * Multipart/OUR_OPENPGP_ENCLOSURE_SUBTYPE
 *   part 1 has been freed
 *   part 2 (decrypted thing) 
 *
 * We also add a description in the multipart body->description
 * (including the result of any signature check).
 */
/*PRIVATE*/ int
do_decode(BODY *b, long msgno, const char *section)
{
    char    newSec[100];
    gpgme_error_t err;
    gpgme_ctx_t	  ctx;
    gpgme_data_t ciphertext, plaintext;

    void * descr = NULL;
    PGPDATA *	pgpdata = NULL;

    int 	modified_the_body = 0;


    dprint((3, "do_decoding(msgno=%ld type=%d subtype=%s section=%s)", msgno, b->type, b->subtype ? b->subtype : "NULL", (section && *section) ? section : (section != NULL) ? "Top" : "NULL"));
    err = openpgp_init();
    if (GPG_ERR_NO_ERROR == err)
	err = openpgp_new_context(&ctx);
    if (GPG_ERR_NO_ERROR != err) {
	dprint((1, "do_decoding: gpgme error %s", gpgme_strerror(err)));
	return err;
    }


    do {
	PART * part;


	/* Check first part of body, has to contain "Version: 1"
	 * in a application/pgp-encrypted part */

	part = b->nested.part;
	if (part->body.type != TYPEAPPLICATION		&&
	    strucmp(part->body.subtype, "pgp-encrypted")) {
	    dprint((1, "do_decoding: unexpected part %u/%s",part->body.type,part->body.subtype));
	}

	/* Check first part of body, has to contain "Version: 1". */
	{
	    char      buffer[256];
	    int	      found = 0;
	    STORE_S * store;

	    snprintf(newSec, sizeof newSec, "%s%s1", section ? section : "", (section && *section) ? "." : "");
	    store = get_part_contents(msgno, newSec);
	    so_seek(store, 0, SEEK_SET);
	    for (;;) {
		char * p = so_fgets(store, buffer, sizeof buffer);
		if (NULL == p)
		    break;
		if (!strucmp(buffer, "Version: 1")) {
		    found = TRUE;
		    break;
		}
	    }
	    if (!found) {
		dprint((1, "do_decoding: no 'Version: 1' marker"));
	    }
	}


	part = part->next;
	if (part->body.type != TYPEAPPLICATION	&&
	    strucmp(part->body.subtype, "octet-stream")) {
	    dprint((1, "do_decoding: unexpected part %u/%s",part->body.type,part->body.subtype));
	}

	/* Check second part (types), get the binary data and decode it. */

	snprintf(newSec, sizeof newSec, "%s%s2", section ? section : "", (section && *section) ? "." : "");
	if (NULL == (ciphertext = get_data_from_part(msgno, newSec)))
	    break;
	err = gpgme_data_seek(ciphertext, 0, SEEK_SET); /* rewind b4 decoding */
	err = gpgme_data_new(&plaintext);
	if (GPG_ERR_NO_ERROR != err) {
	    dprint((1, "gpgme_data_new(): %s", gpgme_strerror(err)));
	    break;
	}
	err = gpgme_op_decrypt_verify(ctx, ciphertext, plaintext);
	if (GPG_ERR_NO_ERROR != err) {
	    dprint((1, "gpgme_op_decrypt_verify(): %s", gpgme_strerror(err)));
	    break;
	}

	pgpdata = fs_get(sizeof(PGPDATA));
	memset(pgpdata, 0, sizeof *pgpdata);
	openpgp_check_decrypt(ctx, pgpdata, NULL);
	openpgp_check_verify(ctx, pgpdata, NULL);

	if (pgpdata->failed_decryption) {
	    descr = cpystr(_("This message failed decryption." NEWLINE));
	}
	else if (0 == pgpdata->bad_sigs) {
	    descr = cpystr(0 != pgpdata->valid_sigs
			   ? _("This message was cryptographically signed." NEWLINE)
			   : _("This message couldn't be verified." NEWLINE));
	}
	else {
	    descr = cpystr(0 != pgpdata->valid_sigs
			   ? _("This message was cryptographically signed by some signatures." NEWLINE)
			   : _("This message contains bad signatures." NEWLINE));
	}
    } while (0);
    gpgme_data_release(ciphertext);	ciphertext = NULL;


    if (GPG_ERR_NO_ERROR == err  &&  NULL != plaintext) do {
	/* The decoded part 'plaintext' contains a flattened MIME object
	 * (starting with "Content-Type: xxx").  It needs to be turned
	 * into a BODY, replacing the BODY of the encrypted PART. */

	size_t blength;
	char * partdata = gpgme_data_release_and_get_mem(plaintext, &blength);
        char * h;
        char * bstart;

        BODY	 *body;
        ENVELOPE *env;
        STRING	  s;
	PART	* p1;


	plaintext = NULL;			/* see above: released */
	dprint((2,"decoded: %.128s\n",partdata));

	h = partdata;				/* part "header" */
	bstart = strstr(h, "\n\n");
	bstart += 2;				/* skip over CRLF*2 */

	INIT(&s, mail_string, bstart, strlen(bstart));
	rfc822_parse_msg_full(&env, &body, h, bstart-h-1, &s, BADHOST, 0, 0);
	mail_free_envelope(&env);	   /* don't care about this */

	/* Convert original multipart/encrypted body
	 * (application/pgp-encrypted + application/octet-stream)
	 * to multipart/OUR_PGP_ENCLOSUR_SUBTYPE body with one sub-part
	 * (the decrypted body).  Free the second subpart. */

	b->type = TYPEMULTIPART;
	if (b->subtype)
	    fs_give((void **)&b->subtype);

	/* This subtype is used in mailview.c to annotate the display of
	 * encrypted or signed messages.  This subtype also means that
	 * 'sparep' points to a valid PGPDATA structure. */

	b->subtype = cpystr(OUR_PGP_ENCLOSURE_SUBTYPE);
	b->encoding = ENC8BIT;

	if (b->description)
	    fs_give((void **)&body->description);
	b->description = descr;	descr = NULL;
	b->sparep = pgpdata;	pgpdata = NULL;

	if (b->disposition.type)
	    fs_give((void **)&b->disposition.type);
	if (b->contents.text.data)
	    fs_give((void **)&b->contents.text.data);
	if (b->parameter)
	    mail_free_body_parameter(&b->parameter);

	p1 = b->nested.part;			/* to be replaced */
	assert (p1 != NULL);
	assert (p1->next != NULL);
	mail_free_body_part(&p1->next);		/* remove octet-stream */

	/* Copy over the contents of our parsed body */

	p1->body = *body;

	/* IMPORTANT BIT: set the body->contents.text.data elements
	 * to contain the decrypted data. Otherwise, it'll try to
	 * load it from the original data. Eek. */

	create_local_cache(bstart, &p1->body);

	/* Don't need locally allocated storage any longer. */

	gpgme_free(partdata);
	fs_give((void **)&body);

	modified_the_body = 1;
    } while (0);


    gpgme_data_release(plaintext);	plaintext = NULL;
    gpgme_release(ctx);

    fs_give((void **)&pgpdata);
    return modified_the_body;
}




/*
 *	b		descrption of mailbody structure
 *	msgno		to get message data from MESSAGESTREAM
 *	section		addresses the section to analyse/fiddle
 *
 * Recursively handle OpenPGP bodies in our message.
 *
 * Returns non-zero if some fiddling was done.
 */
PRIVATE int
do_fiddle_openpgp_message(BODY *b, long msgno, char *section)
{
    int modified_the_body = 0;

    if (NULL == b)
	return 0;

    dprint((3, "do_fiddle_openpgp_message(msgno=%ld type=%d subtype=%s section=%s)", msgno, b->type, b->subtype ? b->subtype : "NULL", (section && *section) ? section : (section != NULL) ? "Top" : "NULL"));

    if (b->type == TYPEMULTIPART) {

	/* Analyze all parts, OpenPGP data might be buried deep down. */

	char * const prot = parameter_val(b->parameter, "protocol");
	if (!strucmp(b->subtype,"signed")	&&
	    !strucmp(prot, "application/pgp-signature")) {

            /* A multipart signed entity. */

            modified_the_body += do_detached_signature_verify(b, msgno, section);
        }
	else if (!strucmp(b->subtype,"encrypted")	&&
		 !strucmp(prot, "application/pgp-encrypted")) {

            /* A multipart encrypted entity. */

            modified_the_body += do_decode(b, msgno, section);
	}
	else if (MIME_MSG(b->type, b->subtype)) {
	    modified_the_body += do_fiddle_openpgp_message(b->nested.msg->body, msgno, section);
	}
	else {

	    PART *  p;
	    int	    partNum;
	    char    newSec[100];

            for (p=b->nested.part,partNum=1; p; p=p->next,partNum++) {

                /* Append part number to the section string */

                snprintf(newSec, sizeof(newSec), "%s%s%d", section, *section ? "." : "", partNum);

                modified_the_body += do_fiddle_openpgp_message(&p->body, msgno, newSec);
            }
        }
    }

    return modified_the_body;
}




/*
 *	b		body of message, *structure* filled
 *	msgno		use 'msgno' to get message data
 *			from MESSAGESTREAM
 *
 * Called for every message to fiddle a message in-place
 * by decrypting/verifying OpenPGP entities.  There is no
 * garantee that OpenPGP parts are contained, check yourself.
 * Returns non-zero if something was changed.
 */
PUBLIC int
fiddle_openpgp_message(BODY *b, long msgno)
{
    return do_fiddle_openpgp_message(b, msgno, "");
}


/********************************************************************************/




/*
 * Sign a message. Called from call_mailer in send.c.
 *
 * This takes the header for the outgoing message as well as a pointer
 * to the current body (which may be reallocated).
 */
PUBLIC int
sign_outgoing_message(METAENV *header, BODY **bodyP, int dont_detach)
{
    BODY    *oldbody = *bodyP;
    int	    result = 0;

    gpgme_error_t   err;
    gpgme_ctx_t     ctx;
    gpgme_data_t    message, signature;


    dprint((3, "sign_outgoing_message()"));
    err = openpgp_init();
    if (GPG_ERR_NO_ERROR != err)
	return err;

    do {
	gpgme_sign_result_t	gpgres;
	BODY * newBody = NULL;
	PART * p1 = NULL;
	PART * p2 = NULL;


	/* Create our own context for this message. */

	err = openpgp_new_context(&ctx);
	if (GPG_ERR_NO_ERROR != err) {
	    break;
	}
	gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
	gpgme_set_armor(ctx, 1);
	gpgme_set_textmode(ctx, 1);	   /* CRLF line-endings etc */


	/* Add signers key to context */

	err = set_signer(ctx, header);
	if (GPG_ERR_NO_ERROR != err)
	    break;


	/* Create and initialize data buffers for message and signature. */

	err = flatten_body(oldbody, &message);
	if (GPG_ERR_NO_ERROR == err)
	    err = gpgme_data_new(&signature);
	if (GPG_ERR_NO_ERROR != err)
	    break;

	if (0 /*dont_detach*/) {
	    STORE_S * outs;

	    /* The simple case: message and signature are located
	     * in 'signature'. */

	    err = gpgme_op_sign(ctx, message, signature, GPGME_SIG_MODE_NORMAL);
	    if (GPG_ERR_NO_ERROR != err)
		break;
	    gpgres = gpgme_op_sign_result(ctx);
	    check_sign_result(gpgres, GPGME_SIG_MODE_NORMAL);

	    outs = store_from_gpgme(signature);

	    newBody = mail_newbody();
	    newBody->contents.text.data = (unsigned char *)outs;
	    *bodyP = newBody;

	    result = 1;
	}
	else {
	    STORE_S * s1, * s2;

	    /* Create detached signature in 'signature'
	     * (cleartext selected above). */

	    err = gpgme_op_sign(ctx, message, signature, GPGME_SIG_MODE_DETACH);
	    if (GPG_ERR_NO_ERROR != err)
		break;
	    gpgres = gpgme_op_sign_result(ctx);
	    check_sign_result(gpgres, GPGME_SIG_MODE_DETACH);


	    /* Copy gpgme data to STORE_S data, copy 'message' because
	     * data may have been altered (MIME canonical data). */

	    s1 = store_from_gpgme(message);
	    s2 = store_from_gpgme(signature);


	    /* Create a new body to contain the signed message.
	     *
	     * multipart/signed; blah blah blah
	     *      copy of existing body, possible containing several
	     *	parts (1 or 1.1., 1.2, 1.3)
	     *
	     *	2 OpenPGP object 
	     */

	    newBody = mail_newbody();

	    newBody->type = TYPEMULTIPART;
	    newBody->subtype = cpystr("signed");
	    newBody->encoding = ENC7BIT;

	    set_parameter(&newBody->parameter, "protocol", "application/pgp-signature");
	    set_parameter(&newBody->parameter, "micalg", "PGP-SHA1");

	    p1 = mail_newbody_part();		/* will get the old body */
	    p2 = mail_newbody_part();		/* gets signature */

	    p1->body.contents.text.data = (unsigned char *)s1;
	    p1->next = p2;

	    setup_body(&p2->body, "OpenPGP Cryptographic Signature", "pgp-signature", "signature.asc");
	    p2->body.contents.text.data = (unsigned char *)s2;

	    newBody->nested.part = p1;
	    *bodyP = newBody;

	    result = 1;
	}

    } while (0);


    /* Release all allocated resources */

    gpgme_data_release(signature);
    gpgme_data_release(message);
    gpgme_release(ctx);

    /*FIXME: should we release 'oldbody'?*/

    mail_free_body(&oldbody);

    dprint((2, "sign_outgoing_message returns %d", err));
    return err;
}




/*
 * Encrypt a message on the way out. Called from call_mailer in send.c
 * The body may be reallocated.
 */
PUBLIC int
encrypt_outgoing_message(METAENV *header, BODY **bodyP, int const do_sign)
{
    BODY    *oldbody = *bodyP;
    int		 result = 0;

    gpgme_error_t   err;
    gpgme_ctx_t     ctx;
    gpgme_data_t    message, ciphertext;
    gpgme_key_t *   rset = NULL;



    dprint((3, "encrypt_outgoing_message()"));
    err = openpgp_init();
    if (GPG_ERR_NO_ERROR != err)
	return err;


    do {
	STORE_S * s1, * s2;

	BODY * newBody = NULL;
	PART * p1 = NULL;
	PART * p2 = NULL;


	/* Create our own context for this message. */

	err = openpgp_new_context(&ctx);
	if (GPG_ERR_NO_ERROR != err) {
	    break;
	}
	gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
	gpgme_set_armor(ctx, 1);
	gpgme_set_textmode(ctx, 1);	   /* CRLF line-endings etc */


	err = create_keyset(ctx, header, 1, &rset);
	if (GPG_ERR_NO_ERROR != err)
	    break;
	if (do_sign) {
	    err = set_signer(ctx, header);
	    if (GPG_ERR_NO_ERROR != err)
		break;
	}


	/* Create and initialize data buffers for message and signature. */

	err = flatten_body(oldbody, &message);
	if (GPG_ERR_NO_ERROR == err)
	    err = gpgme_data_new(&ciphertext);
	if (GPG_ERR_NO_ERROR != err)
	    break;


	if (do_sign) {
	    err = gpgme_op_encrypt_sign(ctx, rset, GPGME_ENCRYPT_ALWAYS_TRUST,
					message, ciphertext);
	}
	else {
	    err = gpgme_op_encrypt(ctx, rset, GPGME_ENCRYPT_ALWAYS_TRUST,
				   message, ciphertext);
	}

	/* Copy gpgme data to STORE_S data */

	s1 = so_get(TmpFileStar, NULL, EDIT_ACCESS);
	so_puts(s1, "Version: 1");
	s2 = store_from_gpgme(ciphertext);

	/* Create a new body to contain the encrypted message.
	 *
	 * multipart/signed; blah blah blah
	 */

	newBody = mail_newbody();

	newBody->type = TYPEAPPLICATION;
	newBody->subtype = cpystr("encrypted");
	newBody->encoding = ENCBINARY;

	set_parameter(&newBody->parameter, "protocol", "application/pgp-encrypted");

	p1 = mail_newbody_part();		/* will get protocol version */
	p2 = mail_newbody_part();		/* gets ciphertext */

	setup_body(&p1->body, "OpenPGP control information", "pgp-encrypted", NULL);
	so_seek(s1, 0, SEEK_SET);
	p1->body.contents.text.data = (unsigned char *)s1;

	setup_body(&p2->body, "OpenPGP encrypted data", "octet-stream", NULL);
	so_seek(s2, 0, SEEK_SET);
	p2->body.contents.text.data = (unsigned char *)s2;

	*bodyP = newBody;

	result = 1;
    } while (0);


    /* Release all allocated resources */

    fs_give((void **)&rset);
    gpgme_data_release(ciphertext);
    gpgme_data_release(message);
    gpgme_release(ctx);

    /*FIXME: should we release 'oldbody'?*/

    mail_free_body(&oldbody);

    dprint((2, "encrypt_outgoing_message returns %d", result));
    return result;
}

#endif /* OPENPGP */
