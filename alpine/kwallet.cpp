/*
 * kwallet.cpp: KWallet password cache for the Alpine Messaging System
 *
 * ========================================================================
 * Copyright 2009 Jeff Frasca, 
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * ========================================================================
 *
 * This file is derived from Subversion's kwallet.cpp from their 
 * svn_kwallet_auth module.  Svn's kwallet.cpp was obtained under 
 * the terms of the Apache 2.0 license.
 */

#include <config.h>

#ifdef KWALLET

/* basic includes */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dbus/dbus.h>
#include <QtCore/QCoreApplication>
#include <QtCore/QList>
#include <QtCore/QMap>
#include <QtCore/QString>
#include <QtGui/QApplication>
#include <QtGui/QX11Info>

#include <kaboutdata.h>
#include <kcmdlineargs.h>
#include <kcomponentdata.h>
#include <klocalizedstring.h>
#include <kwallet.h>
#include <kwindowsystem.h>
#include <netwm.h>
#include <netwm_def.h>

extern "C" {
#   include "headers.h"
#   include "alpine.h"
#   include "imap.h"
#   include "status.h"
#   include "mailview.h"
#   include "mailcmd.h"
#   include "radio.h"
#   include "keymenu.h"
#   include "signal.h"
#   include "mailpart.h"
#   include "mailindx.h"
#   include "arg.h"
#   include "busy.h"
#   include "titlebar.h"
#   include "../pith/state.h"
#   include "../pith/conf.h"
#   include "../pith/msgno.h"
#   include "../pith/filter.h"
#   include "../pith/news.h"
#   include "../pith/util.h"
#   include "../pith/list.h"
#   include "../pith/margin.h"
}

/*-----------------------------------------------------------------------*/
/* KWallet local password provider (adapted from subversion)             */
/*-----------------------------------------------------------------------*/


#define INITIALIZE_APPLICATION                                            \
    if (!qapp) {                                                          \
        if (! qApp) {                                                     \
            int argc = 1;                                                 \
            qapp = new QCoreApplication(argc,                             \
                    (char *[1]) {(char *) "alpine"});                     \
        }                                                                 \
    }

QCoreApplication *qapp = NULL;
KWallet::Wallet *wallet = NULL;

static QString
get_wallet_name(void)
{
#if 0 // original SVN code.  For right now, just use the default wallet.
      // I'm leaving this code to show how svn interfaces to their config
      // system (mostly for the QString::fromUtf8() call).
    svn_config_t *config =
        static_cast<svn_config_t *> (apr_hash_get(parameters,
                    SVN_AUTH_PARAM_CONFIG_CATEGORY_CONFIG,
                    APR_HASH_KEY_STRING));
    const char *wallet_name;
    svn_config_get(config,
            &wallet_name,
            SVN_CONFIG_SECTION_AUTH,
            SVN_CONFIG_OPTION_KWALLET_WALLET,
            "");
    if (strcmp(wallet_name, "") == 0) {
    }
    else {
        return QString::fromUtf8(wallet_name);
    }
#endif
  return KWallet::Wallet::NetworkWallet();
}

// Konsole leaves a WINDOWID env set.  I believe 1 is the root 
// window, so this should work by default, the kwallet dialog 
// might end up in a funny spot with out the env variable.
static WId
get_wid(void)
{
  FILE *logf = NULL;
  WId wid = 1;
  const char *wid_env_string = getenv("WINDOWID");
  logf = fopen("alpine.log", "a");
  if (wid_env_string) {
      long wid_env = atol(wid_env_string);
      if (wid_env != 0) {
          wid = wid_env;
      }
  }
  logf && fprintf(logf, "WId: %d, env:WINDOWID: %s\n", wid, wid_env_string);

  fclose(logf);

  return wid;
}

// This was more complex for subversion, I'm leaving it as a wrapper to minimize 
// the changes to the rest of the code.
static KWallet::Wallet *
get_wallet(QString wallet_name)
{
  return KWallet::Wallet::openWallet(wallet_name, get_wid(), KWallet::Wallet::Synchronous);
}

/* Implementation of svn_auth__password_get_t that retrieves
   the password from KWallet. */
extern "C" int 
kwallet_password_get(MMLOGIN_S **l)
{
    if (! dbus_bus_get(DBUS_BUS_SESSION, NULL)) {
         return 0;
    }

    INITIALIZE_APPLICATION;

    KCmdLineArgs::init(1, &ps_global->pine_name,
            QByteArray::fromRawData(ps_global->pine_name, strlen(ps_global->pine_name)),
            QByteArray::QByteArray (),
            ki18n("alpine"),
            PACKAGE_VERSION,
            ki18n("Alpine Messaging System"),
            KCmdLineArgs::CmdLineArgKDE);
    KComponentData component_data(KCmdLineArgs::aboutData());
    QString wallet_name = get_wallet_name();
    QString folder = QString::fromUtf8("Alpine");
    QStringList keys;
    MMLOGIN_S *lp;
    int r = 0;

    if (!wallet) {
        QString wallet_name = get_wallet_name();
        wallet = get_wallet(wallet_name);
    }


    if (wallet) {
        if (wallet->setFolder(folder)) {
            keys = wallet->entryList();
            char *key_str = NULL;
            char *pw_ent;
            QStringListIterator i(keys);
            QString pw;
            QString key; // = QString::fromUtf8("m*"); // grab all of 'em.
            while (i.hasNext()) {
                if (key_str) free(key_str);
                key = i.next();
                key_str = strdup(key.toUtf8().data());
                if (wallet->readPassword(key, pw)) continue;
                pw_ent = pw.toUtf8().data();
                /* Password keys are: <hostname:port>/<user>
                 * And the password entries are: <password>\n<altflag>\n<torighthost>
                 */
                STRLIST_S hostlist[2];
                int flags = 0;
                char *user;
                char *s, *f = NULL;

                hostlist[0].name = key_str; 
                if (s = strchr(key_str, '/')) 
                    *s++ = '\0';
                else 
                    continue;

                user = s;

                if (s = strchr(pw_ent, '\n')) {
                    *s++ = '\0';
                    f = s;

                    if (s = strchr(s, '\n')) {
                        *s++ = '\0';
                        hostlist[0].next = &hostlist[1];
                        hostlist[1].next = NULL;
                        hostlist[1].name = s;
                    } else 
                        hostlist[0].next = NULL;
                } else 
                    continue;
                
                flags = atoi(f);

                imap_set_passwd(l, pw_ent, user, hostlist, flags & 0x01, 0, 0);
                r = 1; // we loaded at least one.
            }
            if (key_str) free(key_str);
        }
    }
    return r;
}

/* Implementation of svn_auth__password_set_t that stores
   the password in KWallet. */
extern "C" int
kwallet_password_set(MMLOGIN_S *l)
{

    if (! dbus_bus_get(DBUS_BUS_SESSION, NULL)) {
        return 0;
    }

    INITIALIZE_APPLICATION ;

    KCmdLineArgs::init(1, &ps_global->pine_name,
                QByteArray::fromRawData(ps_global->pine_name, strlen(ps_global->pine_name)),
                QByteArray::QByteArray (),
                ki18n("alpine"),
                PACKAGE_VERSION,
                ki18n("Alpine Messaging System"),
                KCmdLineArgs::CmdLineArgKDE);
    KComponentData component_data(KCmdLineArgs::aboutData());
    QString folder = QString::fromUtf8("Alpine");

    if (!wallet) {
        QString wallet_name = get_wallet_name();
        wallet = get_wallet(wallet_name);
    }

    if (wallet) {
        if (! wallet->hasFolder(folder)) {
            wallet->createFolder(folder);
        }
        if (wallet->setFolder(folder)) {
            /* Password keys are: <hostname:port>/<user>
             * And the password entries are: <passwod>\n<altflag>\n<torighthost>
             */
            for (; l; l = l->next) {
                QString key = QString::fromUtf8((l->hosts && l->hosts->name) ? l->hosts->name : "") 
                    + "/" + QString::fromUtf8(l->user ? l->user : "");
                QString pw_ent = QString::fromUtf8(l->passwd ? l->passwd : "")
                    + "\n" + QString::number(l->altflag,10);
                QString cur_pw;

                if (l->hosts && l->hosts->next && l->hosts->next->name) 
                    pw_ent += "\n" + QString::fromUtf8(l->hosts->next->name);

                wallet->writePassword(key, pw_ent);
            }
        } else 
            return 0;
        return 1;
    }

    return 0;
}

#endif // KWALLET
