#!/usr/bin/env python
# -*- coding: utf-8 -*-

#   GNU General Public License

#   Telia Play KODI Addon
#   Copyright (C) 2022 Mariusz89B

#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.

#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.

#   You should have received a copy of the GNU General Public License
#   along with this program. If not, see https://www.gnu.org/licenses.

#   MIT License

#   Permission is hereby granted, free of charge, to any person obtaining a copy
#   of this software and associated documentation files (the "Software"), to deal
#   in the Software without restriction, including without limitation the rights
#   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#   copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:

#   The above copyright notice and this permission notice shall be included in all
#   copies or substantial portions of the Software.

#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#   SOFTWARE.

#   Disclaimer
#   This add-on is unoffical and is not endorsed or supported by Telia Company AB in any way. Any trademarks used belong to their owning companies and organisations.

import sys

import xbmc
import xbmcaddon
import xbmcgui
import xbmcplugin
import xbmcvfs

import urllib.parse as urlparse
from urllib.parse import urlencode, quote_plus, quote, unquote

from contextlib import contextmanager

import json
import re
import requests

localized = xbmcaddon.Addon().getLocalizedString

class c_ext_info():
    def __init__(self):
        params = dict(urlparse.parse_qsl(sys.argv[3]))
        title = params.get('label')

        self.ext_info(title)

    def check_ext_info(self):
        return xbmc.getCondVisibility('System.AddonIsEnabled({id})'.format(id='script.extendedinfo'))

    def check_movie_db_helper(self):
        return xbmc.getCondVisibility('System.AddonIsEnabled({id})'.format(id='plugin.video.themoviedb.helper'))

    @contextmanager
    def busydialog(self):
        xbmc.executebuiltin('ActivateWindow(busydialognocancel)')
        try:
            yield
        finally:
            xbmc.executebuiltin('Dialog.Close(busydialognocancel)')

    def ext_info(self, title):
        extInfo = self.check_ext_info()
        mvDbHelper = self.check_movie_db_helper()

        check = True

        if not extInfo and not mvDbHelper:
            check = False

        if check:
            match = re.search('(.*?)\([0-9]{4}\)$', title)
            if match:
                title = match.group(1).strip()
                title = "Movie"
            if title == "Movie":
                selection = 0
            elif title == "":
                selection = 1
            else:
                selection = xbmcgui.Dialog().select(localized(30024), [localized(30025), localized(30026)])
                if selection == -1:
                    return

            where = ["movie", "tv"]

            key = '4d7b67222e47d5d8a6176fcacbfe9240'

            url = 'https://api.themoviedb.org/3/search/{where}?query={query}&api_key={key}&include_adult=false&page=1'.format(where=where[selection], query=title, key=key).encode()

            r = requests.get(url)
            data = json.loads(r.content)
            results = data.get('results')
            id = ''
            with self.busydialog():
                if results:
                    if len(results) > 0:
                        names = ["{} ({})".format(x.get('name') or x.get('title'), x.get('first_air_date') or x.get('release_date'))
                                 for x in results]
                        what = xbmcgui.Dialog().select(title, names)
                        if what > -1:
                            id = results[what].get('id')
                            ttype = results[what].get('media_ttype')
                            if ttype not in ["movie", "tv"]:
                                if selection == 0:
                                    ttype = "movie"
                                else:
                                    ttype = "tv"
                            if ttype == 'movie':
                                if extInfo:
                                    xbmc.executebuiltin('RunScript(script.extendedinfo,info=extendedinfo,name={title},id={id})'.format(title=title, id=id))
                                elif mvDbHelper:
                                    xbmc.executebuiltin('Dialog.Close(all,true)')
                                    xbmc.executebuiltin('ActivateWindow(Videos,"plugin://plugin.video.themoviedb.helper/?info=search&type=movie&query={title}&tmdb_id={id}",return)'.format(title=title, id=id))
                            elif ttype == 'tv':
                                if extInfo:
                                    xbmc.executebuiltin('RunScript(script.extendedinfo,info=extendedtvinfo,name={title},id={id})'.format(title=title, id=id))
                                elif mvDbHelper:
                                    xbmc.executebuiltin('Dialog.Close(all,true)')
                                    xbmc.executebuiltin('ActivateWindow(Videos,"plugin://plugin.video.themoviedb.helper/?info=search&type=tv&query={title}&tmdb_id={id}",return)'.format(title=title, id=id))
                            else:
                                xbmcgui.Dialog().notification(localized(30012), localized(30016).format(title))

                    else:
                        if selection == 0:
                            xbmcgui.Dialog().notification(localized(30012), localized(30017).format(title))
                            search = xbmcgui.Dialog().input(localized(30019), title)
                            if search:
                                if extInfo:
                                    xbmc.executebuiltin('RunScript(script.extendedinfo,info=extendedinfo,name={title})'.format(title=search))
                                elif mvDbHelper:
                                    xbmc.executebuiltin('Dialog.Close(all,true)')
                                    xbmc.executebuiltin('ActivateWindow(Videos,"plugin://plugin.video.themoviedb.helper/?info=search&type=movies&query={title}",return)'.format(title=title))
                            else:
                                return
                        elif selection == 1:
                            xbmcgui.Dialog().notification(localized(30012), localized(30018).format(title))
                            search = xbmcgui.Dialog().input(localized(30019), title)
                            if search:
                                if extInfo:
                                    xbmc.executebuiltin('RunScript(script.extendedinfo,info=extendedtvinfo,name={title})'.format(title=search))
                                elif mvDbHelper:
                                    xbmc.executebuiltin('Dialog.Close(all,true)')
                                    xbmc.executebuiltin('ActivateWindow(Videos,"plugin://plugin.video.themoviedb.helper/?info=search&type=tv&query={title}",return)'.format(title=title))
                            else:
                                return
                        else:
                            xbmcgui.Dialog().notification(localized(30012), localized(30016).format(title))
                else:
                    if selection == 0:
                        xbmcgui.Dialog().notification(localized(30012), localized(30017).format(title))
                        search = xbmcgui.Dialog().input(localized(30019), title)
                        if search:
                            if extInfo:
                                xbmc.executebuiltin('RunScript(script.extendedinfo,info=extendedinfo,name={title})'.format(title=search))
                            elif mvDbHelper:
                                xbmc.executebuiltin('Dialog.Close(all,true)')
                                xbmc.executebuiltin('ActivateWindow(Videos,"plugin://plugin.video.themoviedb.helper/?info=search&type=movies&query={title}",return)'.format(title=search))
                        else:
                            return
                    elif selection == 1:
                        xbmcgui.Dialog().notification(localized(30012), localized(30018).format(title))
                        search = xbmcgui.Dialog().input(localized(30019), title)
                        if search:
                            if extInfo:
                                xbmc.executebuiltin('RunScript(script.extendedinfo,info=extendedtvinfo,name={title})'.format(title=search))
                            elif mvDbHelper:
                                xbmc.executebuiltin('Dialog.Close(all,true)')
                                xbmc.executebuiltin('ActivateWindow(Videos,"plugin://plugin.video.themoviedb.helper/?info=search&type=tv&query={title}",return)'.format(title=search))
                        else:
                            return
                    else:
                        xbmcgui.Dialog().notification(localized(30012), localized(30016).format(title))

        else:
            sel = xbmcgui.Dialog().select(localized(30020), ['script.extendedinfo', 'plugin.video.themoviedb.helper'])
            restart = True

            if sel < 0:
                return
            if sel == 0:
                selected = 'script.extendedinfo'
            elif sel == 1: 
                selected = 'plugin.video.themoviedb.helper'
                restart = False

            try:
                res = xbmc.executebuiltin('InstallAddon({0})'.format(selected))
                if not res:
                    installed = xbmc.getCondVisibility('System.HasAddon({id})'.format(id=selected))
                    if installed:
                        xbmc.executebuiltin('EnableAddon({0})'.format(selected))

            except:
                res = None

            if restart:
                if res:
                    xbmcgui.Dialog().ok(localized(30012), localized(30021))
                    self.exitAddon()
                else:
                    xbmcgui.Dialog().ok(localized(30022), localized(30023).format('{0}'.format(selected)))
                    return