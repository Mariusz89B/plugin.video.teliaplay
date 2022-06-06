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
import os

import xbmc
import xbmcaddon
import xbmcgui
import xbmcplugin
import xbmcvfs

import urllib.parse as urlparse
from urllib.parse import urlencode, quote_plus, quote, unquote

from datetime import *

import requests
from requests.exceptions import HTTPError, ConnectionError, Timeout, RequestException

import json
import re
import time
import threading
import six
import uuid

from ext import c_ext_info

base_url = sys.argv[0]
addon_handle = int(sys.argv[1])
params = dict(urlparse.parse_qsl(sys.argv[2][1:]))
addon = xbmcaddon.Addon(id='plugin.video.teliaplay')

exlink = params.get('url', None)
extitle = params.get('label', None)
exid = params.get('media_id', None)
excatchup = params.get('catchup', None)
exstart = params.get('start', None)
exend = params.get('end', None)

profile_path = xbmcvfs.translatePath(addon.getAddonInfo('profile'))

localized = xbmcaddon.Addon().getLocalizedString
x_localized = xbmc.getLocalizedString

path = addon.getAddonInfo('path')
resources = os.path.join(path, 'resources')
icons = os.path.join(resources, 'icons')

thumb = path + 'icon.png'
poster = path + 'icon.png'
banner = path + 'banner.jpg'
clearlogo = path + 'clearlogo.png'
fanart = resources + 'fanart.jpg'
icon = path + 'icon.png'

tv_icon = os.path.join(icons, 'tv.png')
vod_icon = os.path.join(icons, 'vod.png')
sport_icon = os.path.join(icons, 'sport.png')
kids_icon = os.path.join(icons, 'kids.png')
fav_icon = os.path.join(icons, 'fav.png')
search_icon = os.path.join(icons, 'search.png')
lock_icon = os.path.join(icons, 'lock.png')
settings_icon = os.path.join(icons, 'settings.png')

login = addon.getSetting('teliaplay_username').strip()
password = addon.getSetting('teliaplay_password').strip()

country = int(addon.getSetting('teliaplay_locale'))

base = ['https://teliatv.dk', 'https://www.teliaplay.se']
referer = ['https://teliatv.dk/', 'https://www.teliaplay.se/']
host = ['www.teliatv.dk', 'www.teliaplay.se']

cc = ['dk', 'se']
ca = ['DK', 'SE']

sess = requests.Session()
timeouts = (5, 5)

UA = xbmc.getUserAgent()

class proxydt(datetime):
    @staticmethod
    def strptime(date_string, format):
        import time
        try:
            res = datetime.strptime(date_string, format)
        except:
            res = datetime(*(time.strptime(date_string, format)[0:6]))
        return res

proxydt = proxydt

class Threading(object):
    def __init__(self):
        self.thread = threading.Thread(target=self.run, args=())
        self.thread.daemon = True
        self.thread.start()

    def run(self):
        while not xbmc.Monitor().abortRequested():
            ab = check_refresh()
            if not ab:
                result = check_login()
                if result is not None:
                    validTo, beartoken, refrtoken, cookies = result

                    addon.setSetting('teliaplay_validto', str(validTo))
                    addon.setSetting('teliaplay_beartoken', str(beartoken))
                    addon.setSetting('teliaplay_refrtoken', str(refrtoken))
                    addon.setSetting('teliaplay_cookies', str(cookies))

                time.sleep(30)

            if xbmc.Monitor().waitForAbort(1):
                break

def build_url(query):
    return base_url + '?' + urlencode(query)

def add_item(label, url, mode, folder, playable, media_id=None, catchup=None, start=None, end=None, thumb=None, poster=None, banner=None, clearlogo=None, icon=None, fanart=None, plot=None, context_menu=None, item_count=None, info_labels=False, page=0):
    list_item = xbmcgui.ListItem(label=label)

    if playable:
        list_item.setProperty('IsPlayable', 'true')

        if context_menu:
            info = x_localized(19047)
            context_menu.insert(0, (info, 'Action(Info)'))

    if context_menu:
        list_item.addContextMenuItems(context_menu, replaceItems=True)

    if not info_labels:
        info_labels = {'title': label}

    list_item.setInfo(type='Video', infoLabels=info_labels)

    thumb = thumb if thumb else icon
    poster = poster if poster else icon
    banner = banner if banner else icon
    clearlogo = clearlogo if clearlogo else icon

    list_item.setArt({'thumb': thumb, 'poster': poster, 'banner': banner, 'fanart': fanart, 'clearlogo': clearlogo})

    xbmcplugin.addDirectoryItem(
        handle=addon_handle,
        url=build_url({'label': label, 'mode': mode, 'url': url, 'media_id': media_id, 'catchup': catchup, 'start': start, 'end': end, 'page': page, 'plot': plot, 'image': icon}),
        listitem=list_item,
        isFolder=folder)

def send_req(url, post=False, json=None, headers=None, data=None, params=None, cookies=None, verify=True, allow_redirects=False, timeout=None):
    try:
        if post:
            response = sess.post(url, headers=headers, json=json, data=data, params=params, cookies=cookies, verify=verify, allow_redirects=allow_redirects, timeout=timeout)
        else:
            response = sess.get(url, headers=headers, json=json, data=data, params=params, cookies=cookies, verify=verify, allow_redirects=allow_redirects, timeout=timeout)

    except HTTPError as e:
        print('HTTPError: {}'.format(str(e)))
        response = False

    except ConnectionError as e:
        print('ConnectionError: {}'.format(str(e)))
        response = False

    except Timeout as e:
        print('Timeout: {}'.format(str(e))) 
        response = False

    except RequestException as e:
        print('RequestException: {}'.format(str(e))) 
        response = False

    except:
        xbmcgui.Dialog().notification(localized(30012), localized(30006))
        response = False

    return response

def create_data():
    dashjs = str(uuid.uuid4())
    addon.setSetting('teliaplay_devush', 'WEB-' + str(dashjs))

    tv_client_boot_id = str(uuid.uuid4())
    addon.setSetting('teliaplay_tv_client_boot_id', str(tv_client_boot_id))

    timestamp = int(time.time())*1000
    addon.setSetting('teliaplay_timestamp', str(timestamp))

    sessionid = six.text_type(uuid.uuid4())
    addon.setSetting('teliaplay_sess_id', str(sessionid))

    return dashjs, tv_client_boot_id, timestamp, sessionid

def check_login():
        result = None

        valid_to = addon.getSetting('teliaplay_validto')
        beartoken = addon.getSetting('teliaplay_beartoken')
        refrtoken = addon.getSetting('teliaplay_refrtoken')
        cookies = addon.getSetting('teliaplay_cookies')

        refresh = refresh_timedelta(valid_to)

        if not valid_to:
            valid_to = datetime.now() - timedelta(days=1)

        if not beartoken and refresh < timedelta(minutes=1):
            login, profile = login_data(reconnect=True)

            result = valid_to, beartoken, refrtoken, cookies

        return result

def check_refresh():
        valid_to = addon.getSetting('teliaplay_validto')
        beartoken = addon.getSetting('teliaplay_beartoken')

        refresh = refresh_timedelta(valid_to)

        if not valid_to:
            valid_to = datetime.now() - timedelta(days=1)

        if refresh is not None:
            refr = True if not beartoken or refresh < timedelta(minutes=1) else False
        else:
            refr = False

        return refr

def refresh_timedelta(valid_to):
        result = None

        if 'Z' in valid_to:
            valid_to = iso8601.parse_date(valid_to)
        elif valid_to != '':
            if not valid_to:
                try:
                    date_time_format = '%Y-%m-%dT%H:%M:%S.%f+' + valid_to.split('+')[1]
                except:
                    date_time_format = '%Y-%m-%dT%H:%M:%S.%f+' + valid_to.split('+')[0]

                valid_to = datetime(*(time.strptime(valid_to, date_time_format)[0:6]))
                timestamp = int(time.mktime(valid_to.timetuple()))
                token_valid_to = datetime.fromtimestamp(int(timestamp))
            else:
                token_valid_to = datetime.now()
        else:
            token_valid_to = datetime.now()

        result = token_valid_to - datetime.now()

        return result

def login_service():
    try:
        dashjs = addon.getSetting('teliaplay_devush')
        if dashjs == '':
            try:
                msg = localized(30000)
                xbmcgui.Dialog().ok(localized(30012), str(msg))
            except:
                pass

            create_data()

            login = login_data(reconnect=False)
        else:
            login = True

        if login:
            run = Threading()

        return login

    except Exception as ex:
        print('login_service exception: {}'.format(ex))
        addon.setSetting('teliaplay_devush', '')
        xbmcgui.Dialog().notification(localized(30012), localized(30006))
    return False

def login_data(reconnect, retry=0):
    dashjs, tv_client_boot_id, timestamp, sessionid = create_data()

    try:
        url = 'https://log.tvoip.telia.com:6003/logstash'

        headers = {
            'Host': 'log.tvoip.telia.com:6003',
            'User-Agent': UA,
            'Content-Type': 'text/plain;charset=UTF-8',
            'Accept': '*/*',
            'Sec-GPC': '1',
            'Origin': base[country],
            'Sec-Fetch-Site': 'cross-site',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Dest': 'empty',
            'Referer': referer[country],
            'Accept-Language': 'en-US,en;q=0.9',
        }

        data = {
            'bootId': tv_client_boot_id,
            'networkType': 'UNKNOWN',
            'deviceId': dashjs,
            'deviceType': 'WEB',
            'model': 'unknown_model',
            'productName': 'Microsoft Edge 101.0.1210.32',
            'platformName': 'Windows',
            'platformVersion': 'NT 10.0',
            'nativeVersion': 'unknown_platformVersion',
            'uiName': 'one-web-login',
            'client': 'WEB',
            'uiVersion': '1.35.0',
            'environment': 'PROD',
            'country': ca[country],
            'brand': 'TELIA',
            'logType': 'STATISTICS_HTTP',
            'payloads': [{
                'sequence': 1,
                'timestamp': timestamp,
                'level': 'ERROR',
                'loggerId': 'telia-data-backend/System',
                'message': 'Failed to get service status due to timeout after 1000 ms'
                }]
            }

        response = send_req(url, post=True, headers=headers, json=data, verify=True, timeout=timeouts)

        url = 'https://logingateway-telia.clientapi-prod.live.tv.telia.net/logingateway/rest/v1/authenticate'

        headers = {
            'accept': '*/*',
            'accept-language': 'sv,en;q=0.9,en-GB;q=0.8,en-US;q=0.7,pl;q=0.6,fr;q=0.5',
            'DNT': '1',
            'origin': 'https://login.teliaplay.{cc}'.format(cc=cc[country]),
            'referer': 'https://login.teliaplay.{cc}/'.format(cc=cc[country]),
            'user-agent': UA,
            'x-country': ca[country],
        }

        params = {
            'redirectUri': 'https://www.teliaplay.{cc}/'.format(cc=cc[country]),
        }

        data = {
            'deviceId': dashjs,
            'deviceType': 'WEB',
            'password': password,
            'username': login,
            'whiteLabelBrand': 'TELIA',
        }

        response = send_req(url, post=True, headers=headers, json=data, params=params, verify=True, timeout=timeouts)

        code = ''

        if not response:
            xbmcgui.Dialog().notification(localized(30012), localized(30006))
            return

        j_response = response.json()
        code = j_response['redirectUri'].replace('https://www.teliaplay.{cc}/?code='.format(cc=cc[country]), '')

        url = 'https://logingateway-telia.clientapi-prod.live.tv.telia.net/logingateway/rest/v1/oauth/token'

        headers = {
            'accept-language': 'sv,en;q=0.9,en-GB;q=0.8,en-US;q=0.7,pl;q=0.6,fr;q=0.5',
            'DNT': '1',
            'origin': 'https://www.teliaplay.{cc}'.format(cc=cc[country]),
            'referer': 'https://www.teliaplay.{cc}/'.format(cc=cc[country]),
            'user-agent': UA,
            'x-country': ca[country],
            'accept': 'application/json',
            'tv-client-boot-id': tv_client_boot_id,
            'tv-client-name': 'web',
        }

        params = {
            'code': code,
        }

        response = send_req(url, post=True, params=params, headers=headers, timeout=timeouts)

        if not response:
            if reconnect and retry < 3:
                retry += 1
                login_service(reconnect=True, retry=retry)
            else:
                xbmcgui.Dialog().notification(localized(30012), localized(30007))
                return False

        j_response = response.json()

        try:
            if 'Username/password was incorrect' in j_response['errorMessage']:
                xbmcgui.Dialog().notification(localized(30012), localized(30007))
                return False
        except:
            pass

        validTo = j_response.get('teliaplay_validTo', '')
        addon.setSetting('teliaplay_validto', str(validTo))

        beartoken = j_response.get('accessToken', '')
        addon.setSetting('teliaplay_beartoken', str(beartoken))

        refrtoken = j_response.get('refreshToken', '')
        addon.setSetting('teliaplay_refrtoken', str(refrtoken))

        url = 'https://ottapi.prod.telia.net/web/{cc}/tvclientgateway/rest/secure/v1/provision'.format(cc=cc[country])

        headers = {
            'host': 'ottapi.prod.telia.net',
            'authorization': 'Bearer ' + beartoken,
            'If-Modified-Since': '0',
            'user-agent': UA,
            'tv-client-boot-id': tv_client_boot_id,
            'content-type': 'application/json',
            'accept': '*/*',
            'sec-GPC': '1',
            'origin': base[country],
            'referer': referer[country],
            'accept-language': 'en-US,en;q=0.9',
        }

        data = {
            'deviceId': dashjs,
            'drmType': 'WIDEVINE',
            'uiName': 'one-web',
            'uiVersion': '1.43.0',
            'nativeVersion': 'NT 10.0',
            'model': 'windows_desktop',
            'networkType': 'unknown',
            'productName': 'Microsoft Edge 101.0.1210.32',
            'platformName': 'Windows',
            'platformVersion': 'NT 10.0',
        }

        response = send_req(url, post=True, headers=headers, json=data, verify=True, timeout=timeouts)

        try:
            response = response.json()
            if response['errorCode'] == 61004:
                print('errorCode 61004')
                xbmcgui.Dialog().notification(localized(30012), localized(30013))
                addon.setSetting('teliaplay_sess_id', '')
                addon.setSetting('teliaplay_devush', '')
                if reconnect:
                    login_service(reconnect=True)
                else:
                    return False

            elif response['errorCode'] == 9030:
                print('errorCode 9030')
                if not reconnect:
                    xbmcgui.Dialog().notification(localized(30012), localized(30006))
                addon.setSetting('teliaplay_sess_id', '')
                addon.setSetting('teliaplay_devush', '')
                if reconnect:
                    login_service(reconnect=True)
                else:
                    return False

            elif response['errorCode'] == 61002:
                print('errorCode 61002')
                if not reconnect:
                    xbmcgui.Dialog().notification(localized(30012), localized(30006))
                tv_client_boot_id = str(uuid.uuid4())
                addon.setSetting('teliaplay_tv_client_boot_id', str(tv_client_boot_id))
                if reconnect:
                    login_service(reconnect=True)
                else:
                    return False

        except:
            pass

        cookies = {}

        cookies = sess.cookies
        addon.setSetting('teliaplay_cookies', str(cookies))

        url = 'https://ottapi.prod.telia.net/web/{cc}/tvclientgateway/rest/secure/v1/pubsub'.format(cc=cc[country])

        headers = {
            'user-agent': UA,
            'accept': '*/*',
            'accept-language': "sv,en;q=0.9,en-GB;q=0.8,en-US;q=0.7,pl;q=0.6",
            'authorization': 'Bearer ' + beartoken,
            'tv-client-boot-id': tv_client_boot_id,
        }

        response = send_req(url, headers=headers, cookies=sess.cookies, allow_redirects=False, timeout=timeouts)

        if not response:
            if reconnect:
                login_service(reconnect=True)
            else:
                return False

        response = response.json()

        usern = response['channels']['engagement']
        addon.setSetting('teliaplay_usern', str(usern))

        subtoken = response['config']['subscriberToken']
        addon.setSetting('teliaplay_subtoken', str(subtoken))

        return True

    except Exception as ex:
        print('login_data exception: {}'.format(ex))

    return False

def video_on_demand():
    add_item(label=localized(30030), url='', mode='vod_genre_movies', icon=icon, fanart=fanart, folder=True, playable=False)
    add_item(label=localized(30031), url='', mode='vod_genre_series', icon=icon, fanart=fanart, folder=True, playable=False)

    xbmcplugin.endOfDirectory(addon_handle, cacheToDisc=False)

def vod_genre(genre):
    beartoken = addon.getSetting('teliaplay_beartoken')
    tv_client_boot_id = addon.getSetting('teliaplay_tv_client_boot_id')

    url = 'https://graphql-telia.t6a.net/'

    headers = {
        'authorization': 'Bearer ' + beartoken,
        'tv-client-name': 'androidmob',
        'tv-client-version': '4.7.0',
        'tv-client-boot-id': tv_client_boot_id,
        'x-country': ca[country],
        'content-type': 'application/json',
        'accept-encoding': 'gzip',
        'user-agent': 'okhttp/4.9.3',
    }

    json = {
        'operationName': 'getPage',

        'variables': {
            'id': '{0}'.format(genre),
            'limit': 10,
            'pagePanelsOffset': 10
        },

        'extensions': '{"persistedQuery":{"version":1,"sha256Hash":"7473d510f7c82bb7a158c97deca754cc483ba65c44b2955d51713dc59e594e6f"}}',
        #'query': 'query getSubPages($id: String!) { page(id: $id) { id subPages { items{ id name } } } }'
        }

    response = send_req(url, post=True, json=json, headers=headers)

    if response:
        j_response = response.json()

        genres = []

        beartoken = addon.getSetting('teliaplay_beartoken')
        tv_client_boot_id = addon.getSetting('teliaplay_tv_client_boot_id')

        url = 'https://graphql-telia.t6a.net/'

        headers = {
            'authorization': 'Bearer ' + beartoken,
            'tv-client-name': 'androidmob',
            'tv-client-version': '4.7.0',
            'tv-client-boot-id': tv_client_boot_id,
            'x-country': ca[country],
            'content-type': 'application/json',
            'accept-encoding': 'gzip',
            'user-agent': 'okhttp/4.9.3',
        }

        json = {
            'operationName': 'getCommonBrowsePage',
            'variables': {
                'mediaContentLimit': 16,
                'pageId': genre
            },

            'query': 'query getCommonBrowsePage($pageId: String!, $mediaContentLimit: Int!) { page(id: $pageId) { id pagePanels { items { __typename title id ...MobileShowcasePanel ...MobileMediaPanel ...MobileSelectionMediaPanel ...MobileSingleFeaturePanel ...MobileStoresPanel } } } }  fragment PlaybackSpec on PlaybackSpec { accessControl videoId videoIdType watchMode }  fragment Vod on Vod { audioLang { name code } playbackSpec { __typename ...PlaybackSpec } price { readable } validFrom { timestamp readableDistance(type: FUZZY) } validTo { timestamp } }  fragment Linear on PlaybackPlayLinear { item { startover { playbackSpec { __typename ...PlaybackSpec } } playbackSpec { __typename ...PlaybackSpec } startTime { timestamp readableDistance(type: FUZZY) } endTime { timestamp } } }  fragment Rental on PlaybackPlayVodRental { item { __typename ...Vod } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) msTo } } }  fragment Recording on PlaybackPlayRecording { item { playbackSpec { __typename ...PlaybackSpec } audioLang { name code } validFrom { timestamp } validTo { timestamp } } startover { playbackSpec { __typename ...PlaybackSpec } } }  fragment SubscriptionProductStandard on SubscriptionProductStandard { id price { readable } }  fragment SubscriptionProductDualEntry on SubscriptionProductDualEntry { id }  fragment SubscriptionProductTVE on SubscriptionProductTVE { id }  fragment SubscriptionProductFallback on SubscriptionProductFallback { id }  fragment Playback on Playback { play { subscription { item { __typename ...Vod } } linear { __typename ...Linear } rental { __typename ...Rental } npvr { __typename ...Recording } } buy { subscriptions { item { __typename id name ...SubscriptionProductStandard ...SubscriptionProductDualEntry ...SubscriptionProductTVE ...SubscriptionProductFallback } } rental { item { price { readable } validFrom { timestamp } validTo { timestamp } } } npvr { __typename } } }  fragment Store on Store { name icons { dark { sourceNonEncoded } } }  fragment MobileShowcaseMovie on Movie { id title userData { progress { position } favorite } images { backdrop16x9 { sourceNonEncoded } } playback { __typename ...Playback } store { __typename ...Store } }  fragment MobileShowcaseEpisode on Episode { id title userData { progress { position } favorite } images { backdrop16x9 { sourceNonEncoded } } playback { __typename ...Playback } series { id } store { __typename ...Store } }  fragment MobileShowcaseSeries on Series { id title userData { favorite } images { backdrop16x9 { sourceNonEncoded } } webview { url } suggestedEpisode { id playback { __typename ...Playback } } store { __typename ...Store } }  fragment MobileShowcaseSportEvent on SportEvent { id title userData { progress { position } favorite } images { backdrop16x9 { sourceNonEncoded } } playback { __typename ...Playback } store { __typename ...Store } }  fragment ChannelPlayback on ChannelPlayback { play { playbackSpec { __typename ...PlaybackSpec } } buy { subscriptions { item { id } } } }  fragment MobileShowcaseChannel on Channel { channelPlayback: playback { __typename ...ChannelPlayback } }  fragment MobileShowcasePanel on ShowcasePanel { id title showcaseContent { items { id showcaseTitle { text } kicker images { showcase16x9 { sourceNonEncoded } showcase16x7 { sourceNonEncoded } showcase7x10 { sourceNonEncoded } showcase2x3 { sourceNonEncoded } } promotion { link { id type } content { __typename ...MobileShowcaseMovie ...MobileShowcaseEpisode ...MobileShowcaseSeries ...MobileShowcaseSportEvent ...MobileShowcaseChannel } } } } }  fragment MobilePageMovie on Movie { id title playback { __typename ...Playback } images { backdrop16x9 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } } descriptionLong price { readable } genre yearProduction { number } ageRating { number } duration { readableShort } ratings { imdb { readableScore } } productionCountries userData { progress { percent position } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) } } } store { name } availability { from { text } } availableNow labels { premiereAnnouncement { text } } }  fragment MobilePageSeries on Series { id title images { backdrop16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } } description genre ageRating { number } ratings { imdb { readableScore } } label webview { url } isRentalSeries }  fragment MobilePageEpisode on Episode { id title images { backdrop16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } screenshot16x9 { sourceNonEncoded } } descriptionLong price { readable } genre yearProduction { number } episodeNumber { number readable } seasonNumber { number readable } playback { __typename ...Playback } series { id title } ageRating { number } duration { readableShort } userData { progress { percent position } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) } } } store { name } }  fragment MobilePageSportEvent on SportEvent { id title playback { __typename ...Playback } images { backdrop16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } } availability { from { text timestamp } } descriptionLong genre badges { uhd { text } } productionCountries ageRating { number } duration { readableShort } store { name } league labels { airtime { text } } yearProduction { number } userData { progress { percent position } } venue }  fragment MobilePageMediaPanelContent on MediaPanelItemContent { __typename ... on Movie { __typename ...MobilePageMovie } ... on Series { __typename ...MobilePageSeries } ... on Episode { __typename ...MobilePageEpisode } ... on SportEvent { __typename ...MobilePageSportEvent } }  fragment MobileMediaPanel on MediaPanel { id title kicker displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } mediaContent(limit: $mediaContentLimit) { pageInfo { hasNextPage } items { media { __typename ...MobilePageMediaPanelContent } } } }  fragment MobileSelectionMediaPanel on SelectionMediaPanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } selectionMediaContent(config: { limit: $mediaContentLimit } ) { pageInfo { hasNextPage } items { media { __typename ...MobilePageMediaPanelContent } } } link { id type } }  fragment MobileSingleFeaturePanelMedia on SingleFeaturePanelMedia { __typename ... on Movie { __typename ...MobilePageMovie } ... on Series { __typename ...MobilePageSeries } ... on SportEvent { __typename ...MobilePageSportEvent } }  fragment MobileSingleFeaturePanel on SingleFeaturePanel { id title subtitle images { __typename ... on SingleFeaturePanelImages { promo16x9 { sourceNonEncoded } } } media { __typename ...MobileSingleFeaturePanelMedia } }  fragment MobilePageStore on Store { id __typename name icons { light { sourceNonEncoded } dark { sourceNonEncoded } } }  fragment MobileStoresPanel on StoresPanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } storesContent(limit: $mediaContentLimit) { pageInfo { hasNextPage } items { __typename ...MobilePageStore } } }'
        }

        response = send_req(url, post=True, json=json, headers=headers)
        if response:
            j_response = response.json()
            data = j_response['data']['page']['pagePanels']['items']

            key = -1
            for item in data:
                key += 1
                genres.append((key, item['title']))

            for gen in genres:
                add_item(label=gen[1], url=str(gen[0])+'|'+genre, mode='vod', icon=icon, fanart=fanart, folder=True, playable=False)

    xbmcplugin.endOfDirectory(addon_handle)

def vod(genre_id):
    idx = int(genre_id.split('|')[0])
    genre = genre_id.split('|')[-1]

    beartoken = addon.getSetting('teliaplay_beartoken')
    tv_client_boot_id = addon.getSetting('teliaplay_tv_client_boot_id')

    url = 'https://graphql-telia.t6a.net/'

    headers = {
        'authorization': 'Bearer ' + beartoken,
        'tv-client-name': 'androidmob',
        'tv-client-version': '4.7.0',
        'tv-client-boot-id': tv_client_boot_id,
        'x-country': ca[country],
        'content-type': 'application/json',
        'accept-encoding': 'gzip',
        'user-agent': 'okhttp/4.9.3',
    }

    json = {
        'operationName': 'getCommonBrowsePage',
        'variables': {
            'mediaContentLimit': 16,
            'pageId': genre
        },

        'query': 'query getCommonBrowsePage($pageId: String!, $mediaContentLimit: Int!) { page(id: $pageId) { id pagePanels { items { __typename title id ...MobileShowcasePanel ...MobileMediaPanel ...MobileSelectionMediaPanel ...MobileSingleFeaturePanel ...MobileStoresPanel } } } }  fragment PlaybackSpec on PlaybackSpec { accessControl videoId videoIdType watchMode }  fragment Vod on Vod { audioLang { name code } playbackSpec { __typename ...PlaybackSpec } price { readable } validFrom { timestamp readableDistance(type: FUZZY) } validTo { timestamp } }  fragment Linear on PlaybackPlayLinear { item { startover { playbackSpec { __typename ...PlaybackSpec } } playbackSpec { __typename ...PlaybackSpec } startTime { timestamp readableDistance(type: FUZZY) } endTime { timestamp } } }  fragment Rental on PlaybackPlayVodRental { item { __typename ...Vod } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) msTo } } }  fragment Recording on PlaybackPlayRecording { item { playbackSpec { __typename ...PlaybackSpec } audioLang { name code } validFrom { timestamp } validTo { timestamp } } startover { playbackSpec { __typename ...PlaybackSpec } } }  fragment SubscriptionProductStandard on SubscriptionProductStandard { id price { readable } }  fragment SubscriptionProductDualEntry on SubscriptionProductDualEntry { id }  fragment SubscriptionProductTVE on SubscriptionProductTVE { id }  fragment SubscriptionProductFallback on SubscriptionProductFallback { id }  fragment Playback on Playback { play { subscription { item { __typename ...Vod } } linear { __typename ...Linear } rental { __typename ...Rental } npvr { __typename ...Recording } } buy { subscriptions { item { __typename id name ...SubscriptionProductStandard ...SubscriptionProductDualEntry ...SubscriptionProductTVE ...SubscriptionProductFallback } } rental { item { price { readable } validFrom { timestamp } validTo { timestamp } } } npvr { __typename } } }  fragment Store on Store { name icons { dark { sourceNonEncoded } } }  fragment MobileShowcaseMovie on Movie { id title userData { progress { position } favorite } images { backdrop16x9 { sourceNonEncoded } } playback { __typename ...Playback } store { __typename ...Store } }  fragment MobileShowcaseEpisode on Episode { id title userData { progress { position } favorite } images { backdrop16x9 { sourceNonEncoded } } playback { __typename ...Playback } series { id } store { __typename ...Store } }  fragment MobileShowcaseSeries on Series { id title userData { favorite } images { backdrop16x9 { sourceNonEncoded } } webview { url } suggestedEpisode { id playback { __typename ...Playback } } store { __typename ...Store } }  fragment MobileShowcaseSportEvent on SportEvent { id title userData { progress { position } favorite } images { backdrop16x9 { sourceNonEncoded } } playback { __typename ...Playback } store { __typename ...Store } }  fragment ChannelPlayback on ChannelPlayback { play { playbackSpec { __typename ...PlaybackSpec } } buy { subscriptions { item { id } } } }  fragment MobileShowcaseChannel on Channel { channelPlayback: playback { __typename ...ChannelPlayback } }  fragment MobileShowcasePanel on ShowcasePanel { id title showcaseContent { items { id showcaseTitle { text } kicker images { showcase16x9 { sourceNonEncoded } showcase16x7 { sourceNonEncoded } showcase7x10 { sourceNonEncoded } showcase2x3 { sourceNonEncoded } } promotion { link { id type } content { __typename ...MobileShowcaseMovie ...MobileShowcaseEpisode ...MobileShowcaseSeries ...MobileShowcaseSportEvent ...MobileShowcaseChannel } } } } }  fragment MobilePageMovie on Movie { id title playback { __typename ...Playback } images { backdrop16x9 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } } descriptionLong price { readable } genre yearProduction { number } ageRating { number } duration { readableShort } ratings { imdb { readableScore } } productionCountries userData { progress { percent position } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) } } } store { name } availability { from { text } } availableNow labels { premiereAnnouncement { text } } }  fragment MobilePageSeries on Series { id title images { backdrop16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } } description genre ageRating { number } ratings { imdb { readableScore } } label webview { url } isRentalSeries }  fragment MobilePageEpisode on Episode { id title images { backdrop16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } screenshot16x9 { sourceNonEncoded } } descriptionLong price { readable } genre yearProduction { number } episodeNumber { number readable } seasonNumber { number readable } playback { __typename ...Playback } series { id title } ageRating { number } duration { readableShort } userData { progress { percent position } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) } } } store { name } }  fragment MobilePageSportEvent on SportEvent { id title playback { __typename ...Playback } images { backdrop16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } } availability { from { text timestamp } } descriptionLong genre badges { uhd { text } } productionCountries ageRating { number } duration { readableShort } store { name } league labels { airtime { text } } yearProduction { number } userData { progress { percent position } } venue }  fragment MobilePageMediaPanelContent on MediaPanelItemContent { __typename ... on Movie { __typename ...MobilePageMovie } ... on Series { __typename ...MobilePageSeries } ... on Episode { __typename ...MobilePageEpisode } ... on SportEvent { __typename ...MobilePageSportEvent } }  fragment MobileMediaPanel on MediaPanel { id title kicker displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } mediaContent(limit: $mediaContentLimit) { pageInfo { hasNextPage } items { media { __typename ...MobilePageMediaPanelContent } } } }  fragment MobileSelectionMediaPanel on SelectionMediaPanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } selectionMediaContent(config: { limit: $mediaContentLimit } ) { pageInfo { hasNextPage } items { media { __typename ...MobilePageMediaPanelContent } } } link { id type } }  fragment MobileSingleFeaturePanelMedia on SingleFeaturePanelMedia { __typename ... on Movie { __typename ...MobilePageMovie } ... on Series { __typename ...MobilePageSeries } ... on SportEvent { __typename ...MobilePageSportEvent } }  fragment MobileSingleFeaturePanel on SingleFeaturePanel { id title subtitle images { __typename ... on SingleFeaturePanelImages { promo16x9 { sourceNonEncoded } } } media { __typename ...MobileSingleFeaturePanelMedia } }  fragment MobilePageStore on Store { id __typename name icons { light { sourceNonEncoded } dark { sourceNonEncoded } } }  fragment MobileStoresPanel on StoresPanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } storesContent(limit: $mediaContentLimit) { pageInfo { hasNextPage } items { __typename ...MobilePageStore } } }'
    }

    response = send_req(url, post=True, json=json, headers=headers)
    if response:
        j_response = response.json()
        try:
            data = j_response['data']['page']['pagePanels']['items'][idx]
            items = None

            selection = data.get('selectionMediaContent')
            media = data.get('mediaContent')
            stores = data.get('storesContent')
            showcase = data.get('showcaseContent')

            if selection:
                items = selection.get('items')

            elif media:
                items = media.get('items')

            elif showcase:
                items = showcase.get('items')

            else:
                items = stores.get('items')

            if not items:
                xbmcgui.Dialog().notification(localized(30012), localized(30048))
                return

            get_items(items)
        except:
            xbmcgui.Dialog().notification(localized(30012), localized(30048))
            return

def get_items(data):
    titles = set()
    count = 0

    for item in data:
        media = item.get('media')
        if not media:
            media = item

        if media:
            typename = media.get('__typename')
            mode = 'play'
            folder = False
            playable = True

            if typename == 'Movie':
                mode = 'play'

            elif typename == 'Series':
                mode = 'seasons'
                folder = True
                playable = False

            elif typename == 'SportEvent':
                mode = 'play'

            title = media.get('title')
            if not title:
                title = media.get('name')

            label = title
            media_id = media.get('id')
            genre = media.get('genre')

            availability = media.get('availability')
            if availability:
                start = availability
                if start:
                    fr = start.get('from')
                    if fr:
                        timestamp = fr.get('timestamp')
                        if isinstance(timestamp, int):
                            start_time = timestamp // 1000

                            dt_start = datetime.fromtimestamp(start_time)
                            da_start = dt_start.strftime('%H:%M')

                            if da_start != '00:00':
                                label = title + ' [COLOR grey]({0})[/COLOR]'.format(da_start)

            outline = media.get('description')
            plot = media.get('descriptionLong')
            if not plot:
                plot = outline

            date = ''
            year = media.get('yearProduction')
            if year:
                date = year.get('readable')

            age = media.get('ageRating')

            rating = ''
            ratings = media.get('ratings')
            if ratings:
                imdb = ratings.get('imdb')
                if imdb:
                    rating = imdb.get('readableScore')

            duration = ''
            d = media.get('duration')
            if d:
                duration = d.get('seconds')

            media_id = media.get('id')
            playback = media.get('playback')
            if playback:
                play = playback.get('play')
                linear = play.get('linear')
                if linear:
                    item = linear.get('item')
                    media_id = item['playbackSpec']['videoId']

                rental = play.get('rental')
                if rental:
                    for item in rental:
                        media_id = item['item']['playbackSpec']['videoId']

                subscription = play.get('subscription')
                if subscription:
                    for item in subscription:
                        media_id = item['item']['playbackSpec']['videoId']

            poster = ''
            icon = ''
            images = media.get('images')
            if images:
                card_2x3 = images.get('showcard2x3')
                if card_2x3:
                    src = card_2x3.get('sourceNonEncoded')
                    if not src:
                        src = card_2x3.get('source')
                    if src:
                        poster = unquote(src)

                card_16x9 = images.get('showcard16x9')
                if card_16x9:
                    src = card_16x9.get('sourceNonEncoded')
                    if not src:
                        src = card_16x9.get('source')
                    if src:
                        icon = unquote(src)

            ext = localized(30027)
            context_menu = [('{0}'.format(ext), 'RunScript(plugin.video.teliaplay,0,?mode=ext,label={0})'.format(title))]

            xbmcplugin.addSortMethod(addon_handle, sortMethod=xbmcplugin.SORT_METHOD_TITLE, label2Mask = "%R, %Y, %P")

            if title not in titles:
                add_item(label=title, url='vod', mode=mode, media_id=media_id, folder=folder, playable=playable, info_labels={'title':label, 'originaltitle':title, 'plot':plot, 'plotoutline':outline, 'aired':date, 'dateadded':date, 'duration':duration, 'genre':genre}, icon=icon, poster=poster, fanart=fanart, context_menu=context_menu, item_count=count)
                titles.add(title)

    xbmcplugin.setContent(addon_handle, 'sets')
    xbmcplugin.endOfDirectory(addon_handle)

def vod_seasons(media_id):
    beartoken = addon.getSetting('teliaplay_beartoken')
    tv_client_boot_id = addon.getSetting('teliaplay_tv_client_boot_id')

    url = 'https://graphql-telia.t6a.net/'

    headers = {
        'authorization': 'Bearer ' + beartoken,
        'tv-client-name': 'androidmob',
        'tv-client-version': '4.7.0',
        'tv-client-boot-id': tv_client_boot_id,
        'x-country': ca[country],
        'content-type': 'application/json',
        'accept-encoding': 'gzip',
        'user-agent': 'okhttp/4.9.3',
    }

    json = {
        'operationName': 'getMobileSeries',

        'variables': {
            'id': media_id
        },

        'query': 'query getMobileSeries($id: String!) { series(id: $id) { __typename ...MobileSeriesDetailsItem } }  fragment PlaybackSpec on PlaybackSpec { accessControl videoId videoIdType watchMode }  fragment Vod on Vod { audioLang { name code } playbackSpec { __typename ...PlaybackSpec } price { readable } validFrom { timestamp readableDistance(type: FUZZY) } validTo { timestamp } }  fragment Linear on PlaybackPlayLinear { item { startover { playbackSpec { __typename ...PlaybackSpec } } playbackSpec { __typename ...PlaybackSpec } startTime { timestamp readableDistance(type: FUZZY) } endTime { timestamp } } }  fragment Rental on PlaybackPlayVodRental { item { __typename ...Vod } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) msTo } } }  fragment Recording on PlaybackPlayRecording { item { playbackSpec { __typename ...PlaybackSpec } audioLang { name code } validFrom { timestamp } validTo { timestamp } } startover { playbackSpec { __typename ...PlaybackSpec } } }  fragment SubscriptionProductStandard on SubscriptionProductStandard { id price { readable } }  fragment SubscriptionProductDualEntry on SubscriptionProductDualEntry { id }  fragment SubscriptionProductTVE on SubscriptionProductTVE { id }  fragment SubscriptionProductFallback on SubscriptionProductFallback { id }  fragment Playback on Playback { play { subscription { item { __typename ...Vod } } linear { __typename ...Linear } rental { __typename ...Rental } npvr { __typename ...Recording } } buy { subscriptions { item { __typename id name ...SubscriptionProductStandard ...SubscriptionProductDualEntry ...SubscriptionProductTVE ...SubscriptionProductFallback } } rental { item { price { readable } validFrom { timestamp } validTo { timestamp } } } npvr { __typename } } }  fragment MobileSuggestedEpisode on Episode { id title descriptionLong seasonNumber { number } availability { to { text } } directors actors vignette { hero16x9 { mpeg4 { url } webm { url } } } episodeNumber { number } playback { __typename ...Playback } userData { progress { position percent } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) } } } duration { readableShort } price { readable } images { showcard2x3 { sourceNonEncoded } screenshot16x9 { sourceNonEncoded } } }  fragment MobileUpcomingEpisode on UpcomingEpisode { id title episodeNumber { number } seasonNumber { readable } availability { from { text } } availability { from { text } } images { backdrop16x9 { sourceNonEncoded } } duration { readableShort } }  fragment MobileSeriesDetailsItem on Series { id title images { backdrop16x9 { sourceNonEncoded } } genre ageRating { readable number } ratings { imdb { readableScore url } } description actors userData { favorite } suggestedEpisode { __typename ...MobileSuggestedEpisode } label numberOfEpisodes { number } numberOfSeasons { number } vignette { hero16x9 { mpeg4 { url } webm { url } } } store { name } seasonLinks { items { id numberOfEpisodes { number readable } seasonNumber { number readable } } } upcomingEpisode { __typename ...MobileUpcomingEpisode } isRentalSeries }'
    }

    response = send_req(url, post=True, json=json, headers=headers)
    if response:
        j_response = response.json()
        try:
            seasons = j_response['data']['series']['seasonLinks']['items']
        except:
            xbmcgui.Dialog().notification(localized(30012), localized(30048))
            return

        for item in seasons:
            season_id = item['id']

            json = {
                'operationName': 'GetMobileSeason',

                'variables': {
                    'id': season_id,
                    'limit': 300,
                    'offset': 0
                },

                'query': 'query GetMobileSeason($id: String!, $limit: Int!, $offset: Int!) { season(seasonId: $id) { seasonNumber { readable number } id episodes(limit: $limit, offset: $offset) { __typename ...MobileSeasonEpisode } } }  fragment PlaybackSpec on PlaybackSpec { accessControl videoId videoIdType watchMode }  fragment Vod on Vod { audioLang { name code } playbackSpec { __typename ...PlaybackSpec } price { readable } validFrom { timestamp readableDistance(type: FUZZY) } validTo { timestamp } }  fragment Linear on PlaybackPlayLinear { item { startover { playbackSpec { __typename ...PlaybackSpec } } playbackSpec { __typename ...PlaybackSpec } startTime { timestamp readableDistance(type: FUZZY) } endTime { timestamp } } }  fragment Rental on PlaybackPlayVodRental { item { __typename ...Vod } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) msTo } } }  fragment Recording on PlaybackPlayRecording { item { playbackSpec { __typename ...PlaybackSpec } audioLang { name code } validFrom { timestamp } validTo { timestamp } } startover { playbackSpec { __typename ...PlaybackSpec } } }  fragment SubscriptionProductStandard on SubscriptionProductStandard { id price { readable } }  fragment SubscriptionProductDualEntry on SubscriptionProductDualEntry { id }  fragment SubscriptionProductTVE on SubscriptionProductTVE { id }  fragment SubscriptionProductFallback on SubscriptionProductFallback { id }  fragment Playback on Playback { play { subscription { item { __typename ...Vod } } linear { __typename ...Linear } rental { __typename ...Rental } npvr { __typename ...Recording } } buy { subscriptions { item { __typename id name ...SubscriptionProductStandard ...SubscriptionProductDualEntry ...SubscriptionProductTVE ...SubscriptionProductFallback } } rental { item { price { readable } validFrom { timestamp } validTo { timestamp } } } npvr { __typename } } }  fragment MobileSeasonEpisode on Episodes { episodeItems { id title descriptionLong genre duration { seconds readableShort } images { showcard2x3 { sourceNonEncoded } screenshot16x9 { sourceNonEncoded } } availability { from { text timestamp } to { text } } downloadAvailable seasonNumber { number } episodeNumber { number readable } price { readable } playback { __typename ...Playback } userData { progress { position percent } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) } } } } }'
            }

            response = send_req(url, post=True, json=json, headers=headers)
            if response:
                j_response = response.json()
                season = j_response['data']['season']['seasonNumber']['number']

                label = localized(30033) + ' ' + str(season)
                add_item(label=label, url=season, mode='episodes', media_id=season_id, playable=False, folder=True, icon=icon, fanart=fanart)

    xbmcplugin.endOfDirectory(addon_handle)

def vod_episodes(season, season_id):
    beartoken = addon.getSetting('teliaplay_beartoken')
    tv_client_boot_id = addon.getSetting('teliaplay_tv_client_boot_id')

    url = 'https://graphql-telia.t6a.net/'

    headers = {
        'authorization': 'Bearer ' + beartoken,
        'tv-client-name': 'androidmob',
        'tv-client-version': '4.7.0',
        'tv-client-boot-id': tv_client_boot_id,
        'x-country': ca[country],
        'content-type': 'application/json',
        'accept-encoding': 'gzip',
        'user-agent': 'okhttp/4.9.3',
    }

    json = {
        'operationName': 'GetMobileSeason',

        'variables': {
            'id': season_id,
            'limit': 300,
            'offset': 0
        },

        'query': 'query GetMobileSeason($id: String!, $limit: Int!, $offset: Int!) { season(seasonId: $id) { seasonNumber { readable number } id episodes(limit: $limit, offset: $offset) { __typename ...MobileSeasonEpisode } } }  fragment PlaybackSpec on PlaybackSpec { accessControl videoId videoIdType watchMode }  fragment Vod on Vod { audioLang { name code } playbackSpec { __typename ...PlaybackSpec } price { readable } validFrom { timestamp readableDistance(type: FUZZY) } validTo { timestamp } }  fragment Linear on PlaybackPlayLinear { item { startover { playbackSpec { __typename ...PlaybackSpec } } playbackSpec { __typename ...PlaybackSpec } startTime { timestamp readableDistance(type: FUZZY) } endTime { timestamp } } }  fragment Rental on PlaybackPlayVodRental { item { __typename ...Vod } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) msTo } } }  fragment Recording on PlaybackPlayRecording { item { playbackSpec { __typename ...PlaybackSpec } audioLang { name code } validFrom { timestamp } validTo { timestamp } } startover { playbackSpec { __typename ...PlaybackSpec } } }  fragment SubscriptionProductStandard on SubscriptionProductStandard { id price { readable } }  fragment SubscriptionProductDualEntry on SubscriptionProductDualEntry { id }  fragment SubscriptionProductTVE on SubscriptionProductTVE { id }  fragment SubscriptionProductFallback on SubscriptionProductFallback { id }  fragment Playback on Playback { play { subscription { item { __typename ...Vod } } linear { __typename ...Linear } rental { __typename ...Rental } npvr { __typename ...Recording } } buy { subscriptions { item { __typename id name ...SubscriptionProductStandard ...SubscriptionProductDualEntry ...SubscriptionProductTVE ...SubscriptionProductFallback } } rental { item { price { readable } validFrom { timestamp } validTo { timestamp } } } npvr { __typename } } }  fragment MobileSeasonEpisode on Episodes { episodeItems { id title descriptionLong genre duration { seconds readableShort } images { showcard2x3 { sourceNonEncoded } screenshot16x9 { sourceNonEncoded } } availability { from { text timestamp } to { text } } downloadAvailable seasonNumber { number readable } episodeNumber { number readable } price { readable } playback { __typename ...Playback } userData { progress { position percent } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) } } } } }'
    }

    response = send_req(url, post=True, json=json, headers=headers)
    if response:
        j_response = response.json()
        try:
            items = j_response['data']['season']['episodes']['episodeItems']
        except:
            xbmcgui.Dialog().notification(localized(30012), localized(30048))
            return

        count = 0

        for item in items:
            count += 1

            season_num = item['seasonNumber']['number']

            if int(season) == int(season_num):
                title = item.get('title')
                media_id = item.get('id')

                episode_raw = item.get('episodeNumber')
                if episode_raw:
                    episode_read = episode_raw['readable']

                season_raw = item.get('seasonNumber')
                if season_raw:
                    season_read = season_raw['readable']

                label = episode_read

                plot = item.get('descriptionLong')
                directors = item.get('directors')
                actors = item.get('actors')
                genre = item.get('genre')
                sub_genre = item.get('subGenres')

                age = ''
                age_rating = item.get('ageRating')
                if age_rating:
                    age = age_rating.get('readable')

                date = ''
                year = item.get('yearProduction')
                if year:
                    date = year.get('readable')

                images = item.get('images')
                if images:
                    poster = ''
                    card_2x3 = images.get('showcard2x3')
                    if card_2x3:
                        src = card_2x3.get('sourceNonEncoded')
                        if not src:
                            src = card_2x3.get('source')
                        if src:
                            poster = unquote(src)

                    icon = ''
                    card_16x9 = images.get('showcard16x9')
                    if card_16x9:
                        src = card_16x9.get('sourceNonEncoded')
                        if not src:
                            src = card_16x9.get('source')
                        if src:
                            icon = unquote(src)

                ext = localized(30027)
                context_menu = [('{0}'.format(ext), 'RunScript(plugin.video.teliaplay,0,?mode=ext,label={0})'.format(title))]

                add_item(label=label, url='vod', mode='play', media_id=media_id, folder=False, playable=True, info_labels={'title':title, 'originaltitle':title, 'plot':plot, 'genre':genre}, icon=icon, poster=poster, fanart=fanart, context_menu=context_menu, item_count=count)

    xbmcplugin.setContent(addon_handle, 'sets')
    xbmcplugin.endOfDirectory(addon_handle)

def vod_search():
    file_name = os.path.join(profile_path, 'title_search.list')
    f = xbmcvfs.File(file_name, 'rb')
    searches = sorted(f.read().splitlines())
    f.close()

    actions = [localized(30035), localized(30036)] + searches

    action = xbmcgui.Dialog().select(localized(30037), actions)
    if action == -1:
        return
    elif action == 0:
        pass
    elif action == 1:
        which = xbmcgui.Dialog().multiselect(localized(30036), searches)
        if which is None:
            return
        else:
            for item in reversed(which):
                del searches[item]

            f = xbmcvfs.File(file_name, 'wb')
            f.write(bytearray('\n'.join(searches), 'utf-8'))
            f.close()
            return
    else:
        if searches:
            title = searches[action - 2]

    if action == 0:
        search = xbmcgui.Dialog().input(localized(30032), type=xbmcgui.INPUT_ALPHANUM)

    else:
        search = title

    if not search:
        return

    searches = (set([search] + searches))
    f = xbmcvfs.File(file_name, 'wb')
    f.write(bytearray('\n'.join(searches), 'utf-8'))
    f.close()

    return search

def search(query):
    if query:
        beartoken = addon.getSetting('teliaplay_beartoken')
        tv_client_boot_id = addon.getSetting('teliaplay_tv_client_boot_id')

        url = 'https://graphql-telia.t6a.net/'

        headers = {
            'authorization': 'Bearer ' + beartoken,
            'tv-client-name': 'androidmob',
            'tv-client-version': '4.7.0',
            'tv-client-boot-id': tv_client_boot_id,
            'x-country': ca[country],
            'content-type': 'application/json',
            'accept-encoding': 'gzip',
            'user-agent': 'okhttp/4.9.3',
        }

        json = {
            'operationName': 'mobileSearch',

            'variables': {
                'query': '{0}'.format(query),
                'limit': 100,
                'channel': 'NONE',
                'rentals': 'ALL',
                'subscription': 'ALL',
                'includeUpcoming': True,
                'includeLinear': True
            },

            'query': 'query mobileSearch($query: String!, $limit: Int!, $channel: SearchSubscriptionType, $rentals: SearchRentalsType, $subscription: SearchSubscriptionType, $includeUpcoming: Boolean!, $includeLinear: Boolean!) { search2(input: { limit: $limit q: $query includeUpcoming: $includeUpcoming includeLinear: $includeLinear searchType: { channel: $channel rentals: $rentals subscription: $subscription }  } ) { searchItems { media { __typename ... on Movie { __typename ...MobileMovieSearchItem } ... on Series { __typename ...MobileSeriesSearchItem } ... on SportEvent { __typename ...MobileSportEventSearchItem } } } } }  fragment PlaybackSpec on PlaybackSpec { accessControl videoId videoIdType watchMode }  fragment Vod on Vod { audioLang { name code } playbackSpec { __typename ...PlaybackSpec } price { readable } validFrom { timestamp readableDistance(type: FUZZY) } validTo { timestamp } }  fragment Linear on PlaybackPlayLinear { item { startover { playbackSpec { __typename ...PlaybackSpec } } playbackSpec { __typename ...PlaybackSpec } startTime { timestamp readableDistance(type: FUZZY) } endTime { timestamp } } }  fragment Rental on PlaybackPlayVodRental { item { __typename ...Vod } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) msTo } } }  fragment Recording on PlaybackPlayRecording { item { playbackSpec { __typename ...PlaybackSpec } audioLang { name code } validFrom { timestamp } validTo { timestamp } } startover { playbackSpec { __typename ...PlaybackSpec } } }  fragment SubscriptionProductStandard on SubscriptionProductStandard { id price { readable } }  fragment SubscriptionProductDualEntry on SubscriptionProductDualEntry { id }  fragment SubscriptionProductTVE on SubscriptionProductTVE { id }  fragment SubscriptionProductFallback on SubscriptionProductFallback { id }  fragment Playback on Playback { play { subscription { item { __typename ...Vod } } linear { __typename ...Linear } rental { __typename ...Rental } npvr { __typename ...Recording } } buy { subscriptions { item { __typename id name ...SubscriptionProductStandard ...SubscriptionProductDualEntry ...SubscriptionProductTVE ...SubscriptionProductFallback } } rental { item { price { readable } validFrom { timestamp } validTo { timestamp } } } npvr { __typename } } }  fragment MobileMovieSearchItem on Movie { id title descriptionLong images { showcard2x3 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } } genre yearProduction { readable } userData { progress { position } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) } } } playback { __typename ...Playback } price { readable } availableNow labels { premiereAnnouncement { text } } }  fragment MobileSeriesSearchItem on Series { id title description images { showcard2x3 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } } genre webview { url } isRentalSeries label }  fragment MobileSportEventSearchItem on SportEvent { id title descriptionLong images { showcard2x3 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } homeTeamLogo { sourceNonEncoded } awayTeamLogo { sourceNonEncoded } } availability { from { isoString } } league labels { airtime { text } } }'
        }

        response = send_req(url, post=True, json=json, headers=headers)

        if response:
            j_response = response.json()
            data = j_response['data']['search2']['searchItems']
            get_items(data)

def live_channels():
    login = login_service()
    if not login:
        xbmcgui.Dialog().notification(localized(30012), localized(30006))
        raise Exception

    beartoken = addon.getSetting('teliaplay_beartoken')
    tv_client_boot_id = addon.getSetting('teliaplay_tv_client_boot_id')

    try:
        url = 'https://ottapi.prod.telia.net/web/{cc}/engagementgateway/rest/secure/v2/engagementinfo'.format(cc=cc[country])

        headers = {
            "user-agent": UA,
            "accept": "*/*",
            "accept-language": "sv,en;q=0.9,en-GB;q=0.8,en-US;q=0.7,pl;q=0.6",
            "authorization": "Bearer " + beartoken,
        }

        engagementjson = send_req(url, headers=headers, verify=True)
        if not engagementjson:
            raise Exception

        engagementjson = engagementjson.json()

        try:
            engagementLiveChannels = engagementjson['channelIds']
            print(engagementLiveChannels)
        except KeyError as k:
            engagementLiveChannels = []
            print('errorMessage: {k}'.format(k=str(k)))

        engagementPlayChannels = []

        try:
           for channel in engagementjson['stores']:
               engagementPlayChannels.append(channel['id'])

        except KeyError as k:
            print('errorMessage: {k}'.format(k=str(k)))

        url = 'https://graphql-telia.t6a.net/'

        headers = {
            'authority': 'graphql-telia.t6a.net',
            'accept': '*/*',
            'accept-language': 'sv,en;q=0.9,en-GB;q=0.8,en-US;q=0.7,pl;q=0.6,fr;q=0.5',
            'authorization': 'Bearer ' + beartoken,
            'content-type': 'application/json',
            'dnt': '1',
            'origin': base[country],
            'referer': referer[country],
            'tv-client-boot-id': tv_client_boot_id,
            'tv-client-browser': 'Microsoft Edge',
            'tv-client-browser-version': '101.0.1210.32',
            'tv-client-name': 'web',
            'tv-client-os-name': 'Windows',
            'tv-client-os-version': 'NT 10.0',
            'tv-client-tz': 'Europe/Stockholm',
            'tv-client-version': '1.43.2',
            'user-agent': UA,
            'x-country': ca[country],
        }

        json = {
            'operationName': 'getTvChannels',

            'variables': {
                'limit': 500,
                'offset': 0
            },

            'query': 'query getTvChannels($limit: Int!, $offset: Int!) { channels(limit: $limit, offset: $offset) { pageInfo { totalCount hasNextPage } channelItems { id\n name\n icons { dark { source } } }   } }'
        }

        response = send_req(url, post=True, json=json, headers=headers)
        if not response:
            xbmcgui.Dialog().notification(localized(30012), localized(30006))
            raise Exception

        j_response = response.json()
        channels = j_response['data']['channels']['channelItems']

        count = 0

        for channel in channels:
            if channel['id'] in engagementLiveChannels:
                count += 1

                exlink = channel['id']
                name = channel['name']

                try:
                    res = channel["resolutions"]

                    p = re.compile('\d+')
                    res_int = p.search(res[0]).group(0)

                except:
                    res_int = 0

                p = re.compile(r'(\s{0}$)'.format(ca[country]))

                r = p.search(name)
                match = r.group(1) if r else None

                if match:
                    ccCh = ''
                else:
                    ccCh = ca[country]

                if int(res_int) > 576 and ' HD' not in name:
                    title = channel["name"] + ' HD ' + ccCh
                else:
                    title = channel["name"] + ' ' + ccCh

                icon = path + 'icon.png'

                icons = channel.get('icons')
                if icons:
                    img = icons.get('dark').get('source')
                    icon = unquote(img)

                add_item(label=name, url=exlink, mode='programs', icon=icon, folder=True, playable=False, info_labels={'title':title, 'plot':name}, fanart=fanart, item_count=count)

        xbmcplugin.endOfDirectory(addon_handle)

    except Exception as ex:
        print('live_channels exception: {}'.format(ex))

def live_channel(exlink, extitle):
    cc = ['dk', 'se']

    base = ['https://teliatv.dk', 'https://www.teliaplay.se']

    country            = int(addon.getSetting('teliaplay_locale'))
    dashjs             = addon.getSetting('teliaplay_devush')
    beartoken          = addon.getSetting('teliaplay_beartoken')
    tv_client_boot_id  = addon.getSetting('teliaplay_tv_client_boot_id')

    n = datetime.now()
    now = int(time.mktime(n.timetuple())) * 1000

    timestamp = str(((int(time.time() // 86400)) * 86400) * 1000)

    url = 'https://graphql-telia.t6a.net/'

    headers = {
        'authorization': 'Bearer ' + beartoken,
        'tv-client-name': 'androidmob',
        'tv-client-version': '4.7.0',
        'tv-client-boot-id': tv_client_boot_id,
        'x-country': ca[country],
        'content-type': 'application/json',
        'accept-encoding': 'gzip',
        'user-agent': 'okhttp/4.9.3',
    }

    json = {
        'operationName': 'GetChannel',

        'variables': {
            'channelId': '{0}'.format(str(exlink)),
            'programLimit': 100,
            'timestamp': int(timestamp)
        },

        'query': 'query GetChannel($channelId: String!, $timestamp: Timestamp, $programLimit: Int) {\n  channel(id: $channelId) {\n    ...ChannelItem\n    __typename\n  }\n}\n\nfragment ChannelItem on Channel {\n  id\n  name\n  recordAndWatch\n  playback {\n    play {\n      playbackSpec {\n        ...PlaybackSpec\n        __typename\n      }\n      __typename\n    }\n    buy {\n      ...GraphQLChannelPlaybackBuyFragment\n      __typename\n    }\n    __typename\n  }\n  icons {\n    light {\n      sourceNonEncoded\n      __typename\n    }\n    dark {\n      sourceNonEncoded\n      __typename\n    }\n    __typename\n  }\n  programs(timestamp: $timestamp, limit: $programLimit) {\n    programItems {\n      ...ProgramItem\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n\nfragment PlaybackSpec on PlaybackSpec {\n  accessControl\n  videoId\n  videoIdType\n  watchMode\n  __typename\n}\n\nfragment GraphQLChannelPlaybackBuyFragment on ChannelPlaybackBuy {\n  subscriptions {\n    item {\n      ...GraphQLSubscriptionProductStandardFragment\n      ...GraphQLSubscriptionProductIAPFragment\n      ...GraphQLSubscriptionProductTVEFragment\n      ...GraphQLSubscriptionProductDualEntry\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n\nfragment GraphQLSubscriptionProductStandardFragment on SubscriptionProductStandard {\n  id\n  name\n  uniqueSellingPoints {\n    ...GraphQLSubscriptionProductUniqueSellingPoint\n    __typename\n  }\n  gqlPrice: price {\n    readable\n    __typename\n  }\n  __typename\n}\n\nfragment GraphQLSubscriptionProductUniqueSellingPoint on SubscriptionProductUniqueSellingPoint {\n  sellingPoint\n  __typename\n}\n\nfragment GraphQLSubscriptionProductIAPFragment on SubscriptionProductIAP {\n  id\n  name\n  iTunesConnectId\n  uniqueSellingPoints {\n    ...GraphQLSubscriptionProductUniqueSellingPoint\n    __typename\n  }\n  __typename\n}\n\nfragment GraphQLSubscriptionProductTVEFragment on SubscriptionProductTVE {\n  id\n  name\n  __typename\n}\n\nfragment GraphQLSubscriptionProductDualEntry on SubscriptionProductDualEntry {\n  id\n  name\n  __typename\n}\n\nfragment ProgramItem on Program {\n  live\n  id\n  startTime {\n    timestamp\n    isoString\n    __typename\n  }\n  endTime {\n    timestamp\n    isoString\n    __typename\n  }\n  title\n  media {\n    ... on Movie {\n      ...MovieProgram\n      __typename\n    }\n    ... on Episode {\n      ...EpisodeProgram\n      __typename\n    }\n    ... on SportEvent {\n      ...SportProgram\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n\nfragment MovieProgram on Movie {\n  id\n genre\n images {\n    showcard16x9 {\n      sourceNonEncoded\n      __typename\n    }\n    showcard2x3 {\n      sourceNonEncoded\n      __typename\n    }\n    __typename\n  }\n  mediaType\n  title\n  availableNow\n  availability {\n    from {\n      timestamp\n      __typename\n    }\n    to {\n      timestamp\n      __typename\n    }\n    __typename\n  }\n  descriptionLong\n  playback {\n    ...PlaybackItem\n    buy {\n      ...GraphQLPlaybackBuyFragment\n      ...BuyItem\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n\nfragment PlaybackItem on Playback {\n  play {\n    linear {\n      ...Linear\n      __typename\n    }\n    subscription {\n      item {\n        validFrom {\n          timestamp\n          __typename\n        }\n        validTo {\n          timestamp\n          __typename\n        }\n        playbackSpec {\n          ...PlaybackSpec\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    npvr {\n      item {\n        validFrom {\n          timestamp\n          __typename\n        }\n        validTo {\n          timestamp\n          __typename\n        }\n        playbackSpec {\n          ...PlaybackSpec\n          __typename\n        }\n        __typename\n      }\n      live {\n        playbackSpec {\n          ...PlaybackSpec\n          __typename\n        }\n        __typename\n      }\n      startover {\n        playbackSpec {\n          ...PlaybackSpec\n          __typename\n        }\n        __typename\n      }\n      npvrInfo {\n        series {\n          active\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n\nfragment Linear on PlaybackPlayLinear {\n  item {\n    isLive\n    startover {\n      playbackSpec {\n        ...PlaybackSpec\n        __typename\n      }\n      __typename\n    }\n    playbackSpec {\n      ...PlaybackSpec\n      __typename\n    }\n    startTime {\n      timestamp\n      readableDistance(type: FUZZY)\n      __typename\n    }\n    endTime {\n      timestamp\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n\nfragment GraphQLPlaybackBuyFragment on PlaybackBuy {\n  subscriptions {\n    item {\n      ...GraphQLSubscriptionProductStandardFragment\n      ...GraphQLSubscriptionProductIAPFragment\n      ...GraphQLSubscriptionProductTVEFragment\n      ...GraphQLSubscriptionProductDualEntry\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n\nfragment BuyItem on PlaybackBuy {\n  subscription {\n    item {\n      validFrom {\n        timestamp\n        __typename\n      }\n      validTo {\n        timestamp\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  npvr {\n    item {\n      validFrom {\n        timestamp\n        __typename\n      }\n      validTo {\n        timestamp\n        __typename\n      }\n      playbackSpec {\n        ...PlaybackSpec\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n\nfragment EpisodeProgram on Episode {\n  id\n  genre\n images {\n    showcard16x9 {\n      sourceNonEncoded\n      __typename\n    }\n    showcard2x3 {\n      sourceNonEncoded\n      __typename\n    }\n    __typename\n  }\n  availableNow\n  availability {\n    from {\n      timestamp\n      __typename\n    }\n    to {\n      timestamp\n      __typename\n    }\n    __typename\n  }\n  title\n  descriptionLong\n  series {\n    id\n    title\n    isRecordable\n    userData {\n      npvrInfo {\n        active\n        episodes {\n          ongoing\n          recorded\n          scheduled\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  playback {\n    ...PlaybackItem\n    buy {\n      ...GraphQLPlaybackBuyFragment\n      ...BuyItem\n      __typename\n    }\n    __typename\n  }\n  episodeNumber {\n    readable\n    __typename\n  }\n  seasonNumber {\n    readable\n    __typename\n  }\n  __typename\n}\n\nfragment SportProgram on SportEvent {\n  id\n  title\n  availableNow\n  availability {\n    from {\n      timestamp\n      __typename\n    }\n    to {\n      timestamp\n      __typename\n    }\n    __typename\n  }\n  playback {\n    ...PlaybackItem\n    buy {\n      ...GraphQLPlaybackBuyFragment\n      ...BuyItem\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n'
    }

    response = send_req(url, post=True, json=json, headers=headers)
    if response:
        j_response = response.json()

    if j_response.get('errors', ''):
        return None, None

    program_items = j_response['data']['channel']['programs']['programItems']
    if not program_items:
        program_items.append({'title': extitle, 'id': exlink, 'media': {'playback': {'play': {'linear': {'item': {'playbackSpec': {'videoIdType': 'MEDIA', 'watchMode': 'LIVE'}}}}}}})

    count = 0

    for program in program_items:
        count += 1

        title = program['title']
        org_title = title

        now = timestamp

        try:
            start = program['startTime']['timestamp'] // 1000
            dt_start = datetime.fromtimestamp(start)
            st_start = dt_start.strftime('%H:%M')
            da_start = dt_start.strftime('%Y-%m-%d')

            end = program['endTime']['timestamp'] // 1000
            dt_end = datetime.fromtimestamp(end)
            st_end = dt_end.strftime('%H:%M')

            duration = end - start

            aired = da_start
            date = st_start + ' - ' + st_end

            if len(title) > 50:
                title = title[:50]

            if int(now) >= int(start) and int(now) <= int(end):
                name_ = title + '[B][COLOR violet] ● [/COLOR][/B]'

            elif int(end) >= int(now):
                name_ = '[COLOR grey]{0}[/COLOR] [B][/B]'.format(title)

            else:
                name_ = title + '[B][COLOR limegreen] ● [/COLOR][/B]'

            name = name_ + '[COLOR grey]({0})[/COLOR]'.format(date)

        except:
            name_ = title + '[B][COLOR violet] ● [/COLOR][/B]'
            name = name_ + '[COLOR grey](00:00 - 23:59)[/COLOR]'

            start = 0
            end = 0

            duration = ''

            aired = ''
            date = ''

        catchup = 'LIVE'

        media = program.get('media')

        media_id = media.get('id')
        plot = media.get('descriptionLong')
        genre = media.get('genre')

        lang = ''
        audio_lang = media.get('audioLang')
        if audio_lang:
            lang = audio_lang.get('name')

        catchup = ''
        playback = media.get('playback')
        if playback:
            play = playback.get('play')
            if play:
                subscription = play.get('subscription')
                if subscription:
                    for item in subscription:
                        if item:
                            items = item.get('item')
                            if items:
                                playback_spec = items.get('playbackSpec')
                                if playback_spec:
                                    catchup = playback_spec.get('watchMode')
        icon = ''
        poster = ''

        images = media.get('images')
        if images:
            card_2x3 = images.get('showcard2x3')
            if card_2x3:
                src = card_2x3.get('sourceNonEncoded')
                if not src:
                    src = card_2x3.get('source')
                if src:
                    poster = unquote(src)

            card_16x9 = images.get('showcard16x9')
            if card_16x9:
                src = card_16x9.get('sourceNonEncoded')
                if not src:
                    src = card_16x9.get('source')
                if src:
                    icon = unquote(src)

        ext = localized(30027)
        context_menu = [('{0}'.format(ext), 'RunScript(plugin.video.teliaplay,0,?mode=ext,label={0})'.format(title))]

        add_item(label=name, url=exlink, mode='play', media_id=media_id, catchup=catchup, start=start, end=end, folder=False, playable=True, info_labels={'title': title, 'originaltitle': org_title, 'plot': plot, 'plotoutline': plot, 'aired': aired, 'dateadded': date, 'duration': duration, 'genre': genre, 'country': lang}, icon=icon, poster=poster, fanart=fanart, context_menu=context_menu, item_count=count)

    xbmcplugin.setContent(addon_handle, 'sets')
    xbmcplugin.endOfDirectory(addon_handle)

def get_stream(exlink, catchup_type):
    stream_url = None

    dashjs = addon.getSetting('teliaplay_devush')
    beartoken = addon.getSetting('teliaplay_beartoken')
    tv_client_boot_id = addon.getSetting('teliaplay_tv_client_boot_id')

    try:
        sessionid = six.text_type(uuid.uuid4())
        addon.setSetting('teliaplay_sess_id', str(sessionid))

        if catchup_type == 'LIVE':
            stream_type = 'CHANNEL'

            url = 'https://streaminggateway-telia.clientapi-prod.live.tv.telia.net/streaminggateway/rest/secure/v2/streamingticket/{type}/{exlink}?country={cc}'.format(type=stream_type, exlink=(str(exlink)), cc=ca[country])

            headers = {
                'connection': 'keep-alive',
                'tv-client-boot-id': tv_client_boot_id,
                'DNT': '1',
                'authorization': 'Bearer '+ beartoken,
                'tv-client-tz': 'Europe/Stockholm',
                'x-country': cc[country],
                'user-agent': UA,
                'content-type': 'application/json',
                'accept': '*/*',
                'origin': base[country],
                'referer': base[country]+'/',
                'accept-language': 'sv,en;q=0.9,en-GB;q=0.8,en-US;q=0.7,pl;q=0.6',
            }

            params = (
                ('country', ca[country]),
            )

            data = {
                'sessionId': sessionid,
                'whiteLabelBrand': 'TELIA',
                'watchMode': catchup_type,
                'accessControl': 'SUBSCRIPTION',
                'device': {
                    'deviceId': tv_client_boot_id,
                    'category': 'desktop_windows',
                    'packagings': ['DASH_MP4_CTR'],
                    'drmType': 'WIDEVINE',
                    'capabilities': [],
                    'screen': {
                        'height': 1080,
                        'width': 1920
                    },
                    'os': 'Windows',
                    'model': 'windows_desktop'
                },

                'preferences': {
                    'audioLanguage': ['undefined'],
                    'accessibility': []
                }
            }

        else:
            stream_type = 'MEDIA'

            url = 'https://streaminggateway-telia.clientapi-prod.live.tv.telia.net/streaminggateway/rest/secure/v2/streamingticket/{type}/{exlink}?country={cc}'.format(type=stream_type, exlink=(str(exlink)), cc=ca[country])

            headers = {
                'Connection': 'keep-alive',
                'tv-client-boot-id': tv_client_boot_id,
                'DNT': '1',
                'Authorization': 'Bearer '+ beartoken,
                'tv-client-tz': 'Europe/Stockholm',
                'X-Country': cc[country],
                'User-Agent': UA,
                'content-type': 'application/json',
                'Accept': '*/*',
                'Origin': base[country],
                'Referer': base[country]+'/',
                'Accept-Language': 'sv,en;q=0.9,en-GB;q=0.8,en-US;q=0.7,pl;q=0.6',
            }

            params = (
                ('country', ca[country]),
            )

            data = {
                'sessionId': six.text_type(uuid.uuid4()),
                'whiteLabelBrand': 'TELIA',
                'watchMode': catchup_type,
                'accessControl': 'SUBSCRIPTION',
                'device': {
                    'deviceId': tv_client_boot_id,
                    'category': 'desktop_windows',
                    'packagings': ['DASH_MP4_CTR'],
                    'drmType': 'WIDEVINE',
                    'capabilities': [],
                    'screen': {
                        'height': 1080,
                        'width': 1920
                    },
                    'os': 'Windows',
                    'model': 'windows_desktop'
                },

                'preferences': {
                    'audioLanguage': [],
                    'accessibility': []
                }
            }

        response = send_req(url, post=True, headers=headers, json=data, params=params, verify=True, timeout=timeouts)

        if not response:
            xbmcgui.Dialog().notification(localized(30012), localized(30048))
            return None, None

        response = response.json()

        hea = ''

        LICENSE_URL = response.get('streams', '')[0].get('drm', '').get('licenseUrl', '')
        stream_url = response.get('streams', '')[0].get('url', '')
        headr = response.get('streams', '')[0].get('drm', '').get('headers', '')

        if 'X-AxDRM-Message' in headr:
            hea = 'Content-Type=&X-AxDRM-Message=' + dashjs

        elif 'x-dt-auth-token' in headr:
            hea = 'Content-Type=&x-dt-auth-token=' + headr.get('x-dt-auth-token', dashjs)

        else:
            hea = urlencode(headr)

            if 'Content-Type=&' not in hea:
                hea = 'Content-Type=&' + hea

        license_url = LICENSE_URL + '|' + hea + '|R{SSM}|'

        if stream_url is not None and stream_url != "":
            return stream_url, license_url

    except Exception as ex:
        xbmcgui.Dialog().notification(localized(30012), localized(30006))
        print('get_stream exception while looping: {}\n Data: {}'.format(ex, str(stream_url)))

    return None, None

def sports_page():
    add_item(label=localized(30049), url='', mode='sports_table_genre', icon=icon, fanart=fanart, folder=True, playable=False)
    add_item(label=localized(30050), url='', mode='sports_corner_genre', icon=icon, fanart=fanart, folder=True, playable=False)

    xbmcplugin.endOfDirectory(addon_handle)

def sports_genre():
    beartoken          = addon.getSetting('teliaplay_beartoken')
    tv_client_boot_id  = addon.getSetting('teliaplay_tv_client_boot_id')

    n = datetime.now()
    now = int(time.mktime(n.timetuple())) * 1000

    timestamp = str(((int(time.time() // 86400)) * 86400) * 1000)

    res = xbmcgui.Dialog().input(localized(30041), type=xbmcgui.INPUT_DATE)
    if res:
        date_str = '/'.join(i.zfill(2) for i in res.replace(' ', '').split('/'))
        dt_obj = proxydt.strptime(date_str, '%d/%m/%Y')
        date_time = dt_obj.strftime('%Y-%m-%d')

        url = 'https://graphql-telia.t6a.net/'

        headers = {
            'authorization': 'Bearer ' + beartoken,
            'tv-client-name': 'androidmob',
            'tv-client-version': '4.7.0',
            'tv-client-boot-id': tv_client_boot_id,
            'x-country': ca[country],
            'content-type': 'application/json',
            'accept-encoding': 'gzip',
            'user-agent': 'okhttp/4.9.3',
        }

        json = {
            'operationName': 'GetMobileSportTableau',

            'variables': {
                'sportEventListInput': {
                    'date': '{0}'.format(date_time),
                    'genres': [],
                    'onlyInSubscription': True
                }
            },

            'query': 'query GetMobileSportTableau($sportEventListInput: SportEventListInput!) { sportEventList(input: $sportEventListInput) { dates { __typename ...MobileSportEventDate } content { genres { __typename ...MobileSportEventFilter } sections { __typename ...MobileSportEventListSection } } } }  fragment MobileSportEventDate on SportEventDate { label date }  fragment MobileSportEventFilter on SportGenre { label value count }  fragment PlaybackSpec on PlaybackSpec { accessControl videoId videoIdType watchMode }  fragment Vod on Vod { audioLang { name code } playbackSpec { __typename ...PlaybackSpec } price { readable } validFrom { timestamp readableDistance(type: FUZZY) } validTo { timestamp } }  fragment Linear on PlaybackPlayLinear { item { startover { playbackSpec { __typename ...PlaybackSpec } } playbackSpec { __typename ...PlaybackSpec } startTime { timestamp readableDistance(type: FUZZY) } endTime { timestamp } } }  fragment Rental on PlaybackPlayVodRental { item { __typename ...Vod } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) msTo } } }  fragment Recording on PlaybackPlayRecording { item { playbackSpec { __typename ...PlaybackSpec } audioLang { name code } validFrom { timestamp } validTo { timestamp } } startover { playbackSpec { __typename ...PlaybackSpec } } }  fragment SubscriptionProductStandard on SubscriptionProductStandard { id price { readable } }  fragment SubscriptionProductDualEntry on SubscriptionProductDualEntry { id }  fragment SubscriptionProductTVE on SubscriptionProductTVE { id }  fragment SubscriptionProductFallback on SubscriptionProductFallback { id }  fragment Playback on Playback { play { subscription { item { __typename ...Vod } } linear { __typename ...Linear } rental { __typename ...Rental } npvr { __typename ...Recording } } buy { subscriptions { item { __typename id name ...SubscriptionProductStandard ...SubscriptionProductDualEntry ...SubscriptionProductTVE ...SubscriptionProductFallback } } rental { item { price { readable } validFrom { timestamp } validTo { timestamp } } } npvr { __typename } } }  fragment MobilePageMovie on Movie { id title playback { __typename ...Playback } images { backdrop16x9 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } } descriptionLong price { readable } genre yearProduction { number } ageRating { number } duration { readableShort } ratings { imdb { readableScore } } productionCountries userData { progress { percent position } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) } } } store { name } availability { from { text } } availableNow labels { premiereAnnouncement { text } } }  fragment MobilePageSeries on Series { id title images { backdrop16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } } description genre ageRating { number } ratings { imdb { readableScore } } label webview { url } isRentalSeries }  fragment MobilePageSportEvent on SportEvent { id title playback { __typename ...Playback } images { backdrop16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } } availability { from { text timestamp } } descriptionLong genre badges { uhd { text } } productionCountries ageRating { number } duration { readableShort } store { name } league labels { airtime { text } } yearProduction { number } userData { progress { percent position } } venue }  fragment MobileSportEventListSectionItem on SportEventListSectionItem { startTime { timestamp } endTime { timestamp } media { __typename ...MobilePageMovie ...MobilePageSeries ...MobilePageSportEvent } }  fragment MobileSportEventListSection on SportEventListSection { title items { __typename ...MobileSportEventListSectionItem } }'
        }

        response = send_req(url, post=True, json=json, headers=headers)
        if response:
            j_response = response.json()

            genres = []

            data = j_response['data']['sportEventList']['content']['genres']

            for item in data:
                if item['label'] != '':
                    genres.append(item['label'])

            for gen in genres:
                add_item(label=gen, url=str(gen)+'|'+str(date_time), mode='sports_table', icon=icon, fanart=fanart, folder=True, playable=False)

        xbmcplugin.endOfDirectory(addon_handle)

def sports(genre_id):
    idx = genre_id.split('|')[0]
    date_time = genre_id.split('|')[-1]

    beartoken          = addon.getSetting('teliaplay_beartoken')
    tv_client_boot_id  = addon.getSetting('teliaplay_tv_client_boot_id')

    url = 'https://graphql-telia.t6a.net/'

    headers = {
        'authorization': 'Bearer ' + beartoken,
        'tv-client-name': 'androidmob',
        'tv-client-version': '4.7.0',
        'tv-client-boot-id': tv_client_boot_id,
        'x-country': ca[country],
        'content-type': 'application/json',
        'accept-encoding': 'gzip',
        'user-agent': 'okhttp/4.9.3',
    }

    json = {
        'operationName': 'GetMobileSportTableau',

        'variables': {
            'sportEventListInput': {
                'date': '{0}'.format(date_time),
                'genres': [],
                'onlyInSubscription': True
            }
        },

        'query': 'query GetMobileSportTableau($sportEventListInput: SportEventListInput!) { sportEventList(input: $sportEventListInput) { dates { __typename ...MobileSportEventDate } content { genres { __typename ...MobileSportEventFilter } sections { __typename ...MobileSportEventListSection } } } }  fragment MobileSportEventDate on SportEventDate { label date }  fragment MobileSportEventFilter on SportGenre { label value count }  fragment PlaybackSpec on PlaybackSpec { accessControl videoId videoIdType watchMode }  fragment Vod on Vod { audioLang { name code } playbackSpec { __typename ...PlaybackSpec } price { readable } validFrom { timestamp readableDistance(type: FUZZY) } validTo { timestamp } }  fragment Linear on PlaybackPlayLinear { item { startover { playbackSpec { __typename ...PlaybackSpec } } playbackSpec { __typename ...PlaybackSpec } startTime { timestamp readableDistance(type: FUZZY) } endTime { timestamp } } }  fragment Rental on PlaybackPlayVodRental { item { __typename ...Vod } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) msTo } } }  fragment Recording on PlaybackPlayRecording { item { playbackSpec { __typename ...PlaybackSpec } audioLang { name code } validFrom { timestamp } validTo { timestamp } } startover { playbackSpec { __typename ...PlaybackSpec } } }  fragment SubscriptionProductStandard on SubscriptionProductStandard { id price { readable } }  fragment SubscriptionProductDualEntry on SubscriptionProductDualEntry { id }  fragment SubscriptionProductTVE on SubscriptionProductTVE { id }  fragment SubscriptionProductFallback on SubscriptionProductFallback { id }  fragment Playback on Playback { play { subscription { item { __typename ...Vod } } linear { __typename ...Linear } rental { __typename ...Rental } npvr { __typename ...Recording } } buy { subscriptions { item { __typename id name ...SubscriptionProductStandard ...SubscriptionProductDualEntry ...SubscriptionProductTVE ...SubscriptionProductFallback } } rental { item { price { readable } validFrom { timestamp } validTo { timestamp } } } npvr { __typename } } }  fragment MobilePageMovie on Movie { id title playback { __typename ...Playback } images { backdrop16x9 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } } descriptionLong price { readable } genre yearProduction { number } ageRating { number } duration { readableShort } ratings { imdb { readableScore } } productionCountries userData { progress { percent position } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) } } } store { name } availability { from { text } } availableNow labels { premiereAnnouncement { text } } }  fragment MobilePageSeries on Series { id title images { backdrop16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } } description genre ageRating { number } ratings { imdb { readableScore } } label webview { url } isRentalSeries }  fragment MobilePageSportEvent on SportEvent { id title playback { __typename ...Playback } images { backdrop16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } } availability { from { text timestamp } } descriptionLong genre badges { uhd { text } } productionCountries ageRating { number } duration { readableShort } store { name } league labels { airtime { text } } yearProduction { number } userData { progress { percent position } } venue }  fragment MobileSportEventListSectionItem on SportEventListSectionItem { startTime { timestamp } endTime { timestamp } media { __typename ...MobilePageMovie ...MobilePageSeries ...MobilePageSportEvent } }  fragment MobileSportEventListSection on SportEventListSection { title items { __typename ...MobileSportEventListSectionItem } }'
    }

    response = send_req(url, post=True, json=json, headers=headers)
    if response:
        j_response = response.json()

        try:
            data = j_response['data']['sportEventList']['content']['sections']
            items = None

            for i in data:
                for item in i['items']:
                    genre = item['media']['genre']

                    if genre == idx:
                        items = i['items']

                        get_items(items)

        except Exception as ex:
            print('sports table Exception: {}'.format(ex))
            xbmcgui.Dialog().notification(localized(30012), localized(30048))
            return

def sports_corner_genre():
    beartoken          = addon.getSetting('teliaplay_beartoken')
    tv_client_boot_id  = addon.getSetting('teliaplay_tv_client_boot_id')

    n = datetime.now()
    now = int(time.mktime(n.timetuple())) * 1000

    timestamp = str(((int(time.time() // 86400)) * 86400) * 1000)

    url = 'https://graphql-telia.t6a.net/'

    headers = {
        'authorization': 'Bearer ' + beartoken,
        'tv-client-name': 'androidmob',
        'tv-client-version': '4.7.0',
        'tv-client-boot-id': tv_client_boot_id,
        'x-country': ca[country],
        'content-type': 'application/json',
        'accept-encoding': 'gzip',
        'user-agent': 'okhttp/4.9.3',
    }

    json = {
        'operationName': 'getMobilePage',

        'variables': {
            'channelsLimit': 100,
            'mediaContentLimit': 500,
            'pageId': 'sports-corner',
            'timestamp': timestamp
        },

        'query': 'query getMobilePage($pageId: String!, $timestamp: Timestamp!, $channelsLimit: Int!, $mediaContentLimit: Int!) { page(id: $pageId) { id pagePanels(limit: 60) { items { __typename title id ...MobileSelectionMediaPanel ...MobileMediaPanel ...MobileStoresPanel ...MobileRentalsPanel ...MobileTimelinePanel ...MobileShowcasePanel ...MobileContinueWatchingPanel ...MobileMyListPanel ...MobileChannelsPanel ...MobileSingleFeaturePanel ...MobilePageLinkPanel } } } }  fragment PlaybackSpec on PlaybackSpec { accessControl videoId videoIdType watchMode }  fragment Vod on Vod { audioLang { name code } playbackSpec { __typename ...PlaybackSpec } price { readable } validFrom { timestamp readableDistance(type: FUZZY) } validTo { timestamp } }  fragment Linear on PlaybackPlayLinear { item { startover { playbackSpec { __typename ...PlaybackSpec } } playbackSpec { __typename ...PlaybackSpec } startTime { timestamp readableDistance(type: FUZZY) } endTime { timestamp } } }  fragment Rental on PlaybackPlayVodRental { item { __typename ...Vod } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) msTo } } }  fragment Recording on PlaybackPlayRecording { item { playbackSpec { __typename ...PlaybackSpec } audioLang { name code } validFrom { timestamp } validTo { timestamp } } startover { playbackSpec { __typename ...PlaybackSpec } } }  fragment SubscriptionProductStandard on SubscriptionProductStandard { id price { readable } }  fragment SubscriptionProductDualEntry on SubscriptionProductDualEntry { id }  fragment SubscriptionProductTVE on SubscriptionProductTVE { id }  fragment SubscriptionProductFallback on SubscriptionProductFallback { id }  fragment Playback on Playback { play { subscription { item { __typename ...Vod } } linear { __typename ...Linear } rental { __typename ...Rental } npvr { __typename ...Recording } } buy { subscriptions { item { __typename id name ...SubscriptionProductStandard ...SubscriptionProductDualEntry ...SubscriptionProductTVE ...SubscriptionProductFallback } } rental { item { price { readable } validFrom { timestamp } validTo { timestamp } } } npvr { __typename } } }  fragment MobilePageMovie on Movie { id title playback { __typename ...Playback } images { backdrop16x9 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } } descriptionLong price { readable } genre yearProduction { number } ageRating { number } duration { readableShort } ratings { imdb { readableScore } } productionCountries userData { progress { percent position } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) } } } store { name } availability { from { text } } availableNow labels { premiereAnnouncement { text } } }  fragment MobilePageSeries on Series { id title images { backdrop16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } } description genre ageRating { number } ratings { imdb { readableScore } } label webview { url } isRentalSeries }  fragment MobilePageEpisode on Episode { id title images { backdrop16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } screenshot16x9 { sourceNonEncoded } } descriptionLong price { readable } genre yearProduction { number } episodeNumber { number readable } seasonNumber { number readable } playback { __typename ...Playback } series { id title } ageRating { number } duration { readableShort } userData { progress { percent position } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) } } } store { name } }  fragment MobilePageSportEvent on SportEvent { id title playback { __typename ...Playback } images { backdrop16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } } availability { from { text timestamp } } descriptionLong genre badges { uhd { text } } productionCountries ageRating { number } duration { readableShort } store { name } league labels { airtime { text } } yearProduction { number } userData { progress { percent position } } venue }  fragment MobilePageMediaPanelContent on MediaPanelItemContent { __typename ... on Movie { __typename ...MobilePageMovie } ... on Series { __typename ...MobilePageSeries } ... on Episode { __typename ...MobilePageEpisode } ... on SportEvent { __typename ...MobilePageSportEvent } }  fragment MobileSelectionMediaPanel on SelectionMediaPanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } selectionMediaContent(config: { limit: $mediaContentLimit } ) { pageInfo { hasNextPage } items { media { __typename ...MobilePageMediaPanelContent } } } link { id type } }  fragment MobileMediaPanel on MediaPanel { id title kicker displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } mediaContent(limit: $mediaContentLimit) { pageInfo { hasNextPage } items { media { __typename ...MobilePageMediaPanelContent } } } }  fragment MobilePageStore on Store { id __typename name icons { light { sourceNonEncoded } dark { sourceNonEncoded } } }  fragment MobileStoresPanel on StoresPanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } storesContent(limit: $mediaContentLimit) { pageInfo { hasNextPage } items { __typename ...MobilePageStore } } }  fragment MobileRentalsPanelItemContent on RentalsPanelItemContent { __typename ... on Movie { __typename ...MobilePageMovie } ... on Series { __typename ...MobilePageSeries } }  fragment MobileRentalsPanel on RentalsPanel { id title rentalsContent(limit: $mediaContentLimit) { items { media { __typename ...MobileRentalsPanelItemContent } } } }  fragment MobileTimeLinePanelItemContent on TimelinePanelItemContent { __typename ... on Movie { __typename ...MobilePageMovie } ... on Episode { __typename ...MobilePageEpisode } ... on SportEvent { __typename ...MobilePageSportEvent } }  fragment MobileTimelinePanel on TimelinePanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } timelineContent(limit: $mediaContentLimit) { pageInfo { hasNextPage } items { media { __typename ...MobileTimeLinePanelItemContent } startTime { timestamp isoString } endTime { timestamp isoString } } } }  fragment Store on Store { name icons { dark { sourceNonEncoded } } }  fragment MobileShowcaseMovie on Movie { id title userData { progress { position } favorite } images { backdrop16x9 { sourceNonEncoded } } playback { __typename ...Playback } store { __typename ...Store } }  fragment MobileShowcaseEpisode on Episode { id title userData { progress { position } favorite } images { backdrop16x9 { sourceNonEncoded } } playback { __typename ...Playback } series { id } store { __typename ...Store } }  fragment MobileShowcaseSeries on Series { id title userData { favorite } images { backdrop16x9 { sourceNonEncoded } } webview { url } suggestedEpisode { id playback { __typename ...Playback } } store { __typename ...Store } }  fragment MobileShowcaseSportEvent on SportEvent { id title userData { progress { position } favorite } images { backdrop16x9 { sourceNonEncoded } } playback { __typename ...Playback } store { __typename ...Store } }  fragment ChannelPlayback on ChannelPlayback { play { playbackSpec { __typename ...PlaybackSpec } } buy { subscriptions { item { id } } } }  fragment MobileShowcaseChannel on Channel { channelPlayback: playback { __typename ...ChannelPlayback } }  fragment MobileShowcasePanel on ShowcasePanel { id title showcaseContent { items { id showcaseTitle { text } kicker images { showcase16x9 { sourceNonEncoded } showcase16x7 { sourceNonEncoded } showcase7x10 { sourceNonEncoded } showcase2x3 { sourceNonEncoded } } promotion { link { id type } content { __typename ...MobileShowcaseMovie ...MobileShowcaseEpisode ...MobileShowcaseSeries ...MobileShowcaseSportEvent ...MobileShowcaseChannel } } } } }  fragment MobileContinueWatchingPanelItemContent on ContinueWatchingPanelItemContent { __typename ... on Movie { __typename ...MobilePageMovie } ... on Episode { __typename ...MobilePageEpisode } ... on SportEvent { __typename ...MobilePageSportEvent } }  fragment MobileContinueWatchingPanel on ContinueWatchingPanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } continueWatchingContent { items { media { __typename ...MobileContinueWatchingPanelItemContent } } } }  fragment MobileMyListPanelItemContent on MyListPanelItemContent { __typename ... on Movie { __typename ...MobilePageMovie } ... on Series { __typename ...MobilePageSeries } ... on SportEvent { __typename ...MobilePageSportEvent } }  fragment MobileMyListPanel on MyListPanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } myListContent(limit: $mediaContentLimit) { pageInfo { hasNextPage } items { media { __typename ...MobileMyListPanelItemContent } } } }  fragment MobileChannelsPanel on ChannelsPanel { id title channels(limit: $channelsLimit) { pageInfo { hasNextPage } channelItems { id name userData { inEngagement } icons { dark { sourceNonEncoded } } playback { play { playbackSpec { __typename ...PlaybackSpec } } } displayHint { __typename ... on NormalChannelDisplayHint { noProgramsText } ... on LiveOnlyChannelDisplayHint { noProgramsText } } programs(timestamp: $timestamp, limit: 1) { programItems { startTime { timestamp isoString } endTime { timestamp isoString } media { __typename ... on Movie { title } ... on Episode { series { title } } ... on SportEvent { title } } } } } } }  fragment MobileSingleFeaturePanelMedia on SingleFeaturePanelMedia { __typename ... on Movie { __typename ...MobilePageMovie } ... on Series { __typename ...MobilePageSeries } ... on SportEvent { __typename ...MobilePageSportEvent } }  fragment MobileSingleFeaturePanel on SingleFeaturePanel { id title subtitle images { __typename ... on SingleFeaturePanelImages { promo16x9 { sourceNonEncoded } } } media { __typename ...MobileSingleFeaturePanelMedia } }  fragment MobilePageLinkPanel on PageLinkPanel { id title pageLinkContent { items { id name description type images { icon1x1 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } } } } }'
    }

    response = send_req(url, post=True, json=json, headers=headers)
    if response:
        j_response = response.json()

        genres = []

        data = j_response['data']['page']['pagePanels']['items']

        key = -1
        for item in data:
            key += 1
            if item['title'] != '':
                genres.append((key, item['title']))

        for gen in genres:
            add_item(label=gen[1], url=str(gen[0]), mode='sports_corner', icon=icon, fanart=fanart, folder=True, playable=False)

    xbmcplugin.endOfDirectory(addon_handle)

def sports_corner(genre_id):
    idx = int(genre_id)

    beartoken          = addon.getSetting('teliaplay_beartoken')
    tv_client_boot_id  = addon.getSetting('teliaplay_tv_client_boot_id')

    n = datetime.now()
    now = int(time.mktime(n.timetuple())) * 1000

    timestamp = str(((int(time.time() // 86400)) * 86400) * 1000)

    url = 'https://graphql-telia.t6a.net/'

    headers = {
        'authorization': 'Bearer ' + beartoken,
        'tv-client-name': 'androidmob',
        'tv-client-version': '4.7.0',
        'tv-client-boot-id': tv_client_boot_id,
        'x-country': ca[country],
        'content-type': 'application/json',
        'accept-encoding': 'gzip',
        'user-agent': 'okhttp/4.9.3',
    }

    json = {
        'operationName': 'getMobilePage',

        'variables': {
            'channelsLimit': 100,
            'mediaContentLimit': 500,
            'pageId': 'sports-corner',
            'timestamp': timestamp
        },

        'query': 'query getMobilePage($pageId: String!, $timestamp: Timestamp!, $channelsLimit: Int!, $mediaContentLimit: Int!) { page(id: $pageId) { id pagePanels(limit: 60) { items { __typename title id ...MobileSelectionMediaPanel ...MobileMediaPanel ...MobileStoresPanel ...MobileRentalsPanel ...MobileTimelinePanel ...MobileShowcasePanel ...MobileContinueWatchingPanel ...MobileMyListPanel ...MobileChannelsPanel ...MobileSingleFeaturePanel ...MobilePageLinkPanel } } } }  fragment PlaybackSpec on PlaybackSpec { accessControl videoId videoIdType watchMode }  fragment Vod on Vod { audioLang { name code } playbackSpec { __typename ...PlaybackSpec } price { readable } validFrom { timestamp readableDistance(type: FUZZY) } validTo { timestamp } }  fragment Linear on PlaybackPlayLinear { item { startover { playbackSpec { __typename ...PlaybackSpec } } playbackSpec { __typename ...PlaybackSpec } startTime { timestamp readableDistance(type: FUZZY) } endTime { timestamp } } }  fragment Rental on PlaybackPlayVodRental { item { __typename ...Vod } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) msTo } } }  fragment Recording on PlaybackPlayRecording { item { playbackSpec { __typename ...PlaybackSpec } audioLang { name code } validFrom { timestamp } validTo { timestamp } } startover { playbackSpec { __typename ...PlaybackSpec } } }  fragment SubscriptionProductStandard on SubscriptionProductStandard { id price { readable } }  fragment SubscriptionProductDualEntry on SubscriptionProductDualEntry { id }  fragment SubscriptionProductTVE on SubscriptionProductTVE { id }  fragment SubscriptionProductFallback on SubscriptionProductFallback { id }  fragment Playback on Playback { play { subscription { item { __typename ...Vod } } linear { __typename ...Linear } rental { __typename ...Rental } npvr { __typename ...Recording } } buy { subscriptions { item { __typename id name ...SubscriptionProductStandard ...SubscriptionProductDualEntry ...SubscriptionProductTVE ...SubscriptionProductFallback } } rental { item { price { readable } validFrom { timestamp } validTo { timestamp } } } npvr { __typename } } }  fragment MobilePageMovie on Movie { id title playback { __typename ...Playback } images { backdrop16x9 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } } descriptionLong price { readable } genre yearProduction { number } ageRating { number } duration { readableShort } ratings { imdb { readableScore } } productionCountries userData { progress { percent position } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) } } } store { name } availability { from { text } } availableNow labels { premiereAnnouncement { text } } }  fragment MobilePageSeries on Series { id title images { backdrop16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } } description genre ageRating { number } ratings { imdb { readableScore } } label webview { url } isRentalSeries }  fragment MobilePageEpisode on Episode { id title images { backdrop16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } screenshot16x9 { sourceNonEncoded } } descriptionLong price { readable } genre yearProduction { number } episodeNumber { number readable } seasonNumber { number readable } playback { __typename ...Playback } series { id title } ageRating { number } duration { readableShort } userData { progress { percent position } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) } } } store { name } }  fragment MobilePageSportEvent on SportEvent { id title playback { __typename ...Playback } images { backdrop16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } } availability { from { text timestamp } } descriptionLong genre badges { uhd { text } } productionCountries ageRating { number } duration { readableShort } store { name } league labels { airtime { text } } yearProduction { number } userData { progress { percent position } } venue }  fragment MobilePageMediaPanelContent on MediaPanelItemContent { __typename ... on Movie { __typename ...MobilePageMovie } ... on Series { __typename ...MobilePageSeries } ... on Episode { __typename ...MobilePageEpisode } ... on SportEvent { __typename ...MobilePageSportEvent } }  fragment MobileSelectionMediaPanel on SelectionMediaPanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } selectionMediaContent(config: { limit: $mediaContentLimit } ) { pageInfo { hasNextPage } items { media { __typename ...MobilePageMediaPanelContent } } } link { id type } }  fragment MobileMediaPanel on MediaPanel { id title kicker displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } mediaContent(limit: $mediaContentLimit) { pageInfo { hasNextPage } items { media { __typename ...MobilePageMediaPanelContent } } } }  fragment MobilePageStore on Store { id __typename name icons { light { sourceNonEncoded } dark { sourceNonEncoded } } }  fragment MobileStoresPanel on StoresPanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } storesContent(limit: $mediaContentLimit) { pageInfo { hasNextPage } items { __typename ...MobilePageStore } } }  fragment MobileRentalsPanelItemContent on RentalsPanelItemContent { __typename ... on Movie { __typename ...MobilePageMovie } ... on Series { __typename ...MobilePageSeries } }  fragment MobileRentalsPanel on RentalsPanel { id title rentalsContent(limit: $mediaContentLimit) { items { media { __typename ...MobileRentalsPanelItemContent } } } }  fragment MobileTimeLinePanelItemContent on TimelinePanelItemContent { __typename ... on Movie { __typename ...MobilePageMovie } ... on Episode { __typename ...MobilePageEpisode } ... on SportEvent { __typename ...MobilePageSportEvent } }  fragment MobileTimelinePanel on TimelinePanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } timelineContent(limit: $mediaContentLimit) { pageInfo { hasNextPage } items { media { __typename ...MobileTimeLinePanelItemContent } startTime { timestamp isoString } endTime { timestamp isoString } } } }  fragment Store on Store { name icons { dark { sourceNonEncoded } } }  fragment MobileShowcaseMovie on Movie { id title userData { progress { position } favorite } images { backdrop16x9 { sourceNonEncoded } } playback { __typename ...Playback } store { __typename ...Store } }  fragment MobileShowcaseEpisode on Episode { id title userData { progress { position } favorite } images { backdrop16x9 { sourceNonEncoded } } playback { __typename ...Playback } series { id } store { __typename ...Store } }  fragment MobileShowcaseSeries on Series { id title userData { favorite } images { backdrop16x9 { sourceNonEncoded } } webview { url } suggestedEpisode { id playback { __typename ...Playback } } store { __typename ...Store } }  fragment MobileShowcaseSportEvent on SportEvent { id title userData { progress { position } favorite } images { backdrop16x9 { sourceNonEncoded } } playback { __typename ...Playback } store { __typename ...Store } }  fragment ChannelPlayback on ChannelPlayback { play { playbackSpec { __typename ...PlaybackSpec } } buy { subscriptions { item { id } } } }  fragment MobileShowcaseChannel on Channel { channelPlayback: playback { __typename ...ChannelPlayback } }  fragment MobileShowcasePanel on ShowcasePanel { id title showcaseContent { items { id showcaseTitle { text } kicker images { showcase16x9 { sourceNonEncoded } showcase16x7 { sourceNonEncoded } showcase7x10 { sourceNonEncoded } showcase2x3 { sourceNonEncoded } } promotion { link { id type } content { __typename ...MobileShowcaseMovie ...MobileShowcaseEpisode ...MobileShowcaseSeries ...MobileShowcaseSportEvent ...MobileShowcaseChannel } } } } }  fragment MobileContinueWatchingPanelItemContent on ContinueWatchingPanelItemContent { __typename ... on Movie { __typename ...MobilePageMovie } ... on Episode { __typename ...MobilePageEpisode } ... on SportEvent { __typename ...MobilePageSportEvent } }  fragment MobileContinueWatchingPanel on ContinueWatchingPanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } continueWatchingContent { items { media { __typename ...MobileContinueWatchingPanelItemContent } } } }  fragment MobileMyListPanelItemContent on MyListPanelItemContent { __typename ... on Movie { __typename ...MobilePageMovie } ... on Series { __typename ...MobilePageSeries } ... on SportEvent { __typename ...MobilePageSportEvent } }  fragment MobileMyListPanel on MyListPanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } myListContent(limit: $mediaContentLimit) { pageInfo { hasNextPage } items { media { __typename ...MobileMyListPanelItemContent } } } }  fragment MobileChannelsPanel on ChannelsPanel { id title channels(limit: $channelsLimit) { pageInfo { hasNextPage } channelItems { id name userData { inEngagement } icons { dark { sourceNonEncoded } } playback { play { playbackSpec { __typename ...PlaybackSpec } } } displayHint { __typename ... on NormalChannelDisplayHint { noProgramsText } ... on LiveOnlyChannelDisplayHint { noProgramsText } } programs(timestamp: $timestamp, limit: 1) { programItems { startTime { timestamp isoString } endTime { timestamp isoString } media { __typename ... on Movie { title } ... on Episode { series { title } } ... on SportEvent { title } } } } } } }  fragment MobileSingleFeaturePanelMedia on SingleFeaturePanelMedia { __typename ... on Movie { __typename ...MobilePageMovie } ... on Series { __typename ...MobilePageSeries } ... on SportEvent { __typename ...MobilePageSportEvent } }  fragment MobileSingleFeaturePanel on SingleFeaturePanel { id title subtitle images { __typename ... on SingleFeaturePanelImages { promo16x9 { sourceNonEncoded } } } media { __typename ...MobileSingleFeaturePanelMedia } }  fragment MobilePageLinkPanel on PageLinkPanel { id title pageLinkContent { items { id name description type images { icon1x1 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } } } } }'
    }

    response = send_req(url, post=True, json=json, headers=headers)
    if response:
        j_response = response.json()

    try:
        data = j_response['data']['page']['pagePanels']['items'][idx]
        items = None

        pagelink = data.get('pageLinkContent')
        timeline = data.get('timelineContent')
        selection = data.get('selectionMediaContent')
        media = data.get('mediaContent')
        stores = data.get('storesContent')
        showcase = data.get('showcaseContent')

        if pagelink:
            items = pagelink.get('items')

        elif timeline:
            items = timeline.get('items')

        elif selection:
            items = selection.get('items')

        elif media:
            items = media.get('items')

        elif showcase:
            items = showcase.get('items')

        else:
            items = stores.get('items')

        if not items:
            xbmcgui.Dialog().notification(localized(30012), localized(30048))
            return

        get_items(items)

    except Exception as ex:
        print('sports Exception: {}'.format(ex))
        xbmcgui.Dialog().notification(localized(30012), localized(30048))
        return

def kids_genre():
    beartoken = addon.getSetting('teliaplay_beartoken')
    tv_client_boot_id = addon.getSetting('teliaplay_tv_client_boot_id')

    url = 'https://graphql-telia.t6a.net/'

    headers = {
        'authorization': 'Bearer ' + beartoken,
        'tv-client-name': 'androidmob',
        'tv-client-version': '4.7.0',
        'tv-client-boot-id': tv_client_boot_id,
        'x-country': ca[country],
        'content-type': 'application/json',
        'accept-encoding': 'gzip',
        'user-agent': 'okhttp/4.9.3',
    }

    json_data = {
        'operationName': 'getCommonBrowsePage',
        'variables': {
            'mediaContentLimit': 999,
            'pageId': 'play-library-kids'
        },

        'query': 'query getCommonBrowsePage($pageId: String!, $mediaContentLimit: Int!) { page(id: $pageId) { id pagePanels { items { __typename title id ...MobileShowcasePanel ...MobileMediaPanel ...MobileSelectionMediaPanel ...MobileSingleFeaturePanel ...MobileStoresPanel } } } }  fragment PlaybackSpec on PlaybackSpec { accessControl videoId videoIdType watchMode }  fragment Vod on Vod { audioLang { name code } playbackSpec { __typename ...PlaybackSpec } price { readable } validFrom { timestamp readableDistance(type: FUZZY) } validTo { timestamp } }  fragment Linear on PlaybackPlayLinear { item { startover { playbackSpec { __typename ...PlaybackSpec } } playbackSpec { __typename ...PlaybackSpec } startTime { timestamp readableDistance(type: FUZZY) } endTime { timestamp } } }  fragment Rental on PlaybackPlayVodRental { item { __typename ...Vod } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) msTo } } }  fragment Recording on PlaybackPlayRecording { item { playbackSpec { __typename ...PlaybackSpec } audioLang { name code } validFrom { timestamp } validTo { timestamp } } startover { playbackSpec { __typename ...PlaybackSpec } } }  fragment SubscriptionProductStandard on SubscriptionProductStandard { id price { readable } }  fragment SubscriptionProductDualEntry on SubscriptionProductDualEntry { id }  fragment SubscriptionProductTVE on SubscriptionProductTVE { id }  fragment SubscriptionProductFallback on SubscriptionProductFallback { id }  fragment Playback on Playback { play { subscription { item { __typename ...Vod } } linear { __typename ...Linear } rental { __typename ...Rental } npvr { __typename ...Recording } } buy { subscriptions { item { __typename id name ...SubscriptionProductStandard ...SubscriptionProductDualEntry ...SubscriptionProductTVE ...SubscriptionProductFallback } } rental { item { price { readable } validFrom { timestamp } validTo { timestamp } } } npvr { __typename } } }  fragment Store on Store { name icons { dark { sourceNonEncoded } } }  fragment MobileShowcaseMovie on Movie { id title userData { progress { position } favorite } images { backdrop16x9 { sourceNonEncoded } } playback { __typename ...Playback } store { __typename ...Store } }  fragment MobileShowcaseEpisode on Episode { id title userData { progress { position } favorite } images { backdrop16x9 { sourceNonEncoded } } playback { __typename ...Playback } series { id } store { __typename ...Store } }  fragment MobileShowcaseSeries on Series { id title userData { favorite } images { backdrop16x9 { sourceNonEncoded } } webview { url } suggestedEpisode { id playback { __typename ...Playback } } store { __typename ...Store } }  fragment MobileShowcaseSportEvent on SportEvent { id title userData { progress { position } favorite } images { backdrop16x9 { sourceNonEncoded } } playback { __typename ...Playback } store { __typename ...Store } }  fragment ChannelPlayback on ChannelPlayback { play { playbackSpec { __typename ...PlaybackSpec } } buy { subscriptions { item { id } } } }  fragment MobileShowcaseChannel on Channel { channelPlayback: playback { __typename ...ChannelPlayback } }  fragment MobileShowcasePanel on ShowcasePanel { id title showcaseContent { items { id showcaseTitle { text } kicker images { showcase16x9 { sourceNonEncoded } showcase16x7 { sourceNonEncoded } showcase7x10 { sourceNonEncoded } showcase2x3 { sourceNonEncoded } } promotion { link { id type } content { __typename ...MobileShowcaseMovie ...MobileShowcaseEpisode ...MobileShowcaseSeries ...MobileShowcaseSportEvent ...MobileShowcaseChannel } } } } }  fragment MobilePageMovie on Movie { id title playback { __typename ...Playback } images { backdrop16x9 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } } descriptionLong price { readable } genre yearProduction { number } ageRating { number } duration { readableShort } ratings { imdb { readableScore } } productionCountries userData { progress { percent position } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) } } } store { name } availability { from { text } } availableNow labels { premiereAnnouncement { text } } }  fragment MobilePageSeries on Series { id title images { backdrop16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } } description genre ageRating { number } ratings { imdb { readableScore } } label webview { url } isRentalSeries }  fragment MobilePageEpisode on Episode { id title images { backdrop16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } screenshot16x9 { sourceNonEncoded } } descriptionLong price { readable } genre yearProduction { number } episodeNumber { number readable } seasonNumber { number readable } playback { __typename ...Playback } series { id title } ageRating { number } duration { readableShort } userData { progress { percent position } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) } } } store { name } }  fragment MobilePageSportEvent on SportEvent { id title playback { __typename ...Playback } images { backdrop16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } } availability { from { text timestamp } } descriptionLong genre badges { uhd { text } } productionCountries ageRating { number } duration { readableShort } store { name } league labels { airtime { text } } yearProduction { number } userData { progress { percent position } } venue }  fragment MobilePageMediaPanelContent on MediaPanelItemContent { __typename ... on Movie { __typename ...MobilePageMovie } ... on Series { __typename ...MobilePageSeries } ... on Episode { __typename ...MobilePageEpisode } ... on SportEvent { __typename ...MobilePageSportEvent } }  fragment MobileMediaPanel on MediaPanel { id title kicker displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } mediaContent(limit: $mediaContentLimit) { pageInfo { hasNextPage } items { media { __typename ...MobilePageMediaPanelContent } } } }  fragment MobileSelectionMediaPanel on SelectionMediaPanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } selectionMediaContent(config: { limit: $mediaContentLimit } ) { pageInfo { hasNextPage } items { media { __typename ...MobilePageMediaPanelContent } } } link { id type } }  fragment MobileSingleFeaturePanelMedia on SingleFeaturePanelMedia { __typename ... on Movie { __typename ...MobilePageMovie } ... on Series { __typename ...MobilePageSeries } ... on SportEvent { __typename ...MobilePageSportEvent } }  fragment MobileSingleFeaturePanel on SingleFeaturePanel { id title subtitle images { __typename ... on SingleFeaturePanelImages { promo16x9 { sourceNonEncoded } } } media { __typename ...MobileSingleFeaturePanelMedia } }  fragment MobilePageStore on Store { id __typename name icons { light { sourceNonEncoded } dark { sourceNonEncoded } } }  fragment MobileStoresPanel on StoresPanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } storesContent(limit: $mediaContentLimit) { pageInfo { hasNextPage } items { __typename ...MobilePageStore } } }'
    }

    response = send_req(url, post=True, json=json_data, headers=headers)
    if response:
        j_response = response.json()

        genres = []

        data = j_response['data']['page']['pagePanels']['items']

        key = -1
        for item in data:
            key += 1
            genres.append((key, item['title']))

        for gen in genres:
            add_item(label=gen[1], url=str(gen[0]), mode='kids', icon=icon, fanart=fanart, folder=True, playable=False)

        xbmcplugin.endOfDirectory(addon_handle)

def kids(genre_id):
    idx = int(genre_id)

    beartoken = addon.getSetting('teliaplay_beartoken')
    tv_client_boot_id = addon.getSetting('teliaplay_tv_client_boot_id')

    url = 'https://graphql-telia.t6a.net/'

    headers = {
        'authorization': 'Bearer ' + beartoken,
        'tv-client-name': 'androidmob',
        'tv-client-version': '4.7.0',
        'tv-client-boot-id': tv_client_boot_id,
        'x-country': ca[country],
        'content-type': 'application/json',
        'accept-encoding': 'gzip',
        'user-agent': 'okhttp/4.9.3',
    }

    json_data = {
        'operationName': 'getCommonBrowsePage',
        'variables': {
            'mediaContentLimit': 500,
            'pageId': 'play-library-kids'
        },

        'query': 'query getCommonBrowsePage($pageId: String!, $mediaContentLimit: Int!) { page(id: $pageId) { id pagePanels { items { __typename title id ...MobileShowcasePanel ...MobileMediaPanel ...MobileSelectionMediaPanel ...MobileSingleFeaturePanel ...MobileStoresPanel } } } }  fragment PlaybackSpec on PlaybackSpec { accessControl videoId videoIdType watchMode }  fragment Vod on Vod { audioLang { name code } playbackSpec { __typename ...PlaybackSpec } price { readable } validFrom { timestamp readableDistance(type: FUZZY) } validTo { timestamp } }  fragment Linear on PlaybackPlayLinear { item { startover { playbackSpec { __typename ...PlaybackSpec } } playbackSpec { __typename ...PlaybackSpec } startTime { timestamp readableDistance(type: FUZZY) } endTime { timestamp } } }  fragment Rental on PlaybackPlayVodRental { item { __typename ...Vod } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) msTo } } }  fragment Recording on PlaybackPlayRecording { item { playbackSpec { __typename ...PlaybackSpec } audioLang { name code } validFrom { timestamp } validTo { timestamp } } startover { playbackSpec { __typename ...PlaybackSpec } } }  fragment SubscriptionProductStandard on SubscriptionProductStandard { id price { readable } }  fragment SubscriptionProductDualEntry on SubscriptionProductDualEntry { id }  fragment SubscriptionProductTVE on SubscriptionProductTVE { id }  fragment SubscriptionProductFallback on SubscriptionProductFallback { id }  fragment Playback on Playback { play { subscription { item { __typename ...Vod } } linear { __typename ...Linear } rental { __typename ...Rental } npvr { __typename ...Recording } } buy { subscriptions { item { __typename id name ...SubscriptionProductStandard ...SubscriptionProductDualEntry ...SubscriptionProductTVE ...SubscriptionProductFallback } } rental { item { price { readable } validFrom { timestamp } validTo { timestamp } } } npvr { __typename } } }  fragment Store on Store { name icons { dark { sourceNonEncoded } } }  fragment MobileShowcaseMovie on Movie { id title userData { progress { position } favorite } images { backdrop16x9 { sourceNonEncoded } } playback { __typename ...Playback } store { __typename ...Store } }  fragment MobileShowcaseEpisode on Episode { id title userData { progress { position } favorite } images { backdrop16x9 { sourceNonEncoded } } playback { __typename ...Playback } series { id } store { __typename ...Store } }  fragment MobileShowcaseSeries on Series { id title userData { favorite } images { backdrop16x9 { sourceNonEncoded } } webview { url } suggestedEpisode { id playback { __typename ...Playback } } store { __typename ...Store } }  fragment MobileShowcaseSportEvent on SportEvent { id title userData { progress { position } favorite } images { backdrop16x9 { sourceNonEncoded } } playback { __typename ...Playback } store { __typename ...Store } }  fragment ChannelPlayback on ChannelPlayback { play { playbackSpec { __typename ...PlaybackSpec } } buy { subscriptions { item { id } } } }  fragment MobileShowcaseChannel on Channel { channelPlayback: playback { __typename ...ChannelPlayback } }  fragment MobileShowcasePanel on ShowcasePanel { id title showcaseContent { items { id showcaseTitle { text } kicker images { showcase16x9 { sourceNonEncoded } showcase16x7 { sourceNonEncoded } showcase7x10 { sourceNonEncoded } showcase2x3 { sourceNonEncoded } } promotion { link { id type } content { __typename ...MobileShowcaseMovie ...MobileShowcaseEpisode ...MobileShowcaseSeries ...MobileShowcaseSportEvent ...MobileShowcaseChannel } } } } }  fragment MobilePageMovie on Movie { id title playback { __typename ...Playback } images { backdrop16x9 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } } descriptionLong price { readable } genre yearProduction { number } ageRating { number } duration { readableShort } ratings { imdb { readableScore } } productionCountries userData { progress { percent position } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) } } } store { name } availability { from { text } } availableNow labels { premiereAnnouncement { text } } }  fragment MobilePageSeries on Series { id title images { backdrop16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } } description genre ageRating { number } ratings { imdb { readableScore } } label webview { url } isRentalSeries }  fragment MobilePageEpisode on Episode { id title images { backdrop16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } screenshot16x9 { sourceNonEncoded } } descriptionLong price { readable } genre yearProduction { number } episodeNumber { number readable } seasonNumber { number readable } playback { __typename ...Playback } series { id title } ageRating { number } duration { readableShort } userData { progress { percent position } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) } } } store { name } }  fragment MobilePageSportEvent on SportEvent { id title playback { __typename ...Playback } images { backdrop16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } } availability { from { text timestamp } } descriptionLong genre badges { uhd { text } } productionCountries ageRating { number } duration { readableShort } store { name } league labels { airtime { text } } yearProduction { number } userData { progress { percent position } } venue }  fragment MobilePageMediaPanelContent on MediaPanelItemContent { __typename ... on Movie { __typename ...MobilePageMovie } ... on Series { __typename ...MobilePageSeries } ... on Episode { __typename ...MobilePageEpisode } ... on SportEvent { __typename ...MobilePageSportEvent } }  fragment MobileMediaPanel on MediaPanel { id title kicker displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } mediaContent(limit: $mediaContentLimit) { pageInfo { hasNextPage } items { media { __typename ...MobilePageMediaPanelContent } } } }  fragment MobileSelectionMediaPanel on SelectionMediaPanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } selectionMediaContent(config: { limit: $mediaContentLimit } ) { pageInfo { hasNextPage } items { media { __typename ...MobilePageMediaPanelContent } } } link { id type } }  fragment MobileSingleFeaturePanelMedia on SingleFeaturePanelMedia { __typename ... on Movie { __typename ...MobilePageMovie } ... on Series { __typename ...MobilePageSeries } ... on SportEvent { __typename ...MobilePageSportEvent } }  fragment MobileSingleFeaturePanel on SingleFeaturePanel { id title subtitle images { __typename ... on SingleFeaturePanelImages { promo16x9 { sourceNonEncoded } } } media { __typename ...MobileSingleFeaturePanelMedia } }  fragment MobilePageStore on Store { id __typename name icons { light { sourceNonEncoded } dark { sourceNonEncoded } } }  fragment MobileStoresPanel on StoresPanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } storesContent(limit: $mediaContentLimit) { pageInfo { hasNextPage } items { __typename ...MobilePageStore } } }'
    }

    response = send_req(url, post=True, json=json_data, headers=headers)
    if response:
        j_response = response.json()
        try:
            data = j_response['data']['page']['pagePanels']['items'][idx]
            items = None

            selection = data.get('selectionMediaContent')
            media = data.get('mediaContent')
            stores = data.get('storesContent')
            showcase = data.get('showcaseContent')

            if selection:
                items = selection.get('items')

            elif media:
                items = media.get('items')

            elif showcase:
                items = showcase.get('items')

            else:
                items = stores.get('items')

            if not items:
                xbmcgui.Dialog().notification(localized(30012), localized(30048))
                return

            get_items(items)

        except Exception as ex:
            print('kids Exception: {}'.format(ex))
            xbmcgui.Dialog().notification(localized(30012), localized(30048))
            return

def favourites():
    xbmc.executebuiltin("ActivateWindow(10134)")

def play(exlink, title, media_id, catchup_type, start, end):
    if exlink != 'vod':
        now = int(time.time())

        if int(now) >= int(start) and int(now) <= int(end):
            response = xbmcgui.Dialog().yesno(localized(30012), localized(30014))
            if response:
                exlink = media_id
                catchup_type = 'STARTOVER'
            else:
                catchup_type = 'LIVE'
        elif int(end) >= int(now):
            xbmcgui.Dialog().ok(localized(30012), localized(30028))
            return
        else:
            if media_id:
                exlink = media_id

    else:
        catchup_type = 'ONDEMAND'
        exlink = media_id

    strm_url, license_url = get_stream(exlink, catchup_type)

    PROTOCOL = 'mpd'
    DRM = 'com.widevine.alpha'

    import inputstreamhelper
    is_helper = inputstreamhelper.Helper(PROTOCOL, drm=DRM)
    if is_helper.check_inputstream():
        play_item = xbmcgui.ListItem(path=strm_url)
        play_item.setInfo( type="Video", infoLabels={ "Title": title, } )
        play_item.setContentLookup(False)
        play_item.setProperty('inputstream', is_helper.inputstream_addon)
        play_item.setMimeType('application/xml+dash')
        play_item.setProperty('inputstream.adaptive.license_type', DRM)
        play_item.setProperty('inputstream.adaptive.license_key', license_url)
        play_item.setProperty('inputstream.adaptive.stream_headers', 'Referer: https://www.teliaplay.se/&User-Agent='+quote(UA))
        play_item.setProperty('inputstream.adaptive.manifest_type', 'mpd')
        play_item.setProperty('IsPlayable', 'true')
        if catchup_type != 'LIVE':
            play_item.setProperty('inputstream.adaptive.play_timeshift_buffer', 'true')

        xbmcplugin.setResolvedUrl(addon_handle, True, listitem=play_item)


def pincode():
    j_response, pin_code = profile_data()

    res = xbmcgui.Dialog().yesno(localized(30012), localized(30043))
    if res:
        input_ = xbmcgui.Dialog().input(localized(30044), type=xbmcgui.INPUT_ALPHANUM, option=xbmcgui.ALPHANUM_HIDE_INPUT)
        if input_ == pin_code and input_ != '':
            addon.setSetting('teliaplay_childlock', 'false')
        else:
            addon.setSetting('teliaplay_childlock', 'true')
            xbmcgui.Dialog().notification(localized(30012), localized(30045))

def home():
    get_childmode = addon.getSetting('teliaplay_childlock')
    if get_childmode == 'true':
        childmode = True
    else:
        childmode = False

    profile_name = addon.getSetting('teliaplay_profile_name')
    profile_avatar = addon.getSetting('teliaplay_profile_avatar')
    if profile_name == '':
        profile_name = 'Telia Play'
        profile_avatar = icon

    login = login_service()

    if login and not childmode:
        add_item(label=localized(30009).format(profile_name), url='', mode='logged', icon=profile_avatar, fanart=fanart, folder=False, playable=False)
        add_item(label=localized(30010), url='', mode='channels', icon=tv_icon, fanart=fanart, folder=True, playable=False)
        add_item(label=localized(30011), url='', mode='video_on_demand', icon=vod_icon, fanart=fanart, folder=True, playable=False)
        add_item(label=localized(30039), url='', mode='sports_page', icon=sport_icon, fanart=fanart, folder=True, playable=False)
        add_item(label=localized(30040), url='', mode='kids_genre', icon=kids_icon, fanart=fanart, folder=True, playable=False)
        add_item(label=localized(30038), url='', mode='favourites', icon=fav_icon, fanart=fanart, folder=True, playable=False)
        add_item(label=localized(30055), url='', mode='settings', icon=settings_icon, fanart=fanart, folder=False, playable=False)
        add_item(label=localized(30032), url='', mode='search', icon=search_icon, fanart=fanart, folder=True, playable=False)

    elif login and childmode:
        add_item(label=localized(30009).format(profile_name), url='', mode='logged', icon=profile_avatar, fanart=fanart, folder=False, playable=False)
        add_item(label=localized(30040), url='', mode='kids_genre', icon=kids_icon, fanart=fanart, folder=True, playable=False)
        add_item(label=localized(30055), url='', mode='settings', icon=settings_icon, fanart=fanart, folder=False, playable=False)
        add_item(label=localized(30042), url='', mode='pincode', icon=lock_icon, fanart=fanart, folder=False, playable=False)

    else:
        add_item(label=localized(30008), url='', mode='login', icon=icon, fanart=fanart, folder=False, playable=False)

    xbmcplugin.endOfDirectory(addon_handle)

def profile_data():
    profile = ''

    beartoken = addon.getSetting('teliaplay_beartoken')
    tv_client_boot_id = addon.getSetting('teliaplay_tv_client_boot_id')

    url = 'https://graphql-telia.t6a.net/graphql'

    headers = {
        'authority': 'graphql-telia.t6a.net',
        'accept': '*/*',
        'accept-language': 'sv,en;q=0.9,en-GB;q=0.8,en-US;q=0.7,pl;q=0.6,fr;q=0.5',
        'authorization': 'Bearer ' + beartoken,
        'content-type': 'application/json',
        'dnt': '1',
        'origin': base[country],
        'referer': base[country]+'/',
        'tv-client-boot-id': tv_client_boot_id,
        'tv-client-browser': 'Microsoft Edge',
        'tv-client-browser-version': '101.0.1210.39',
        'tv-client-name': 'web',
        'tv-client-os-name': 'Windows',
        'tv-client-os-version': 'NT 10.0',
        'tv-client-tz': 'Europe/Stockholm',
        'tv-client-version': '1.46.0',
        'user-agent': UA,
        'x-country': ca[country],
    }

    params = {
        'operationName': 'getUserProfileInfo',

        'variables': {},

        'query': 'query getUserProfileInfo { user { name childLock { enabled pinCode } profiles { id alias ageGroup isCurrent avatar { __typename ...Avatar } theme { __typename ...Theme } } } }  fragment Avatar on Avatar { id head { sourceNonEncoded } body { sourceNonEncoded } }  fragment Theme on Theme { id topImageUrl topSquareImageUrl shadowImageUrl colors { primary secondary background panelTitle } }'
    }

    response = send_req(url, params=params, headers=headers)
    if response:
        j_response = response.json()
        data = j_response['data']['user']

        child_lock = data.get('childLock')
        if child_lock:
            lock = child_lock.get('enabled')
            addon.setSetting('teliaplay_childlock', str(lock).lower())

            pin_code = child_lock.get('pinCode')
            if pin_code:
                pin_code = str(pin_code)

            adult_enabled = addon.getSetting('teliaplay_adult_enabled')
            if adult_enabled == 'true':
                adult = True
            else:
                adult = False

            pin_code_ = addon.getSetting('teliaplay_pincode')

            if pin_code == pin_code_ and pin_code_ != '' and adult:
                addon.setSetting('teliaplay_childlock', 'false')

        return j_response, pin_code

def profiles(j_response):
    data = j_response['data']['user']

    profiles = []

    for item in data['profiles']:
        profile = item['alias']
        avatar = item['avatar']['head']['sourceNonEncoded']
        profiles.append((profile, avatar))

    items = []
    for item in profiles:

        list_item = xbmcgui.ListItem(item[0])
        list_item.setArt({'poster': str(item[1]), 'icon': str(item[1])})
        items.append(list_item)

    ret = xbmcgui.Dialog().select('Profile', list(items), useDetails=True)
    if ret < 0:
        return

    profile = profiles[ret]

    addon.setSetting('teliaplay_profile_name', profile[0])
    addon.setSetting('teliaplay_profile_avatar', profile[-1]) 

def router(param):
    args = dict(urlparse.parse_qsl(param))
    if args:
        mode = args.get('mode', None)

        if mode == 'play':
            play(exlink, extitle, exid, excatchup, exstart, exend)

        elif mode == 'programs':
            live_channel(exlink, extitle)

        elif mode == 'channels':
            live_channels()

        elif mode == 'video_on_demand':
            video_on_demand()

        elif mode == 'vod_genre_movies':
            movies = 'movie-corner'
            vod_genre(movies)

        elif mode == 'vod_genre_series':
            series = 'program-series-corner'
            vod_genre(series)

        elif mode == 'vod':
            vod(exlink)

        elif mode == 'seasons':
            vod_seasons(exid)

        elif mode == 'episodes':
            vod_episodes(exlink, exid)

        elif mode == 'sports_page':
            sports_page()

        elif mode == 'sports_table_genre':
            sports_genre()

        elif mode == 'sports_table':
            sports(exlink)

        elif mode == 'sports_corner_genre':
            sports_corner_genre()

        elif mode == 'sports_corner':
            sports_corner(exlink)

        elif mode == 'kids_genre':
            kids_genre()

        elif mode == 'kids':
            kids(exlink)

        elif mode == 'favourites':
            favourites()

        elif mode == 'search':
            query = vod_search()
            search(query)

        elif mode == 'ext':
            c_ext_info()

        elif mode == 'settings':
            addon.openSettings()
            xbmc.executebuiltin('Container.Refresh()')

        elif mode == 'login':
            addon.openSettings()
            xbmc.executebuiltin('Container.Refresh()')

        elif mode == 'logged':
            j_response, pin_code = profile_data()
            profiles(j_response)
            xbmc.executebuiltin('Container.Refresh()')

        elif mode == 'pincode':
            pincode()
            xbmc.executebuiltin('Container.Refresh()')

    else:
        home()

if __name__ == '__main__':
    router(sys.argv[2][1:])