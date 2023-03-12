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

import iso8601
import re
import six
import time
import uuid

from ext import c_ext_info

base_url = sys.argv[0]
addon_handle = int(sys.argv[1])
params = dict(urlparse.parse_qsl(sys.argv[2][1:]))
addon = xbmcaddon.Addon(id='plugin.video.teliaplay')

exlink = params.get('url', '')
extitle = params.get('title', '')
exid = params.get('media_id', '')
excatchup = params.get('catchup', '')
exstart = params.get('start', '')
exend = params.get('end', '')
exlabels = params.get('info_labels', '')

profile_path = xbmcvfs.translatePath(addon.getAddonInfo('profile'))

localized = xbmcaddon.Addon().getLocalizedString
x_localized = xbmc.getLocalizedString

path = addon.getAddonInfo('path')
resources = os.path.join(path, 'resources')
icons = os.path.join(resources, 'icons')

thumb = os.path.join(path, 'icon.png')
poster = os.path.join(path, 'icon.png')
banner = os.path.join(resources, 'banner.jpg')
clearlogo = os.path.join(resources, 'clearlogo.png')
fanart = os.path.join(resources, 'fanart.jpg')
icon = os.path.join(path, 'icon.png')

live_icon = os.path.join(icons, 'live.png')
tv_icon = os.path.join(icons, 'tv.png')
vod_icon = os.path.join(icons, 'vod.png')
sport_icon = os.path.join(icons, 'sport.png')
kids_icon = os.path.join(icons, 'kids.png')
fav_icon = os.path.join(icons, 'fav.png')
search_icon = os.path.join(icons, 'search.png')
lock_icon = os.path.join(icons, 'lock.png')
settings_icon = os.path.join(icons, 'settings.png')

catchup_msg = addon.getSetting('teliaplay_play_beginning')
if catchup_msg == 'true':
    play_beginning = True
else:
    play_beginning = False

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

def build_url(query):
    query = {k: v for k, v in query.items() if v != ''}
    return base_url + '?' + urlencode(query)

def add_item(label, url, mode, folder, playable, media_id='', catchup='', start='', end='', plot='', thumb=None, poster=None, banner=None, clearlogo=None, icon=None, fanart=None, context_menu=None, item_count=None, info_labels=False, page=0):
    if not info_labels:
        info_labels = {'title': label}

    title = info_labels.get('title')

    list_item = xbmcgui.ListItem(label=title)

    if playable:
        list_item.setProperty('IsPlayable', 'true')

        if context_menu:
            info = x_localized(19047)
            context_menu.insert(0, (info, 'Action(Info)'))

    else:
        list_item.setProperty('IsPlayable', 'false')

    if context_menu:
        list_item.addContextMenuItems(context_menu, replaceItems=True)

    list_item.setInfo(type='Video', infoLabels=info_labels)

    thumb = thumb if thumb else icon
    poster = poster if poster else icon
    banner = banner if banner else icon
    clearlogo = clearlogo if clearlogo else icon
    fanart = fanart if fanart else icon

    if not icon:
        icon = ''

    list_item.setArt({'thumb': thumb, 'poster': poster, 'banner': banner, 'fanart': fanart, 'clearlogo': clearlogo})

    xbmcplugin.addDirectoryItem(
        handle=addon_handle,
        url=build_url({'title': title, 'mode': mode, 'url': url, 'media_id': media_id, 'catchup': catchup, 'start': start, 'end': end, 'info_labels': info_labels}),
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
    login = True

    valid_to = addon.getSetting('teliaplay_validto')
    beartoken = addon.getSetting('teliaplay_beartoken')
    refrtoken = addon.getSetting('teliaplay_refrtoken')
    cookies = addon.getSetting('teliaplay_cookies')

    refresh = refresh_timedelta(valid_to)

    if not beartoken or refresh < timedelta(minutes=1):
        login = login_data(reconnect=False)

    return login

def refresh_timedelta(valid_to):
    result = None

    if 'Z' in str(valid_to):
        valid_to = iso8601.parse_date(valid_to)
    elif valid_to:
        if 'T' in str(valid_to):
            try:
                date_time_format = '%Y-%m-%dT%H:%M:%S.%f+' + valid_to.split('+')[1]
            except:
                date_time_format = '%Y-%m-%dT%H:%M:%S.%f+' + valid_to.split('+')[0]

            valid_to = datetime(*(time.strptime(valid_to, date_time_format)[0:6]))
            timestamp = int(time.mktime(valid_to.timetuple()))
            token_valid_to = datetime.fromtimestamp(int(timestamp))
        else:
            token_valid_to = valid_to
    else:
        token_valid_to = datetime.now()

    result = token_valid_to - datetime.now()

    return result

def login_service():
    try:
        login = False

        dashjs = addon.getSetting('teliaplay_devush')
        valid_to = addon.getSetting('teliaplay_validto')
        if (dashjs == '' or valid_to == ''):
            try:
                msg = localized(30000)
                xbmcgui.Dialog().ok(localized(30012), str(msg))
            except:
                pass

            create_data()
            login = login_data(reconnect=False)

        else:
            login = check_login()

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
            'host': 'log.tvoip.telia.com:6003',
            'user-agent': UA,
            'content-type': 'text/plain;charset=UTF-8',
            'accept': '*/*',
            'origin': base[country],
            'referer': referer[country],
            'accept-language': 'en-US,en;q=0.9',
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
            'dnt': '1',
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
            return False

        j_response = response.json()
        code = j_response['redirectUri'].replace('https://www.teliaplay.{cc}/?code='.format(cc=cc[country]), '')

        url = 'https://logingateway-telia.clientapi-prod.live.tv.telia.net/logingateway/rest/v1/oauth/token'

        headers = {
            'accept-language': 'sv,en;q=0.9,en-GB;q=0.8,en-US;q=0.7,pl;q=0.6,fr;q=0.5',
            'dnt': '1',
            'origin': base[country],
            'referer': referer[country],
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
                login_data(reconnect=True, retry=retry)
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

        validTo = j_response.get('validTo', '')
        addon.setSetting('teliaplay_validto', str(validTo))

        beartoken = j_response.get('accessToken', '')
        addon.setSetting('teliaplay_beartoken', str(beartoken))

        refrtoken = j_response.get('refreshToken', '')
        addon.setSetting('teliaplay_refrtoken', str(refrtoken))

        url = 'https://ottapi.prod.telia.net/web/{cc}/tvclientgateway/rest/secure/v1/provision'.format(cc=cc[country])

        headers = {
            'host': 'ottapi.prod.telia.net',
            'authorization': 'Bearer ' + beartoken,
            'if-modified-since': '0',
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
                if reconnect and retry < 1:
                    retry += 1
                    login_data(reconnect=True, retry=retry)
                else:
                    return False

            elif response['errorCode'] == 9030:
                print('errorCode 9030')
                if not reconnect:
                    xbmcgui.Dialog().notification(localized(30012), localized(30006))
                addon.setSetting('teliaplay_sess_id', '')
                addon.setSetting('teliaplay_devush', '')
                if reconnect and retry < 1:
                    retry += 1
                    login_data(reconnect=True, retry=retry)
                else:
                    return False

            elif response['errorCode'] == 61002:
                print('errorCode 61002')
                if not reconnect:
                    xbmcgui.Dialog().notification(localized(30012), localized(30006))
                tv_client_boot_id = str(uuid.uuid4())
                addon.setSetting('teliaplay_tv_client_boot_id', str(tv_client_boot_id))
                if reconnect and retry < 1:
                    retry += 1
                    login_data(reconnect=True, retry=retry)
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
            if reconnect and retry < 3:
                retry += 1
                login_data(reconnect=True, retry=retry)
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
    login = check_login()
    if not login:
        login_data(reconnect=False)

    add_item(label=localized(30030), url='', mode='vod_genre_movies', icon=icon, fanart=fanart, folder=True, playable=False)
    add_item(label=localized(30031), url='', mode='vod_genre_series', icon=icon, fanart=fanart, folder=True, playable=False)

    xbmcplugin.endOfDirectory(addon_handle)

def vod_genre(genre):
    beartoken = addon.getSetting('teliaplay_beartoken')
    tv_client_boot_id = addon.getSetting('teliaplay_tv_client_boot_id')

    genres = []

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
            'mediaContentLimit': 60,
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

            items = None

            title = item['title']

            selection = item.get('selectionMediaContent')
            media = item.get('mediaContent')
            stores = item.get('storesContent')
            showcase = item.get('showcaseContent')

            if selection:
                items = selection.get('items')

            elif media:
                items = media.get('items')

            elif showcase:
                items = showcase.get('items')
                if not title:
                    title = localized(30066)

            elif stores:
                items = stores.get('items')

            if items:
                genres.append((key, title))

        for gen in genres:
            add_item(label=gen[1], url=str(gen[0])+'|'+genre, mode='vod', icon=icon, fanart=fanart, folder=True, playable=False)

    xbmcplugin.endOfDirectory(addon_handle)

def store(store_id):
    idx = int(store_id.split('|')[0])
    store = store_id.split('|')[-1]

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
        'operationName': 'getMobileStore',
        'variables': {
            'mediaContentLimit': 60,
            'id': store
        },

        'query': 'query getMobileStore($id: String!, $mediaContentLimit: Int!, $offset: Int) { store(id: $id) { id name pagePanels { items { __typename title id ...MobileSelectionMediaPanel ...MobileMediaPanel ...MobileStoresPanel ...MobileRentalsPanel ...MobileTimelinePanel ...MobileShowcasePanel ...MobileContinueWatchingPanel ...MobileMyListPanel ...MobilePageLinkPanel ...MobileSingleFeaturePanel } } } }  fragment PlaybackSpec on PlaybackSpec { accessControl videoId videoIdType watchMode }  fragment Vod on Vod { audioLang { name code } playbackSpec { __typename ...PlaybackSpec } price { readable } validFrom { timestamp readableDistance(type: FUZZY) } validTo { timestamp } }  fragment Linear on PlaybackPlayLinear { item { startover { playbackSpec { __typename ...PlaybackSpec } } playbackSpec { __typename ...PlaybackSpec } startTime { timestamp readableDistance(type: FUZZY) } endTime { timestamp } } }  fragment Rental on PlaybackPlayVodRental { item { __typename ...Vod } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) sTo } } }  fragment Recording on PlaybackPlayRecording { item { playbackSpec { __typename ...PlaybackSpec } audioLang { name code } validFrom { timestamp } validTo { timestamp } } startover { playbackSpec { __typename ...PlaybackSpec } } }  fragment DeepLink on DeepLink { uri serviceName googlePlayStoreId validFrom { timestamp } validTo { timestamp } }  fragment SubscriptionProductStandard on SubscriptionProductStandard { id price { readable } }  fragment SubscriptionProductDualEntry on SubscriptionProductDualEntry { id }  fragment SubscriptionProductTVE on SubscriptionProductTVE { id }  fragment SubscriptionProductFallback on SubscriptionProductFallback { id }  fragment Playback on Playback { play { subscription { item { __typename ...Vod } } linear { __typename ...Linear } rental { __typename ...Rental } npvr { __typename ...Recording } deepLinks { item { __typename ...DeepLink } } } buy { subscriptions { item { __typename id name ...SubscriptionProductStandard ...SubscriptionProductDualEntry ...SubscriptionProductTVE ...SubscriptionProductFallback } } rental { item { price { readable } validFrom { timestamp } validTo { timestamp } } } npvr { item { playbackSpec { __typename ...PlaybackSpec } } } deepLinks { item { __typename ...DeepLink } } } }  fragment MobilePageMovie on Movie { id title playback { __typename ...Playback } images { backdrop16x9 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } } descriptionLong price { readable } genre yearProduction { number } ageRating { readable } duration { readableShort } ratings { imdb { readableScore } } productionCountries userData { progress { percent position } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) } } } store { name } availability { from { text } } availableNow labels { premiereAnnouncement { text } } }  fragment MobilePageSeries on Series { id title images { backdrop16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } } description genre ageRating { readable } ratings { imdb { readableScore } } label webview { url } isRentalSeries }  fragment MobilePageEpisode on Episode { id title images { backdrop16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } screenshot16x9 { sourceNonEncoded } } descriptionLong price { readable } genre yearProduction { number } episodeNumber { number readable } seasonNumber { number readable } playback { __typename ...Playback } series { id title } ageRating { readable } duration { readableShort } userData { progress { percent position } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) } } } store { name } }  fragment MobilePageSportEvent on SportEvent { id title playback { __typename ...Playback } images { backdrop16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } } availability { from { text timestamp } } descriptionLong genre badges { uhd { text } } productionCountries ageRating { readable } duration { readableShort } store { name } league labels { airtime { text } } yearProduction { number } userData { progress { percent position } } venue }  fragment MobilePageMediaPanelContent on MediaPanelItemContent { __typename ... on Movie { __typename ...MobilePageMovie } ... on Series { __typename ...MobilePageSeries } ... on Episode { __typename ...MobilePageEpisode } ... on SportEvent { __typename ...MobilePageSportEvent } }  fragment MobileSelectionMediaPanel on SelectionMediaPanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } ... on DisplayHintList { listSubType } ... on DisplayHintGrid { gridSubType } } selectionMediaContent(config: { limit: $mediaContentLimit offset: $offset } ) { pageInfo { hasNextPage nextPageOffset } items { media { __typename ...MobilePageMediaPanelContent } } } link { id type } }  fragment MobileMediaPanel on MediaPanel { id title kicker displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } ... on DisplayHintList { listSubType } ... on DisplayHintGrid { gridSubType } } mediaContent(limit: $mediaContentLimit, offset: $offset) { pageInfo { hasNextPage nextPageOffset } items { media { __typename ...MobilePageMediaPanelContent } } } }  fragment MobilePageStore on Store { id __typename name icons { light { sourceNonEncoded } dark { sourceNonEncoded } } }  fragment MobileStoresPanel on StoresPanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } ... on DisplayHintGrid { gridSubType } ... on DisplayHintList { listSubType } } storesContent(limit: $mediaContentLimit, offset: $offset) { pageInfo { hasNextPage nextPageOffset } items { __typename ...MobilePageStore } } }  fragment MobileRentalsPanelItemContent on RentalsPanelItemContent { __typename ... on Movie { __typename ...MobilePageMovie } ... on Series { __typename ...MobilePageSeries } }  fragment MobileRentalsPanel on RentalsPanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } rentalsContent(limit: $mediaContentLimit, offset: $offset) { pageInfo { hasNextPage nextPageOffset } items { media { __typename ...MobileRentalsPanelItemContent } } } }  fragment MobileTimeLinePanelItemContent on TimelinePanelItemContent { __typename ... on Movie { __typename ...MobilePageMovie } ... on Episode { __typename ...MobilePageEpisode } ... on SportEvent { __typename ...MobilePageSportEvent } }  fragment MobileTimelinePanel on TimelinePanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } timelineContent(limit: $mediaContentLimit, offset: $offset) { pageInfo { hasNextPage nextPageOffset } items { media { __typename ...MobileTimeLinePanelItemContent } startTime { timestamp isoString } endTime { timestamp isoString } } } }  fragment Store on Store { name icons { dark { sourceNonEncoded } } }  fragment MobileShowcaseMovie on Movie { id title userData { progress { position } favorite } images { backdrop16x9 { sourceNonEncoded } } playback { __typename ...Playback } store { __typename ...Store } }  fragment MobileShowcaseEpisode on Episode { id title userData { progress { position } favorite } images { backdrop16x9 { sourceNonEncoded } } playback { __typename ...Playback } series { id } store { __typename ...Store } }  fragment MobileShowcaseSeries on Series { id title userData { favorite } images { backdrop16x9 { sourceNonEncoded } } webview { url } suggestedEpisode { id playback { __typename ...Playback } } store { __typename ...Store } }  fragment MobileShowcaseSportEvent on SportEvent { id title userData { progress { position } favorite } images { backdrop16x9 { sourceNonEncoded } } playback { __typename ...Playback } store { __typename ...Store } }  fragment ChannelPlayback on ChannelPlayback { play { playbackSpec { __typename ...PlaybackSpec } } buy { subscriptions { item { id } } } }  fragment MobileShowcaseChannel on Channel { channelPlayback: playback { __typename ...ChannelPlayback } }  fragment MobileShowcasePanel on ShowcasePanel { id title showcaseContent { items { id showcaseTitle { text } kicker images { showcase16x9 { sourceNonEncoded } showcase16x7 { sourceNonEncoded } showcase7x10 { sourceNonEncoded } showcase2x3 { sourceNonEncoded } } promotion { link { id type } content { __typename ...MobileShowcaseMovie ...MobileShowcaseEpisode ...MobileShowcaseSeries ...MobileShowcaseSportEvent ...MobileShowcaseChannel } } } } }  fragment MobileContinueWatchingPanelItemContent on ContinueWatchingPanelItemContent { __typename ... on Movie { __typename ...MobilePageMovie } ... on Episode { __typename ...MobilePageEpisode } ... on SportEvent { __typename ...MobilePageSportEvent } }  fragment MobileContinueWatchingPanel on ContinueWatchingPanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } continueWatchingContent { items { media { __typename ...MobileContinueWatchingPanelItemContent } } } }  fragment MobileMyListPanelItemContent on MyListPanelItemContent { __typename ... on Movie { __typename ...MobilePageMovie } ... on Series { __typename ...MobilePageSeries } ... on SportEvent { __typename ...MobilePageSportEvent } }  fragment MobileMyListPanel on MyListPanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } myListContent(limit: $mediaContentLimit) { pageInfo { hasNextPage nextPageOffset } items { media { __typename ...MobileMyListPanelItemContent } } } }  fragment MobilePageLinkPanel on PageLinkPanel { id title pageLinkContent { items { id name description type images { icon1x1 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } } } } }  fragment MobileSingleFeaturePanelMedia on SingleFeaturePanelMedia { __typename ... on Movie { __typename ...MobilePageMovie } ... on Series { __typename ...MobilePageSeries } ... on SportEvent { __typename ...MobilePageSportEvent } }  fragment MobileSingleFeaturePanel on SingleFeaturePanel { id title subtitle images { __typename ... on SingleFeaturePanelImages { promo16x9 { sourceNonEncoded } } } media { __typename ...MobileSingleFeaturePanelMedia } }'
    }

    response = send_req(url, post=True, json=json, headers=headers)
    if response:
        j_response = response.json()
        try:
            data = j_response['data']['store']['pagePanels']['items'][idx]
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

            elif stores:
                items = stores.get('items')

            if not items:
                xbmcgui.Dialog().notification(localized(30012), localized(30048))
                return

            get_items(items)

        except Exception as ex:
            print('vod Exception: {}'.format(ex))
            xbmcgui.Dialog().notification(localized(30012), localized(30048))
            return

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
            'mediaContentLimit': 60,
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

            elif stores:
                items = stores.get('items')

            if not items:
                xbmcgui.Dialog().notification(localized(30012), localized(30048))
                return

            get_items(items)

        except Exception as ex:
            print('vod Exception: {}'.format(ex))
            xbmcgui.Dialog().notification(localized(30012), localized(30048))
            return

def get_items(data, mode=None, thumb=thumb, poster=poster, banner=banner, clearlogo=clearlogo, icon=icon, fanart=fanart):
    titles = set()
    count = 0

    for item in data:
        media = item.get('media')
        if not media:
            media = item

        if media:
            media_id = None
            typename = media.get('__typename')

            promo = media.get('promotion')
            if promo:
                content = promo.get('content')
                if content:
                    media_id = content.get('id')
                    typename = content.get('__typename')

            type_ = media.get('type')

            url = 'vod'

            if typename == 'Movie':
                mode = 'play'
                folder = False
                playable = True

            elif typename == 'Series':
                mode = 'seasons'
                folder = True
                playable = False

            elif typename == 'SportEvent':
                mode = 'play'
                folder = False
                playable = True

            elif typename == 'Store':
                mode = 'vod_store'
                folder = True
                playable = False

            else:
                folder = True
                playable = False

                if not mode:
                    mode = 'play'
                    folder = False
                    playable = True

            label = media.get('title')
            if not label:
                label = media.get('name')
                if not label:
                    showcase_title = media.get('showcaseTitle')
                    if showcase_title:
                        label = showcase_title.get('text')

            genre = media.get('genre')

            title = label

            timestamp = None

            start = item.get('startTime')
            if start:
                timestamp = start.get('timestamp')

            else:
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
                if os.name == 'nt':
                    da_start = dt_start.strftime('%A %#d/%#m %H:%M')
                else:
                    da_start = dt_start.strftime('%A %-d/%-m %H:%M')

                if da_start != '00:00':
                    title = label + ' [COLOR grey]({0})[/COLOR]'.format(da_start)

            outline = media.get('description')
            plot = media.get('descriptionLong')
            if not plot:
                plot = outline

            date = ''
            year = media.get('yearProduction')
            if year:
                date = year.get('readable')

            age = ''
            age_rating = media.get('ageRating')
            if age_rating:
                age = age_rating.get('readable')

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

            if not media_id:
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

            images = media.get('images')
            if images:
                card_1x1 = images.get('icon1x1') if images.get('icon1x1') else images.get('icon1x1')
                if card_1x1:
                    src = card_1x1.get('sourceNonEncoded')
                    if not src:
                        src = card_1x1.get('source')
                    if src:
                        poster = unquote(src)
                else:
                    poster = fanart

                card_2x3 = images.get('showcard2x3') if images.get('showcard2x3') else images.get('showcase2x3')
                if card_2x3:
                    src = card_2x3.get('sourceNonEncoded')
                    if not src:
                        src = card_2x3.get('source')
                    if src:
                        poster = unquote(src)
                else:
                    poster = fanart

                card_16x9 = images.get('showcard16x9') if images.get('showcard16x9') else images.get('showcase16x9')
                if card_16x9:
                    src = card_16x9.get('sourceNonEncoded')
                    if not src:
                        src = card_16x9.get('source')
                    if src:
                        poster = unquote(src)
                else:
                    poster = fanart

            else:
                icons = media.get('icons')
                if icons:
                    poster = icons.get('dark').get('sourceNonEncoded')
                    plot = typename
                else:
                    poster = fanart

            ext = localized(30027)
            context_menu = [('{0}'.format(ext), 'RunScript(plugin.video.teliaplay,0,?mode=ext,label={0})'.format(title))]

            #xbmcplugin.addSortMethod(addon_handle, sortMethod=xbmcplugin.SORT_METHOD_TITLE, label2Mask = "%R, %Y, %P")

            if title not in titles:
                count += 1
                add_item(label=label, url=url, mode=mode, media_id=media_id, folder=folder, playable=playable, info_labels={'title': title, 'sorttitle': title, 'originaltitle': title, 'plot': plot, 'plotoutline': outline, 'aired': date, 'dateadded': date, 'duration': duration, 'genre': genre, 'userrating': rating, 'mpaa': age}, icon=icon, poster=poster, fanart=fanart, context_menu=context_menu, item_count=count)
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

        except Exception as ex:
            print('vod seasons Exception: {}'.format(ex))
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

        except Exception as ex:
            print('vod episodes Exception: {}'.format(ex))
            xbmcgui.Dialog().notification(localized(30012), localized(30048))
            return

        count = 0

        for item in items:
            count += 1

            season_num = item['seasonNumber']['number']

            if int(season) == int(season_num):
                label = item.get('title')
                media_id = item.get('id')

                episode_raw = item.get('episodeNumber')
                if episode_raw:
                    episode_read = str(episode_raw['readable'])
                    nr_pattern = re.compile(r'(\d+)')
                    r = nr_pattern.search(episode_read)
                    episode_nr = r.group(1) if r else ''
                else:
                    episode_nr = ''

                season_raw = item.get('seasonNumber')
                if season_raw:
                    season_read = str(season_raw['readable'])
                    nr_pattern = re.compile(r'(\d+)')
                    r = nr_pattern.search(season_read)
                    season_nr = r.group(1) if r else ''
                else:
                    season_nr = ''

                title = episode_read

                plot = item.get('descriptionLong')
                directors = item.get('directors')

                actors_lst = []
                actors = item.get('actors')
                if actors:
                    actors_lst = actors.split(',')

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
                    else:
                        poster = fanart

                    icon = ''
                    card_16x9 = images.get('showcard16x9')
                    if card_16x9:
                        src = card_16x9.get('sourceNonEncoded')
                        if not src:
                            src = card_16x9.get('source')
                        if src:
                            icon = unquote(src)
                    else:
                        poster = fanart

                ext = localized(30027)
                context_menu = [('{0}'.format(ext), 'RunScript(plugin.video.teliaplay,0,?mode=ext,label={0})'.format(label))]

                add_item(label=label, url='vod', mode='play', media_id=media_id, folder=False, playable=True, info_labels={'title': title, 'sorttitle': title, 'originaltitle': title, 'plot': plot, 'genre': genre, 'director': directors, 'cast': actors_lst, 'sortepisode': episode_nr, 'sortseason': season_nr, 'mpaa': age, 'year': date}, icon=icon, poster=poster, fanart=fanart, context_menu=context_menu, item_count=count)

    xbmcplugin.setContent(addon_handle, 'sets')
    xbmcplugin.endOfDirectory(addon_handle)

def vod_store(store_id):
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
        'operationName': 'getMobileStore',

        'variables': {
            'id': store_id,
            'mediaContentLimit': 60,
        },

        'query': 'query getMobileStore($id: String!, $mediaContentLimit: Int!, $offset: Int) { store(id: $id) { id name pagePanels { items { __typename title id ...MobileSelectionMediaPanel ...MobileMediaPanel ...MobileStoresPanel ...MobileRentalsPanel ...MobileTimelinePanel ...MobileShowcasePanel ...MobileContinueWatchingPanel ...MobileMyListPanel ...MobilePageLinkPanel ...MobileSingleFeaturePanel } } } }  fragment PlaybackSpec on PlaybackSpec { accessControl videoId videoIdType watchMode }  fragment Vod on Vod { audioLang { name code } playbackSpec { __typename ...PlaybackSpec } price { readable } validFrom { timestamp readableDistance(type: FUZZY) } validTo { timestamp } }  fragment Linear on PlaybackPlayLinear { item { startover { playbackSpec { __typename ...PlaybackSpec } } playbackSpec { __typename ...PlaybackSpec } startTime { timestamp readableDistance(type: FUZZY) } endTime { timestamp } } }  fragment Rental on PlaybackPlayVodRental { item { __typename ...Vod } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) sTo } } }  fragment Recording on PlaybackPlayRecording { item { playbackSpec { __typename ...PlaybackSpec } audioLang { name code } validFrom { timestamp } validTo { timestamp } } startover { playbackSpec { __typename ...PlaybackSpec } } }  fragment DeepLink on DeepLink { uri serviceName googlePlayStoreId validFrom { timestamp } validTo { timestamp } }  fragment SubscriptionProductStandard on SubscriptionProductStandard { id price { readable } }  fragment SubscriptionProductDualEntry on SubscriptionProductDualEntry { id }  fragment SubscriptionProductTVE on SubscriptionProductTVE { id }  fragment SubscriptionProductFallback on SubscriptionProductFallback { id }  fragment Playback on Playback { play { subscription { item { __typename ...Vod } } linear { __typename ...Linear } rental { __typename ...Rental } npvr { __typename ...Recording } deepLinks { item { __typename ...DeepLink } } } buy { subscriptions { item { __typename id name ...SubscriptionProductStandard ...SubscriptionProductDualEntry ...SubscriptionProductTVE ...SubscriptionProductFallback } } rental { item { price { readable } validFrom { timestamp } validTo { timestamp } } } npvr { item { playbackSpec { __typename ...PlaybackSpec } } } deepLinks { item { __typename ...DeepLink } } } }  fragment MobilePageMovie on Movie { id title playback { __typename ...Playback } images { backdrop16x9 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } } descriptionLong price { readable } genre yearProduction { number } ageRating { readable } duration { readableShort } ratings { imdb { readableScore } } productionCountries userData { progress { percent position } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) } } } store { name } availability { from { text } } availableNow labels { premiereAnnouncement { text } } }  fragment MobilePageSeries on Series { id title images { backdrop16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } } description genre ageRating { readable } ratings { imdb { readableScore } } label webview { url } isRentalSeries }  fragment MobilePageEpisode on Episode { id title images { backdrop16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } screenshot16x9 { sourceNonEncoded } } descriptionLong price { readable } genre yearProduction { number } episodeNumber { number readable } seasonNumber { number readable } playback { __typename ...Playback } series { id title } ageRating { readable } duration { readableShort } userData { progress { percent position } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) } } } store { name } }  fragment MobilePageSportEvent on SportEvent { id title playback { __typename ...Playback } images { backdrop16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } } availability { from { text timestamp } } descriptionLong genre badges { uhd { text } } productionCountries ageRating { readable } duration { readableShort } store { name } league labels { airtime { text } } yearProduction { number } userData { progress { percent position } } venue }  fragment MobilePageMediaPanelContent on MediaPanelItemContent { __typename ... on Movie { __typename ...MobilePageMovie } ... on Series { __typename ...MobilePageSeries } ... on Episode { __typename ...MobilePageEpisode } ... on SportEvent { __typename ...MobilePageSportEvent } }  fragment MobileSelectionMediaPanel on SelectionMediaPanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } ... on DisplayHintList { listSubType } ... on DisplayHintGrid { gridSubType } } selectionMediaContent(config: { limit: $mediaContentLimit offset: $offset } ) { pageInfo { hasNextPage nextPageOffset } items { media { __typename ...MobilePageMediaPanelContent } } } link { id type } }  fragment MobileMediaPanel on MediaPanel { id title kicker displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } ... on DisplayHintList { listSubType } ... on DisplayHintGrid { gridSubType } } mediaContent(limit: $mediaContentLimit, offset: $offset) { pageInfo { hasNextPage nextPageOffset } items { media { __typename ...MobilePageMediaPanelContent } } } }  fragment MobilePageStore on Store { id __typename name icons { light { sourceNonEncoded } dark { sourceNonEncoded } } }  fragment MobileStoresPanel on StoresPanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } ... on DisplayHintGrid { gridSubType } ... on DisplayHintList { listSubType } } storesContent(limit: $mediaContentLimit, offset: $offset) { pageInfo { hasNextPage nextPageOffset } items { __typename ...MobilePageStore } } }  fragment MobileRentalsPanelItemContent on RentalsPanelItemContent { __typename ... on Movie { __typename ...MobilePageMovie } ... on Series { __typename ...MobilePageSeries } }  fragment MobileRentalsPanel on RentalsPanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } rentalsContent(limit: $mediaContentLimit, offset: $offset) { pageInfo { hasNextPage nextPageOffset } items { media { __typename ...MobileRentalsPanelItemContent } } } }  fragment MobileTimeLinePanelItemContent on TimelinePanelItemContent { __typename ... on Movie { __typename ...MobilePageMovie } ... on Episode { __typename ...MobilePageEpisode } ... on SportEvent { __typename ...MobilePageSportEvent } }  fragment MobileTimelinePanel on TimelinePanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } timelineContent(limit: $mediaContentLimit, offset: $offset) { pageInfo { hasNextPage nextPageOffset } items { media { __typename ...MobileTimeLinePanelItemContent } startTime { timestamp isoString } endTime { timestamp isoString } } } }  fragment Store on Store { name icons { dark { sourceNonEncoded } } }  fragment MobileShowcaseMovie on Movie { id title userData { progress { position } favorite } images { backdrop16x9 { sourceNonEncoded } } playback { __typename ...Playback } store { __typename ...Store } }  fragment MobileShowcaseEpisode on Episode { id title userData { progress { position } favorite } images { backdrop16x9 { sourceNonEncoded } } playback { __typename ...Playback } series { id } store { __typename ...Store } }  fragment MobileShowcaseSeries on Series { id title userData { favorite } images { backdrop16x9 { sourceNonEncoded } } webview { url } suggestedEpisode { id playback { __typename ...Playback } } store { __typename ...Store } }  fragment MobileShowcaseSportEvent on SportEvent { id title userData { progress { position } favorite } images { backdrop16x9 { sourceNonEncoded } } playback { __typename ...Playback } store { __typename ...Store } }  fragment ChannelPlayback on ChannelPlayback { play { playbackSpec { __typename ...PlaybackSpec } } buy { subscriptions { item { id } } } }  fragment MobileShowcaseChannel on Channel { channelPlayback: playback { __typename ...ChannelPlayback } }  fragment MobileShowcasePanel on ShowcasePanel { id title showcaseContent { items { id showcaseTitle { text } kicker images { showcase16x9 { sourceNonEncoded } showcase16x7 { sourceNonEncoded } showcase7x10 { sourceNonEncoded } showcase2x3 { sourceNonEncoded } } promotion { link { id type } content { __typename ...MobileShowcaseMovie ...MobileShowcaseEpisode ...MobileShowcaseSeries ...MobileShowcaseSportEvent ...MobileShowcaseChannel } } } } }  fragment MobileContinueWatchingPanelItemContent on ContinueWatchingPanelItemContent { __typename ... on Movie { __typename ...MobilePageMovie } ... on Episode { __typename ...MobilePageEpisode } ... on SportEvent { __typename ...MobilePageSportEvent } }  fragment MobileContinueWatchingPanel on ContinueWatchingPanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } continueWatchingContent { items { media { __typename ...MobileContinueWatchingPanelItemContent } } } }  fragment MobileMyListPanelItemContent on MyListPanelItemContent { __typename ... on Movie { __typename ...MobilePageMovie } ... on Series { __typename ...MobilePageSeries } ... on SportEvent { __typename ...MobilePageSportEvent } }  fragment MobileMyListPanel on MyListPanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } myListContent(limit: $mediaContentLimit) { pageInfo { hasNextPage nextPageOffset } items { media { __typename ...MobileMyListPanelItemContent } } } }  fragment MobilePageLinkPanel on PageLinkPanel { id title pageLinkContent { items { id name description type images { icon1x1 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } } } } }  fragment MobileSingleFeaturePanelMedia on SingleFeaturePanelMedia { __typename ... on Movie { __typename ...MobilePageMovie } ... on Series { __typename ...MobilePageSeries } ... on SportEvent { __typename ...MobilePageSportEvent } }  fragment MobileSingleFeaturePanel on SingleFeaturePanel { id title subtitle images { __typename ... on SingleFeaturePanelImages { promo16x9 { sourceNonEncoded } } } media { __typename ...MobileSingleFeaturePanelMedia } }'
    }

    response = send_req(url, post=True, json=json, headers=headers)
    if response:
        j_response = response.json()
        try:
            data = j_response['data']['store']['pagePanels']['items']

            genres = []

            key = -1
            for item in data:
                key += 1

                items = None

                selection = item.get('selectionMediaContent')
                media = item.get('mediaContent')
                stores = item.get('storesContent')

                if selection:
                    items = selection.get('items')

                elif media:
                    items = media.get('items')

                elif stores:
                    items = stores.get('items')

                if items:
                    title = item['title']
                    if not title:
                        title = localized(30065)
                    genres.append((key, title))

            for gen in genres:
                add_item(label=gen[1], url=str(gen[0])+'|'+str(store_id), mode='store', icon=icon, fanart=fanart, folder=True, playable=False)

        except Exception as ex:
            print('vod_store Exception: {}'.format(ex))
            xbmcgui.Dialog().notification(localized(30012), localized(30048))
            return

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
    login = check_login()
    if not login:
        login_data(reconnect=False)

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

def now_playing(thumb=thumb, poster=poster, banner=banner, clearlogo=clearlogo, icon=icon, fanart=fanart):
    login = check_login()
    if not login:
        login_data(reconnect=False)

    country            = int(addon.getSetting('teliaplay_locale'))
    beartoken          = addon.getSetting('teliaplay_beartoken')
    tv_client_boot_id  = addon.getSetting('teliaplay_tv_client_boot_id')

    n = datetime.now()
    now = int(time.mktime(n.timetuple())) * 1000

    try:
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
            "operationName": "GetEPGChannelList",
            "query": "query GetEPGChannelList($channelLimit: Int, $programLimit: Int, $timestamp: Timestamp!) {\n  channels(limit: $channelLimit) {\n    channelItems {\n      ...ChannelItem\n      __typename\n    }\n    __typename\n  }\n}\n\nfragment ChannelItem on Channel {\n  id\n  name\n  recordAndWatch\n  playback {\n    play {\n      playbackSpec {\n        ...PlaybackSpec\n        __typename\n      }\n      __typename\n    }\n    buy {\n      ...GraphQLChannelPlaybackBuyFragment\n      __typename\n    }\n    __typename\n  }\n  icons {\n    light {\n      sourceNonEncoded\n      __typename\n    }\n    dark {\n      sourceNonEncoded\n      __typename\n    }\n    __typename\n  }\n  programs(timestamp: $timestamp, limit: $programLimit) {\n    programItems {\n      ...ProgramItem\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n\nfragment PlaybackSpec on PlaybackSpec {\n  accessControl\n  videoId\n  videoIdType\n  watchMode\n  __typename\n}\n\nfragment GraphQLChannelPlaybackBuyFragment on ChannelPlaybackBuy {\n  subscriptions {\n    item {\n      ...GraphQLSubscriptionProductStandardFragment\n      ...GraphQLSubscriptionProductIAPFragment\n      ...GraphQLSubscriptionProductTVEFragment\n      ...GraphQLSubscriptionProductDualEntry\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n\nfragment GraphQLSubscriptionProductStandardFragment on SubscriptionProductStandard {\n  id\n  name\n  uniqueSellingPoints {\n    ...GraphQLSubscriptionProductUniqueSellingPoint\n    __typename\n  }\n  gqlPrice: price {\n    readable\n    __typename\n  }\n  __typename\n}\n\nfragment GraphQLSubscriptionProductUniqueSellingPoint on SubscriptionProductUniqueSellingPoint {\n  sellingPoint\n  __typename\n}\n\nfragment GraphQLSubscriptionProductIAPFragment on SubscriptionProductIAP {\n  id\n  name\n  iTunesConnectId\n  uniqueSellingPoints {\n    ...GraphQLSubscriptionProductUniqueSellingPoint\n    __typename\n  }\n  __typename\n}\n\nfragment GraphQLSubscriptionProductTVEFragment on SubscriptionProductTVE {\n  id\n  name\n  __typename\n}\n\nfragment GraphQLSubscriptionProductDualEntry on SubscriptionProductDualEntry {\n  id\n  name\n  __typename\n}\n\nfragment ProgramItem on Program {\n  live\n  id\n  startTime {\n    timestamp\n    isoString\n    __typename\n  }\n  endTime {\n    timestamp\n    isoString\n    __typename\n  }\n  title\n  media {\n    ... on Movie {\n      ...MovieProgram\n      __typename\n    }\n    ... on Episode {\n      ...EpisodeProgram\n      __typename\n    }\n    ... on SportEvent {\n      ...SportProgram\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n\nfragment MovieProgram on Movie {\n  id\n  images {\n    screenshot16x9 {\n      sourceNonEncoded\n      __typename\n    }\n    backdrop16x9 {\n      sourceNonEncoded\n      __typename\n    }\n    __typename\n  }\n  mediaType\n  title\n  availableNow\n  availability {\n    from {\n      timestamp\n      __typename\n    }\n    to {\n      timestamp\n      text\n      __typename\n    }\n    __typename\n  }\n  descriptionLong\n  playback {\n    ...PlaybackItem\n    buy {\n      ...GraphQLPlaybackBuyFragment\n      ...BuyItem\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n\nfragment PlaybackItem on Playback {\n  play {\n    linear {\n      ...Linear\n      __typename\n    }\n    subscription {\n      item {\n        validFrom {\n          timestamp\n          __typename\n        }\n        validTo {\n          timestamp\n          __typename\n        }\n        playbackSpec {\n          ...PlaybackSpec\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    npvr {\n      item {\n        validFrom {\n          timestamp\n          __typename\n        }\n        validTo {\n          timestamp\n          __typename\n        }\n        playbackSpec {\n          ...PlaybackSpec\n          __typename\n        }\n        __typename\n      }\n      live {\n        playbackSpec {\n          ...PlaybackSpec\n          __typename\n        }\n        __typename\n      }\n      startover {\n        playbackSpec {\n          ...PlaybackSpec\n          __typename\n        }\n        __typename\n      }\n      npvrInfo {\n        originalAirDate {\n          startDate {\n            timestamp\n            isoString\n            __typename\n          }\n          __typename\n        }\n        series {\n          active\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n\nfragment Linear on PlaybackPlayLinear {\n  item {\n    isLive\n    startover {\n      playbackSpec {\n        ...PlaybackSpec\n        __typename\n      }\n      __typename\n    }\n    playbackSpec {\n      ...PlaybackSpec\n      __typename\n    }\n    startTime {\n      timestamp\n      readableDistance(type: FUZZY)\n      __typename\n    }\n    endTime {\n      timestamp\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n\nfragment GraphQLPlaybackBuyFragment on PlaybackBuy {\n  subscriptions {\n    item {\n      ...GraphQLSubscriptionProductStandardFragment\n      ...GraphQLSubscriptionProductIAPFragment\n      ...GraphQLSubscriptionProductTVEFragment\n      ...GraphQLSubscriptionProductDualEntry\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n\nfragment BuyItem on PlaybackBuy {\n  subscription {\n    item {\n      validFrom {\n        timestamp\n        __typename\n      }\n      validTo {\n        timestamp\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  npvr {\n    item {\n      validFrom {\n        timestamp\n        __typename\n      }\n      validTo {\n        timestamp\n        __typename\n      }\n      playbackSpec {\n        ...PlaybackSpec\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n\nfragment EpisodeProgram on Episode {\n  id\n  images {\n    screenshot16x9 {\n      sourceNonEncoded\n      __typename\n    }\n    backdrop16x9 {\n      sourceNonEncoded\n      __typename\n    }\n    __typename\n  }\n  availableNow\n  availability {\n    from {\n      timestamp\n      __typename\n    }\n    to {\n      timestamp\n      text\n      __typename\n    }\n    __typename\n  }\n  title\n  descriptionLong\n  series {\n    id\n    title\n    isRecordable\n    userData {\n      npvrInfo {\n        active\n        episodes {\n          ongoing\n          recorded\n          scheduled\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  playback {\n    ...PlaybackItem\n    buy {\n      ...GraphQLPlaybackBuyFragment\n      ...BuyItem\n      __typename\n    }\n    __typename\n  }\n  episodeNumber {\n    readable\n    __typename\n  }\n  seasonNumber {\n    readable\n    __typename\n  }\n  __typename\n}\n\nfragment SportProgram on SportEvent {\n  id\n  title\n  availableNow\n  availability {\n    from {\n      timestamp\n      __typename\n    }\n    to {\n      timestamp\n      text\n      __typename\n    }\n    __typename\n  }\n  playback {\n    ...PlaybackItem\n    buy {\n      ...GraphQLPlaybackBuyFragment\n      ...BuyItem\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n",
            "variables": {
                "channelLimit": 200,
                "programLimit": 1,
                "timestamp": int(now),
            }
        }

        response = send_req(url, post=True, json=json, headers=headers)
        if not response:
            xbmcgui.Dialog().notification(localized(30012), localized(30006))
            raise Exception

        j_response = response.json()
        channels = j_response['data']['channels']['channelItems']

        count = 0

        for channel in channels:
            ch_name = channel.get('name')
            programs = channel.get('programs')
            icons = channel.get('icons')
            exlink = channel.get('id')

            if icons:
                dark = icons.get('dark')
                if dark:
                    src = dark.get('sourceNonEncoded')
                    if src:
                        icon = unquote(src)

            if programs:
                program_items = programs.get('programItems')
                for program in program_items:
                    start = program.get('startTime')
                    if start:
                        start_ts = start.get('timestamp')
                        if isinstance(start_ts, int):
                            start_time = start_ts // 1000
                            dt_start = datetime.fromtimestamp(start_time)
                            st_start = dt_start.strftime('%H:%M')
                    else:
                        st_start = None

                    end = program.get('endTime')
                    if end:
                        end_ts = end.get('timestamp')
                        if isinstance(end_ts, int):
                            end_time = end_ts // 1000
                            dt_end = datetime.fromtimestamp(end_time)
                            st_end = dt_end.strftime('%H:%M')
                    else:
                        st_end = None

                    label = program.get('title')

                    media = program.get('media')
                    if media:
                        count += 1
                        media_id = media.get('id') 

                        images = media.get('images')
                        if images:
                            card_16x9 = images.get('screenshot16x9') if images.get('screenshot16x9') else images.get('backdrop16x9')
                            if card_16x9:
                                src = card_16x9.get('sourceNonEncoded')
                                if not src:
                                    src = card_16x9.get('source')
                                if src:
                                    poster = unquote(src)
                            else:
                                poster = fanart
                        else:
                            poster = fanart

                        plot = media.get('descriptionLong')
                        outline = plot

                        today = datetime.strftime(datetime.now(), '%Y-%m-%d')

                        if st_start and st_end:
                            date = st_start + ' - ' + st_end
                            duration = int(end_time) - int(start_time)
                        else:
                            date = ''
                            duration = ''

                        title = label + '[B][COLOR violet] ● [/COLOR][/B]' + '[COLOR grey]({0})[/COLOR]'.format(date)

                        episode_raw = media.get('episodeNumber')
                        if episode_raw:
                            episode_read = str(episode_raw['readable'])
                            nr_pattern = re.compile(r'(\d+)')
                            r = nr_pattern.search(episode_read)
                            episode_nr = r.group(1) if r else ''
                        else:
                            episode_nr = ''

                        season_raw = media.get('seasonNumber')
                        if season_raw:
                            season_read = str(season_raw['readable'])
                            nr_pattern = re.compile(r'(\d+)')
                            r = nr_pattern.search(season_read)
                            season_nr = r.group(1) if r else ''
                        else:
                            season_nr = ''

                        catchup = 'LIVE'

                        ext = localized(30027)
                        context_menu = [('{0}'.format(ext), 'RunScript(plugin.video.teliaplay,0,?mode=ext,label={0})'.format(label))]

                        add_item(label=label, url=exlink, mode='play', media_id=media_id, catchup=catchup, start=start_time, end=end_time, folder=False, playable=True, info_labels={'title': title, 'sorttitle': title, 'originaltitle': title, 'plot': plot, 'plotoutline': outline, 'aired': today, 'dateadded': today, 'duration': duration, 'sortepisode': episode_nr, 'sortseason': season_nr}, icon=icon, poster=poster, fanart=fanart, context_menu=context_menu, item_count=count)

        xbmcplugin.setContent(addon_handle, 'playlists')
        xbmcplugin.endOfDirectory(addon_handle)

    except Exception as ex:
        print('live_channels exception: {}'.format(ex))

def live_channels():
    channel_lst = []

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
            addon.setSetting('teliaplay_devush', '')
            print('errorMessage: {e}'.format(e=str(engagementjson)))
            return live_channels()

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

                icon = path + 'icon.png'

                icons = channel.get('icons')
                if icons:
                    img = icons.get('dark').get('source')
                    icon = unquote(img)

                channel_lst.append((exlink, name, icon))
                add_item(label=name, url=exlink, mode='programs', icon=icon, folder=True, playable=False, info_labels={'title':name, 'plot':name}, fanart=fanart, item_count=count)

        xbmcplugin.endOfDirectory(addon_handle)

    except Exception as ex:
        print('live_channels exception: {}'.format(ex))

    return channel_lst

def get_programme(exlink, start):
    country            = int(addon.getSetting('teliaplay_locale'))
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
        'operationName': 'GetChannel',

        'variables': {
            'channelId': '{0}'.format(str(exlink)),
            'programLimit': 1,
            'timestamp': int(start) * 1000
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
        xbmcgui.Dialog().notification(localized(30012), localized(30048))
        return

    programs = dict()

    for program in program_items:
        extitle = program.get('title')
        exstart = program.get('startTime')
        if exstart:
            exstart_ts = exstart.get('timestamp') // 1000

        exend = program.get('endTime')
        if exend:
            exend_ts = exend.get('timestamp') // 1000

        excatchup = 'LIVE'
        exid = ''

        media = program.get('media')
        if media:
            exid = media.get('id')
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
                                        excatchup = playback_spec.get('watchMode')

        programs.update({'exlink': exlink, 'extitle': extitle, 'exid': exid, 'excatchup': excatchup, 'exstart': exstart_ts, 'exend': exend_ts})

    if programs:
        return programs
    else:
        return None

def live_channel(exlink, extitle):
    country            = int(addon.getSetting('teliaplay_locale'))
    beartoken          = addon.getSetting('teliaplay_beartoken')
    tv_client_boot_id  = addon.getSetting('teliaplay_tv_client_boot_id')

    n = datetime.now()
    now = int(time.mktime(n.timetuple())) * 1000

    yday = str(((int(time.time() // 86400)) * 86400 - 86400 ) * 1000)
    nday = str(((int(time.time() // 86400)) * 86400) * 1000)
    tday = str(((int(time.time() // 86400)) * 86400 + 86400 ) * 1000)

    timestamps = [yday, nday, tday]

    for timestamp in timestamps:
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

            label = program.get('title')
            org_title = label

            now = int(time.time())

            try:
                start = program.get('startTime')
                if start:
                    start_ts = start.get('timestamp')
                    if isinstance(start_ts, int):
                        start_time = start_ts // 1000
                        dt_start = datetime.fromtimestamp(start_time)
                        st_start = dt_start.strftime('%H:%M')
                        da_start = dt_start.strftime('%Y-%m-%d')
                else:
                    st_start = None

                end = program.get('endTime')
                if end:
                    end_ts = end.get('timestamp')
                    if isinstance(end_ts, int):
                        end_time = end_ts // 1000
                        dt_end = datetime.fromtimestamp(end_time)
                        st_end = dt_end.strftime('%H:%M')
                else:
                    st_end = None

                duration = int(end_time) - int(start_time)

                aired = da_start
                date = st_start + ' - ' + st_end

                if len(label) > 50:
                    label = label[:50]

                if int(now) >= int(start_time) and int(now) <= int(end_time):
                    name_ = label + '[B][COLOR violet] ● [/COLOR][/B]'

                elif int(end_time) >= int(now):
                    name_ = '[COLOR grey]{0}[/COLOR] [B][/B]'.format(label)

                else:
                    name_ = label + '[B][COLOR limegreen] ● [/COLOR][/B]'

                title = name_ + '[COLOR grey]({0})[/COLOR]'.format(date)

            except:
                name_ = label + '[B][COLOR violet] ● [/COLOR][/B]'
                title = name_ + '[COLOR grey](00:00 - 23:59)[/COLOR]'

                start_time = 0
                end_time = 0

                duration = ''

                aired = ''
                date = ''

            media = program.get('media')

            media_id = media.get('id')
            plot = media.get('descriptionLong')
            genre = media.get('genre')

            lang = ''
            audio_lang = media.get('audioLang')
            if audio_lang:
                lang = audio_lang.get('name')

            catchup = 'LIVE'
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
                else:
                    poster = fanart

                card_16x9 = images.get('showcard16x9')
                if card_16x9:
                    src = card_16x9.get('sourceNonEncoded')
                    if not src:
                        src = card_16x9.get('source')
                    if src:
                        icon = unquote(src)
                else:
                    poster = fanart
            else:
                poster = fanart

            ext = localized(30027)
            context_menu = [('{0}'.format(ext), 'RunScript(plugin.video.teliaplay,0,?mode=ext,label={0})'.format(label))]

            add_item(label=label, url=exlink, mode='play', media_id=media_id, catchup=catchup, start=start_time, end=end_time, folder=False, playable=True, info_labels={'title': title, 'sorttitle': title, 'originaltitle': org_title, 'plot': plot, 'plotoutline': plot, 'aired': aired, 'dateadded': date, 'duration': duration, 'genre': genre, 'country': lang}, icon=icon, poster=poster, fanart=fanart, context_menu=context_menu, item_count=count)

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
    login = check_login()
    if not login:
        login_data(reconnect=False)

    add_item(label=localized(30049), url='', mode='sports_table_genre', icon=icon, fanart=fanart, folder=True, playable=False)
    add_item(label=localized(30050), url='', mode='sports_corner_genre', icon=icon, fanart=fanart, folder=True, playable=False)

    xbmcplugin.endOfDirectory(addon_handle)

def sports_genre():
    beartoken          = addon.getSetting('teliaplay_beartoken')
    tv_client_boot_id  = addon.getSetting('teliaplay_tv_client_boot_id')

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
                    count = item.get('count')
                    if count:
                        g_count = int(count)
                    else:
                        g_count = 0

                    if g_count > 0:
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
            items = []

            for i in data:
                for item in i['items']:
                    genre = item['media']['genre']
                    if genre == idx:
                        ts = item['startTime']['timestamp'] // 1000
                        dt_obj = datetime.fromtimestamp(ts)
                        date = dt_obj.date()
                        item_date_time = date.strftime('%Y-%m-%d')
                        if date_time == item_date_time:
                            items.append(item)

            if items:
                get_items(items)
            else:
                print(items)
                raise Exception

        except Exception as ex:
            print('sports table Exception: {}'.format(ex))
            xbmcgui.Dialog().notification(localized(30012), localized(30048))
            return

def sports_corner_genre():
    beartoken          = addon.getSetting('teliaplay_beartoken')
    tv_client_boot_id  = addon.getSetting('teliaplay_tv_client_boot_id')

    start_str = time.strftime('%m-%d-%Y') + ' 00:00:00'
    timestamp = int(time.mktime(time.strptime(start_str, '%m-%d-%Y %H:%M:%S')))

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
            'channelsLimit': 200,
            'mediaContentLimit': 60,
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

            items = None

            pagelink = item.get('pageLinkContent')
            timeline = item.get('timelineContent')
            selection = item.get('selectionMediaContent')
            media = item.get('mediaContent')
            stores = item.get('storesContent')
            showcase = item.get('showcaseContent')

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

            elif stores:
                items = stores.get('items')

            if items:
                if item['title'] != '':
                    sub = True
                    if timeline:
                        content = timeline
                    elif media:
                        content = media
                    else:
                        content = None

                    if content:
                        sub = False
                        for i in content['items']:
                            media = i.get('media')
                            if media:
                                playback = media.get('playback')
                                if playback:
                                    play = playback.get('play')
                                    if play.get('subscription'):
                                        sub = True
                    if sub:
                        genres.append((key, item['title']))

        for gen in genres:
            add_item(label=gen[1], url=str(gen[0]), mode='sports_corner', icon=icon, fanart=fanart, folder=True, playable=False)

    xbmcplugin.endOfDirectory(addon_handle)

def sports_corner(genre_id, media_id):
    if not media_id:
        media_id = 'sports-corner'
        idx = int(genre_id)

    else:
        idx = -1

    beartoken          = addon.getSetting('teliaplay_beartoken')
    tv_client_boot_id  = addon.getSetting('teliaplay_tv_client_boot_id')

    n = datetime.now()
    now = int(time.mktime(n.timetuple())) * 1000

    timestamp = int(((int(time.time() // 86400)) * 86400) * 1000)

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
            'channelsLimit': 200,
            'mediaContentLimit': 60,
            'pageId': media_id,
            'timestamp': timestamp
        },

        'query': 'query getMobilePage($pageId: String!, $timestamp: Timestamp!, $channelsLimit: Int!, $mediaContentLimit: Int!, $offset: Int) { page(id: $pageId) { id pagePanels(limit: 60) { items { __typename title id ...MobileSelectionMediaPanel ...MobileMediaPanel ...MobileStoresPanel ...MobileRentalsPanel ...MobileTimelinePanel ...MobileShowcasePanel ...MobileContinueWatchingPanel ...MobileMyListPanel ...MobileChannelsPanel ...MobileSingleFeaturePanel ...MobilePageLinkPanel } } } }  fragment PlaybackSpec on PlaybackSpec { accessControl videoId videoIdType watchMode }  fragment Vod on Vod { audioLang { name code } playbackSpec { __typename ...PlaybackSpec } price { readable } validFrom { timestamp readableDistance(type: FUZZY) } validTo { timestamp } }  fragment Linear on PlaybackPlayLinear { item { startover { playbackSpec { __typename ...PlaybackSpec } } playbackSpec { __typename ...PlaybackSpec } startTime { timestamp readableDistance(type: FUZZY) } endTime { timestamp } } }  fragment Rental on PlaybackPlayVodRental { item { __typename ...Vod } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) sTo } } }  fragment Recording on PlaybackPlayRecording { item { playbackSpec { __typename ...PlaybackSpec } audioLang { name code } validFrom { timestamp } validTo { timestamp } } startover { playbackSpec { __typename ...PlaybackSpec } } }  fragment DeepLink on DeepLink { uri serviceName googlePlayStoreId validFrom { timestamp } validTo { timestamp } }  fragment SubscriptionProductStandard on SubscriptionProductStandard { id price { readable } }  fragment SubscriptionProductDualEntry on SubscriptionProductDualEntry { id }  fragment SubscriptionProductTVE on SubscriptionProductTVE { id }  fragment SubscriptionProductFallback on SubscriptionProductFallback { id }  fragment Playback on Playback { play { subscription { item { __typename ...Vod } } linear { __typename ...Linear } rental { __typename ...Rental } npvr { __typename ...Recording } deepLinks { item { __typename ...DeepLink } } } buy { subscriptions { item { __typename id name ...SubscriptionProductStandard ...SubscriptionProductDualEntry ...SubscriptionProductTVE ...SubscriptionProductFallback } } rental { item { price { readable } validFrom { timestamp } validTo { timestamp } } } npvr { item { playbackSpec { __typename ...PlaybackSpec } } } deepLinks { item { __typename ...DeepLink } } } }  fragment MobilePageMovie on Movie { id title playback { __typename ...Playback } images { backdrop16x9 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } } descriptionLong price { readable } genre yearProduction { number } ageRating { readable } duration { readableShort } ratings { imdb { readableScore } } productionCountries userData { progress { percent position } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) } } } store { name } availability { from { text } } availableNow labels { premiereAnnouncement { text } } }  fragment MobilePageSeries on Series { id title images { backdrop16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } } description genre ageRating { readable } ratings { imdb { readableScore } } label webview { url } isRentalSeries }  fragment MobilePageEpisode on Episode { id title images { backdrop16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } screenshot16x9 { sourceNonEncoded } } descriptionLong price { readable } genre yearProduction { number } episodeNumber { number readable } seasonNumber { number readable } playback { __typename ...Playback } series { id title } ageRating { readable } duration { readableShort } userData { progress { percent position } rentalInfo { endTime { readableDistance(type: HOURS_OR_MINUTES) } } } store { name } }  fragment MobilePageSportEvent on SportEvent { id title playback { __typename ...Playback } images { backdrop16x9 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } showcard16x9 { sourceNonEncoded } } availability { from { text timestamp } } descriptionLong genre badges { uhd { text } } productionCountries ageRating { readable } duration { readableShort } store { name } league labels { airtime { text } } yearProduction { number } userData { progress { percent position } } venue }  fragment MobilePageMediaPanelContent on MediaPanelItemContent { __typename ... on Movie { __typename ...MobilePageMovie } ... on Series { __typename ...MobilePageSeries } ... on Episode { __typename ...MobilePageEpisode } ... on SportEvent { __typename ...MobilePageSportEvent } }  fragment MobileSelectionMediaPanel on SelectionMediaPanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } ... on DisplayHintList { listSubType } ... on DisplayHintGrid { gridSubType } } selectionMediaContent(config: { limit: $mediaContentLimit offset: $offset } ) { pageInfo { hasNextPage nextPageOffset } items { media { __typename ...MobilePageMediaPanelContent } } } link { id type } }  fragment MobileMediaPanel on MediaPanel { id title kicker displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } ... on DisplayHintList { listSubType } ... on DisplayHintGrid { gridSubType } } mediaContent(limit: $mediaContentLimit, offset: $offset) { pageInfo { hasNextPage nextPageOffset } items { media { __typename ...MobilePageMediaPanelContent } } } }  fragment MobilePageStore on Store { id __typename name icons { light { sourceNonEncoded } dark { sourceNonEncoded } } }  fragment MobileStoresPanel on StoresPanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } ... on DisplayHintGrid { gridSubType } ... on DisplayHintList { listSubType } } storesContent(limit: $mediaContentLimit, offset: $offset) { pageInfo { hasNextPage nextPageOffset } items { __typename ...MobilePageStore } } }  fragment MobileRentalsPanelItemContent on RentalsPanelItemContent { __typename ... on Movie { __typename ...MobilePageMovie } ... on Series { __typename ...MobilePageSeries } }  fragment MobileRentalsPanel on RentalsPanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } rentalsContent(limit: $mediaContentLimit, offset: $offset) { pageInfo { hasNextPage nextPageOffset } items { media { __typename ...MobileRentalsPanelItemContent } } } }  fragment MobileTimeLinePanelItemContent on TimelinePanelItemContent { __typename ... on Movie { __typename ...MobilePageMovie } ... on Episode { __typename ...MobilePageEpisode } ... on SportEvent { __typename ...MobilePageSportEvent } }  fragment MobileTimelinePanel on TimelinePanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } timelineContent(limit: $mediaContentLimit, offset: $offset) { pageInfo { hasNextPage nextPageOffset } items { media { __typename ...MobileTimeLinePanelItemContent } startTime { timestamp isoString } endTime { timestamp isoString } } } }  fragment Store on Store { name icons { dark { sourceNonEncoded } } }  fragment MobileShowcaseMovie on Movie { id title userData { progress { position } favorite } images { backdrop16x9 { sourceNonEncoded } } playback { __typename ...Playback } store { __typename ...Store } }  fragment MobileShowcaseEpisode on Episode { id title userData { progress { position } favorite } images { backdrop16x9 { sourceNonEncoded } } playback { __typename ...Playback } series { id } store { __typename ...Store } }  fragment MobileShowcaseSeries on Series { id title userData { favorite } images { backdrop16x9 { sourceNonEncoded } } webview { url } suggestedEpisode { id playback { __typename ...Playback } } store { __typename ...Store } }  fragment MobileShowcaseSportEvent on SportEvent { id title userData { progress { position } favorite } images { backdrop16x9 { sourceNonEncoded } } playback { __typename ...Playback } store { __typename ...Store } }  fragment ChannelPlayback on ChannelPlayback { play { playbackSpec { __typename ...PlaybackSpec } } buy { subscriptions { item { id } } } }  fragment MobileShowcaseChannel on Channel { channelPlayback: playback { __typename ...ChannelPlayback } }  fragment MobileShowcasePanel on ShowcasePanel { id title showcaseContent { items { id showcaseTitle { text } kicker images { showcase16x9 { sourceNonEncoded } showcase16x7 { sourceNonEncoded } showcase7x10 { sourceNonEncoded } showcase2x3 { sourceNonEncoded } } promotion { link { id type } content { __typename ...MobileShowcaseMovie ...MobileShowcaseEpisode ...MobileShowcaseSeries ...MobileShowcaseSportEvent ...MobileShowcaseChannel } } } } }  fragment MobileContinueWatchingPanelItemContent on ContinueWatchingPanelItemContent { __typename ... on Movie { __typename ...MobilePageMovie } ... on Episode { __typename ...MobilePageEpisode } ... on SportEvent { __typename ...MobilePageSportEvent } }  fragment MobileContinueWatchingPanel on ContinueWatchingPanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } continueWatchingContent { items { media { __typename ...MobileContinueWatchingPanelItemContent } } } }  fragment MobileMyListPanelItemContent on MyListPanelItemContent { __typename ... on Movie { __typename ...MobilePageMovie } ... on Series { __typename ...MobilePageSeries } ... on SportEvent { __typename ...MobilePageSportEvent } }  fragment MobileMyListPanel on MyListPanel { id title displayHint { __typename ... on DisplayHintSwimlane { swimlaneSubType } } myListContent(limit: $mediaContentLimit) { pageInfo { hasNextPage nextPageOffset } items { media { __typename ...MobileMyListPanelItemContent } } } }  fragment ProgramMedia on ProgramMedia { __typename ... on Movie { id title playback { __typename ...Playback } } ... on Episode { id series { title userData { npvrInfo { active } } } playback { __typename ...Playback } } ... on SportEvent { id title playback { __typename ...Playback } } }  fragment MobileChannelsPanel on ChannelsPanel { id title channels(limit: $channelsLimit, offset: $offset) { pageInfo { hasNextPage nextPageOffset } channelItems { id name userData { inEngagement } icons { dark { sourceNonEncoded } } playback { play { playbackSpec { __typename ...PlaybackSpec } } } displayHint { __typename ... on NormalChannelDisplayHint { noProgramsText } ... on LiveOnlyChannelDisplayHint { noProgramsText } } programs(timestamp: $timestamp, limit: 1) { programItems { startTime { timestamp isoString } endTime { timestamp isoString } media { __typename ...ProgramMedia } } } recordAndWatch } } }  fragment MobileSingleFeaturePanelMedia on SingleFeaturePanelMedia { __typename ... on Movie { __typename ...MobilePageMovie } ... on Series { __typename ...MobilePageSeries } ... on SportEvent { __typename ...MobilePageSportEvent } }  fragment MobileSingleFeaturePanel on SingleFeaturePanel { id title subtitle images { __typename ... on SingleFeaturePanelImages { promo16x9 { sourceNonEncoded } } } media { __typename ...MobileSingleFeaturePanelMedia } }  fragment MobilePageLinkPanel on PageLinkPanel { id title pageLinkContent { items { id name description type images { icon1x1 { sourceNonEncoded } showcard2x3 { sourceNonEncoded } } } } }',
    }

    response = send_req(url, post=True, json=json, headers=headers)
    if response:
        j_response = response.json()

    #try:
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

    elif stores:
        items = stores.get('items')

    if not items:
        xbmcgui.Dialog().notification(localized(30012), localized(30048))
        return

    mode = None
    if j_response['data']['page']['id'] == 'sports-corner':
        mode = 'sports_corner'

    get_items(items, mode)

    #except Exception as ex:
        #print('sports Exception: {}'.format(ex))
        #xbmcgui.Dialog().notification(localized(30012), localized(30048))
        #return

def kids_genre():
    login = check_login()
    if not login:
        login_data(reconnect=False)

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
            'mediaContentLimit': 60,
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

            items = None

            selection = item.get('selectionMediaContent')
            media = item.get('mediaContent')
            stores = item.get('storesContent')
            showcase = item.get('showcaseContent')

            if selection:
                items = selection.get('items')

            elif media:
                items = media.get('items')

            elif showcase:
                items = showcase.get('items')

            elif stores:
                items = stores.get('items')

            if items:
                if item['title']:
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
            'mediaContentLimit': 60,
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

            elif stores:
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
    login = check_login()
    if not login:
        login_data(reconnect=False)

    if exlink != 'vod':
        now = int(time.time())

        if int(now) >= int(start) and int(now) <= int(end):
            catchup_type = 'LIVE'
            if play_beginning:
                response = xbmcgui.Dialog().yesno(localized(30012), localized(30014))
                if response:
                    exlink = media_id
                    catchup_type = 'STARTOVER'

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
        play_item.setInfo('Video', infoLabels={'title': title})
        play_item.setContentLookup(False)
        play_item.setProperty('inputstream', is_helper.inputstream_addon)
        play_item.setMimeType('application/xml+dash')
        play_item.setProperty('inputstream.adaptive.license_type', DRM)
        play_item.setProperty('inputstream.adaptive.license_key', license_url)
        play_item.setProperty('inputstream.adaptive.stream_headers', 'Referer: https://www.teliaplay.se/&User-Agent=' + quote(UA))
        play_item.setProperty('inputstream.adaptive.manifest_type', 'mpd')
        play_item.setProperty('IsPlayable', 'true')
        if catchup_type != 'LIVE':
            play_item.setProperty('inputstream.adaptive.play_timeshift_buffer', 'true')
        if catchup_type == 'ONDEMAND':
            play_item.setProperty('inputstream.adaptive.play_timeshift_buffer', 'false')

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
        add_item(label=localized(30067), url='', mode='now_playing', icon=live_icon, fanart=fanart, folder=True, playable=False)
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

    ret = xbmcgui.Dialog().select(localized(30058), list(items), useDetails=True)
    if ret < 0:
        return

    profile = profiles[ret]

    addon.setSetting('teliaplay_profile_name', profile[0])
    addon.setSetting('teliaplay_profile_avatar', profile[-1])

def build_m3u():
    path = xbmcgui.Dialog().browse(0, localized(30062), 'files')
    if path == '':
        return

    xbmcgui.Dialog().notification(localized(30012), localized(30063), xbmcgui.NOTIFICATION_INFO)
    data = '#EXTM3U'

    items = live_channels()
    for item in items:
        cid = item[0]
        url = 'plugin://plugin.video.teliaplay/?title=&mode=play&url={cid}'.format(cid=cid)

        tvg_id = item[1].lower().replace(' ', '_') + '.' + cc[country]
        title = item[1] + ' ' + ca[country]
        icon = item[2]

        data += '\n#EXTINF:-1 tvg-id="{id}" tvg-name="{title}" tvg-logo="{icon}" catchup="default" catchup-days="7" group-title="Telia", {title}\n{url}'.format(id=tvg_id, title=title, url=url, icon=icon)

    with open(path + 'teliaplay_iptv.m3u', 'w+', encoding='utf-8') as f:
        f.write(data)

    xbmcgui.Dialog().notification(localized(30012), localized(30064), xbmcgui.NOTIFICATION_INFO)
    return

def router(param):
    args = dict(urlparse.parse_qsl(param))
    if args:
        mode = args.get('mode', None)

        if mode == 'play':
            utc = args.get('utc')
            if utc:
                start = utc
                url = args.get('url')
                if url:
                    prog = get_programme(url, start)
                    if not prog:
                        return

                    play(prog['exlink'], prog['extitle'], prog['exid'], prog['excatchup'], prog['exstart'], prog['exend'])
            else:
                start = args.get('start')
                url = args.get('url')

                if not start:
                    catchup = 'LIVE'

                    start = 0
                    end = 0

                    play(exlink, extitle, exid, catchup, start, end)

                else:
                    play(exlink, extitle, exid, excatchup, exstart, exend)

        elif mode == 'programs':
            live_channel(exlink, extitle)

        elif mode == 'now_playing':
            now_playing()

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

        elif mode == 'vod_store':
            vod_store(exid)

        elif mode == 'store':
            store(exlink)

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
            sports_corner(exlink, exid)

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

        elif mode == 'build_m3u':
            build_m3u()

    else:
        home()

if __name__ == '__main__':
    router(sys.argv[2][1:])