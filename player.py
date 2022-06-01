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

import xbmc
import threading

class Threading(object):
    def __init__(self):
        self.thread = threading.Thread(target=self.run, args=())
        self.thread.daemon = True
        self.thread.start()

    def run(self):
        xbmc.log("################ Starting VideoPlayer control events ################", level=xbmc.LOGINFO)
        while not xbmc.Monitor().abortRequested():
            self.player = VideoPlayerStateChange()
            if xbmc.Monitor().waitForAbort(1):
                break

class VideoPlayerStateChange(xbmc.Player):
    def __init__(self):
        xbmc.Player.__init__(self) 

    def onPlayBackError(self):
        xbmc.log("################ PlayBack Error ################", level=xbmc.LOGINFO)

    def onPlayBackPaused(self):
        xbmc.log("################ Playback Paused ################", level=xbmc.LOGINFO)

    def onPlayBackResumed(self):
        xbmc.log("################ Playback Resumed ################", level=xbmc.LOGINFO)

    def onPlayBackStarted(self):
        xbmc.log("################ Playback Started ################", level=xbmc.LOGINFO)

if ( __name__ == "__main__" ):
    Threading()