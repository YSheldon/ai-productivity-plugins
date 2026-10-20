"""Order original synthetic pipe replies without inventing or renewing authority."""
from __future__ import annotations

import copy
import time
from urllib.parse import urlsplit


class PartialOrder:
    def __init__(self,channel,*,deny_first=False):
        assert urlsplit(channel.config['origin']).hostname=='127.0.0.1'
        self.channel=channel;self.deny_first=deny_first
        self.send=channel._send;self.event=channel.on_startup
        self.allowed={};self.ready=set();self.denial=None;self.late=None
        self.denials=0;self.released=0;self.late_released=0
        self.ended=False;self.armed=False;self.error=None
        channel._send=self._send;channel.on_startup=self._event

    def _release_denial(self):
        needed=1 if self.deny_first else 2
        if not self.denial or len(self.ready)!=needed or (self.deny_first and not self.late):return
        packet,started=self.denial
        if time.monotonic()-started>=5:
            self.error='denial-barrier-exceeded';return
        self.denial=None
        try:self.send(packet);self.released+=1
        except Exception:self.error='denial-send-failed'

    def _send(self,packet):
        permit=packet.get('permit',{})
        if packet.get('allowed') is True and permit.get('kind')=='initialization-read':
            check=packet['authorization_reply']
            if check in self.allowed:self.error='duplicate-permit'
            self.allowed[check]=copy.deepcopy(permit)
            if self.deny_first and len(self.allowed)==2:
                self.late=(copy.deepcopy(packet),time.monotonic())
                self._release_denial();return
        if set(packet)=={'authorization_reply','allowed'} and packet['allowed'] is False:
            self.denials+=1
            if self.denials!=1:self.error='unexpected-denial';return
            self.denial=(copy.deepcopy(packet),time.monotonic())
            self._release_denial();return
        return self.send(packet)

    def _event(self,frame):
        accepted=self.event(frame)
        if accepted is True:
            if frame.get('kind')=='prerequisite-response' and frame.get('ready') is True and frame.get('check_id') in self.allowed:
                self.ready.add(frame['check_id'])
            if frame.get('kind')=='resume-ended':self.ended=True
            if frame.get('kind') in {'controls-ready','credentials-armed','authentication-forwarded'}:self.armed=True
            self._release_denial()
        return accepted

    def release_late(self):
        assert self.deny_first and self.ended and self.late and self.released==1
        packet,started=self.late
        assert time.monotonic()-started<5,'Exercise cancellation before the original ten-second expiry'
        assert time.time()*1000<packet['permit']['expires_at_ms']
        self.send(packet);self.late=None;self.late_released+=1

    def finish(self):
        self.channel._send=self.send;self.channel.on_startup=self.event
        assert self.error is None,self.error
        assert len(self.allowed)==2 and self.denials==1 and self.released==1
        assert len(self.ready)==(1 if self.deny_first else 2)
        assert self.ended and not self.armed and self.denial is None and self.late is None
        assert self.late_released==int(self.deny_first)
