from __future__ import print_function

import argparse
import collections
import itertools
import logging
import os
import sys

import appdirs
from twisted.internet import defer
from twisted.internet import reactor
from twisted.internet import protocol
from twisted.internet import endpoints
from twisted.python import log

from lbrynet import conf
from lbrynet.core import Error
from lbrynet.core import Wallet
from lbrynet.core import BlobAvailability
from lbrynet.core import BlobManager
from lbrynet.core import HashAnnouncer
from lbrynet.core import PeerManager
from lbrynet.core import Session
from lbrynet.core import log_support
from lbrynet.core import utils
from lbrynet.core.client import DHTPeerFinder
from lbrynet.dht import node
from lbrynet.metadata import Metadata
from lbrynet.core import StreamDescriptor as sd


logger = logging.getLogger()


def main(args=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--limit', type=int)
    parser.add_argument('--download', action='store_true')
    args = parser.parse_args(args)

    log_support.configure_console()

    db_dir = appdirs.user_data_dir('LBRY')
    lbrycrd = appdirs.user_data_dir('lbrycrd')
    storage = Wallet.InMemoryStorage()

    wallet = Wallet.LBRYcrdWallet(storage, wallet_conf=os.path.join(lbrycrd, 'lbrycrd.conf'))
    session = Session.Session(
        0,
        db_dir=db_dir,
        lbryid=utils.generate_id(),
        blob_dir=os.path.join(db_dir, 'blobfiles'),
        dht_node_port=4444,
        known_dht_nodes=conf.settings.known_dht_nodes,
        peer_port=3333,
        use_upnp=False,
        wallet=wallet
    )
    d = session.setup()
    d.addErrback(logAndStop)
    d.addCallback(lambda _: Tracker.load(session))
    d.addErrback(logAndStop)
    d.addCallback(processTracker, args.limit, args.download)
    d.addErrback(logAndStop)
    d.addCallback(lambda _: reactor.stop())
    reactor.run()

def processTracker(tracker, limit, download):
    d = tracker.processNameClaims(limit, download)
    d.addCallback(lambda _: print(tracker.stats))
    return d


def logAndStop(err):
    log_support.failure(err, logger, 'This sucks: %s')
    reactor.stop()


def logAndRaise(err):
    log_support.failure(err, logger, 'This still sucks: %s')
    return err


def timeout(n):
    def wrapper(fn):
        def wrapped(*args, **kwargs):
            d = fn(*args, **kwargs)
            reactor.callLater(n, d.cancel)
            return d
        return wrapped
    return wrapper


class Tracker(object):
    def __init__(self, session, blob_tracker, wallet):
        self.session = session
        self.blob_tracker = blob_tracker
        self.wallet = wallet
        self.names = None
        self.stats = {}

    @classmethod
    def load(cls, session):
        blob_tracker = BlobAvailability.BlobAvailabilityTracker(
            session.blob_manager, session.peer_finder, session.dht_node)
        return cls(session, blob_tracker, session.wallet)

    def processNameClaims(self, limit=None, download=False):
        d = self.wallet.get_nametrie()
        d.addCallback(getNameClaims)
        if limit:
            d.addCallback(itertools.islice, limit)
        d.addCallback(self._setNames)
        d.addCallback(lambda _: self._getSdHashes())
        d.addCallback(lambda _: self._filterNames('sd_hash'))
        d.addCallback(lambda _: self._checkAvailability())
        d.addCallback(lambda _: self._filterNames('is_available'))
        d.addCallback(lambda _: print(self.attempts_counter))
        if download:
            d.addCallback(lambda _: self._downloadAllBlobs())
            d.addCallback(lambda _: self._filterNames('sd_blob'))
        return d

    def _setNames(self, names):
        self.names = [Name(n) for n in names]

    def _getSdHashes(self):
        return defer.DeferredList(
            [n.setSdHash(self.wallet) for n in self.names],
            fireOnOneErrback=True
        )

    def _filterNames(self, attr):
        self.names = [n for n in self.names if getattr(n, attr)]
        self.stats[attr] = len(self.names)
        print("We have {} names with attribute {}".format(len(self.names), attr))

    def attempts_counter(self):
        return collections.Counter([n.availability_attempts for n in self.names])

    def _checkAvailability(self):
        return defer.DeferredList(
            [n.check_availability(self.blob_tracker) for n in self.names],
            fireOnOneErrback=True
        )

    def _downloadAllBlobs(self):
        return defer.DeferredList(
            [n.download_sd_blob(self.session) for n in self.names],
            fireOnOneErrback=True
        )


def skipInvalidStream(err):
    err.trap(Error.InvalidStreamInfoError, AssertionError)


class Name(object):
    # From experience, very few sd_blobs get found after the third attempt
    MAX_ATTEMPTS = 6
    def __init__(self, name):
        self.name = name
        self.sd_hash = None
        self.is_available = None
        self.sd_blob = None
        self.availability_attempts = 0

    def setSdHash(self, wallet):
        d = wallet.get_stream_info_for_name(self.name)
        d.addCallback(Metadata.Metadata)
        d.addCallback(_getSdHash)
        d.addCallback(self._setSdHash)
        d.addErrback(skipInvalidStream)
        return d

    def _setSdHash(self, sd_hash):
        self.sd_hash = sd_hash

    def _check_availability(self, blob_tracker):
        d = blob_tracker.get_blob_availability(self.sd_hash)
        d.addCallback(lambda b: self._setAvailable(b[self.sd_hash]))
        return d

    def check_availability(self, blob_tracker):
        if not self.is_available and self.availability_attempts < self.MAX_ATTEMPTS:
            self.availability_attempts += 1
            if self.availability_attempts > 1:
                logger.info('Attempt %s to find %s', self.availability_attempts, self.name)
            d = self._check_availability(blob_tracker)
            d.addCallback(lambda _: self.check_availability(blob_tracker))
            return d
        else:
            return defer.succeed(True)

    def _setAvailable(self, peer_count):
        self.is_available = peer_count > 0

    def download_sd_blob(self, session):
        print('Trying to get sd_blob for {} using {}'.format(self.name, self.sd_hash))
        d = download_sd_blob_with_timeout(session, self.sd_hash, session.payment_rate_manager)
        d.addCallback(sd.BlobStreamDescriptorReader)
        d.addCallback(self._setSdBlob)
        # swallow errors from the timeout
        d.addErrback(lambda err: err.trap(defer.CancelledError))
        return d

    def _setSdBlob(self, blob):
        print('{} has a blob'.format(self.name))
        self.sd_blob = blob


@timeout(60)
def download_sd_blob_with_timeout(session, sd_hash, payment_rate_manager):
    return sd.download_sd_blob(session, sd_hash, payment_rate_manager)


def getNameClaims(trie):
    for x in trie:
        if 'txid' in x:
            yield x['name']


def _getSdHash(metadata):
    return metadata['sources']['lbry_sd_hash']


if __name__ == '__main__':
    sys.exit(main())
