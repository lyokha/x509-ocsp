{-# LANGUAGE PatternSynonyms, ViewPatterns, RecordWildCards #-}

-----------------------------------------------------------------------------
-- |
-- Module      :  Data.X509.AIA
-- Copyright   :  (c) Alexey Radkov 2024-2026
-- License     :  BSD-style
--
-- Maintainer  :  alexey.radkov@gmail.com
-- Stability   :  experimental
-- Portability :  portable
--
-- Encode and decode X509 Authority Information Access extension.
--
-- This module complies with /rfc5280/.
-----------------------------------------------------------------------------

module Data.X509.AIA (AuthorityInfoAccess (..)
                     ,AIAMethod (..)
                     ,ExtAuthorityInfoAccess (..)
                     ) where

import Data.X509
import Data.ASN1.Types
import Data.ASN1.Stream
import Data.ByteString (ByteString)

pattern OidAIA :: [Integer]
pattern OidAIA = [1, 3, 6, 1, 5, 5, 7, 1, 1]

pattern OidOCSP :: [Integer]
pattern OidOCSP = [1, 3, 6, 1, 5, 5, 7, 48, 1]

pattern OidCAIssuers :: [Integer]
pattern OidCAIssuers = [1, 3, 6, 1, 5, 5, 7, 48, 2]

-- | Authority Info Access description.
--
-- The fields correspond to /accessMethod/ and /accessLocation/ as defined in
-- /rfc5280/.
data AuthorityInfoAccess = AuthorityInfoAccess { aiaMethod :: AIAMethod
                                               , aiaLocation :: ByteString
                                               } deriving (Show, Eq)

-- | Method of Authority Info Access (/OCSP/ or /CA issuers/).
data AIAMethod = OCSP | CAIssuers deriving (Show, Eq)

instance OIDable AIAMethod where
    getObjectID OCSP = OidOCSP
    getObjectID CAIssuers = OidCAIssuers

instance OIDNameable AIAMethod where
    fromObjectID OidOCSP = Just OCSP
    fromObjectID OidCAIssuers = Just CAIssuers
    fromObjectID _ = Nothing

-- | Authority Info Access extension.
--
-- Notable limitations of the 'Extension' instance:
--
-- - encoding of access method /CA Issuers/ is not implemented, trying to
--   encode this will throw an error,
-- - data with a non-string-like access location (e.g. /directoryName/) get
--   skipped while decoding.
newtype ExtAuthorityInfoAccess = ExtAuthorityInfoAccess [AuthorityInfoAccess]
    deriving (Show, Eq)

data DecState = DecStart | DecMethod | DecLocation OID | DecEnd

instance Extension ExtAuthorityInfoAccess where
    extOID = const OidAIA
    extHasNestedASN1 = const True
    extEncode (ExtAuthorityInfoAccess aia) =
        Start Sequence
        : concatMap (\AuthorityInfoAccess {..} ->
                        case aiaMethod of
                            OCSP ->
                                [ Start Sequence
                                , OID $ getObjectID aiaMethod
                                , Other Context 6 aiaLocation
                                , End Sequence
                                ]
                            CAIssuers ->
                                error "encoding CA Issuers is not implemented"
                    ) aia
        ++ [End Sequence]
    extDecode [Start Sequence, End Sequence] =
        Right $ ExtAuthorityInfoAccess []
    extDecode (Start Sequence : encAia) =
        go DecStart encAia []
        where go DecStart (Start Sequence : next) =
                  go DecMethod next
              go DecMethod (OID oid : next) =
                  go (DecLocation oid) next
              go (DecLocation (fromObjectID -> Just v)) cur
                  | Other Context _ s : next <- cur =
                      go DecEnd next . (AuthorityInfoAccess v s :)
                  | otherwise =
                      go DecEnd $ End Sequence : snd (getConstructedEnd 0 cur)
              go DecEnd (End Sequence : next@(Start Sequence : _)) =
                  go DecStart next
              go DecEnd [End Sequence, End Sequence] =
                  Right . ExtAuthorityInfoAccess . reverse
              go _ _ =
                  const $ Left "bad AIA sequence"
    extDecode _ =
        Left "bad AIA sequence"

