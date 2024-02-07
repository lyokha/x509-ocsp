{-# LANGUAGE RecordWildCards, PatternSynonyms #-}

-----------------------------------------------------------------------------
-- |
-- Module      :  Data.X509.AIA
-- Copyright   :  (c) Alexey Radkov 2024
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

module Data.X509.AIA (ExtAuthorityInfoAccess (..)
                     ,AuthorityInfoAccess (..)
                     ,AIAMethod (..)
                     ) where

import Data.X509
import Data.ASN1.Types
import Data.ByteString (ByteString)

pattern OidAIA :: [Integer]
pattern OidAIA = [1, 3, 6, 1, 5, 5, 7, 1, 1]

pattern OidOCSP :: [Integer]
pattern OidOCSP = [1, 3, 6, 1, 5, 5, 7, 48, 1]

pattern OidCAIssuers :: [Integer]
pattern OidCAIssuers = [1, 3, 6, 1, 5, 5, 7, 48, 2]

-- | Authority Info Access extension.
newtype ExtAuthorityInfoAccess = ExtAuthorityInfoAccess [AuthorityInfoAccess]
    deriving (Show, Eq)

-- | Authority Info Access description.
data AuthorityInfoAccess = AuthorityInfoAccess { aiaMethod :: AIAMethod
                                               , aiaLocation :: ByteString
                                               } deriving (Show, Eq)

-- | Method of Authority Info Access (OCSP or CA issuers).
data AIAMethod = OCSP | CAIssuers deriving  (Show, Eq)

instance OIDable AIAMethod where
    getObjectID OCSP = OidOCSP
    getObjectID CAIssuers = OidCAIssuers

instance OIDNameable AIAMethod where
    fromObjectID OidOCSP = Just OCSP
    fromObjectID OidCAIssuers = Just CAIssuers
    fromObjectID _ = Nothing

data DecState = DecStart | DecMethod | DecLocation | DecEnd

instance Extension ExtAuthorityInfoAccess where
    extOID = const OidAIA
    extHasNestedASN1 = const True
    extEncode (ExtAuthorityInfoAccess aia) =
        Start Sequence
        : concatMap (\AuthorityInfoAccess {..} ->
                        [ Start Sequence
                        , OID $ getObjectID aiaMethod
                        , Other Context 6 aiaLocation
                        , End Sequence
                        ]
                    ) aia
        ++ [End Sequence]
    extDecode [Start Sequence, End Sequence] =
        Right $ ExtAuthorityInfoAccess []
    extDecode (Start Sequence : encAia) =
        go DecStart Nothing encAia []
        where go DecStart Nothing (Start Sequence : next) =
                  go DecMethod Nothing next
              go DecMethod Nothing (OID v : next) =
                  go DecLocation (Just v) next
              go DecLocation (Just v) (Other Context 6 s : next) =
                  case fromObjectID v of
                      Nothing -> const $ Left "bad AIA method"
                      Just v' -> go DecEnd Nothing next
                                        . (AuthorityInfoAccess v' s :)
              go DecEnd Nothing (End Sequence : next@(Start Sequence : _)) =
                  go DecStart Nothing next
              go DecEnd Nothing [End Sequence, End Sequence] =
                  Right . ExtAuthorityInfoAccess . reverse
              go _ _ _ = const $ Left "bad or incompatible AIA sequence"
    extDecode _ =
        Left "bad AIA sequence"

