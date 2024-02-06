{-# LANGUAGE ViewPatterns, TypeApplications #-}

-----------------------------------------------------------------------------
-- |
-- Module      :  Data.X509.OCSP
-- Copyright   :  (c) Alexey Radkov 2024
-- License     :  BSD-style
--
-- Maintainer  :  alexey.radkov@gmail.com
-- Stability   :  experimental
-- Portability :  portable
--
-- Encode and decode X509 OCSP request and response.
--
-- This module complies with /rfc6960/.
-----------------------------------------------------------------------------

module Data.X509.OCSP (encodeOCSPRequestASN1
                      ,encodeOCSPRequest
                      ,decodeOCSPResponse
                      ,OCSPResponseStatus (..)
                      ,getOCSPResponseStatus
                      ) where

import Data.X509
import Data.ASN1.Types
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.ASN1.Error
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as L
import Data.Int
import Data.Word
import Data.Bits
import Crypto.Hash.SHA1

derLWidth :: Word8 -> Int64
derLWidth x | testBit x 7 = succ $ fromIntegral $ x .&. 0x7f
            | otherwise = 1

-- | Value of the passed certificate's /issuerNameHash/ according to /rfc6960/.
issuerDNHash :: Certificate -> ByteString
issuerDNHash cert = hashlazy $ encodeASN1 DER dn
    where dn = toASN1 (certIssuerDN cert) []

-- | Value of the passed certificate's /issuerKeyHash/ according to /rfc6960/.
pubKeyHash :: Certificate -> ByteString
pubKeyHash cert = hashlazy $ L.drop (succ $ derLWidth $ L.head pk) pk
    where pk = case toASN1 (certPubKey cert) [] of
                   Start Sequence
                       : Start Sequence : OID _ : _ : End Sequence
                       : v@(BitString _)
                       : _ -> L.drop 1 $ encodeASN1 DER $ pure v
                   _ -> error "bad pubkey sequence"

-- | Build and encode OCSP request into ASN1 format.
encodeOCSPRequestASN1
    :: Certificate              -- ^ Issuer certificate
    -> Certificate              -- ^ Certificate
    -> [ASN1]
encodeOCSPRequestASN1 issuerCert cert = [Start Sequence
                                        ,Start Sequence
                                        ,Start Sequence
                                        ,Start Sequence
                                        ,Start Sequence
                                        ,Start Sequence
                                        ,OID [1, 3, 14, 3, 2, 26]
                                        ,Null
                                        ,End Sequence
                                        ,OctetString $ issuerDNHash cert
                                        ,OctetString $ pubKeyHash issuerCert
                                        ,IntVal $ certSerial cert
                                        ,End Sequence
                                        ,End Sequence
                                        ,End Sequence
                                        ,End Sequence
                                        ,End Sequence
                                        ]

-- | Build and encode OCSP request into ASN1 DER format.
encodeOCSPRequest
    :: Certificate              -- ^ Issuer certificate
    -> Certificate              -- ^ Certificate
    -> L.ByteString
encodeOCSPRequest = (encodeASN1 DER .) . encodeOCSPRequestASN1

-- | Decode OCSP response into ASN1 format.
decodeOCSPResponse
    :: L.ByteString             -- ^ OCSP response
    -> Either ASN1Error [ASN1]
decodeOCSPResponse = decodeASN1 DER

-- | Status of the OCSP response as defined in /rfc6960/.
data OCSPResponseStatus = OCSPRespSuccessful
                        | OCSPRespMalformedRequest
                        | OCSPRespInternalError
                        | OCSPRespUnused1
                        | OCSPRespTryLater
                        | OCSPRespSigRequired
                        | OCSPRespUnauthorized
                        deriving (Show, Eq, Bounded, Enum)

-- | Get status of the OCSP response from its ASN1 description.
getOCSPResponseStatus :: [ASN1] -> OCSPResponseStatus
getOCSPResponseStatus (Start Sequence : Enumerated (fromIntegral -> v) : _)
    | v <= fromEnum (maxBound @OCSPResponseStatus) = toEnum v
getOCSPResponseStatus _ = error "bad OCSP response"

