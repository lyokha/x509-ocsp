{-# LANGUAGE PatternSynonyms, ViewPatterns, LambdaCase #-}

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
-- Encode and decode X509 OCSP requests and responses.
--
-- This module complies with /rfc6960/.
-----------------------------------------------------------------------------

module Data.X509.OCSP (CertId (..)
                      ,encodeOCSPRequestASN1
                      ,encodeOCSPRequest
                      ,OCSPResponse (..)
                      ,OCSPResponseStatus (..)
                      ,OCSPResponsePayload (..)
                      ,OCSPResponseCertData (..)
                      ,OCSPResponseCertStatus (..)
                      ,decodeOCSPResponse
                      ) where

import Data.X509
import Data.ASN1.Types
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.ASN1.Stream
import Data.ASN1.Error
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as L
import Data.Int
import Data.Word
import Data.Bits
import Crypto.Hash.SHA1
import Control.Arrow

pattern OidAlgorithmSHA1 :: [Integer]
pattern OidAlgorithmSHA1 = [1, 3, 14, 3, 2, 26]

pattern OidBasicOCSPResponse :: [Integer]
pattern OidBasicOCSPResponse = [1, 3, 6, 1, 5, 5, 7, 48, 1, 1]

derLWidth :: Word8 -> Int64
derLWidth x | testBit x 7 = succ $ fromIntegral $ x .&. 0x7f
            | otherwise = 1

issuerDNHash :: Certificate -> ByteString
issuerDNHash cert = hashlazy $ encodeASN1 DER dn
    where dn = toASN1 (certIssuerDN cert) []

pubKeyHash :: Certificate -> ByteString
pubKeyHash cert = hashlazy $ L.drop (succ $ derLWidth $ L.head pk) pk
    where pk = case toASN1 (certPubKey cert) [] of
                   Start Sequence
                     : Start Sequence
                     : OID _
                     : _
                     : End Sequence
                     : v@(BitString _)
                     : _ -> L.drop 1 $ encodeASN1 DER $ pure v
                   _ -> error "bad pubkey sequence"

-- | Certificate Id.
--
-- This data is used when building OCSP requests and parsing OCSP responses.
data CertId = CertId { certIdIssuerNameHash :: ByteString
                       -- ^ Value of /issuerNameHash/ as defined in /rfc6960/
                     , certIdIssuerKeyHash :: ByteString
                       -- ^ Value of /issuerKeyHash/ as defined in /rfc6960/
                     , certIdSerialNumber :: Integer
                       -- ^ Certificate serial number
                     } deriving (Show, Eq)

-- | Build and encode OCSP request in ASN1 format.
--
-- The returned value contains the encoded request and an object of type
-- 'CertId' with hashes calculated by /SHA1/ algorithm.
encodeOCSPRequestASN1
    :: Certificate              -- ^ Certificate
    -> Certificate              -- ^ Issuer certificate
    -> ([ASN1], CertId)
encodeOCSPRequestASN1 cert issuerCert =
    let h1 = issuerDNHash cert
        h2 = pubKeyHash issuerCert
        sn = certSerial cert
    in ( [ Start Sequence
         , Start Sequence
         , Start Sequence
         , Start Sequence
         , Start Sequence
         , Start Sequence
         , OID OidAlgorithmSHA1
         , Null
         , End Sequence
         , OctetString h1
         , OctetString h2
         , IntVal sn
         , End Sequence
         , End Sequence
         , End Sequence
         , End Sequence
         , End Sequence
         ]
       , CertId h1 h2 sn
       )

-- | Build and encode OCSP request in ASN1 DER format.
--
-- The returned value contains the encoded request and an object of type
-- 'CertId' with hashes calculated by /SHA1/ algorithm.
encodeOCSPRequest
    :: Certificate              -- ^ Certificate
    -> Certificate              -- ^ Issuer certificate
    -> (L.ByteString, CertId)
encodeOCSPRequest = (first (encodeASN1 DER) .) . encodeOCSPRequestASN1

-- | OCSP response data.
data OCSPResponse =
    OCSPResponse { ocspRespStatus :: OCSPResponseStatus
                   -- ^ Response status
                 , ocspRespPayload :: Maybe OCSPResponsePayload
                   -- ^ Response payload data
                 } deriving (Show, Eq)

-- | Status of OCSP response as defined in /rfc6960/.
data OCSPResponseStatus = OCSPRespSuccessful
                        | OCSPRespMalformedRequest
                        | OCSPRespInternalError
                        | OCSPRespUnused1
                        | OCSPRespTryLater
                        | OCSPRespSigRequired
                        | OCSPRespUnauthorized
                        deriving (Show, Eq, Bounded, Enum)

-- | Payload data of OCSP response.
data OCSPResponsePayload =
    OCSPResponsePayload { ocspRespCertData :: OCSPResponseCertData
                          -- ^ Selected certificate data
                        , ocspRespData :: [ASN1]
                          -- ^ Whole response payload
                        } deriving (Show, Eq)

-- | Selected certificate data of OCSP response.
data OCSPResponseCertData =
    OCSPResponseCertData { ocspRespCertStatus :: OCSPResponseCertStatus
                           -- ^ Certificate status
                         , ocspRespCertThisUpdate :: ASN1
                           -- ^ Value of /thisUpdate/ as defined in /rfc6960/
                         , ocspRespCertNextUpdate :: Maybe ASN1
                           -- ^ Value of /nextUpdate/ as defined in /rfc6960/
                         } deriving (Show, Eq)

-- | Certificate status of OCSP response as defined in /rfc6960/.
data OCSPResponseCertStatus = OCSPRespCertGood
                            | OCSPRespCertRevoked
                            | OCSPRespCertUnknown
                            deriving (Show, Eq, Bounded, Enum)

-- | Decode OCSP response.
--
-- The value of the /certificate id/ is expected to be equal to what was
-- returned by 'encodeOCSPRequest' as it is used to check the correctness of
-- the response.
--
-- The /Left/ value gets returned on parse errors detected by 'decodeASN1'.
-- The /Right/ value with /Nothing/ gets returned on unexpected ASN.1 contents.
decodeOCSPResponse
    :: CertId                   -- ^ Certificate Id
    -> L.ByteString             -- ^ OCSP response
    -> Either ASN1Error (Maybe OCSPResponse)
decodeOCSPResponse certId resp = decodeASN1 DER resp >>= \case
    [ Start Sequence
      , Enumerated (toEnum . fromIntegral -> v)
      , End Sequence
      ] -> Right $ Just $ OCSPResponse v Nothing
    [ Start Sequence
      , Enumerated (toEnum . fromIntegral -> v)
      , Start (Container Context 0)
      , Start Sequence
      , OID OidBasicOCSPResponse
      , OctetString resp'
      , End Sequence
      , End (Container Context 0)
      , End Sequence
      ] -> do
          pl <- decodeASN1 DER $ L.fromStrict resp'
          Right $
              case pl of
                  Start Sequence
                    : Start Sequence
                    : Start (Container Context ctx)
                    : c1 | ctx `elem` [0..2] -> do
                        let skipVersion =
                                if ctx == 0
                                    then drop 1 . skipCurrentContainer
                                    else id
                        Just $ getCurrentContainerContents $
                            drop 2 $ skipCurrentContainer $ skipVersion c1
                  _ -> Nothing
              >>= \case
                      Start Sequence
                        : Start Sequence
                        : Start Sequence
                        : OID _
                        : _
                        : End Sequence
                        : OctetString h1
                        : OctetString h2
                        : IntVal sn
                        : End Sequence
                        : c2 | CertId h1 h2 sn == certId ->
                            case c2 of
                                Other Context (toEnum -> n) _
                                  : c3 -> Just (n, c3)
                                Start (Container Context (toEnum -> n))
                                  : c3 -> Just (n, skipCurrentContainer c3)
                                _ -> Nothing
                      _ -> Nothing
              >>= \(n, tc1) -> case tc1 of
                                   tu@(ASN1Time TimeGeneralized _ _)
                                     : c4 -> Just (n, tu, c4)
                                   _ -> Nothing
              >>= \(st, tu, tc2) -> do
                  let nu = case tc2 of
                               Start (Container Context 0)
                                 : t@(ASN1Time TimeGeneralized _ _)
                                 : End (Container Context 0)
                                 : _ -> Just t
                               _ -> Nothing
                  Just $ OCSPResponse v $
                      Just $ OCSPResponsePayload
                          (OCSPResponseCertData st tu nu) pl
    _ -> Right Nothing
    where getCurrentContainerContents = fst . getConstructedEnd 0
          skipCurrentContainer = snd . getConstructedEnd 0

