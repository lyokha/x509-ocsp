{-# LANGUAGE LambdaCase, PatternSynonyms #-}

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
                      ,OCSPResponseStatus (..)
                      ,OCSPResponseCertStatus (..)
                      ,OCSPResponse (..)
                      ,OCSPResponsePayload (..)
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
                       : Start Sequence : OID _ : _ : End Sequence
                       : v@(BitString _)
                       : _ -> L.drop 1 $ encodeASN1 DER $ pure v
                   _ -> error "bad pubkey sequence"

-- | Certificate Id.
--
-- This data is used when building OCSP requests and parsing OCSP responses.
data CertId = CertId { certIdIssuerNameHash :: ByteString
                       -- ^ Value of /issuerNameHash/ as defined in /rfc6960/
                     , certIdPubKeyHash :: ByteString
                       -- ^ Value of /issuerKeyHash/ as defined in /rfc6960/
                     , certIdSerialNumber :: Integer
                       -- ^ Serial number of checked certificate
                     } deriving (Show, Eq)

-- | Build and encode OCSP request into ASN1 format.
--
-- Returns encoded request with an object of type 'CertId' which contains
-- hashes calculated using /SHA1/ algorithm.
encodeOCSPRequestASN1
    :: Certificate              -- ^ Issuer certificate
    -> Certificate              -- ^ Checked certificate
    -> ([ASN1], CertId)
encodeOCSPRequestASN1 issuerCert cert =
    let h1 = issuerDNHash cert
        h2 = pubKeyHash issuerCert
        sn = certSerial cert
    in ([Start Sequence
        ,Start Sequence
        ,Start Sequence
        ,Start Sequence
        ,Start Sequence
        ,Start Sequence
        ,OID OidAlgorithmSHA1
        ,Null
        ,End Sequence
        ,OctetString h1
        ,OctetString h2
        ,IntVal sn
        ,End Sequence
        ,End Sequence
        ,End Sequence
        ,End Sequence
        ,End Sequence
        ]
       ,CertId h1 h2 sn
       )

-- | Build and encode OCSP request into ASN1 DER format.
--
-- Returns encoded request with an object of type 'CertId' which contains
-- hashes calculated using /SHA1/ algorithm.
encodeOCSPRequest
    :: Certificate              -- ^ Issuer certificate
    -> Certificate              -- ^ Checked certificate
    -> (L.ByteString, CertId)
encodeOCSPRequest = (first (encodeASN1 DER) .) . encodeOCSPRequestASN1

-- | Status of the OCSP response as defined in /rfc6960/.
data OCSPResponseStatus = OCSPRespSuccessful
                        | OCSPRespMalformedRequest
                        | OCSPRespInternalError
                        | OCSPRespUnused1
                        | OCSPRespTryLater
                        | OCSPRespSigRequired
                        | OCSPRespUnauthorized
                        deriving (Show, Eq, Bounded, Enum)

-- | Status of the checked certificate as defined in /rfc6960/.
data OCSPResponseCertStatus = OCSPRespCertGood
                            | OCSPRespCertRevoked
                            | OCSPRespCertUnknown
                            deriving (Show, Eq, Bounded, Enum)

-- | OCSP response data.
data OCSPResponse =
    OCSPResponse { ocspRespStatus :: OCSPResponseStatus
                   -- ^ Response status
                 , ocspRespPayload :: Maybe OCSPResponsePayload
                   -- ^ Response payload data
                 } deriving (Show, Eq)

-- | OCSP response payload data.
data OCSPResponsePayload =
    OCSPResponsePayload { ocspRespCertStatus :: OCSPResponseCertStatus
                          -- ^ Status of checked certificate
                        , ocspRespData :: [ASN1]
                          -- ^ Whole response payload
                        } deriving (Show, Eq)

-- | Decode OCSP response.
--
-- Value of the /certificate id/ is expected to be equal to what was returned
-- by 'encodeOCSPRequest': it is used to check the correctness of the response.
decodeOCSPResponse
    :: CertId                   -- ^ Certificate Id
    -> L.ByteString             -- ^ OCSP response
    -> Either ASN1Error (Maybe OCSPResponse)
decodeOCSPResponse certId resp = decodeASN1 DER resp >>= \case
    [ Start Sequence
      , Enumerated v
      , End Sequence
      ] -> return $ Just $ OCSPResponse (toEnum $ fromIntegral v) Nothing
    [ Start Sequence
      , Enumerated v
      , Start (Container Context 0)
      , Start Sequence
      , OID OidBasicOCSPResponse
      , OctetString resp'
      , End Sequence
      , End (Container Context 0)
      , End Sequence
      ] -> do
          pl <- decodeASN1 DER $ L.fromStrict resp'
          let sr = case pl of
                       ( Start Sequence
                         : Start Sequence
                         : Start (Container Context 1)
                         : c1
                         ) -> fst $ getConstructedEnd 0 $ drop 2 $ snd $
                             getConstructedEnd 0 c1
                       _ -> []
          return $ case sr of
                       (Start Sequence
                         : Start Sequence
                         : Start Sequence
                         : OID _
                         : _
                         : End Sequence
                         : OctetString h1
                         : OctetString h2
                         : IntVal sn
                         : End Sequence
                         : certStatus
                         : _
                         ) -> if CertId h1 h2 sn == certId
                                  then case certStatus of
                                           Other Context n _ ->
                                               buildResponse v (toEnum n) pl
                                           Start (Container Context 1) ->
                                               buildResponse v
                                                   OCSPRespCertRevoked pl
                                           _ -> Nothing
                                  else Nothing
                       _ -> Nothing
    _ -> return Nothing
    where buildResponse v n pl = Just $
              OCSPResponse (toEnum $ fromIntegral v) $ Just $
                  OCSPResponsePayload n pl

