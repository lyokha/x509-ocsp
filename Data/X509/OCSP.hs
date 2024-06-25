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

module Data.X509.OCSP (
    -- * Shared data
                       CertId (..)
    -- * OCSP request
                      ,encodeOCSPRequestASN1
                      ,encodeOCSPRequest
    -- * OCSP response
                      ,OCSPResponse (..)
                      ,OCSPResponseStatus (..)
                      ,OCSPResponsePayload (..)
                      ,OCSPResponseCertData (..)
                      ,OCSPResponseCertStatus (..)
                      ,decodeOCSPResponse
    -- * OCSP response verification
                      ,OCSPResponseVerificationData (..)
                      ,getOCSPResponseVerificationData
                      ,getOCSPResponseVerificationData'
                      ) where

import Data.X509
import Data.ASN1.Types
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.ASN1.BitArray
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
                     : v@BitString {}
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

-- | Build and encode OCSP request in ASN.1 format.
--
-- The returned value contains the encoded request and an object of type
-- 'CertId' with hashes calculated by the SHA1 algorithm.
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

-- | Build and encode OCSP request in ASN.1\/DER format.
--
-- The returned value contains the encoded request and an object of type
-- 'CertId' with hashes calculated by the SHA1 algorithm.
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
                        , ocspRespASN1 :: [ASN1]
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
          pl <- decodeASN1' DER resp'
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

-- | Verification data from OCSP response payload.
--
-- This data can be used to verify the signature of the OCSP response with
-- 'Data.X509.Validation.verifySignature'. The response is signed with
-- signature /ocspRespSignature/. Binary data /ocspRespDer/ and algorthm
-- /ocspRespSignatureAlg/ are what was used to sign the response. The
-- verification process may require the public key of the issuer certificate
-- if it's not attached in /ocspRespCerts/.
--
-- See details of signing and verification of OCSP responses in /rfc6960/.
--
-- Below is a simple implementation of the OCSP response signature verification.
--
-- @
-- {-# LANGUAGE RecordWildCards #-}
--
-- -- ...
--
-- verifySignature\' :: 'OCSPResponse' -> 'Certificate' -> t'Data.X509.Validation.SignatureVerification'
-- verifySignature\' resp v'Certificate' {..}
--     | Just __/OCSPResponseVerificationData/__ {..} <-
--         'getOCSPResponseVerificationData' resp =
--             'Data.X509.Validation.verifySignature' __/ocspRespSignatureAlg/__ 'certPubKey' __/ocspRespDer/__
--                 __/ocspRespSignature/__
--     | otherwise = 'Data.X509.Validation.SignatureFailed' 'Data.X509.Validation.SignatureInvalid'
-- @
--
-- Note that the issuer certificate gets passed to /verifySignature\'/ rather
-- than looked up in /ocspRespCerts/. The OCSP Signature Authority Delegation
-- is not checked in the function.
--
-- To verify update times, check the values of 'ocspRespCertThisUpdate' and
-- 'ocspRespCertNextUpdate'.
data OCSPResponseVerificationData =
    OCSPResponseVerificationData { ocspRespDer :: ByteString
                                   -- ^ Response data (DER-encoded)
                                 , ocspRespSignatureAlg :: SignatureALG
                                   -- ^ Signature algorithm
                                 , ocspRespSignature :: ByteString
                                   -- ^ Signature
                                 , ocspRespCerts :: [Certificate]
                                   -- ^ Certificates
                                 } deriving (Show, Eq)

-- | Get verification data from OCSP response.
--
-- The function returns /Nothing/ on unexpected ASN.1 contents.
getOCSPResponseVerificationData
    :: OCSPResponse             -- ^ OCSP response
    -> Maybe OCSPResponseVerificationData
getOCSPResponseVerificationData (ocspRespPayload -> Just resp) =
    getOCSPResponseVerificationData' $ ocspRespASN1 resp
getOCSPResponseVerificationData _ = Nothing

-- | Get verification data from OCSP response payload.
--
-- This is a variant of 'getOCSPResponseVerificationData' that accepts the
-- OCSP response payload in ASN.1 format. The function returns /Nothing/ on
-- unexpected ASN.1 contents.
getOCSPResponseVerificationData'
    :: [ASN1]                   -- ^ OCSP response payload
    -> Maybe OCSPResponseVerificationData
getOCSPResponseVerificationData' (Start Sequence : Start Sequence : c1) = do
    let (wrapInSequence -> resp'', next) = getConstructedEnd 0 c1
        der = encodeASN1' DER resp''
    case next of
        Start Sequence : c2 -> do
            let (wrapInSequence -> alg, next') = getConstructedEnd 0 c2
            (alg', _) <- either (const Nothing) Just $ fromASN1 alg
            case next' of
                BitString (BitArray _ sig) : c3
                    | c3 == [End Sequence] ->
                        Just $ OCSPResponseVerificationData
                            der alg' sig []
                    | Start (Container Context 0)
                        : Start Sequence
                        : certs <- getCurrentContainerContents c3 -> do
                            certs' <- reverse <$> collectCerts certs []
                            Just $ OCSPResponseVerificationData
                                der alg' sig certs'
                _ -> Nothing
        _ -> Nothing
    where collectCerts (Start Sequence : c4) certs
              | (Start Sequence : cert, c5) <- getConstructedEnd 0 c4 =
                  case fromASN1 (getCurrentContainerContents cert) of
                      Right (cert', _) -> collectCerts c5 $ cert' : certs
                      _ -> Nothing
          collectCerts [End Sequence, End (Container Context 0)] certs =
              Just certs
          collectCerts _ _ =
              Nothing
          wrapInSequence = (Start Sequence :) . (++ [End Sequence])
getOCSPResponseVerificationData' _ = Nothing

getCurrentContainerContents :: [ASN1] -> [ASN1]
getCurrentContainerContents = fst . getConstructedEnd 0

skipCurrentContainer :: [ASN1] -> [ASN1]
skipCurrentContainer = snd . getConstructedEnd 0

