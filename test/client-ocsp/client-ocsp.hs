{-# LANGUAGE ViewPatterns, OverloadedStrings, RecordWildCards #-}

module Main where

import Data.X509
import Data.X509.Validation
import Data.X509.CertificateStore
import Data.X509.AIA
import Data.X509.OCSP
import Data.ASN1.Types
import Data.Default.Class
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Char8 as C8
import System.X509
import Time.System
import Data.Hourglass
import Data.Maybe
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Network.Connection
import Network.TLS
import Network.TLS.Extra.Cipher

mkManager :: Manager -> IO Manager
mkManager man = do
    systemCAStore <- getSystemCertificateStore
    newTlsManagerWith $
        mkManagerSettings (TLSSettings $ defaultParams systemCAStore) Nothing
    where defaultParams store = (defaultParamsClient "" "")
              { clientShared = def
                  { sharedCAStore = store }
              , clientHooks = def
                  { onServerCertificate = validateWithOCSPReq man }
              , clientSupported = def
                  { supportedCiphers = ciphersuite_default }
              }

-- Note: (mis)using CacheSaysNo reason on OCSP failures.
validateWithOCSPReq :: Manager -> OnServerCertificate
validateWithOCSPReq man store cache sid
        chain@(CertificateChain (map getCertificate -> certs)) =
    validateDefault store cache sid chain >>= flip go certs
    where go [] (certS : certI : _) =
              case extensionGet $ certExtensions certS of
                  Just (ExtAuthorityInfoAccess
                           (dropWhile ((OCSP /=) . aiaMethod) ->
                               (aiaLocation -> url) : _
                           )
                       ) -> do
                      req <- parseRequest $ C8.unpack url
                      let (body, certId) = encodeOCSPRequest certS certI
                          headers = [ ( "Content-Type"
                                      , "application/ocsp-request"
                                      )
                                    ]
                          req' = req { method = "POST"
                                     , requestHeaders = headers
                                     , requestBody = RequestBodyLBS body
                                     }
                      resp <- responseBody <$> httpLbs req' man
                      case decodeOCSPResponse certId resp of
                          Right (Just (OCSPResponse OCSPRespSuccessful
                                           (Just
                                               (OCSPResponsePayload
                                                   OCSPResponseCertData {..}
                                                   resp'
                                               )
                                           )
                                      )
                                ) -> do
                                    now <- dateCurrent
                                    return $ checks
                                         [ checkCertStatus ocspRespCertStatus
                                         , checkSignature resp' certI
                                         , checkUpdateTime now
                                               ocspRespCertThisUpdate
                                               ocspRespCertNextUpdate
                                         ]
                          Right (Just (OCSPResponse s Nothing)) -> return $
                              failure $ "OCSP: bad response status " <> show s
                          r -> return $
                              failure $ "OCSP: bad response " <> show r
                  _ -> return $
                         failure "OCSP: no OCSP data in server certificate"
              where checkCertStatus OCSPRespCertGood = success
                    checkCertStatus s = failure $
                        "OCSP: bad certificate status " <> show s
                    checkSignature resp cert =
                        case verifySignature' resp cert of
                            SignaturePass -> success
                            SignatureFailed e -> failure $
                                "OCSP: bad signature: " <> show e
                    checkUpdateTime now (ASN1Time TimeGeneralized dttu tuo)
                        (Just (ASN1Time TimeGeneralized dtnu nuo))
                            | globalTime tuo dttu <= now
                            , globalTime nuo dtnu >= now = success
                    checkUpdateTime now (ASN1Time TimeGeneralized dttu tuo)
                        Nothing
                            | globalTime tuo dttu <= now = success
                    checkUpdateTime now tu nu = failure $
                        "OCSP: bad update times: this update: " <> show tu <>
                        ", next update: " <> show nu <> ", now: " <> show now
                    globalTime = (localTimeToGlobal .)
                               . localTime . fromMaybe (TimezoneOffset 0)
          go [] [certS] =
              maybe (return $ failure "OCSP: cannot find trusted certificate")
                  (go [] . (certS :) . pure . getCertificate) $
                      findCertificate (certIssuerDN certS) store
          -- go [] [] is redundant as EmptyChain gets caught in validateDefault
          go verr _ =
              return verr
          success = []
          failure = pure . CacheSaysNo
          checks = foldl1 (<>)

verifySignature' :: [ASN1] -> Certificate -> SignatureVerification
verifySignature' resp certI
    | Just OCSPResponseVerificationData {..} <-
        getOCSPResponseVerificationData' resp =
            case ocspRespCerts of
                (Signed cert alg sig, der) : _
                    | Just (ExtExtendedKeyUsage eku) <-
                        extensionGet $ certExtensions cert
                    , KeyUsagePurpose_OCSPSigning `elem` eku ->
                        case verifySignature alg (certPubKey certI) der sig of
                            SignaturePass -> verifySignature
                                ocspRespSignatureAlg (certPubKey cert)
                                    ocspRespDer ocspRespSignature
                            v -> v
                _ -> verifySignature ocspRespSignatureAlg (certPubKey certI)
                         ocspRespDer ocspRespSignature
    | otherwise = SignatureFailed SignatureInvalid

main :: IO ()
main = do
    manOCSP <- newManager defaultManagerSettings
    man <- mkManager manOCSP
    req <- parseRequest "https://localhost:8010"
    resp <- httpLbs req man
    C8.putStrLn $ "Response: " <> L.toStrict (responseBody resp)

