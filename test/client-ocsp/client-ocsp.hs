{-# LANGUAGE ViewPatterns, OverloadedStrings #-}

module Main where

import Data.X509
import Data.X509.Validation
import Data.X509.AIA
import Data.X509.OCSP
import Data.Default.Class
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Char8 as C8
import System.X509
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
validateWithOCSPReq man store cache sid chain = do
    verr <- validateDefault store cache sid chain
    if null verr
        then case chain of
                 CertificateChain [ getCertificate -> certS
                                  , getCertificate -> certR
                                  ] -> do
                     case extensionGet $ certExtensions certS of
                         Just (ExtAuthorityInfoAccess
                                        (AuthorityInfoAccess OCSP url : _)
                              ) -> do
                             req <- parseRequest $ C8.unpack url
                             let (body, certId) = encodeOCSPRequest certR certS
                                 req' = req { method = "POST"
                                            , requestHeaders = headers
                                            , requestBody = RequestBodyLBS body
                                            }
                             resp <- responseBody <$> httpLbs req' man
                             return $ case decodeOCSPResponse certId resp of
                                 Right (Just (OCSPResponse OCSPRespSuccessful
                                                 (Just
                                                     (OCSPResponsePayload s _)
                                                 )
                                             )
                                       ) ->
                                     if s == OCSPRespCertGood
                                         then success
                                         else failure $
                                            "OCSP: bad certificate status " ++
                                                show s
                                 Right (Just (OCSPResponse s _)) ->
                                     failure $ "OCSP: bad response status " ++
                                         show s
                                 _ -> failure "OCSP: bad response"
                         _ -> return $ failure
                                "OCSP: no OCSP data in server certificate"
                 _ -> return $ failure
                        "OCSP: unexpected size of certificate chain"
        else return verr
    where headers = [("Content-Type", "application/ocsp-request")]
          success = []
          failure = pure . CacheSaysNo

main :: IO ()
main = do
    manOCSP <- newManager defaultManagerSettings
    man <- mkManager manOCSP
    req <- parseRequest "https://localhost:8010"
    resp <- httpLbs req man
    C8.putStrLn $ "Response: " <> L.toStrict (responseBody resp)

