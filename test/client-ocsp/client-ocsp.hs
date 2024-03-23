{-# LANGUAGE ViewPatterns, OverloadedStrings #-}

module Main where

import Data.X509
import Data.X509.Validation
import Data.X509.CertificateStore
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
validateWithOCSPReq man store cache sid chain@(CertificateChain certs) =
    validateDefault store cache sid chain >>= flip go certs
    where go [] ((getCertificate -> certS) : (getCertificate -> certI) : _) =
              case extensionGet $ certExtensions certS of
                  Just (ExtAuthorityInfoAccess
                           (dropWhile ((OCSP /=) . aiaMethod) ->
                               AuthorityInfoAccess OCSP url : _
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
                      return $ case decodeOCSPResponse certId resp of
                          Right (Just (OCSPResponse OCSPRespSuccessful
                                          (Just
                                              (OCSPResponsePayload
                                                  (OCSPResponseCertData s _ _) _
                                              )
                                          )
                                      )
                                ) | s == OCSPRespCertGood -> success
                                  | otherwise -> failure $
                                      "OCSP: bad certificate status " ++ show s
                          Right (Just (OCSPResponse s Nothing)) ->
                              failure $ "OCSP: bad response status " ++ show s
                          _ -> failure "OCSP: bad response"
                  _ -> return $
                         failure "OCSP: no OCSP data in server certificate"
          go [] [signedCertS] = do
              let certS = getCertificate signedCertS
              maybe (return $ failure "OCSP: cannot find trusted certificate")
                  (go [] . (signedCertS :) . pure) $
                      findCertificate (certIssuerDN certS) store
          go [] [] =
              return $ failure "OCSP: empty certificate chain"
          go verr _ =
              return verr
          success = []
          failure = pure . CacheSaysNo

main :: IO ()
main = do
    manOCSP <- newManager defaultManagerSettings
    man <- mkManager manOCSP
    req <- parseRequest "https://localhost:8010"
    resp <- httpLbs req man
    C8.putStrLn $ "Response: " <> L.toStrict (responseBody resp)

