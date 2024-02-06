{-# LANGUAGE ViewPatterns, OverloadedStrings #-}

module Main where

import Data.X509
import Data.X509.Validation
import Data.X509.AIA
import Data.X509.OCSP
import Data.Default.Class
import Data.List
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Char8 as C8
import System.X509
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Network.Connection
import Network.TLS
import Network.TLS.Extra.Cipher

-- run openssl ocsp -index /dev/null -port 8081 \
--   -rsigner certs/root/rootCA.crt -rkey certs/root/rootCA.key \
--   -CA certs/root/rootCA.crt -text
-- from the upper directory to serve OCSP requests.

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

validateWithOCSPReq :: Manager -> OnServerCertificate
validateWithOCSPReq man store cache sid chain = do
    verr <- validateDefault store cache sid chain
    if null verr
        then case chain of
                 CertificateChain ( (getCertificate -> certS)
                                  : (getCertificate -> certR)
                                  : _
                                  ) -> do
                     let Extensions extsS = certExtensions certS
                         aia = extsS >>= find isExtAIA >>= extensionDecode
                     case aia of
                         Just (Right
                                   (ExtAuthorityInfoAccess
                                        (AuthorityInfoAccess OCSP url : _)
                                   )
                              ) -> do
                             req <- parseRequest $ C8.unpack url
                             let body = encodeOCSPRequest certR certS
                                 req' = req { method = "POST"
                                            , requestHeaders =
                                                  [("Content-Type"
                                                   ,"application/ocsp-request")
                                                  ]
                                            , requestBody = RequestBodyLBS body
                                            }
                             resp <- responseBody <$> httpLbs req' man
                             return $ case decodeOCSPResponse resp of
                                 Right v ->
                                     case getOCSPResponseStatus v of
                                         OCSPRespSuccessful -> []
                                         s -> [CacheSaysNo $
                                                   "OCSP: status " ++ show s
                                              ]
                                 _ -> []
                         _ -> return [CacheSaysNo
                                          "OCSP: no AIA in server certificate"
                                     ]
                 _ -> return [CacheSaysNo
                                  "OCSP: certificate chain is too short"
                             ]
        else return verr

main :: IO ()
main = do
    manOCSP <- newManager defaultManagerSettings
    man <- mkManager manOCSP
    req <- parseRequest "https://localhost:8010"
    resp <- httpLbs req man
    C8.putStrLn $ "Response: " `C8.append` L.toStrict (responseBody resp)

