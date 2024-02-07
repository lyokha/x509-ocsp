{-# LANGUAGE OverloadedStrings #-}

module Main where

import Data.X509.AIA
import Data.X509.OCSP
import Data.X509
import Data.PEM
import Test.HUnit
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.ASN1.Types
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.List (uncons)
import Control.Monad
 
toCertificate :: ByteString -> Certificate
toCertificate cert = either error getCertificate $ do
    pem <- pemParseBS cert >>= maybe (Left "no pems") (pure . fst) . uncons
    decodeSignedObject $ pemContent pem
 
testAIA :: Certificate -> Test
testAIA cert = TestCase $ extensionGet (certExtensions cert) @?= expected
    where expected = Just $
              ExtAuthorityInfoAccess
                  [AuthorityInfoAccess { aiaMethod = OCSP
                                       , aiaLocation = "http://localhost:8081"
                                       }
                  ]
 
testOCSPRequestASN1 :: Certificate -> Certificate -> [ASN1] -> Test
testOCSPRequestASN1 issuerCert cert = TestCase . (buildRequest @?=)
    where buildRequest = fst $ encodeOCSPRequestASN1 issuerCert cert
 
testOCSPRequest :: Certificate -> Certificate -> ByteString -> Test
testOCSPRequest issuerCert cert = TestCase . (buildRequest @?=) . L.fromStrict
    where buildRequest = fst $ encodeOCSPRequest issuerCert cert
 
testOCSPResponse :: CertId -> ByteString -> Test
testOCSPResponse certId resp =
    TestCase $ getRespStatus @?= Just OCSPRespCertGood
    where getRespStatus = either (const Nothing)
              (fmap ocspRespPayload >=> fmap ocspRespCertStatus) $
                  decodeOCSPResponse certId $ L.fromStrict resp

main :: IO ()
main = do
    certS <- toCertificate <$> B.readFile "test/data/certs/server/server.crt"
    certR <- toCertificate <$> B.readFile "test/data/certs/root/rootCA.crt"

    let certId = snd $ encodeOCSPRequestASN1 certR certS

    reqDer <- B.readFile "test/data/req.der"
    let req = either (error . show) id $ decodeASN1 DER $ L.fromStrict reqDer

    respDer <- B.readFile "test/data/resp.der"

    runTestTTAndExit $ TestList
        [TestLabel "testAIA"             $ testAIA certS
        ,TestLabel "testOCSPRequestASN1" $ testOCSPRequestASN1 certR certS req
        ,TestLabel "testOCSPRequest"     $ testOCSPRequest certR certS reqDer
        ,TestLabel "testOCSPResponse"    $ testOCSPResponse certId respDer
        ]

