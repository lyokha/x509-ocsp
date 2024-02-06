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
import Data.List
 
toCertificate :: ByteString -> Certificate
toCertificate cert = either error getCertificate $ do
    pem <- pemParseBS cert >>= maybe (Left "no pems") (pure . fst) . uncons
    decodeSignedObject $ pemContent pem
 
testAIA :: Certificate -> Test
testAIA cert = TestCase $ getAIAFromCert @?= expected
    where getAIAFromCert =
              let Extensions exts = certExtensions cert
              in exts >>= find isExtAIA >>= extensionDecode
          expected = Just $ Right $
              ExtAuthorityInfoAccess
                  [AuthorityInfoAccess { aiaMethod = OCSP
                                       , aiaLocation = "http://localhost:8081"
                                       }
                  ]
 
testOCSPRequestASN1 :: Certificate -> Certificate -> [ASN1] -> Test
testOCSPRequestASN1 issuerCert cert = TestCase . (buildRequest @?=)
    where buildRequest = encodeOCSPRequestASN1 issuerCert cert
 
testOCSPRequest :: Certificate -> Certificate -> ByteString -> Test
testOCSPRequest issuerCert cert = TestCase . (buildRequest @?=) . L.fromStrict
    where buildRequest = encodeOCSPRequest issuerCert cert
 
testOCSPResponse :: ByteString -> Test
testOCSPResponse resp = TestCase $ getRespStatus @?= Just OCSPRespSuccessful
    where getRespStatus =
              either (const Nothing) (pure . getOCSPResponseStatus) $
                  decodeOCSPResponse $ L.fromStrict resp

main :: IO ()
main = do
    certS <- toCertificate <$> B.readFile "test/data/certs/server/server.crt"
    certR <- toCertificate <$> B.readFile "test/data/certs/root/rootCA.crt"

    reqDer <- B.readFile "test/data/req.der"
    let req = either (error . show) id $ decodeASN1 DER $ L.fromStrict reqDer

    respDer <- B.readFile "test/data/resp.der"

    runTestTTAndExit $ TestList
        [TestLabel "testAIA"             $ testAIA certS
        ,TestLabel "testOCSPRequestASN1" $ testOCSPRequestASN1 certR certS req
        ,TestLabel "testOCSPRequest"     $ testOCSPRequest certR certS reqDer
        ,TestLabel "testOCSPResponse"    $ testOCSPResponse respDer
        ]

