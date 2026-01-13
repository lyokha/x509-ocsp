{-# LANGUAGE RecordWildCards, OverloadedStrings #-}

module Main where

import Data.X509.AIA
import Data.X509.OCSP
import Data.X509.Validation
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
testOCSPRequestASN1 cert issuerCert = TestCase . (buildRequest @?=)
    where buildRequest = fst $ encodeOCSPRequestASN1 cert issuerCert

testOCSPRequest :: Certificate -> Certificate -> ByteString -> Test
testOCSPRequest cert issuerCert = TestCase . (buildRequest @?=) . L.fromStrict
    where buildRequest = fst $ encodeOCSPRequest cert issuerCert

testOCSPResponse :: Maybe OCSPResponse -> Test
testOCSPResponse resp =
    TestCase $ getRespStatus @?= Just OCSPRespCertGood
    where getRespStatus = ocspRespCertStatus . ocspRespCertData <$>
              (resp >>= ocspRespPayload)

verifyOCSPResponse :: Certificate -> Maybe OCSPResponse -> Test
verifyOCSPResponse issuerCert resp =
    TestCase $ getVerificationStatus @?= Just SignaturePass
    where getVerificationStatus = (`verifySignature'` issuerCert) <$> resp

verifySignature' :: OCSPResponse -> Certificate -> SignatureVerification
verifySignature' resp Certificate {..}
    | Just OCSPResponseVerificationData {..} <-
        getOCSPResponseVerificationData resp =
            verifySignature ocspRespSignatureAlg certPubKey ocspRespDer
                ocspRespSignature
    | otherwise = SignatureFailed SignatureInvalid

main :: IO ()
main = do
    certS <- toCertificate <$> B.readFile "test/data/certs/server/server.crt"
    certI <- toCertificate <$> B.readFile "test/data/certs/root/rootCA.crt"

    let certId = snd $ encodeOCSPRequestASN1 certS certI

    reqDer <- B.readFile "test/data/req.der"
    let req = showError $ decodeASN1' DER reqDer

    respDer <- B.readFile "test/data/resp.der"
    let resp = showError $ decodeOCSPResponse certId $ L.fromStrict respDer

    runTestTTAndExit $ TestList
        [TestLabel "testAIA"             $ testAIA certS
        ,TestLabel "testOCSPRequestASN1" $ testOCSPRequestASN1 certS certI req
        ,TestLabel "testOCSPRequest"     $ testOCSPRequest certS certI reqDer
        ,TestLabel "testOCSPResponse"    $ testOCSPResponse resp
        ,TestLabel "verifyOCSPResponse"  $ verifyOCSPResponse certI resp
        ]

    where showError = either (error . show) id

