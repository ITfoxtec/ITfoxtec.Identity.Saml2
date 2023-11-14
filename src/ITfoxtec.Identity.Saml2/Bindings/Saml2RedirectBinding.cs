﻿using ITfoxtec.Identity.Saml2.Cryptography;
using ITfoxtec.Identity.Saml2.Http;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Util;

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

namespace ITfoxtec.Identity.Saml2
{
    public class Saml2RedirectBinding : Saml2Binding<Saml2RedirectBinding>
    {
        public Uri RedirectLocation { get; protected set; }

        public string Signature { get; protected set; }

        protected override Saml2RedirectBinding BindInternal(Saml2Request saml2RequestResponse, string messageName)
        {
            base.BindInternal(saml2RequestResponse);

            if (saml2RequestResponse is Saml2AuthnResponse)
            {
                if (saml2RequestResponse.Config.AuthnResponseSignType != Saml2AuthnResponseSignTypes.SignResponse)
                    throw new InvalidSaml2BindingException($"Redirect binding do not support {saml2RequestResponse.Config.AuthnResponseSignType}, only {nameof(Saml2AuthnResponseSignTypes.SignResponse)} is supported.");

                if (saml2RequestResponse.Config.EncryptionCertificate != null)
                    throw new InvalidSaml2BindingException("Redirect binding do not support authn response encryption, only supported by post binding.");
            }

            if ((!(saml2RequestResponse is Saml2AuthnRequest) || saml2RequestResponse.Config.SignAuthnRequest) && saml2RequestResponse.Config.SigningCertificate != null)
            {
                Cryptography.SignatureAlgorithm.ValidateAlgorithm(saml2RequestResponse.Config.SignatureAlgorithm);
                Cryptography.XmlCanonicalizationMethod.ValidateCanonicalizationMethod(saml2RequestResponse.Config.XmlCanonicalizationMethod);
                SignatureAlgorithm = saml2RequestResponse.Config.SignatureAlgorithm;
                XmlCanonicalizationMethod = saml2RequestResponse.Config.XmlCanonicalizationMethod;
            }

            var requestQueryString = string.Join("&", RequestQueryString(saml2RequestResponse, messageName));
            if ((!(saml2RequestResponse is Saml2AuthnRequest) || saml2RequestResponse.Config.SignAuthnRequest) && saml2RequestResponse.Config.SigningCertificate != null)
            {
                requestQueryString = SigneQueryString(requestQueryString, saml2RequestResponse.Config.SigningCertificate);
            }

            RedirectLocation = new Uri(string.Join(saml2RequestResponse.Destination.OriginalString.Contains('?') ? "&" : "?", saml2RequestResponse.Destination.OriginalString, requestQueryString));

            return this;
        }

        private string SigneQueryString(string queryString, X509Certificate2 signingCertificate)
        {
            var saml2Signed = new Saml2SignedText(signingCertificate, SignatureAlgorithm);
            Signature = Convert.ToBase64String(saml2Signed.SignData(Encoding.UTF8.GetBytes(queryString)));

            return string.Join("&", queryString, string.Join("=", Saml2Constants.Message.Signature, Uri.EscapeDataString(Signature)));
        }

        private IEnumerable<string> RequestQueryString(Saml2Request saml2RequestResponse, string messageName)
        {
            yield return string.Join("=", messageName, Uri.EscapeDataString(CompressRequest()));

            if (!string.IsNullOrWhiteSpace(RelayState))
            {
                yield return string.Join("=", Saml2Constants.Message.RelayState, Uri.EscapeDataString(RelayState));
            }

            if ((!(saml2RequestResponse is Saml2AuthnRequest) || saml2RequestResponse.Config.SignAuthnRequest) && saml2RequestResponse.Config.SigningCertificate != null)
            {
                yield return string.Join("=", Saml2Constants.Message.SigAlg, Uri.EscapeDataString(SignatureAlgorithm));
            }
        }

        private string CompressRequest()
        {
            using (var compressedStream = new MemoryStream())
            using (var deflateStream = new DeflateStream(compressedStream, CompressionMode.Compress))
            {
                using (var originalStream = new StreamWriter(deflateStream))
                {
                    originalStream.Write(XmlDocument.OuterXml);
                }

                return Convert.ToBase64String(compressedStream.ToArray());
            }
        }

        protected override Saml2Request UnbindInternal(HttpRequest request, Saml2Request saml2RequestResponse, string messageName)
        {
            UnbindInternal(request, saml2RequestResponse);

            if (!"GET".Equals(request.Method, StringComparison.InvariantCultureIgnoreCase))
                throw new InvalidSaml2BindingException("Not redirect binding (HTTP GET).");

            if (!request.Query.AllKeys.Contains(messageName))
                throw new Saml2BindingException("HTTP Query String does not contain " + messageName);

            if ((!(saml2RequestResponse is Saml2AuthnRequest) || saml2RequestResponse.Config.SignAuthnRequest) &&
                saml2RequestResponse.SignatureValidationCertificates != null && saml2RequestResponse.SignatureValidationCertificates.Count() > 0)
            {
                if (!request.Query.AllKeys.Contains(Saml2Constants.Message.Signature))
                    throw new Saml2BindingException("HTTP Query String does not contain " + Saml2Constants.Message.Signature);

                if (!request.Query.AllKeys.Contains(Saml2Constants.Message.SigAlg))
                    throw new Saml2BindingException("HTTP Query String does not contain " + Saml2Constants.Message.SigAlg);
            }

            if (request.Query.AllKeys.Contains(Saml2Constants.Message.RelayState))
            {
                RelayState = request.Query[Saml2Constants.Message.RelayState];
            }

            if ((!(saml2RequestResponse is Saml2AuthnRequest) || saml2RequestResponse.Config.SignAuthnRequest) &&
                saml2RequestResponse.SignatureValidationCertificates != null && saml2RequestResponse.SignatureValidationCertificates.Count() > 0)
            {
                var actualSignatureAlgorithm = request.Query[Saml2Constants.Message.SigAlg];
                if (saml2RequestResponse.SignatureAlgorithm == null)
                {
                    saml2RequestResponse.SignatureAlgorithm = actualSignatureAlgorithm;
                }
                else if (!saml2RequestResponse.SignatureAlgorithm.Equals(actualSignatureAlgorithm, StringComparison.InvariantCulture))
                {
                    throw new Exception($"Signature Algorithm do not match. Expected algorithm {saml2RequestResponse.SignatureAlgorithm} actual algorithm {actualSignatureAlgorithm}");
                }

                if (saml2RequestResponse.XmlCanonicalizationMethod == null)
                {
                    saml2RequestResponse.XmlCanonicalizationMethod = saml2RequestResponse.Config.XmlCanonicalizationMethod;
                }

                Cryptography.SignatureAlgorithm.ValidateAlgorithm(saml2RequestResponse.SignatureAlgorithm);
                Cryptography.XmlCanonicalizationMethod.ValidateCanonicalizationMethod(saml2RequestResponse.XmlCanonicalizationMethod);
                SignatureAlgorithm = saml2RequestResponse.SignatureAlgorithm;
                XmlCanonicalizationMethod = saml2RequestResponse.XmlCanonicalizationMethod;

                Signature = request.Query[Saml2Constants.Message.Signature];
                ValidateQueryStringSignature(saml2RequestResponse, request.QueryString, messageName, Convert.FromBase64String(Signature), saml2RequestResponse.SignatureValidationCertificates);
            }

            return Read(request, saml2RequestResponse, messageName, false, true);
        }

        protected override Saml2Request Read(HttpRequest request, Saml2Request saml2RequestResponse, string messageName, bool validate, bool detectReplayedTokens)
        {
            if (!"GET".Equals(request.Method, StringComparison.InvariantCultureIgnoreCase))
                throw new InvalidSaml2BindingException("Not redirect binding (HTTP GET).");

            if (!request.Query.AllKeys.Contains(messageName))
                throw new Saml2BindingException("HTTP Query String does not contain " + messageName);

            if (request.Query.AllKeys.Contains(Saml2Constants.Message.RelayState))
            {
                RelayState = request.Query[Saml2Constants.Message.RelayState];
            }

            saml2RequestResponse.Read(DecompressResponse(request.Query[messageName]), validate, detectReplayedTokens);
            XmlDocument = saml2RequestResponse.XmlDocument;
            return saml2RequestResponse;
        }

        protected override bool IsRequestResponseInternal(HttpRequest request, string messageName)
        {
            return (request.Query?.AllKeys?.Contains(messageName)).GetValueOrDefault(false);
        }

        private void ValidateQueryStringSignature(Saml2Request saml2RequestResponse, string queryString, string messageName, byte[] signatureValue, IEnumerable<X509Certificate2> signatureValidationCertificates)
        {
            foreach (var signatureValidationCertificate in signatureValidationCertificates)
            {
                var saml2Sign = new Saml2SignedText(signatureValidationCertificate, SignatureAlgorithm);
                if (saml2Sign.CheckSignature(Encoding.UTF8.GetBytes(new RawSaml2QueryString(queryString, messageName).SignedQueryString), signatureValue))
                {
                    // Check if certificate used to sign is valid
                    saml2RequestResponse.IdentityConfiguration.CertificateValidator.Validate(signatureValidationCertificate);

                    // Signature is valid.
                    return;
                }
            }
            throw new InvalidSignatureException("Signature is invalid.");
        }

        private string DecompressResponse(string value)
        {
            using (var originalStream = new MemoryStream(Convert.FromBase64String(value)))
            using (var decompressedStream = new MemoryStream())
            {
                using (var deflateStream = new DeflateStream(originalStream, CompressionMode.Decompress))
                {
                    deflateStream.CopyTo(decompressedStream);
                }
                return Encoding.UTF8.GetString(decompressedStream.ToArray());
            }
        }
    }
}
